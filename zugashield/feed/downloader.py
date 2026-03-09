"""
ZugaShield Threat Feed — Download, Verify, Extract.

Downloads signature bundles from GitHub Releases, verifies their
cryptographic signatures and SHA-256 hashes, then extracts to a
staging directory for hot-reload.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from zugashield.config import ShieldConfig
from zugashield.feed.checker import Manifest
from zugashield.feed.signer import verify_signature

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def download_and_verify(
    manifest: Manifest,
    config: ShieldConfig,
    state_dir: str,
) -> Optional[Path]:
    """
    Download a signature bundle, verify it, and extract to staging dir.

    Steps:
        1. Download zip to temp dir
        2. Download .minisig signature file
        3. Verify minisign signature (if enabled)
        4. Verify SHA-256 against manifest hash
        5. Extract to ``{state_dir}/signatures-v{version}/``
        6. Run integrity check on extracted files

    Returns:
        Path to the extracted signatures dir, or None on any failure.
    """
    if httpx is None:
        raise ImportError("httpx is required for feed updates: pip install zugashield[feed]")

    state_path = Path(state_dir).expanduser()
    state_path.mkdir(parents=True, exist_ok=True)
    target_dir = state_path / f"signatures-v{manifest.version}"
    tmp_dir = None

    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="zugashield-feed-"))
        zip_path = tmp_dir / f"signatures-v{manifest.version}.zip"
        sig_path = tmp_dir / f"signatures-v{manifest.version}.zip.minisig"

        # 1. Download zip
        logger.info("[feed] Downloading signatures v%s...", manifest.version)
        try:
            with httpx.stream(
                "GET",
                manifest.download_url,
                timeout=config.feed_timeout,
                follow_redirects=True,
            ) as resp:
                resp.raise_for_status()
                with open(zip_path, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=8192):
                        f.write(chunk)
        except Exception as e:
            logger.error("[feed] Download failed: %s", e)
            return None

        # 2. Download minisign signature
        if config.feed_verify_signatures:
            sig_url = f"{manifest.download_url}.minisig"
            try:
                resp = httpx.get(
                    sig_url,
                    timeout=config.feed_timeout,
                    follow_redirects=True,
                )
                resp.raise_for_status()
                sig_path.write_bytes(resp.content)
            except Exception as e:
                logger.error("[feed] Signature download failed: %s", e)
                return None

            # 3. Verify minisign signature
            if not verify_signature(zip_path, sig_path):
                logger.error("[feed] Signature verification FAILED — aborting")
                return None

        # 4. Verify SHA-256
        if manifest.sha256:
            actual_hash = hashlib.sha256(zip_path.read_bytes()).hexdigest()
            if actual_hash != manifest.sha256:
                logger.error(
                    "[feed] SHA-256 mismatch: expected %s, got %s",
                    manifest.sha256[:16],
                    actual_hash[:16],
                )
                return None
            logger.debug("[feed] SHA-256 verified")

        # 5. Extract to staging dir
        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # Security: reject paths that escape the target dir
                for member in zf.namelist():
                    resolved = (target_dir / member).resolve()
                    if not str(resolved).startswith(str(target_dir.resolve())):
                        logger.error("[feed] Zip path traversal detected: %s", member)
                        shutil.rmtree(target_dir)
                        return None
                zf.extractall(target_dir)
        except zipfile.BadZipFile as e:
            logger.error("[feed] Invalid zip file: %s", e)
            shutil.rmtree(target_dir, ignore_errors=True)
            return None

        # 6. Validate extracted signatures using ThreatCatalog integrity check
        try:
            from zugashield.threat_catalog import ThreatCatalog

            test_catalog = ThreatCatalog.__new__(ThreatCatalog)
            test_catalog._verify_integrity = True
            test_catalog._verify_signature_integrity(target_dir)
        except Exception as e:
            logger.error("[feed] Extracted signatures failed integrity check: %s", e)
            shutil.rmtree(target_dir, ignore_errors=True)
            return None

        logger.info(
            "[feed] Downloaded and verified v%s to %s",
            manifest.version,
            target_dir,
        )
        return target_dir

    except Exception as e:
        logger.error("[feed] Unexpected error during download: %s", e)
        if target_dir and target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        return None

    finally:
        # Clean up temp files
        if tmp_dir and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
