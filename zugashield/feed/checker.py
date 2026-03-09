"""
ZugaShield Threat Feed — Update Checker.

Performs conditional HTTP GET against the manifest to detect new
signature releases. Uses ETag headers for zero-cost "no update"
responses (HTTP 304).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from zugashield.config import ShieldConfig
from zugashield.feed.state import UpdateState

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class Manifest:
    """Parsed manifest from a signature release."""

    version: str
    sha256: str
    signature_count: int
    min_client: str
    download_url: str
    etag: str = ""


def _compare_versions(a: str, b: str) -> int:
    """Compare semver strings. Returns >0 if a > b, 0 if equal, <0 if a < b."""
    try:
        a_parts = [int(x) for x in a.split(".")]
        b_parts = [int(x) for x in b.split(".")]
        for x, y in zip(a_parts, b_parts):
            if x != y:
                return x - y
        return len(a_parts) - len(b_parts)
    except (ValueError, AttributeError):
        return 0


def check_for_update(
    config: ShieldConfig,
    state: UpdateState,
) -> Optional[Manifest]:
    """
    Check if a new signature version is available.

    Performs a conditional GET on ``{feed_url}/manifest.json`` using
    the stored ETag. Returns ``None`` if no update is available
    (304 Not Modified) or if the remote version is not newer.

    Returns:
        Manifest if an update is available, None otherwise.
    """
    if httpx is None:
        raise ImportError("httpx is required for feed updates: pip install zugashield[feed]")

    manifest_url = f"{config.feed_url.rstrip('/')}/manifest.json"
    headers = {}
    if state.etag:
        headers["If-None-Match"] = state.etag

    try:
        resp = httpx.get(
            manifest_url,
            headers=headers,
            timeout=config.feed_timeout,
            follow_redirects=True,
        )
    except Exception as e:
        logger.warning("[feed] Manifest fetch failed: %s", e)
        return None

    if resp.status_code == 304:
        logger.debug("[feed] Manifest unchanged (ETag match)")
        return None

    if resp.status_code != 200:
        logger.warning("[feed] Manifest returned HTTP %d", resp.status_code)
        return None

    try:
        data = resp.json()
    except Exception as e:
        logger.warning("[feed] Invalid manifest JSON: %s", e)
        return None

    remote_version = data.get("version", "0.0.0")
    if _compare_versions(remote_version, state.last_applied_version) <= 0:
        logger.debug(
            "[feed] Remote v%s <= local v%s, skipping",
            remote_version,
            state.last_applied_version,
        )
        return None

    # Build download URL — manifest can override, else derive from feed_url
    download_url = data.get(
        "download_url",
        f"{config.feed_url.rstrip('/')}/signatures-v{remote_version}.zip",
    )

    manifest = Manifest(
        version=remote_version,
        sha256=data.get("sha256", ""),
        signature_count=data.get("signature_count", 0),
        min_client=data.get("min_client", "0.0.0"),
        download_url=download_url,
        etag=resp.headers.get("etag", ""),
    )

    # Check minimum client version
    from zugashield._version import __version__

    if _compare_versions(manifest.min_client, __version__) > 0:
        logger.warning(
            "[feed] Signatures v%s require client >= %s (current: %s)",
            manifest.version,
            manifest.min_client,
            __version__,
        )
        return None

    logger.info(
        "[feed] Update available: v%s -> v%s (%d signatures)",
        state.last_applied_version,
        manifest.version,
        manifest.signature_count,
    )
    return manifest
