"""
End-to-end integration test for ZugaShield Threat Feed.

Spins up a mock HTTP server that serves manifest + zip,
then verifies the daemon picks up the update and applies it.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import zipfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Optional

import pytest

from zugashield.config import ShieldConfig
from zugashield.threat_catalog import ThreatCatalog


def _build_test_signatures(sig_dir: Path, version: str = "2.0.0") -> None:
    """Create a minimal valid signatures directory."""
    sig_dir.mkdir(parents=True, exist_ok=True)

    sigs = {
        "name": "Feed Test Signatures",
        "category": "prompt_injection",
        "signatures": [
            {
                "id": "FEED-001",
                "category": "prompt_injection",
                "name": "Feed Test Pattern",
                "description": "New pattern from feed",
                "patterns": ["feed_unique_test_pattern_xyz"],
                "severity": "critical",
                "confidence": 0.99,
                "enabled": True,
            },
        ],
    }

    version_data = {
        "version": version,
        "last_updated": "2026-02-17T12:00:00Z",
        "total_signatures": 1,
    }

    sig_file = sig_dir / "prompt_injection.json"
    sig_file.write_text(json.dumps(sigs), encoding="utf-8")

    version_file = sig_dir / "catalog_version.json"
    version_file.write_text(json.dumps(version_data), encoding="utf-8")

    # Integrity
    integrity = {}
    for f in sig_dir.glob("*.json"):
        integrity[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    (sig_dir / "integrity.json").write_text(json.dumps(integrity), encoding="utf-8")


def _build_release_bundle(
    release_dir: Path, sig_dir: Path, version: str, *, sign: bool = False
) -> dict:
    """Package signatures into a zip and create manifest, optionally signed."""
    release_dir.mkdir(parents=True, exist_ok=True)

    zip_name = f"signatures-v{version}.zip"
    zip_path = release_dir / zip_name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sig_dir.glob("*.json"):
            zf.write(f, f.name)

    sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()

    manifest = {
        "version": version,
        "sha256": sha256,
        "signature_count": 1,
        "min_client": "0.0.1",
    }
    (release_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    if sign:
        from zugashield.feed.signer import sign_file

        # Real secret key matching the hardcoded public key
        sig_content = sign_file(
            zip_path,
            secret_key_hex="e02512b377dec4297c1e9c92f764fd38c10d9291173dcf4754988a859bd86a14",
            key_id_hex="a4ec7e83594ad0aa",
        )
        (release_dir / f"{zip_name}.minisig").write_text(sig_content, encoding="utf-8")

    return manifest


class FeedHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves from a directory with ETag support."""

    etag_value: Optional[str] = '"test-etag-123"'
    serve_directory: str = "."

    def __init__(self, *args, **kwargs):
        # Pass the class-level directory to SimpleHTTPRequestHandler
        super().__init__(*args, directory=self.serve_directory, **kwargs)

    def do_GET(self):
        # ETag support for manifest
        if self.path.endswith("manifest.json"):
            if_none_match = self.headers.get("If-None-Match")
            if if_none_match and if_none_match == self.etag_value:
                self.send_response(304)
                self.end_headers()
                return

        # Serve file normally
        super().do_GET()

    def send_response(self, code, message=None):
        super().send_response(code, message)
        if hasattr(self, 'path') and self.path.endswith("manifest.json") and code == 200:
            self.send_header("ETag", self.etag_value)

    def log_message(self, format, *args):
        pass  # Suppress logs


@pytest.mark.slow
class TestFeedE2E:
    def test_daemon_picks_up_update(self, tmp_path):
        """Full E2E: mock server → daemon poll → hot-reload → new patterns detected."""
        # Build test content
        sig_dir = tmp_path / "new_sigs"
        release_dir = tmp_path / "serve"
        _build_test_signatures(sig_dir, version="2.0.0")
        _build_release_bundle(release_dir, sig_dir, version="2.0.0")

        # Start mock HTTP server
        handler = type("H", (FeedHandler,), {"serve_directory": str(release_dir)})

        # Try a few ports in case one is in use
        server = None
        port = 0
        for p in range(18900, 18910):
            try:
                server = HTTPServer(("127.0.0.1", p), handler)
                port = p
                break
            except OSError:
                continue

        if server is None:
            pytest.skip("Could not bind to any test port")

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # Create catalog and config
            catalog = ThreatCatalog(verify_integrity=False)
            state_dir = str(tmp_path / "state")

            config = ShieldConfig(
                feed_enabled=True,
                feed_url=f"http://127.0.0.1:{port}",
                feed_poll_interval=1,  # Very fast for testing
                feed_startup_jitter=0,
                feed_timeout=5,
                feed_state_dir=state_dir,
                feed_verify_signatures=False,  # No minisign for E2E test
                feed_fail_open=True,
            )

            # Verify the new pattern is NOT detected yet
            detections = catalog.check("feed_unique_test_pattern_xyz")
            assert not any(d.signature_id == "FEED-001" for d in detections)

            # Start updater
            from zugashield.feed.updater import SignatureUpdater

            updater = SignatureUpdater(catalog, config)
            updater.start()

            # Wait for the update to be applied (with timeout)
            deadline = time.time() + 10
            while time.time() < deadline:
                if updater._updates_applied > 0:
                    break
                time.sleep(0.2)

            updater.stop()
            updater.join(timeout=3)

            # Now the new pattern SHOULD be detected
            assert updater._updates_applied >= 1
            detections = catalog.check("feed_unique_test_pattern_xyz")
            assert any(d.signature_id == "FEED-001" for d in detections)
            assert catalog._version == "2.0.0"

        finally:
            server.shutdown()

    def test_etag_cache_prevents_redownload(self, tmp_path):
        """After applying an update, a second check should get 304."""
        sig_dir = tmp_path / "new_sigs"
        release_dir = tmp_path / "serve"
        _build_test_signatures(sig_dir, version="2.0.0")
        _build_release_bundle(release_dir, sig_dir, version="2.0.0")

        handler = type("H", (FeedHandler,), {"serve_directory": str(release_dir)})
        server = None
        port = 0
        for p in range(18910, 18920):
            try:
                server = HTTPServer(("127.0.0.1", p), handler)
                port = p
                break
            except OSError:
                continue

        if server is None:
            pytest.skip("Could not bind to any test port")

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            from zugashield.feed.checker import check_for_update
            from zugashield.feed.state import UpdateState

            config = ShieldConfig(
                feed_enabled=True,
                feed_url=f"http://127.0.0.1:{port}",
                feed_timeout=5,
                feed_verify_signatures=False,
            )

            # First check: should find update
            state = UpdateState(last_applied_version="1.0.0")
            manifest = check_for_update(config, state)
            assert manifest is not None
            assert manifest.version == "2.0.0"

            # Second check with the ETag: should get 304
            state2 = UpdateState(
                etag=manifest.etag,
                last_applied_version="2.0.0",
            )
            manifest2 = check_for_update(config, state2)
            assert manifest2 is None  # 304 — no update

        finally:
            server.shutdown()

    def test_signed_update_with_verification(self, tmp_path):
        """Full E2E with real Ed25519 signature verification enabled."""
        # Build and SIGN the release bundle
        sig_dir = tmp_path / "new_sigs"
        release_dir = tmp_path / "serve"
        _build_test_signatures(sig_dir, version="3.0.0")
        _build_release_bundle(release_dir, sig_dir, version="3.0.0", sign=True)

        # Verify the .minisig file was created
        assert (release_dir / "signatures-v3.0.0.zip.minisig").exists()

        handler = type("H", (FeedHandler,), {"serve_directory": str(release_dir)})
        server = None
        port = 0
        for p in range(18920, 18930):
            try:
                server = HTTPServer(("127.0.0.1", p), handler)
                port = p
                break
            except OSError:
                continue

        if server is None:
            pytest.skip("Could not bind to any test port")

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            catalog = ThreatCatalog(verify_integrity=False)
            state_dir = str(tmp_path / "state")

            config = ShieldConfig(
                feed_enabled=True,
                feed_url=f"http://127.0.0.1:{port}",
                feed_poll_interval=1,
                feed_startup_jitter=0,
                feed_timeout=5,
                feed_state_dir=state_dir,
                feed_verify_signatures=True,  # ENABLED — real crypto verification
                feed_fail_open=True,
            )

            from zugashield.feed.updater import SignatureUpdater

            updater = SignatureUpdater(catalog, config)
            updater.start()

            deadline = time.time() + 10
            while time.time() < deadline:
                if updater._updates_applied > 0:
                    break
                time.sleep(0.2)

            updater.stop()
            updater.join(timeout=3)

            # Signed update should have been applied
            assert updater._updates_applied >= 1
            assert catalog._version == "3.0.0"

            detections = catalog.check("feed_unique_test_pattern_xyz")
            assert any(d.signature_id == "FEED-001" for d in detections)

        finally:
            server.shutdown()
