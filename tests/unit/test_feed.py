"""
Unit tests for ZugaShield Threat Feed system.

Tests state persistence, update checking, downloading, signature
verification, hot-reload, thread safety, and the packager CLI.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from zugashield.config import ShieldConfig
from zugashield.threat_catalog import ThreatCatalog


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_state_dir(tmp_path):
    """Temporary directory for update state."""
    return str(tmp_path / "zugashield-state")


@pytest.fixture
def sample_signatures_dir(tmp_path):
    """Create a minimal valid signatures directory."""
    sig_dir = tmp_path / "signatures"
    sig_dir.mkdir()

    sigs = {
        "name": "Test Signatures",
        "description": "Test file",
        "category": "prompt_injection",
        "signatures": [
            {
                "id": "TEST-001",
                "category": "prompt_injection",
                "name": "Test Pattern",
                "description": "Test injection pattern",
                "patterns": ["test_inject_pattern_\\d+"],
                "severity": "critical",
                "confidence": 0.95,
                "false_positive_rate": 0.01,
                "references": [],
                "enabled": True,
            },
            {
                "id": "TEST-002",
                "category": "prompt_injection",
                "name": "Another Test",
                "description": "Another test",
                "patterns": ["another_test_pattern"],
                "severity": "high",
                "confidence": 0.9,
                "false_positive_rate": 0.02,
                "references": [],
                "enabled": True,
            },
        ],
    }

    version = {
        "version": "2.0.0",
        "last_updated": "2026-02-17T12:00:00Z",
        "total_signatures": 2,
    }

    sig_file = sig_dir / "prompt_injection.json"
    sig_file.write_text(json.dumps(sigs), encoding="utf-8")

    version_file = sig_dir / "catalog_version.json"
    version_file.write_text(json.dumps(version), encoding="utf-8")

    # Create integrity.json
    integrity = {}
    for f in sig_dir.glob("*.json"):
        integrity[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()

    integrity_file = sig_dir / "integrity.json"
    integrity_file.write_text(json.dumps(integrity), encoding="utf-8")

    return sig_dir


@pytest.fixture
def sample_zip(tmp_path, sample_signatures_dir):
    """Create a valid signatures zip from the sample dir."""
    zip_path = tmp_path / "signatures-v2.0.0.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sample_signatures_dir.glob("*.json"):
            zf.write(f, f.name)
    return zip_path


# ============================================================================
# State tests
# ============================================================================


class TestUpdateState:
    def test_load_missing_returns_defaults(self, tmp_state_dir):
        from zugashield.feed.state import load_state

        state = load_state(tmp_state_dir)
        assert state.etag == ""
        assert state.last_applied_version == "0.0.0"
        assert state.last_signature_count == 0

    def test_save_and_load_roundtrip(self, tmp_state_dir):
        from zugashield.feed.state import UpdateState, load_state, save_state

        state = UpdateState(
            etag='"abc123"',
            last_check="2026-02-17T14:00:00Z",
            last_applied_version="1.2.3",
            last_signature_count=142,
        )
        save_state(tmp_state_dir, state)
        loaded = load_state(tmp_state_dir)

        assert loaded.etag == '"abc123"'
        assert loaded.last_applied_version == "1.2.3"
        assert loaded.last_signature_count == 142

    def test_with_update_returns_new_state(self):
        from zugashield.feed.state import UpdateState

        state = UpdateState(etag='"old"', last_applied_version="1.0.0")
        new = state.with_update("2.0.0", 200)

        assert new.last_applied_version == "2.0.0"
        assert new.last_signature_count == 200
        assert new.last_check != ""
        # Original unchanged
        assert state.last_applied_version == "1.0.0"

    def test_creates_directory_on_save(self, tmp_path):
        from zugashield.feed.state import UpdateState, save_state

        deep_dir = str(tmp_path / "a" / "b" / "c")
        save_state(deep_dir, UpdateState())
        assert (Path(deep_dir) / "update_state.json").exists()

    def test_corrupted_state_returns_defaults(self, tmp_state_dir):
        from zugashield.feed.state import load_state

        Path(tmp_state_dir).mkdir(parents=True)
        (Path(tmp_state_dir) / "update_state.json").write_text("not json")

        state = load_state(tmp_state_dir)
        assert state.last_applied_version == "0.0.0"


# ============================================================================
# Checker tests
# ============================================================================


class TestUpdateChecker:
    def test_304_returns_none(self, tmp_state_dir):
        from zugashield.feed.checker import check_for_update
        from zugashield.feed.state import UpdateState

        config = ShieldConfig(
            feed_enabled=True,
            feed_url="https://example.com/releases",
            feed_timeout=5,
        )
        state = UpdateState(etag='"abc"')

        mock_resp = MagicMock()
        mock_resp.status_code = 304

        with patch("zugashield.feed.checker.httpx") as mock_httpx:
            mock_httpx.get.return_value = mock_resp
            result = check_for_update(config, state)

        assert result is None

    def test_200_with_newer_version_returns_manifest(self, tmp_state_dir):
        from zugashield.feed.checker import check_for_update
        from zugashield.feed.state import UpdateState

        config = ShieldConfig(
            feed_enabled=True,
            feed_url="https://example.com/releases",
            feed_timeout=5,
        )
        state = UpdateState(last_applied_version="1.0.0")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "version": "2.0.0",
            "sha256": "abc123",
            "signature_count": 150,
            "min_client": "0.0.1",
        }
        mock_resp.headers = {"etag": '"new-etag"'}

        with patch("zugashield.feed.checker.httpx") as mock_httpx:
            mock_httpx.get.return_value = mock_resp
            result = check_for_update(config, state)

        assert result is not None
        assert result.version == "2.0.0"
        assert result.sha256 == "abc123"
        assert result.etag == '"new-etag"'

    def test_same_version_returns_none(self):
        from zugashield.feed.checker import check_for_update
        from zugashield.feed.state import UpdateState

        config = ShieldConfig(
            feed_enabled=True,
            feed_url="https://example.com/releases",
            feed_timeout=5,
        )
        state = UpdateState(last_applied_version="2.0.0")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"version": "2.0.0"}
        mock_resp.headers = {}

        with patch("zugashield.feed.checker.httpx") as mock_httpx:
            mock_httpx.get.return_value = mock_resp
            result = check_for_update(config, state)

        assert result is None

    def test_network_error_returns_none(self):
        from zugashield.feed.checker import check_for_update
        from zugashield.feed.state import UpdateState

        config = ShieldConfig(
            feed_enabled=True,
            feed_url="https://example.com/releases",
            feed_timeout=5,
        )
        state = UpdateState()

        with patch("zugashield.feed.checker.httpx") as mock_httpx:
            mock_httpx.get.side_effect = Exception("Connection refused")
            result = check_for_update(config, state)

        assert result is None

    def test_min_client_too_high_returns_none(self):
        from zugashield.feed.checker import check_for_update
        from zugashield.feed.state import UpdateState

        config = ShieldConfig(
            feed_enabled=True,
            feed_url="https://example.com/releases",
            feed_timeout=5,
        )
        state = UpdateState(last_applied_version="1.0.0")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "version": "2.0.0",
            "min_client": "99.0.0",  # Way higher than any real version
        }
        mock_resp.headers = {}

        with patch("zugashield.feed.checker.httpx") as mock_httpx:
            mock_httpx.get.return_value = mock_resp
            result = check_for_update(config, state)

        assert result is None


class TestVersionComparison:
    def test_compare_versions(self):
        from zugashield.feed.checker import _compare_versions

        assert _compare_versions("2.0.0", "1.0.0") > 0
        assert _compare_versions("1.0.0", "2.0.0") < 0
        assert _compare_versions("1.0.0", "1.0.0") == 0
        assert _compare_versions("1.1.0", "1.0.0") > 0
        assert _compare_versions("1.0.1", "1.0.0") > 0


# ============================================================================
# Hot-reload tests
# ============================================================================


class TestHotReload:
    def test_hot_reload_loads_new_signatures(self, sample_signatures_dir):
        catalog = ThreatCatalog(verify_integrity=True)
        original_count = catalog._total_signatures

        count = catalog.hot_reload(str(sample_signatures_dir))

        assert count == 2
        assert catalog._total_signatures == 2
        assert catalog._version == "2.0.0"

    def test_hot_reload_detects_new_patterns(self, sample_signatures_dir):
        catalog = ThreatCatalog(verify_integrity=False)
        catalog.hot_reload(str(sample_signatures_dir))

        detections = catalog.check("test_inject_pattern_42")
        assert len(detections) > 0
        assert detections[0].signature_id == "TEST-001"

    def test_hot_reload_missing_dir_keeps_existing(self):
        catalog = ThreatCatalog(verify_integrity=True)
        original_count = catalog._total_signatures

        count = catalog.hot_reload("/nonexistent/path")
        assert count == original_count

    def test_hot_reload_zero_sigs_aborts(self, tmp_path):
        """Empty signatures dir should not replace existing catalog."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        (empty_dir / "catalog_version.json").write_text('{"version": "3.0.0"}')

        catalog = ThreatCatalog(verify_integrity=False)
        original_count = catalog._total_signatures

        count = catalog.hot_reload(str(empty_dir))
        assert count == original_count
        assert catalog._version != "3.0.0"  # Version should NOT change

    def test_hot_reload_thread_safety(self, sample_signatures_dir):
        """Concurrent reads during hot_reload should not crash."""
        catalog = ThreatCatalog(verify_integrity=False)
        errors = []
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                try:
                    catalog.check("test some text for thread safety")
                except Exception as e:
                    errors.append(str(e))

        # Start readers
        readers = [threading.Thread(target=reader) for _ in range(4)]
        for r in readers:
            r.start()

        # Do hot_reload while readers are active
        for _ in range(5):
            catalog.hot_reload(str(sample_signatures_dir))
            time.sleep(0.01)

        stop.set()
        for r in readers:
            r.join(timeout=2)

        assert len(errors) == 0, f"Thread safety errors: {errors}"


# ============================================================================
# Config feed fields tests
# ============================================================================


class TestFeedConfig:
    def test_defaults(self):
        config = ShieldConfig()
        assert config.feed_enabled is False
        assert config.feed_poll_interval == 3600
        assert config.feed_startup_jitter == 300
        assert config.feed_timeout == 30
        assert config.feed_state_dir == "~/.zugashield"
        assert config.feed_verify_signatures is True
        assert config.feed_fail_open is True

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_FEED_ENABLED", "true")
        monkeypatch.setenv("ZUGASHIELD_FEED_POLL_INTERVAL", "1800")
        config = ShieldConfig.from_env()
        assert config.feed_enabled is True
        assert config.feed_poll_interval == 1800

    def test_minimum_poll_interval_enforced(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_FEED_POLL_INTERVAL", "60")
        config = ShieldConfig.from_env()
        assert config.feed_poll_interval >= 900

    def test_builder_enable_feed(self):
        config = ShieldConfig.builder().enable_feed(interval=1800).build()
        assert config.feed_enabled is True
        assert config.feed_poll_interval == 1800

    def test_builder_enable_feed_minimum_interval(self):
        config = ShieldConfig.builder().enable_feed(interval=100).build()
        assert config.feed_poll_interval >= 900


# ============================================================================
# Downloader tests
# ============================================================================


class TestDownloader:
    def test_zip_path_traversal_rejected(self, tmp_path):
        """Zip files with path traversal should be rejected."""
        # Create a malicious zip with path traversal
        zip_path = tmp_path / "malicious.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../../etc/passwd", "root:x:0:0")

        from zugashield.feed.checker import Manifest
        from zugashield.feed.downloader import download_and_verify

        manifest = Manifest(
            version="9.9.9",
            sha256="",
            signature_count=0,
            min_client="0.0.0",
            download_url="https://example.com/malicious.zip",
        )

        config = ShieldConfig(
            feed_enabled=True,
            feed_verify_signatures=False,  # Skip sig verification for this test
            feed_timeout=5,
        )

        # Mock httpx to return the malicious zip
        mock_stream_resp = MagicMock()
        mock_stream_resp.__enter__ = MagicMock(return_value=mock_stream_resp)
        mock_stream_resp.__exit__ = MagicMock(return_value=False)
        mock_stream_resp.raise_for_status = MagicMock()
        mock_stream_resp.iter_bytes = MagicMock(return_value=[zip_path.read_bytes()])

        with patch("zugashield.feed.downloader.httpx") as mock_httpx:
            mock_httpx.stream.return_value = mock_stream_resp
            result = download_and_verify(manifest, config, str(tmp_path / "state"))

        assert result is None  # Should be rejected

    def test_sha256_mismatch_rejected(self, tmp_path, sample_zip):
        """Download with wrong SHA-256 should be rejected."""
        from zugashield.feed.checker import Manifest
        from zugashield.feed.downloader import download_and_verify

        manifest = Manifest(
            version="2.0.0",
            sha256="wrong_hash_value",
            signature_count=2,
            min_client="0.0.0",
            download_url="https://example.com/sigs.zip",
        )

        config = ShieldConfig(
            feed_enabled=True,
            feed_verify_signatures=False,
            feed_timeout=5,
        )

        mock_stream_resp = MagicMock()
        mock_stream_resp.__enter__ = MagicMock(return_value=mock_stream_resp)
        mock_stream_resp.__exit__ = MagicMock(return_value=False)
        mock_stream_resp.raise_for_status = MagicMock()
        mock_stream_resp.iter_bytes = MagicMock(return_value=[sample_zip.read_bytes()])

        with patch("zugashield.feed.downloader.httpx") as mock_httpx:
            mock_httpx.stream.return_value = mock_stream_resp
            result = download_and_verify(manifest, config, str(tmp_path / "state"))

        assert result is None


# ============================================================================
# Signer tests
# ============================================================================


class TestSigner:
    def test_sign_and_verify_roundtrip(self, tmp_path):
        """Sign a file, verify it passes, tamper and verify it fails."""
        from zugashield.feed.signer import sign_file, verify_signature

        # Real secret key matching the hardcoded public key
        sk_hex = "e02512b377dec4297c1e9c92f764fd38c10d9291173dcf4754988a859bd86a14"
        keyid_hex = "a4ec7e83594ad0aa"

        test_file = tmp_path / "signatures.zip"
        test_file.write_bytes(b"ZugaShield test payload for signing")

        # Sign
        sig_content = sign_file(test_file, sk_hex, keyid_hex)
        sig_file = tmp_path / "signatures.zip.minisig"
        sig_file.write_text(sig_content)

        # Verify — should pass
        assert verify_signature(test_file, sig_file) is True

    def test_tampered_file_fails_verification(self, tmp_path):
        """Signature should fail after file is tampered."""
        from zugashield.feed.signer import sign_file, verify_signature

        sk_hex = "e02512b377dec4297c1e9c92f764fd38c10d9291173dcf4754988a859bd86a14"
        keyid_hex = "a4ec7e83594ad0aa"

        test_file = tmp_path / "signatures.zip"
        test_file.write_bytes(b"original content")

        sig_content = sign_file(test_file, sk_hex, keyid_hex)
        sig_file = tmp_path / "signatures.zip.minisig"
        sig_file.write_text(sig_content)

        # Tamper with file
        test_file.write_bytes(b"TAMPERED content")
        assert verify_signature(test_file, sig_file) is False

    def test_wrong_key_fails_verification(self, tmp_path):
        """Signature from wrong key should fail against hardcoded pubkey."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64

        # Generate a DIFFERENT keypair (not the hardcoded one)
        wrong_key = Ed25519PrivateKey.generate()
        test_file = tmp_path / "signatures.zip"
        test_file.write_bytes(b"test content")

        # Sign with the wrong key
        from cryptography.hazmat.primitives import serialization
        sig = wrong_key.sign(test_file.read_bytes())
        key_id = b"\x00" * 8
        sig_payload = b"Ed" + key_id + sig
        sig_b64 = base64.b64encode(sig_payload).decode()

        sig_file = tmp_path / "signatures.zip.minisig"
        sig_file.write_text(
            f"untrusted comment: wrong key\n{sig_b64}\ntrusted comment: test\nAAAA\n"
        )

        from zugashield.feed.signer import verify_signature
        assert verify_signature(test_file, sig_file) is False

    def test_verify_no_backend_returns_false(self, tmp_path):
        """Without cryptography or minisign, verification should fail."""
        from zugashield.feed.signer import verify_signature

        file_path = tmp_path / "test.zip"
        file_path.write_bytes(b"test data")
        sig_path = tmp_path / "test.zip.minisig"
        sig_path.write_text("untrusted comment: test\nYWJj\ntrusted comment: t\nYWJj")

        with patch("zugashield.feed.signer._verify_cryptography", side_effect=ImportError):
            with patch("zugashield.feed.signer._verify_minisign", side_effect=ImportError):
                result = verify_signature(file_path, sig_path)

        assert result is False


# ============================================================================
# Updater daemon tests
# ============================================================================


class TestUpdaterDaemon:
    def test_updater_stops_cleanly(self):
        catalog = ThreatCatalog(verify_integrity=False)
        config = ShieldConfig(
            feed_enabled=True,
            feed_startup_jitter=0,
            feed_poll_interval=3600,
        )

        from zugashield.feed.updater import SignatureUpdater

        updater = SignatureUpdater(catalog, config)
        updater.start()
        assert updater.is_alive()

        updater.stop()
        updater.join(timeout=2)
        assert not updater.is_alive()

    def test_updater_get_stats(self):
        catalog = ThreatCatalog(verify_integrity=False)
        config = ShieldConfig(
            feed_enabled=True,
            feed_startup_jitter=0,
            feed_poll_interval=3600,
        )

        from zugashield.feed.updater import SignatureUpdater

        updater = SignatureUpdater(catalog, config)
        stats = updater.get_stats()

        assert stats["running"] is False
        assert stats["updates_applied"] == 0
        assert stats["poll_interval"] == 3600

    def test_updater_survives_check_failure(self):
        """Updater should not crash if check_and_apply raises."""
        catalog = ThreatCatalog(verify_integrity=False)
        config = ShieldConfig(
            feed_enabled=True,
            feed_startup_jitter=0,
            feed_poll_interval=1,  # Will be clamped to 900 in from_env, but direct construction allows it
        )

        from zugashield.feed.updater import SignatureUpdater

        updater = SignatureUpdater(catalog, config)

        # Mock the check to raise an error
        with patch.object(updater, "_check_and_apply", side_effect=RuntimeError("boom")):
            updater._safe_check()

        assert updater._last_error == "boom"


# ============================================================================
# ZugaShield integration tests
# ============================================================================


class TestZugaShieldFeedIntegration:
    def test_feed_disabled_by_default(self):
        from zugashield import ZugaShield

        shield = ZugaShield(ShieldConfig(feed_enabled=False))
        assert shield._updater is None

    def test_feed_enabled_starts_daemon(self):
        from zugashield import ZugaShield

        config = ShieldConfig(
            feed_enabled=True,
            feed_startup_jitter=9999,  # Large jitter so it doesn't actually check
        )

        # Mock httpx import to succeed
        shield = ZugaShield(config)

        if shield._updater is not None:
            assert shield._updater.is_alive()
            shield._updater.stop()
            shield._updater.join(timeout=2)

    def test_dashboard_includes_feed_stats(self):
        from zugashield import ZugaShield

        config = ShieldConfig(
            feed_enabled=True,
            feed_startup_jitter=9999,
        )
        shield = ZugaShield(config)

        if shield._updater is not None:
            data = shield.get_dashboard_data()
            assert "feed" in data
            assert "running" in data["feed"]

            shield._updater.stop()
            shield._updater.join(timeout=2)

    def test_builder_enable_feed(self):
        from zugashield import ZugaShield

        shield = (
            ZugaShield.builder()
            .enable_feed(interval=1800)
            .build()
        )

        assert shield._config.feed_enabled is True
        assert shield._config.feed_poll_interval == 1800

        if shield._updater is not None:
            shield._updater.stop()
            shield._updater.join(timeout=2)


# ============================================================================
# Packager tests
# ============================================================================


class TestPackager:
    def test_package_creates_zip_and_manifest(self, tmp_path):
        from zugashield.feed.packager import package_signatures

        output_dir = str(tmp_path / "release")
        zip_path = package_signatures(
            version="1.0.0",
            output_dir=output_dir,
        )

        assert zip_path.exists()
        assert (Path(output_dir) / "manifest.json").exists()

        manifest = json.loads((Path(output_dir) / "manifest.json").read_text())
        assert manifest["version"] == "1.0.0"
        assert manifest["sha256"] != ""
        assert manifest["signature_count"] > 0

    def test_package_zip_is_valid(self, tmp_path):
        from zugashield.feed.packager import package_signatures

        output_dir = str(tmp_path / "release")
        zip_path = package_signatures(
            version="1.0.0",
            output_dir=output_dir,
        )

        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert "catalog_version.json" in names
            assert "integrity.json" in names
            assert any(n.endswith(".json") for n in names)

    def test_package_manifest_sha256_matches_zip(self, tmp_path):
        from zugashield.feed.packager import package_signatures

        output_dir = str(tmp_path / "release")
        zip_path = package_signatures(
            version="1.0.0",
            output_dir=output_dir,
        )

        manifest = json.loads((Path(output_dir) / "manifest.json").read_text())
        actual_hash = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        assert manifest["sha256"] == actual_hash
