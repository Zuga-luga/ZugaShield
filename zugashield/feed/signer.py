"""
ZugaShield Threat Feed — Ed25519 Signature Verification.

Verifies minisign-format signatures on downloaded signature bundles.
Uses the ``cryptography`` library (widely available) as the primary
backend, with the ``minisign`` Python package as an alternative.

Minisign format reference:
    Public key:  base64(2-byte algo "Ed" + 8-byte key_id + 32-byte pk)
    Signature:   Line 1: "untrusted comment: ..."
                 Line 2: base64(2-byte algo "Ed" + 8-byte key_id + 64-byte sig)
                 Line 3: "trusted comment: ..."
                 Line 4: base64(64-byte global_sig)
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

from zugashield.feed.pubkey import ZUGASHIELD_PUBKEY

logger = logging.getLogger(__name__)


def _parse_pubkey() -> bytes:
    """Extract the raw 32-byte Ed25519 public key from minisign format."""
    raw = base64.b64decode(ZUGASHIELD_PUBKEY)
    # Layout: 2-byte algo + 8-byte key_id + 32-byte public_key = 42 bytes
    if len(raw) != 42:
        raise ValueError(f"Invalid public key length: {len(raw)} (expected 42)")
    return raw[10:]  # Skip algo + key_id, take last 32 bytes


def _parse_signature(sig_path: Path) -> bytes:
    """Extract the raw 64-byte Ed25519 signature from a .minisig file."""
    lines = sig_path.read_text(encoding="utf-8").strip().split("\n")
    if len(lines) < 2:
        raise ValueError("Signature file has fewer than 2 lines")
    # Line 0: "untrusted comment: ..."
    # Line 1: base64(2-byte algo + 8-byte key_id + 64-byte signature)
    raw = base64.b64decode(lines[1])
    if len(raw) != 74:
        raise ValueError(f"Invalid signature payload length: {len(raw)} (expected 74)")
    return raw[10:]  # Skip algo + key_id, take 64-byte Ed25519 signature


def verify_signature(file_path: Path, sig_path: Path) -> bool:
    """
    Verify a minisign signature against the hardcoded public key.

    Tries cryptography first (most common), then minisign package.
    Returns True if verified, False on any failure.
    """
    # Try cryptography (most commonly available)
    try:
        return _verify_cryptography(file_path, sig_path)
    except ImportError:
        pass

    # Try minisign package
    try:
        return _verify_minisign(file_path, sig_path)
    except ImportError:
        pass

    logger.error(
        "[feed] No signature verification backend available. "
        "Install 'cryptography' or 'minisign' package."
    )
    return False


def _verify_cryptography(file_path: Path, sig_path: Path) -> bool:
    """Verify using the cryptography library with raw Ed25519."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pk_bytes = _parse_pubkey()
        sig_bytes = _parse_signature(sig_path)
        public_key = Ed25519PublicKey.from_public_bytes(pk_bytes)
        file_data = file_path.read_bytes()
        public_key.verify(sig_bytes, file_data)
        logger.debug("[feed] Ed25519 verification passed")
        return True
    except Exception as e:
        logger.error("[feed] Ed25519 verification failed: %s", e)
        return False


def _verify_minisign(file_path: Path, sig_path: Path) -> bool:
    """Verify using the minisign Python package."""
    import minisign

    try:
        pk = minisign.PublicKey(ZUGASHIELD_PUBKEY)
        signature = minisign.Signature.from_file(str(sig_path))
        pk.verify(file_path.read_bytes(), signature)
        logger.debug("[feed] Minisign package verification passed")
        return True
    except Exception as e:
        logger.error("[feed] Minisign package verification failed: %s", e)
        return False


def sign_file(file_path: Path, secret_key_hex: str, key_id_hex: str) -> str:
    """
    Sign a file and return the .minisig content string.

    This is used by the packager CLI and tests. Not used at runtime.

    Args:
        file_path: Path to file to sign.
        secret_key_hex: Hex-encoded 32-byte Ed25519 secret key.
        key_id_hex: Hex-encoded 8-byte key ID.

    Returns:
        Minisig file content (string with 4 lines).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk_bytes = bytes.fromhex(secret_key_hex)
    key_id = bytes.fromhex(key_id_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(sk_bytes)

    file_data = file_path.read_bytes()
    signature = private_key.sign(file_data)

    # Build minisig payload: 2-byte algo + 8-byte key_id + 64-byte signature
    sig_payload = b"Ed" + key_id + signature
    sig_b64 = base64.b64encode(sig_payload).decode()

    # Global signature over (signature + trusted comment)
    trusted_comment = f"timestamp:{int(file_path.stat().st_mtime)}\tfile:{file_path.name}"
    global_sig = private_key.sign(signature + trusted_comment.encode())
    global_sig_b64 = base64.b64encode(global_sig).decode()

    return (
        f"untrusted comment: signature from zugashield-feed\n"
        f"{sig_b64}\n"
        f"trusted comment: {trusted_comment}\n"
        f"{global_sig_b64}\n"
    )
