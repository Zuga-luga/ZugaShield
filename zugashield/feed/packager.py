"""
ZugaShield Threat Feed — Signature Packager CLI.

CLI tool for maintainers to package, sign, and verify signature
bundles for GitHub Releases.

Usage:
    # Package current signatures into a release bundle
    zugashield-feed package --version 1.3.0 --output ./release/

    # Sign the bundle (requires minisign secret key)
    zugashield-feed sign --key ~/.minisign/zugashield.sec ./release/signatures-v1.3.0.zip

    # Verify a bundle (for testing)
    zugashield-feed verify ./release/signatures-v1.3.0.zip
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def package_signatures(version: str, output_dir: str, signatures_dir: str | None = None) -> Path:
    """Package signatures into a versioned zip with manifest."""
    sig_dir = Path(signatures_dir) if signatures_dir else (Path(__file__).parent.parent / "signatures")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not sig_dir.exists():
        print(f"Error: Signatures directory not found: {sig_dir}", file=sys.stderr)
        sys.exit(1)

    zip_name = f"signatures-v{version}.zip"
    zip_path = out_dir / zip_name

    # Count signatures
    sig_count = 0
    for json_file in sig_dir.glob("*.json"):
        if json_file.name in ("catalog_version.json", "integrity.json"):
            continue
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            sig_count += len(data.get("signatures", []))
        except Exception:
            pass

    # Create zip
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for json_file in sorted(sig_dir.glob("*.json")):
            zf.write(json_file, json_file.name)

    # Compute SHA-256
    sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()

    # Create manifest
    from zugashield._version import __version__

    manifest = {
        "version": version,
        "sha256": sha256,
        "signature_count": sig_count,
        "min_client": __version__,
        "created": datetime.now(timezone.utc).isoformat(),
        "download_url": f"signatures-v{version}.zip",
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Packaged {sig_count} signatures into {zip_path}")
    print(f"SHA-256: {sha256}")
    print(f"Manifest: {manifest_path}")
    return zip_path


def sign_bundle(zip_path: str, secret_key: str) -> None:
    """
    Sign a zip bundle.

    Tries minisign CLI first, falls back to Python cryptography signing.
    The ``secret_key`` can be a path to a minisign .sec file (for CLI)
    or a hex-encoded Ed25519 secret key with key_id (format: ``hex_sk:hex_keyid``).
    """
    zip_file = Path(zip_path)
    if not zip_file.exists():
        print(f"Error: File not found: {zip_file}", file=sys.stderr)
        sys.exit(1)

    # If secret_key contains ':', treat as hex sk:keyid for Python signing
    if ":" in secret_key:
        sk_hex, keyid_hex = secret_key.split(":", 1)
        from zugashield.feed.signer import sign_file

        sig_content = sign_file(zip_file, sk_hex, keyid_hex)
        sig_file = Path(f"{zip_path}.minisig")
        sig_file.write_text(sig_content, encoding="utf-8")
        print(f"Signed (Python Ed25519): {sig_file}")
        return

    # Otherwise try minisign CLI with .sec file
    try:
        subprocess.run(
            ["minisign", "-Sm", str(zip_file), "-s", secret_key],
            capture_output=True,
            text=True,
            check=True,
        )
        print(f"Signed (minisign CLI): {zip_file}.minisig")
    except FileNotFoundError:
        print(
            "Error: minisign CLI not found. Install it or use hex key format (sk_hex:keyid_hex).",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error signing: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def verify_bundle(zip_path: str) -> None:
    """Verify a signed bundle against the hardcoded public key."""
    zip_file = Path(zip_path)
    sig_file = Path(f"{zip_path}.minisig")

    if not zip_file.exists():
        print(f"Error: File not found: {zip_file}", file=sys.stderr)
        sys.exit(1)
    if not sig_file.exists():
        print(f"Error: Signature not found: {sig_file}", file=sys.stderr)
        sys.exit(1)

    from zugashield.feed.signer import verify_signature

    if verify_signature(zip_file, sig_file):
        print("Verification: PASSED")
    else:
        print("Verification: FAILED", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """CLI entry point for zugashield-feed."""
    parser = argparse.ArgumentParser(
        prog="zugashield-feed",
        description="ZugaShield signature feed management tool",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # package subcommand
    pkg = subparsers.add_parser("package", help="Package signatures into a release bundle")
    pkg.add_argument("--version", required=True, help="Version string (e.g., 1.3.0)")
    pkg.add_argument("--output", default="./release", help="Output directory")
    pkg.add_argument("--signatures-dir", default=None, help="Signatures directory (default: bundled)")

    # sign subcommand
    sign = subparsers.add_parser("sign", help="Sign a bundle with minisign")
    sign.add_argument("--key", required=True, help="Path to minisign secret key")
    sign.add_argument("file", help="Zip file to sign")

    # verify subcommand
    ver = subparsers.add_parser("verify", help="Verify a signed bundle")
    ver.add_argument("file", help="Zip file to verify")

    args = parser.parse_args()

    if args.command == "package":
        package_signatures(args.version, args.output, args.signatures_dir)
    elif args.command == "sign":
        sign_bundle(args.file, args.key)
    elif args.command == "verify":
        verify_bundle(args.file)


if __name__ == "__main__":
    main()
