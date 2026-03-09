# Threat Feed (Auto-Updating Signatures)

The threat feed system automatically downloads new signature releases, verifies their authenticity, and hot-reloads the catalog without downtime. It is opt-in — disabled by default.

## Enable

```python
from zugashield import ZugaShield

shield = (ZugaShield.builder()
    .enable_feed(interval=3600)  # Check every hour
    .build())
```

Via environment variables:

```bash
ZUGASHIELD_FEED_ENABLED=true
ZUGASHIELD_FEED_POLL_INTERVAL=3600
```

## Architecture

```
SignatureUpdater (daemon thread)
  ├── check_for_update()     # Conditional HTTP GET on manifest.json
  ├── download_and_verify()  # Download zip, verify signature + hash, extract
  ├── ThreatCatalog.hot_reload()  # Atomic swap of signatures
  └── save_state()           # Persist ETag + version to disk
```

### Daemon Thread

`SignatureUpdater` is a `threading.Thread(daemon=True)`. It starts with a random jitter delay (0 to `feed_startup_jitter` seconds, default 300) to prevent thundering herd when many instances start simultaneously.

**Design invariants:**

- Never crashes: all exceptions are caught, logged, and swallowed
- Never blocks startup: daemon thread, jitter delay
- Fail-open: update failures leave existing signatures untouched
- Zero cost on no-update: ETag conditional HTTP returns 304

## Update Protocol

### 1. Check for Update

A conditional `GET` is sent to `{feed_url}/manifest.json` with an `If-None-Match` header containing the stored ETag:

```
GET /manifest.json HTTP/1.1
If-None-Match: "abc123"
```

- `304 Not Modified` → no update, return
- `200 OK` → parse manifest, compare versions

```json
{
  "version": "1.6.0",
  "sha256": "abc123...",
  "signature_count": 158,
  "min_client": "0.9.0",
  "download_url": "signatures-v1.6.0.zip"
}
```

The `min_client` field is compared against the installed ZugaShield version. If the new signatures require a newer client, the update is skipped.

### 2. Download

The zip bundle is downloaded via streaming HTTP (`httpx.stream`).

### 3. Verify Ed25519 Signature

A `.minisig` file is downloaded alongside the zip and verified against a hardcoded Ed25519 public key embedded in `zugashield.feed.pubkey`:

```python
# Minisign format
# Public key:  base64(2-byte algo "Ed" + 8-byte key_id + 32-byte pk)
# Signature:   4-line minisig file format
```

Verification uses the `cryptography` library (preferred) or the `minisign` package as fallback. If neither is installed, verification fails and the update is rejected.

Set `feed_verify_signatures=False` to skip this check (not recommended for production).

### 4. Verify SHA-256

The zip's SHA-256 is computed and compared against the manifest's `sha256` field.

### 5. Extract and Validate

The zip is extracted to `{feed_state_dir}/signatures-v{version}/`. Zip path traversal attacks are rejected: any member path that resolves outside the target directory causes the entire extraction to abort.

After extraction, the new directory is validated using `ThreatCatalog`'s integrity check (verifying `integrity.json` hashes).

### 6. Hot-Reload

`ThreatCatalog.hot_reload()` atomically swaps the signatures dict under a lock. Readers that already grabbed a reference to the old dict continue safely.

### 7. Persist State

The new version, ETag, and signature count are saved to `{feed_state_dir}/update_state.json`:

```json
{
  "etag": "\"abc123\"",
  "last_check": "2026-02-17T10:00:00+00:00",
  "last_applied_version": "1.6.0",
  "last_signature_count": 158
}
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `feed_enabled` | `false` | Enable the feed daemon |
| `feed_url` | GitHub releases URL | Base URL for manifest and bundles |
| `feed_poll_interval` | `3600` | Poll interval in seconds (minimum 900) |
| `feed_startup_jitter` | `300` | Max random startup delay in seconds |
| `feed_timeout` | `30` | HTTP timeout in seconds |
| `feed_state_dir` | `~/.zugashield` | ETag cache and downloaded signatures |
| `feed_verify_signatures` | `true` | Require Ed25519 minisign verification |
| `feed_fail_open` | `true` | Continue if update fails (existing sigs remain) |

## Dashboard Status

```python
data = shield.get_dashboard_data()
feed_status = data.get("feed")
# {
#   "running": True,
#   "updates_applied": 2,
#   "last_error": None,
#   "poll_interval": 3600
# }
```

## Packaging and Signing (Maintainers)

```bash
# Package signatures into a release bundle
zugashield-feed package --version 1.6.0 --output ./release/

# Sign with minisign CLI
zugashield-feed sign --key ~/.minisign/zugashield.sec ./release/signatures-v1.6.0.zip

# Or sign with Python Ed25519 (hex sk:keyid format)
zugashield-feed sign --key "<sk_hex>:<keyid_hex>" ./release/signatures-v1.6.0.zip

# Verify the bundle
zugashield-feed verify ./release/signatures-v1.6.0.zip
```

Last Updated: 2026-02-17
