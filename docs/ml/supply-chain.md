# ML Supply Chain Security

ZugaShield applies multiple layers of verification to ensure that ML models have not been tampered with between publication and inference.

## Overview

| Check | When | Blocks On |
|-------|------|-----------|
| SHA-256 sidecar | Model load | Hash mismatch |
| Canary validation | Model load | Canary prompt not detected |
| Version pinning | Model load | Version mismatch (if configured) |
| TF-IDF bundle integrity | Model load | Malformed bundle structure |

## SHA-256 Hash Verification

When a model is downloaded via `zugashield-ml download`, a sidecar hash file is written alongside the ONNX model:

```
~/.zugashield/models/deberta_injection.onnx
~/.zugashield/models/deberta_injection.onnx.sha256
```

The sidecar format follows the standard checksum convention:

```
<hex-sha256>  deberta_injection.onnx
```

On each load, `MLDetectorLayer` computes the SHA-256 of the model file and compares it against the sidecar. A mismatch causes the ONNX tier to be disabled (fail-open to the TF-IDF tier) and logs an error.

### Checking Manually

```bash
zugashield-ml info
# Shows: Integrity: VERIFIED  or  Integrity: MISMATCH
```

### Signature Integrity for Bundled Signatures

The threat catalog verifies SHA-256 hashes of JSON signature files on load via `integrity.json`:

```python
# integrity.json structure
{
    "prompt_injection.json": "abc123...",
    "tool_exploitation.json": "def456...",
    ...
}
```

If any signature file's hash does not match the recorded value, `ThreatCatalog` raises `SecurityError` before loading any signatures. This check can be disabled in development by removing `integrity.json` from the signatures directory (dev mode).

## Canary Validation

The TF-IDF classifier is validated at load time against a set of known injection prompts ("canaries"). If the model fails to detect these canaries, it is considered corrupt or incompatible and the TF-IDF tier is disabled.

Canary validation is run once at startup, not on every inference call.

## Version Pinning

You can require an exact model version to prevent accidental use of an older or mismatched model:

```python
from zugashield.config import ShieldConfig

config = ShieldConfig(ml_model_version="2.0.0")
# Empty string (default) = accept any version
```

The version is read from the `__zugashield_meta__` key in the `.joblib` bundle.

## TF-IDF Bundle Integrity

The `.joblib` bundle is validated for structural integrity on load:

- Must be a dict (not a raw sklearn object)
- Must contain `tfidf` and `clf` keys
- `has_heuristic_features` must match `n_heuristic_features`
- Feature dimensions must be consistent

## Benchmark Models

The `benchmark_configs.py` script disables signature verification when evaluating candidate models:

```python
config = ShieldConfig(
    verify_signatures=False,   # Benchmark mode only
    ml_onnx_enabled=False,
)
```

Do not use `verify_signatures=False` in production.

## Environment Variable

```bash
# Disable signature verification (testing only)
ZUGASHIELD_VERIFY_SIGNATURES=false
```

Last Updated: 2026-02-17
