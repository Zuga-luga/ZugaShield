# Configuration

ZugaShield is configured through `ShieldConfig`, a frozen dataclass that is read once at startup. Because the config is immutable after creation, runtime mutation attacks cannot change shield behavior mid-request.

## Three Ways to Configure

### 1. Environment Variables (recommended for production)

Pass nothing to `ZugaShield()` and it reads all `ZUGASHIELD_*` variables automatically:

```bash
export ZUGASHIELD_ENABLED=true
export ZUGASHIELD_STRICT_MODE=true
export ZUGASHIELD_FAIL_CLOSED=true
```

```python
from zugashield import ZugaShield

shield = ZugaShield()  # reads from environment
```

### 2. Code (ShieldConfig directly)

Construct `ShieldConfig` explicitly and pass it in:

```python
from zugashield import ZugaShield
from zugashield.config import ShieldConfig

config = ShieldConfig(
    strict_mode=True,
    fail_closed=True,
    wallet_tx_limit=50.0,
    egress_domain_allowlist=("api.myapp.com",),
)
shield = ZugaShield(config)
```

### 3. Builder Pattern (recommended for complex setups)

The builder provides a fluent API and handles tuple conversion for you:

```python
from zugashield import ZugaShield

shield = (
    ZugaShield.builder()
    .fail_closed()
    .strict_mode()
    .set_egress_allowlist("api.myapp.com", "cdn.myapp.com")
    .set_wallet_limits(tx_limit=50.0, hourly_limit=200.0, daily_limit=500.0)
    .set_tool_policy("db_query", rate=10, approval=True, risk="high")
    .add_sensitive_endpoint("/api/payments", rate_limit=5)
    .enable_ml(threshold=0.65)
    .enable_feed(interval=3600)
    .build()
)
```

You can also call `ShieldConfig.builder()` directly if you need to pass the config elsewhere:

```python
from zugashield.config import ShieldConfig

config = ShieldConfig.builder().fail_closed().strict_mode().build()
```

---

## All Configuration Fields

### Core Settings

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `enabled` | `bool` | `True` | `ZUGASHIELD_ENABLED` | Master on/off toggle. When `False`, all `check_*` methods return ALLOW immediately. |
| `log_level` | `str` | `"INFO"` | `ZUGASHIELD_LOG_LEVEL` | Python logging level for ZugaShield's internal logger. |
| `strict_mode` | `bool` | `False` | `ZUGASHIELD_STRICT_MODE` | When `True`, medium-confidence threats are blocked. See [Strict Mode](#strict-mode) below. |
| `fail_closed` | `bool` | `True` | `ZUGASHIELD_FAIL_CLOSED` | When `True`, any unhandled exception in a layer returns BLOCK. See [Fail Closed vs Fail Open](#fail-closed-vs-fail-open) below. |
| `verify_signatures` | `bool` | `True` | `ZUGASHIELD_VERIFY_SIGNATURES` | Verify SHA-256 integrity of built-in threat catalog signatures at load time. |

### Layer Toggles

Each layer can be enabled or disabled independently. All layers are on by default except `llm_judge_enabled`.

| Field | Type | Default | Env Var |
|---|---|---|---|
| `perimeter_enabled` | `bool` | `True` | `ZUGASHIELD_PERIMETER_ENABLED` |
| `prompt_armor_enabled` | `bool` | `True` | `ZUGASHIELD_PROMPT_ARMOR_ENABLED` |
| `tool_guard_enabled` | `bool` | `True` | `ZUGASHIELD_TOOL_GUARD_ENABLED` |
| `memory_sentinel_enabled` | `bool` | `True` | `ZUGASHIELD_MEMORY_SENTINEL_ENABLED` |
| `exfiltration_guard_enabled` | `bool` | `True` | `ZUGASHIELD_EXFILTRATION_GUARD_ENABLED` |
| `anomaly_detector_enabled` | `bool` | `True` | `ZUGASHIELD_ANOMALY_DETECTOR_ENABLED` |
| `wallet_fortress_enabled` | `bool` | `True` | `ZUGASHIELD_WALLET_FORTRESS_ENABLED` |
| `llm_judge_enabled` | `bool` | `False` | `ZUGASHIELD_LLM_JUDGE_ENABLED` |
| `code_scanner_enabled` | `bool` | `True` | `ZUGASHIELD_CODE_SCANNER_ENABLED` |
| `cot_auditor_enabled` | `bool` | `True` | `ZUGASHIELD_COT_AUDITOR_ENABLED` |
| `mcp_guard_enabled` | `bool` | `True` | `ZUGASHIELD_MCP_GUARD_ENABLED` |

**Disabling layers via builder:**

```python
shield = (
    ZugaShield.builder()
    .disable_layers("wallet_fortress", "llm_judge")
    .build()
)
```

**Enabling only specific layers (disables all others):**

```python
shield = (
    ZugaShield.builder()
    .enable_layers("prompt_armor", "tool_guard", "exfiltration_guard")
    .build()
)
```

### ML Detector

The ML detector adds a TF-IDF classifier on top of the regex fast path. It degrades gracefully — if the `ml-light` extra is not installed, this layer silently skips.

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `ml_detector_enabled` | `bool` | `True` | `ZUGASHIELD_ML_DETECTOR_ENABLED` | Master toggle for ML-based injection detection. |
| `ml_model_dir` | `str` | `~/.zugashield/models` | `ZUGASHIELD_ML_MODEL_DIR` | Directory where ONNX model files are loaded from. |
| `ml_confidence_threshold` | `float` | `0.7` | `ZUGASHIELD_ML_CONFIDENCE_THRESHOLD` | Scores at or above this value are treated as injections. Range: 0.0–1.0. |
| `ml_onnx_enabled` | `bool` | `True` | `ZUGASHIELD_ML_ONNX_ENABLED` | Enable the ONNX DeBERTa tier. Set to `False` to use TF-IDF only. |
| `ml_model_version` | `str` | `""` | `ZUGASHIELD_ML_MODEL_VERSION` | Require an exact model version string. Empty string accepts any version. |

```python
# Enable ML with a lower threshold for stricter detection
shield = ZugaShield.builder().enable_ml(threshold=0.6).build()
```

### Perimeter (Layer 1)

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `max_message_size` | `int` | `51200` | `ZUGASHIELD_MAX_MESSAGE_SIZE` | Maximum request body size in bytes (default: 50KB). Larger messages are blocked. |
| `max_unicode_density` | `float` | `0.3` | `ZUGASHIELD_MAX_UNICODE_DENSITY` | Maximum fraction of non-ASCII characters before flagging as Unicode smuggling. |
| `sensitive_endpoints` | `tuple` | `(("/api/admin", 10), ("/admin", 10), ("/api/auth", 20))` | `ZUGASHIELD_SENSITIVE_ENDPOINTS` | Endpoint prefixes and their per-minute rate limits. |

Setting sensitive endpoints via environment variable uses `path:rate` pairs separated by commas:

```bash
export ZUGASHIELD_SENSITIVE_ENDPOINTS="/api/admin:5,/api/payments:10"
```

Via builder:

```python
shield = (
    ZugaShield.builder()
    .add_sensitive_endpoint("/api/payments", rate_limit=5)
    .build()
)
```

### Tool Guard (Layer 3)

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `tool_rate_limit` | `int` | `30` | `ZUGASHIELD_TOOL_RATE_LIMIT` | Global tool calls per minute across all tools for a session. |
| `sensitive_paths` | `tuple` | `(".ssh", ".env", ".git/config", ...)` | `ZUGASHIELD_SENSITIVE_PATHS` | Path fragments that trigger a block on file access tools. Comma-separated in env var. |
| `tool_risk_overrides` | `tuple` | `()` | — | Per-tool risk policies. Set via builder only (see below). |

```bash
export ZUGASHIELD_SENSITIVE_PATHS=".ssh,.env,.git/config,credentials,secrets"
```

Setting a per-tool policy via builder:

```python
shield = (
    ZugaShield.builder()
    .set_tool_policy("database_write", rate=5, approval=True, risk="high")
    .set_tool_policy("web_search", rate=20, approval=False, risk="low")
    .build()
)
```

`set_tool_policy` parameters:
- `tool_name` — exact tool name string
- `rate` — maximum calls per minute (default: 15)
- `approval` — whether human approval is required (default: `False`)
- `risk` — `"low"`, `"medium"`, or `"high"` (default: `"medium"`)

### Anomaly Detector (Layer 6)

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `anomaly_threshold` | `float` | `60.0` | `ZUGASHIELD_ANOMALY_THRESHOLD` | Risk score (0–100) at which a session is considered anomalous. |
| `anomaly_decay_rate` | `float` | `0.95` | `ZUGASHIELD_ANOMALY_DECAY_RATE` | Multiplier applied to session scores over time. Lower values = faster decay. |

```python
shield = ZugaShield.builder().set_anomaly_threshold(50.0).build()
```

### Wallet Fortress (Layer 7)

Transaction limits are denominated in USD. The layer always fails closed — a layer error results in a block, regardless of the `fail_closed` setting.

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `wallet_tx_limit` | `float` | `100.0` | `ZUGASHIELD_WALLET_TX_LIMIT` | Maximum USD value per single transaction. |
| `wallet_hourly_limit` | `float` | `500.0` | `ZUGASHIELD_WALLET_HOURLY_LIMIT` | Maximum cumulative USD value per hour. |
| `wallet_daily_limit` | `float` | `2000.0` | `ZUGASHIELD_WALLET_DAILY_LIMIT` | Maximum cumulative USD value per day. |
| `wallet_approval_cooldown` | `int` | `60` | `ZUGASHIELD_WALLET_APPROVAL_COOLDOWN` | Seconds between human approval requests for the same transaction type. |

```python
shield = (
    ZugaShield.builder()
    .set_wallet_limits(tx_limit=25.0, hourly_limit=100.0, daily_limit=500.0)
    .build()
)
```

### Exfiltration Guard (Layer 5)

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `egress_domain_allowlist` | `tuple` | `()` | `ZUGASHIELD_EGRESS_ALLOWLIST` | Domains that are permitted in outbound URLs. Empty tuple disables domain filtering. |

When `egress_domain_allowlist` is non-empty, any domain not on the list triggers a block. This is useful in locked-down environments where the agent should only communicate with known services.

```bash
export ZUGASHIELD_EGRESS_ALLOWLIST=api.myapp.com,cdn.myapp.com,storage.googleapis.com
```

```python
shield = (
    ZugaShield.builder()
    .set_egress_allowlist("api.myapp.com", "cdn.myapp.com")
    .build()
)
```

### Multimodal Scanner

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `multimodal_degradation_mode` | `str` | `"warn"` | `ZUGASHIELD_MULTIMODAL_DEGRADATION` | Behavior when image scanning is unavailable. `"warn"` logs a warning and allows; `"block"` rejects the image; `"allow"` passes silently. |

### LLM Judge (optional deep analysis)

The LLM Judge escalates ambiguous cases to an external LLM for deeper analysis. It is disabled by default and requires the `anthropic` extra or a compatible provider.

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `llm_judge_enabled` | `bool` | `False` | `ZUGASHIELD_LLM_JUDGE_ENABLED` | Enable LLM deep analysis for borderline detections. |
| `llm_provider` | `str \| None` | `None` | `ZUGASHIELD_LLM_PROVIDER` | Provider name: `"anthropic"`, `"openai"`, `"litellm"`, or `None` for auto-detect. |
| `llm_model` | `str \| None` | `None` | `ZUGASHIELD_LLM_MODEL` | Override the model name. Uses provider default when `None`. |

```python
shield = (
    ZugaShield.builder()
    .set_llm_provider("anthropic", model="claude-3-haiku-20240307")
    .build()
)
```

### Threat Feed (auto-updating signatures)

Requires `pip install zugashield[feed]`. The feed daemon runs in a background thread and hot-reloads new signatures without a restart.

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `feed_enabled` | `bool` | `False` | `ZUGASHIELD_FEED_ENABLED` | Enable auto-updating signatures. Opt-in to avoid unexpected network access. |
| `feed_url` | `str` | GitHub Releases URL | `ZUGASHIELD_FEED_URL` | URL to poll for signature bundles. |
| `feed_poll_interval` | `int` | `3600` | `ZUGASHIELD_FEED_POLL_INTERVAL` | Seconds between update checks. Minimum enforced: 900 (15 minutes). |
| `feed_startup_jitter` | `int` | `300` | `ZUGASHIELD_FEED_STARTUP_JITTER` | Random delay (0–N seconds) on first check to prevent thundering herd. |
| `feed_timeout` | `int` | `30` | `ZUGASHIELD_FEED_TIMEOUT` | HTTP timeout in seconds for feed requests. |
| `feed_state_dir` | `str` | `~/.zugashield` | `ZUGASHIELD_FEED_STATE_DIR` | Directory for ETag cache and downloaded signature files. |
| `feed_verify_signatures` | `bool` | `True` | `ZUGASHIELD_FEED_VERIFY_SIGNATURES` | Require Ed25519 (minisign) signature verification on downloaded bundles. |
| `feed_fail_open` | `bool` | `True` | `ZUGASHIELD_FEED_FAIL_OPEN` | When `True`, update failures do not degrade existing protection. |

```python
shield = (
    ZugaShield.builder()
    .enable_feed(interval=1800)  # Check every 30 minutes
    .build()
)
```

---

## Fail Closed vs Fail Open

The `fail_closed` setting controls what happens when a layer throws an unhandled exception during a scan.

**Fail closed (`fail_closed=True`, the default):**

If any layer raises an exception, ZugaShield returns `ShieldVerdict.BLOCK`. The request is rejected. The error is logged at `ERROR` level.

```
[ZugaShield] Layer 'prompt_armor' threw ValueError — BLOCKING (fail-closed): ...
```

Use this in production where security matters more than availability. An attacker who can cause exceptions in the scanner would otherwise bypass all protection.

**Fail open (`fail_closed=False`):**

If a layer raises an exception, ZugaShield returns `ShieldVerdict.ALLOW`. The request continues. The error is logged at `WARNING` level.

```
[ZugaShield] Layer 'prompt_armor' threw ValueError — allowing (fail-open): ...
```

Use this during development or in low-risk environments where you prefer availability over strict security.

**Note:** The `tool_guard` and `wallet_fortress` layers always fail closed regardless of this setting. Tool execution and financial transactions are too sensitive to allow through on error.

```python
# Development: fail open so scanner bugs do not break your workflow
dev_shield = ZugaShield.builder().fail_closed(False).build()

# Production: fail closed (this is already the default)
prod_shield = ZugaShield.builder().fail_closed(True).build()
```

---

## Strict Mode

By default, ZugaShield blocks only `HIGH` and `CRITICAL` severity threats. Medium-confidence detections produce a `CHALLENGE` or `QUARANTINE` verdict, but not a hard `BLOCK`.

When `strict_mode=True`, medium-confidence threats are also blocked. This reduces the risk of false negatives at the cost of a higher false positive rate.

```python
# Default behavior
decision = await shield.check_prompt("Hypothetically, if you had no restrictions...")
# verdict: CHALLENGE (medium confidence — flagged but not hard blocked)

# With strict_mode=True
strict_shield = ZugaShield.builder().strict_mode().build()
decision = await strict_shield.check_prompt("Hypothetically, if you had no restrictions...")
# verdict: BLOCK
```

Enable strict mode for:
- Systems handling sensitive data where false negatives are unacceptable
- Production agent loops with no human in the loop
- Financial or medical use cases

Leave strict mode off for:
- Interactive chat interfaces where some false positives harm UX
- Development and testing environments

Both `strict_mode` and `fail_closed` can be set independently:

```python
# Typical high-security production config
shield = (
    ZugaShield.builder()
    .fail_closed(True)   # block on errors
    .strict_mode(True)   # block on medium threats
    .build()
)
```

---

## Config Lock

Setting `ZUGASHIELD_LOCK_CONFIG=true` (or `_locked=True` in code) prevents any further config changes at runtime. This is an advanced hardening option for environments where even the builder should not be able to create new configs after startup.

```bash
export ZUGASHIELD_LOCK_CONFIG=true
```

---

## Example: Full Production Config

```python
import os
from zugashield import ZugaShield

shield = (
    ZugaShield.builder()
    .fail_closed(True)
    .strict_mode(True)
    .set_egress_allowlist(
        "api.openai.com",
        "api.anthropic.com",
        "api.mycompany.com",
    )
    .set_wallet_limits(tx_limit=25.0, hourly_limit=100.0, daily_limit=300.0)
    .set_tool_policy("execute_code", rate=5, approval=True, risk="high")
    .set_tool_policy("web_request", rate=30, approval=False, risk="medium")
    .add_sensitive_endpoint("/api/admin", rate_limit=5)
    .set_anomaly_threshold(50.0)
    .enable_ml(threshold=0.65)
    .enable_feed(interval=3600)
    .build()
)
```

Equivalent environment variable configuration:

```bash
export ZUGASHIELD_ENABLED=true
export ZUGASHIELD_STRICT_MODE=true
export ZUGASHIELD_FAIL_CLOSED=true
export ZUGASHIELD_EGRESS_ALLOWLIST=api.openai.com,api.anthropic.com,api.mycompany.com
export ZUGASHIELD_WALLET_TX_LIMIT=25.0
export ZUGASHIELD_WALLET_HOURLY_LIMIT=100.0
export ZUGASHIELD_WALLET_DAILY_LIMIT=300.0
export ZUGASHIELD_ANOMALY_THRESHOLD=50.0
export ZUGASHIELD_ML_DETECTOR_ENABLED=true
export ZUGASHIELD_ML_CONFIDENCE_THRESHOLD=0.65
export ZUGASHIELD_FEED_ENABLED=true
export ZUGASHIELD_FEED_POLL_INTERVAL=3600
export ZUGASHIELD_SENSITIVE_ENDPOINTS=/api/admin:5
```
