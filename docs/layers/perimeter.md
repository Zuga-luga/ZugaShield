# Layer 1: Perimeter

**Module:** `zugashield/layers/perimeter.py`
**Class:** `PerimeterLayer`
**Last Updated:** 2026-02-17

## Purpose

The Perimeter is the first line of defense. It runs as HTTP middleware and validates every inbound request before it reaches any route handler or AI component. Its goal is to stop volumetric and structural attacks at the edge — prompt stuffing, rate abuse, and Unicode smuggling in headers — before they consume any downstream processing resources.

Checks complete in under 1 millisecond for typical requests.

## What It Detects

### Request Size Limits (PM-SIZE)

Oversized requests are a prompt stuffing vector. A large payload can inject thousands of tokens of attacker-controlled content before the model's own context. The layer compares the `Content-Length` header against the configured maximum and blocks requests that exceed it.

**Threat level:** MEDIUM
**Verdict:** BLOCK
**Confidence:** 0.95

### Endpoint Rate Limiting (PM-RATE, PM-RATE-GLOBAL)

Sensitive endpoints such as `/api/admin` and `/api/auth` are rate-limited per client IP. The layer maintains a sliding 60-second window of request timestamps for each `(client_ip, endpoint)` pair. When the count exceeds the configured limit, the request is challenged.

A second global rate check uses a SHA-256 hash of `(client_ip + user_agent)` to catch coordinated attacks where an attacker rotates session identifiers while keeping the same IP and browser fingerprint. The global limit is twice the per-session limit to accommodate legitimate multi-tab usage.

**Threat level:** MEDIUM
**Verdict:** CHALLENGE
**Confidence:** 0.90 (per-session), 0.85 (global)

### Unicode in Headers (PM-HDR)

Non-ASCII characters in request headers outside of `Cookie`, `User-Agent`, and `Accept-Language` are a smuggling indicator. The layer counts non-ASCII bytes in each header value and flags headers that contain any, with a recommendation to normalize the value.

**Threat level:** LOW
**Verdict:** SANITIZE
**Confidence:** 0.60

### Body Unicode Density (PM-UNI)

A request body where more than 30% of characters are non-ASCII (by default) is flagged for inspection. This catches Unicode-heavy payloads that may contain homoglyph substitutions or invisible character injections that the Prompt Armor layer will analyze more deeply.

**Threat level:** LOW
**Verdict:** SANITIZE
**Confidence:** 0.55

## Verdict Logic

| Max Threat Level | Verdict |
|---|---|
| CRITICAL or HIGH | BLOCK |
| MEDIUM or below | CHALLENGE |

## Configuration

| Option | Environment Variable | Default | Description |
|---|---|---|---|
| `perimeter_enabled` | `ZUGASHIELD_PERIMETER_ENABLED` | `true` | Enable or disable this layer |
| `max_message_size` | `ZUGASHIELD_MAX_MESSAGE_SIZE` | `51200` | Maximum request body size in bytes (50 KB) |
| `max_unicode_density` | `ZUGASHIELD_MAX_UNICODE_DENSITY` | `0.3` | Maximum fraction of non-ASCII characters before flagging (30%) |
| `sensitive_endpoints` | `ZUGASHIELD_SENSITIVE_ENDPOINTS` | See below | Endpoint prefixes and their per-minute rate limits |

**Default sensitive endpoints:**

| Endpoint Prefix | Requests per Minute |
|---|---|
| `/api/admin` | 10 |
| `/admin` | 10 |
| `/api/auth` | 20 |

The environment variable format for custom endpoints is comma-separated `path:limit` pairs:

```
ZUGASHIELD_SENSITIVE_ENDPOINTS=/api/admin:10,/api/auth:20,/api/pay:5
```

## Example Attacks Caught

**Prompt stuffing via oversized POST:**
A 500 KB JSON body containing a system prompt replacement padded with filler text. Blocked at the perimeter before any parsing.

**Rate abuse on authentication endpoint:**
A bot submitting credential-stuffing attempts at 200 requests per minute against `/api/auth`. The 20 req/min limit triggers a CHALLENGE on the 21st request.

**Unicode header smuggling:**
A custom `X-Forwarded-Context` header containing Cyrillic look-alike characters intended to slip injected instructions past a downstream log parser. Flagged with PM-HDR and sanitized.

**Distributed rate abuse:**
Multiple session tokens from the same IP and user agent fingerprint hammering `/api/admin`. The global IP+UA hash check (PM-RATE-GLOBAL) triggers even when per-session counts look normal.

## Code Examples

### Basic integration with FastAPI middleware

```python
from zugashield import ZugaShield
from zugashield.config import ShieldConfig

config = ShieldConfig.builder() \
    .add_sensitive_endpoint("/api/pay", rate_limit=5) \
    .add_sensitive_endpoint("/api/admin", rate_limit=10) \
    .build()

shield = ZugaShield(config)

# The FastAPI integration automatically installs the perimeter as middleware
from zugashield.integrations.fastapi import ZugaShieldMiddleware
from fastapi import FastAPI

app = FastAPI()
app.add_middleware(ZugaShieldMiddleware, shield=shield)
```

### Calling the perimeter layer directly

```python
import asyncio
from zugashield.layers.perimeter import PerimeterLayer
from zugashield.config import ShieldConfig
from zugashield.threat_catalog import ThreatCatalog

config = ShieldConfig()
catalog = ThreatCatalog()
perimeter = PerimeterLayer(config, catalog)

async def main():
    decision = await perimeter.check(
        path="/api/admin/users",
        method="POST",
        content_length=120000,  # 120 KB — over the 50 KB limit
        body="...",
        headers={"X-Custom": "normal-value"},
        client_ip="203.0.113.42",
        user_agent="Mozilla/5.0",
    )
    print(decision.verdict)          # ShieldVerdict.BLOCK
    print(decision.threats_detected[0].signature_id)  # PM-SIZE

asyncio.run(main())
```

### Custom size limit via environment variable

```bash
# Tighten the limit for a high-security deployment
ZUGASHIELD_MAX_MESSAGE_SIZE=10240  # 10 KB

# Relax the limit for a document processing endpoint
ZUGASHIELD_MAX_MESSAGE_SIZE=524288  # 512 KB
```

### Retrieving layer statistics

```python
stats = perimeter.get_stats()
# {
#   "layer": "perimeter",
#   "checks": 4821,
#   "blocked": 3,
#   "rate_limits": 12,
#   "oversized": 1,
#   "global_rate_limits": 2
# }
```

## Implementation Notes

- The rate tracker uses `deque(maxlen=200)` per `(client_ip, endpoint)` pair, so memory is bounded even under sustained attack.
- The global rate tracker is module-level (`_global_rate_tracker`) and persists across `PerimeterLayer` instances within the same process, enabling coordination detection across requests that arrive on different ASGI workers sharing a process.
- The `Cookie`, `User-Agent`, and `Accept-Language` headers are explicitly excluded from the Unicode header check because those fields legitimately contain non-ASCII content in internationalized environments.
- Elapsed time is measured with `time.perf_counter()` for sub-millisecond precision and reported in the `ShieldDecision.elapsed_ms` field.
