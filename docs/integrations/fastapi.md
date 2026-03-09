# FastAPI Integration

ZugaShield provides middleware, a dashboard router, and a per-route decorator for FastAPI.

## Install

```bash
pip install "zugashield[fastapi]"
```

## Middleware

`create_shield_middleware` attaches ZugaShield as a Starlette `BaseHTTPMiddleware`. Every incoming HTTP request is checked through the perimeter layer (Layer 1) before reaching route handlers. Blocked requests receive a `403` JSON response.

```python
from fastapi import FastAPI
from zugashield import ZugaShield
from zugashield.integrations.fastapi import create_shield_middleware

shield = ZugaShield()
app = FastAPI()
create_shield_middleware(app, shield=shield)
```

**Blocked response:**

```json
{
  "error": "blocked_by_zugashield",
  "verdict": "block",
  "layer": "perimeter",
  "threat": "Prompt injection detected",
  "category": "prompt_injection"
}
```

The middleware is fail-open: if ZugaShield raises an unexpected exception, the request passes through. Set `fail_closed=True` in `ShieldConfig` to reverse this.

## Dashboard Router

`create_dashboard_router` creates a read-only FastAPI `APIRouter` with five monitoring endpoints.

```python
from zugashield.integrations.fastapi import create_dashboard_router

router = create_dashboard_router(shield_getter=lambda: shield)
app.include_router(router, prefix="/api/shield")
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/shield/status` | Shield enabled/disabled, layer config, strict/fail-closed flags |
| GET | `/api/shield/threats` | Recent blocked and quarantined threats |
| GET | `/api/shield/anomaly-score` | Session anomaly score |
| GET | `/api/shield/dashboard` | Aggregated stats: catalog, audit counters, per-layer stats |
| GET | `/api/shield/audit` | Raw audit log with optional filtering |

#### GET /status

```json
{
  "enabled": true,
  "strict_mode": false,
  "fail_closed": true,
  "enabled_layers": {
    "perimeter": true,
    "prompt_armor": true,
    "tool_guard": true
  }
}
```

#### GET /threats

Query params: `limit` (1–500, default 50), `layer` (optional filter).

```json
{
  "count": 2,
  "threats": [
    {
      "verdict": "block",
      "layer": "prompt_armor",
      "timestamp": "2026-02-17T10:00:00Z"
    }
  ]
}
```

#### GET /anomaly-score

Query params: `session_id` (default: `"default"`).

```json
{
  "session_id": "user-abc",
  "session_score": 42.5,
  "cumulative_score": 18.1,
  "threat_level": "medium",
  "contributing_event_count": 3
}
```

#### GET /audit

Query params: `limit` (1–1000, default 100), `layer` (optional).

```json
{
  "events": [...]
}
```

The legacy alias `create_shield_router` is kept for backwards compatibility.

## Per-Route Decorator

Use `shield_protect` when you want protection on specific routes without global middleware.

```python
from fastapi import Request
from zugashield.integrations.fastapi import shield_protect

@app.post("/api/sensitive")
@shield_protect()
async def sensitive_endpoint(request: Request):
    return {"ok": True}
```

With body inspection:

```python
@app.post("/api/chat")
@shield_protect(check_body=True)
async def chat(request: Request):
    ...
```

The decorator searches `args` and `kwargs` for a `Request` object. If none is found (e.g., dependency injection only), the check is skipped.

## Complete Example

```python
from fastapi import FastAPI, Request
from zugashield import ZugaShield
from zugashield.integrations.fastapi import (
    create_shield_middleware,
    create_dashboard_router,
    shield_protect,
)

shield = ZugaShield()
app = FastAPI()

# Global perimeter check
create_shield_middleware(app, shield=shield)

# Dashboard at /api/shield/*
router = create_dashboard_router(shield_getter=lambda: shield)
app.include_router(router, prefix="/api/shield")

# Extra protection on a sensitive route
@app.post("/api/admin/action")
@shield_protect(check_body=True)
async def admin_action(request: Request):
    return {"status": "ok"}
```

Last Updated: 2026-02-17
