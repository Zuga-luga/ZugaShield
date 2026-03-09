# Starlette / ASGI Middleware

`ZugaShieldMiddleware` is a pure ASGI middleware compatible with any ASGI framework: Starlette, FastAPI, Litestar, Quart, etc.

The FastAPI integration (`zugashield.integrations.fastapi`) builds on top of this class via Starlette's `BaseHTTPMiddleware`. Use this middleware directly when working with raw Starlette or other ASGI frameworks.

## Install

```bash
pip install zugashield
# No additional dependencies for pure ASGI usage
```

## Usage

### Starlette

```python
from starlette.applications import Starlette
from zugashield import ZugaShield
from zugashield.integrations.starlette import ZugaShieldMiddleware

shield = ZugaShield()
app = Starlette()
app.add_middleware(ZugaShieldMiddleware, shield=shield)
```

### Raw ASGI Wrapping

```python
from zugashield.integrations.starlette import ZugaShieldMiddleware

app = ZugaShieldMiddleware(your_asgi_app)
```

### With Path Exclusions

```python
app.add_middleware(
    ZugaShieldMiddleware,
    shield=shield,
    exclude_paths=("/health", "/metrics", "/readyz"),
)
```

Paths matching any prefix in `exclude_paths` bypass the shield entirely. Tool call hooks never bypass, but HTTP healthcheck endpoints typically should.

## Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `app` | ASGI callable | required | Inner ASGI application |
| `shield` | ZugaShield | None | Shield instance. Defaults to singleton via `get_zugashield()` |
| `config` | ShieldConfig | None | Create a new shield with this config (ignored when `shield` is provided) |
| `fail_closed` | bool | `False` | Block on unexpected ZugaShield errors instead of passing through |
| `exclude_paths` | tuple | `()` | Path prefixes to bypass |

## Behavior

- Only HTTP scopes are intercepted. WebSocket and lifespan scopes pass through unchanged.
- Blocked requests receive an immediate `403` JSON response:

```json
{
  "error": "blocked_by_zugashield",
  "verdict": "block",
  "layer": "perimeter",
  "threat": "...",
  "category": "..."
}
```

- When `fail_closed=True` and ZugaShield raises an exception, a `503` response is returned:

```json
{
  "error": "zugashield_error",
  "detail": "Security check failed; request blocked (fail_closed=True)"
}
```

- When `fail_closed=False` (default), exceptions are logged and the request passes through.

## Response Headers

Blocked responses include:

```
X-ZugaShield: blocked
Content-Type: application/json
```

Error responses (fail_closed) include:

```
X-ZugaShield: error
```

## Lazy Initialization

The shield singleton is initialized on the first request, not at startup. This avoids blocking the ASGI lifespan event if model loading is slow.

## Complete Example

```python
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from zugashield import ZugaShield
from zugashield.integrations.starlette import ZugaShieldMiddleware

async def homepage(request):
    return JSONResponse({"hello": "world"})

shield = ZugaShield()

app = Starlette(routes=[Route("/", homepage)])
app.add_middleware(
    ZugaShieldMiddleware,
    shield=shield,
    fail_closed=True,
    exclude_paths=("/health",),
)
```

Last Updated: 2026-02-17
