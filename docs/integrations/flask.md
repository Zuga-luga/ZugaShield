# Flask Integration

ZugaShield provides a Flask extension with `before_request`/`after_request` hooks and a dashboard Blueprint.

## Install

```bash
pip install "zugashield[flask]"
```

## Extension (create_flask_extension)

Registers hooks on a Flask application so every request is checked through the perimeter layer (Layer 1). Blocked requests receive a `403` JSON response before any route handler runs. The shield decision is stored on Flask's `g` object as `g.shield_decision` for downstream inspection.

```python
from flask import Flask
from zugashield import ZugaShield
from zugashield.integrations.flask import create_flask_extension

app = Flask(__name__)
shield = ZugaShield()
create_flask_extension(app, shield=shield)
```

### Application Factory Pattern (init_app)

```python
from flask import Flask
from zugashield import ZugaShield
from zugashield.integrations.flask import create_flask_extension

shield = ZugaShield()
shield_ext = create_flask_extension(shield=shield)  # app=None defers init

def create_app():
    app = Flask(__name__)
    shield_ext.init_app(app)
    return app
```

### Response Header

The `after_request` hook adds an `X-ZugaShield` header to every response carrying the verdict value (`allow`, `block`, `quarantine`, etc.).

### Accessing the Decision in Routes

```python
from flask import g, jsonify

@app.get("/api/data")
def get_data():
    decision = getattr(g, "shield_decision", None)
    if decision and decision.is_blocked:
        return jsonify({"error": "blocked"}), 403
    return jsonify({"data": "..."})
```

### Blocked Response

```json
{
  "error": "blocked_by_zugashield",
  "verdict": "block",
  "layer": "perimeter",
  "threat": "Suspicious request pattern",
  "category": "behavioral_anomaly"
}
```

The extension is fail-open: exceptions in the before_request hook are caught and logged, setting `g.shield_decision = None`.

## Dashboard Blueprint (create_dashboard_blueprint)

Exposes the same five monitoring endpoints as the FastAPI router.

```python
from zugashield.integrations.flask import create_dashboard_blueprint

bp = create_dashboard_blueprint(
    prefix="/api/shield",
    shield_getter=lambda: shield,
)
app.register_blueprint(bp)
```

### Endpoints

| Method | Path | Query Params |
|--------|------|-------------|
| GET | `/api/shield/status` | — |
| GET | `/api/shield/threats` | `limit`, `layer` |
| GET | `/api/shield/anomaly-score` | `session_id` |
| GET | `/api/shield/dashboard` | — |
| GET | `/api/shield/audit` | `limit`, `layer` |

All endpoints return JSON. Defaults: `limit=50` for threats, `limit=100` for audit.

## Async Note

Flask is synchronous. ZugaShield's async checks are driven via a thread-pool helper (`concurrent.futures.ThreadPoolExecutor`) when an event loop is already running, or via `asyncio.run()` otherwise. This is compatible with both standard Flask and Flask 2.x async mode.

## Complete Example

```python
from flask import Flask
from zugashield import ZugaShield
from zugashield.integrations.flask import (
    create_flask_extension,
    create_dashboard_blueprint,
)

shield = ZugaShield()
app = Flask(__name__)

create_flask_extension(app, shield=shield)

bp = create_dashboard_blueprint(
    prefix="/api/shield",
    shield_getter=lambda: shield,
)
app.register_blueprint(bp)

@app.get("/api/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run()
```

Last Updated: 2026-02-17
