"""
ZugaShield Flask Integration
==============================

Demonstrates three integration patterns for Flask:

    1. Full extension via create_flask_extension()
       - before_request hook checks every request through the perimeter layer
       - after_request hook adds X-ZugaShield header
       - g.shield_decision available inside route handlers

    2. Dashboard Blueprint via create_dashboard_blueprint()
       - Mounts read-only monitoring endpoints at /shield/*

    3. Manual per-route guard
       - Explicit shield.check_prompt() call inside a route handler

Install:
    pip install zugashield[flask]

Run:
    python examples/flask_integration.py

Test:
    curl http://localhost:5001/chat -X POST -H "Content-Type: application/json" \
         -d '{"message": "Hello, world!"}'
    curl http://localhost:5001/shield/dashboard
    curl http://localhost:5001/shield/threats
"""

from flask import Flask, g, jsonify, request as flask_request

from zugashield import ZugaShield
from zugashield.integrations.flask import (
    create_dashboard_blueprint,
    create_flask_extension,
)

# ---------------------------------------------------------------------------
# Configure the shield
# ---------------------------------------------------------------------------

shield = (
    ZugaShield.builder()
    .fail_closed(True)
    .add_sensitive_endpoint("/admin", rate_limit=5)
    .build()
)

# ---------------------------------------------------------------------------
# Create the Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Pattern 1: Global extension — wraps every request in the perimeter layer.
# Blocked requests get a 403 JSON response before any route handler runs.
# g.shield_decision is set on the Flask g object for downstream use.
create_flask_extension(app, shield=shield)

# Pattern 2: Dashboard blueprint — exposes monitoring endpoints.
# Mounts: GET /shield/status, /shield/threats, /shield/anomaly-score,
#         /shield/dashboard, /shield/audit
blueprint = create_dashboard_blueprint(
    prefix="/shield",
    shield_getter=lambda: shield,
)
app.register_blueprint(blueprint)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/chat")
def chat():
    """
    Chat endpoint with manual per-layer shield checks.

    The global extension already checked the perimeter (Layer 1).
    Here we add prompt injection (Layer 2) and output DLP (Layer 5).
    """
    body = flask_request.get_json(silent=True) or {}
    user_message = body.get("message", "")

    if not user_message:
        return jsonify({"error": "message is required"}), 400

    # Layer 2: Prompt Armor
    input_decision = shield.check_prompt_sync(
        user_message,
        context={"session_id": body.get("session_id", "default")},
    )
    if input_decision.is_blocked:
        return jsonify({
            "error": "blocked_by_zugashield",
            "layer": input_decision.layer,
            "threats": [t.description for t in input_decision.threats_detected],
        }), 403

    # ... your LLM call here ...
    llm_response = f"Echo: {user_message}"

    # Layer 5: Exfiltration Guard
    output_decision = shield.check_output_sync(llm_response)
    if output_decision.is_blocked:
        return jsonify({"response": "[Response blocked: potential data leak]"}), 200

    # Expose the perimeter decision from g (set by the extension's before_request)
    perimeter_verdict = "unknown"
    if hasattr(g, "shield_decision") and g.shield_decision:
        perimeter_verdict = g.shield_decision.verdict.value

    return jsonify({
        "response": llm_response,
        "shield": {
            "perimeter": perimeter_verdict,
            "prompt": input_decision.verdict.value,
            "output": output_decision.verdict.value,
        },
    })


@app.post("/tools/execute")
def execute_tool():
    """Tool execution endpoint with Layer 3: Tool Guard check."""
    body = flask_request.get_json(silent=True) or {}
    tool_name = body.get("tool", "")
    params = body.get("params", {})
    session_id = body.get("session_id", "default")

    if not tool_name:
        return jsonify({"error": "tool is required"}), 400

    # Layer 3: Tool Guard (synchronous wrapper)
    decision = shield.check_tool_call_sync(tool_name, params, session_id)
    if decision.is_blocked:
        return jsonify({
            "error": "tool_blocked",
            "tool": tool_name,
            "verdict": decision.verdict.value,
            "threats": [t.description for t in decision.threats_detected],
        }), 403

    return jsonify({
        "tool": tool_name,
        "status": "executed",
        "shield_verdict": decision.verdict.value,
    })


@app.get("/sessions/<session_id>/risk")
def session_risk(session_id: str):
    """Return the anomaly score for a session (Layer 6: Anomaly Detector)."""
    score = shield.get_session_risk(session_id)
    return jsonify({
        "session_id": session_id,
        "score": score.session_score,
        "cumulative": score.cumulative_score,
        "threat_level": score.threat_level.value,
    })


@app.get("/")
def index():
    return jsonify({
        "service": "ZugaShield Flask Example",
        "version": shield.version,
        "endpoints": ["/chat", "/tools/execute", "/shield/dashboard"],
    })


# ---------------------------------------------------------------------------
# Application factory pattern (alternative to global app)
# ---------------------------------------------------------------------------

def create_app(shield_instance: ZugaShield = None) -> Flask:
    """
    Application factory — use this pattern for testing or multiple configs.

    Example:
        test_shield = ZugaShield.builder().disable_layers("wallet_fortress").build()
        app = create_app(test_shield)
        client = app.test_client()
    """
    flask_app = Flask(__name__)
    _shield = shield_instance or ZugaShield()

    # init_app pattern: pass app to the extension after creation
    ext = create_flask_extension(shield=_shield)
    ext.init_app(flask_app)

    bp = create_dashboard_blueprint(prefix="/shield", shield_getter=lambda: _shield)
    flask_app.register_blueprint(bp)

    return flask_app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"[ZugaShield] Flask example starting on http://localhost:5001")
    print(f"  Signatures loaded: {shield.catalog.get_stats()['total_signatures']}")
    print(f"  Dashboard:         http://localhost:5001/shield/dashboard")
    app.run(host="0.0.0.0", port=5001, debug=False)
