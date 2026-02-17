"""
ZugaShield - Flask Integration
================================

Before/after request hooks and a dashboard Blueprint for Flask applications.

Usage (full extension):
    from flask import Flask
    from zugashield import ZugaShield
    from zugashield.integrations.flask import create_flask_extension

    app = Flask(__name__)
    shield = ZugaShield()
    create_flask_extension(app, shield=shield)

Usage (dashboard Blueprint only):
    from zugashield.integrations.flask import create_dashboard_blueprint

    blueprint = create_dashboard_blueprint(prefix="/shield", shield_getter=lambda: shield)
    app.register_blueprint(blueprint)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

try:
    import flask as _flask  # noqa: F401
    _HAS_FLASK = True
except ImportError:
    _HAS_FLASK = False


def _run_async(coro: Any) -> Any:
    """
    Run an async coroutine from synchronous Flask request context.

    Flask is synchronous so we need a helper to drive the event loop.
    Uses the running loop if one exists (e.g. when using async Flask 2.x),
    otherwise spins up a new loop.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Nest via a thread-safe future (works with Flask's async support)
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def create_flask_extension(
    app: Any = None,
    shield: Any = None,
) -> Any:
    """
    Register ZugaShield as a Flask extension.

    Attaches ``before_request`` and ``after_request`` hooks so every
    incoming request is checked through the perimeter layer (Layer 1).

    Blocked requests receive a 403 JSON response before route handlers run.
    The shield decision is stored on Flask's ``g`` object as ``g.shield_decision``
    for downstream route handlers to inspect.

    Args:
        app:    Flask application instance. If None, returns an uninitialised
                extension that you can call ``ext.init_app(app)`` on later.
        shield: Optional ZugaShield instance. Defaults to singleton.

    Returns:
        The extension object (useful for the init_app pattern).

    Example (application factory):
        shield_ext = create_flask_extension(shield=my_shield)
        # later...
        shield_ext.init_app(app)
    """
    if not _HAS_FLASK:
        raise ImportError(
            "Flask is required for ZugaShield Flask integration. "
            "Install with: pip install zugashield[flask]"
        )

    from flask import Flask, g, jsonify, request as flask_request

    class _ZugaShieldExtension:
        def __init__(self) -> None:
            self._shield = shield

        def _get_shield(self) -> Any:
            if self._shield is None:
                from zugashield import get_zugashield
                self._shield = get_zugashield()
            return self._shield

        def init_app(self, flask_app: Flask) -> None:
            """Register hooks on a Flask application (init_app pattern)."""

            @flask_app.before_request
            def _zugashield_before_request():
                _shield = self._get_shield()
                try:
                    headers = {
                        k.lower(): v
                        for k, v in flask_request.headers.items()
                    }
                    client_ip = flask_request.remote_addr or "unknown"
                    content_length = flask_request.content_length or 0

                    decision = _run_async(
                        _shield.check_request(
                            path=flask_request.path,
                            method=flask_request.method,
                            content_length=content_length,
                            body=None,
                            headers=headers,
                            client_ip=client_ip,
                        )
                    )

                    # Expose decision on g for route handlers
                    g.shield_decision = decision

                    if decision.is_blocked:
                        threat = (
                            decision.threats_detected[0]
                            if decision.threats_detected
                            else None
                        )
                        response = jsonify(
                            {
                                "error": "blocked_by_zugashield",
                                "verdict": decision.verdict.value,
                                "layer": decision.layer,
                                "threat": (
                                    threat.description if threat else "Request blocked"
                                ),
                                "category": (
                                    threat.category.value if threat else None
                                ),
                            }
                        )
                        response.status_code = 403
                        return response

                except Exception:
                    logger.exception(
                        "[ZugaShield] Flask before_request error — fail-open"
                    )
                    g.shield_decision = None

            @flask_app.after_request
            def _zugashield_after_request(response):
                # Attach a header so clients know the shield ran
                decision = getattr(g, "shield_decision", None)
                if decision is not None:
                    response.headers["X-ZugaShield"] = decision.verdict.value
                return response

            logger.info("[ZugaShield] Flask extension registered on %s", flask_app.name)

    ext = _ZugaShieldExtension()
    if app is not None:
        ext.init_app(app)
    return ext


def create_dashboard_blueprint(
    prefix: str = "/shield",
    shield_getter: Optional[Callable] = None,
) -> Any:
    """
    Create a Flask Blueprint exposing the ZugaShield dashboard API.

    Endpoints (relative to the blueprint's url_prefix):
        GET /status        — shield enabled/disabled
        GET /threats       — recent threats
        GET /anomaly-score — session anomaly score (query: session_id)
        GET /dashboard     — aggregated dashboard data
        GET /audit         — audit log (query: limit, layer)

    Args:
        prefix:        URL prefix for the blueprint (used as url_prefix when registering).
        shield_getter: Callable returning a ZugaShield instance.
                       Defaults to the global singleton getter.

    Returns:
        A Flask Blueprint ready to ``app.register_blueprint(bp)``.

    Example:
        bp = create_dashboard_blueprint(prefix="/api/shield", shield_getter=lambda: shield)
        app.register_blueprint(bp)
    """
    if not _HAS_FLASK:
        raise ImportError(
            "Flask is required for ZugaShield Flask integration. "
            "Install with: pip install zugashield[flask]"
        )

    from flask import Blueprint, jsonify, request as flask_request

    def _get_shield() -> Any:
        if shield_getter is not None:
            return shield_getter()
        from zugashield import get_zugashield
        return get_zugashield()

    bp = Blueprint("zugashield", __name__, url_prefix=prefix)

    @bp.get("/status")
    def status():
        """Return shield enabled/disabled + layer configuration."""
        shield = _get_shield()
        state = shield.get_version_state()
        return jsonify(
            {
                "enabled": shield.enabled,
                "strict_mode": shield.config.strict_mode,
                "fail_closed": shield.config.fail_closed,
                "enabled_layers": state["enabled_layers"],
            }
        )

    @bp.get("/threats")
    def threats():
        """Return recent threat detections."""
        shield = _get_shield()
        limit = flask_request.args.get("limit", 50, type=int)
        layer = flask_request.args.get("layer", None)
        events = shield.get_audit_log(limit=limit, layer=layer)
        threat_events = [e for e in events if e.get("verdict") not in ("allow",)]
        return jsonify({"count": len(threat_events), "threats": threat_events})

    @bp.get("/anomaly-score")
    def anomaly_score():
        """Return anomaly score for a session."""
        shield = _get_shield()
        session_id = flask_request.args.get("session_id", "default")
        score = shield.get_session_risk(session_id=session_id)
        return jsonify(
            {
                "session_id": session_id,
                "session_score": score.session_score,
                "cumulative_score": score.cumulative_score,
                "threat_level": score.threat_level.value,
                "contributing_event_count": len(score.contributing_events),
            }
        )

    @bp.get("/dashboard")
    def dashboard():
        """Return aggregated dashboard data."""
        shield = _get_shield()
        return jsonify(shield.get_dashboard_data())

    @bp.get("/audit")
    def audit():
        """Return the raw audit log."""
        shield = _get_shield()
        limit = flask_request.args.get("limit", 100, type=int)
        layer = flask_request.args.get("layer", None)
        return jsonify({"events": shield.get_audit_log(limit=limit, layer=layer)})

    return bp
