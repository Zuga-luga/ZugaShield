"""
ZugaShield - FastAPI Integration
==================================

Middleware, router factory, and per-route decorator for FastAPI.

Usage (middleware + dashboard):
    from zugashield import ZugaShield
    from zugashield.integrations.fastapi import (
        create_shield_middleware,
        create_dashboard_router,
        shield_protect,
    )

    shield = ZugaShield()
    app = FastAPI()
    create_shield_middleware(app, shield=shield)

    router = create_dashboard_router(shield_getter=lambda: shield)
    app.include_router(router, prefix="/api/shield")

Usage (per-route decorator):
    @app.post("/api/chat")
    @shield_protect()
    async def chat_endpoint(request: Request):
        ...
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from fastapi import APIRouter, Depends, Query, Request, Response
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.types import ASGIApp

    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False


# =============================================================================
# Middleware
# =============================================================================


def create_shield_middleware(app: Any, shield: Any = None) -> None:
    """
    Attach ZugaShield as a Starlette/FastAPI middleware.

    All incoming HTTP requests are checked through the perimeter layer (Layer 1).
    Blocked requests receive a 403 JSON response before reaching route handlers.

    Args:
        app: The FastAPI (or Starlette) application instance.
        shield: Optional ZugaShield instance. If not provided, the singleton is used.
    """
    if not _HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for ZugaShield middleware. "
            "Install with: pip install zugashield[fastapi]"
        )

    from zugashield import get_zugashield

    _shield = shield or get_zugashield()

    class _ZugaShieldMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Callable) -> Response:
            try:
                # Extract headers as plain dict
                headers: Dict[str, str] = dict(request.headers)
                client_ip = (
                    request.client.host if request.client else "unknown"
                )
                path = request.url.path
                method = request.method

                content_length = int(headers.get("content-length", 0))

                decision = await _shield.check_request(
                    path=path,
                    method=method,
                    content_length=content_length,
                    body=None,  # Body not consumed at middleware level
                    headers=headers,
                    client_ip=client_ip,
                )

                if decision.is_blocked:
                    threat = (
                        decision.threats_detected[0]
                        if decision.threats_detected
                        else None
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "blocked_by_zugashield",
                            "verdict": decision.verdict.value,
                            "layer": decision.layer,
                            "threat": threat.description if threat else "Unknown threat",
                            "category": threat.category.value if threat else None,
                        },
                    )

            except Exception:
                logger.exception("[ZugaShield] Middleware error — fail-open for request")

            return await call_next(request)

    app.add_middleware(_ZugaShieldMiddleware)
    logger.info("[ZugaShield] FastAPI perimeter middleware attached")


# =============================================================================
# Dashboard router factory
# =============================================================================


def create_dashboard_router(
    shield_getter: Callable,
    prefix: str = "",
) -> "APIRouter":
    """
    Create a FastAPI router for the ZugaShield security dashboard API.

    Exposes five read-only endpoints for monitoring shield state:
        GET {prefix}/status        — shield enabled/disabled + config
        GET {prefix}/threats       — recent blocked/quarantined threats
        GET {prefix}/anomaly-score — session anomaly score
        GET {prefix}/dashboard     — aggregated dashboard data
        GET {prefix}/audit         — full audit log with filtering

    Args:
        shield_getter: Callable returning the ZugaShield instance.
        prefix: Optional URL prefix (e.g. "/api/shield").

    Returns:
        FastAPI APIRouter ready to include_router() into your app.

    Example:
        router = create_dashboard_router(lambda: shield)
        app.include_router(router, prefix="/api/shield")

    Note: Also available via the legacy alias ``create_shield_router``.
    """
    if not _HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for the shield dashboard. "
            "Install with: pip install zugashield[fastapi]"
        )

    router = APIRouter(prefix=prefix, tags=["ZugaShield"])

    # ------------------------------------------------------------------
    # GET /status
    # ------------------------------------------------------------------
    @router.get("/status")
    async def shield_status():
        """Return whether the shield is enabled, and its layer configuration."""
        shield = shield_getter()
        state = shield.get_version_state()
        return {
            "enabled": shield.enabled,
            "strict_mode": shield.config.strict_mode,
            "fail_closed": shield.config.fail_closed,
            "enabled_layers": state["enabled_layers"],
        }

    # ------------------------------------------------------------------
    # GET /threats
    # ------------------------------------------------------------------
    @router.get("/threats")
    async def shield_threats(
        limit: int = Query(50, ge=1, le=500),
        layer: Optional[str] = Query(None),
    ):
        """Return recent threat detections (blocks and quarantines only)."""
        shield = shield_getter()
        events = shield.get_audit_log(limit=limit, layer=layer)
        # Filter to non-allow verdicts — audit only stores these, but be explicit
        threats = [e for e in events if e.get("verdict") not in ("allow",)]
        return {
            "count": len(threats),
            "threats": threats,
        }

    # ------------------------------------------------------------------
    # GET /anomaly-score
    # ------------------------------------------------------------------
    @router.get("/anomaly-score")
    async def shield_anomaly_score(
        session_id: str = Query("default"),
    ):
        """Return the anomaly score for a session."""
        shield = shield_getter()
        score = shield.get_session_risk(session_id=session_id)
        return {
            "session_id": session_id,
            "session_score": score.session_score,
            "cumulative_score": score.cumulative_score,
            "threat_level": score.threat_level.value,
            "contributing_event_count": len(score.contributing_events),
        }

    # ------------------------------------------------------------------
    # GET /dashboard
    # ------------------------------------------------------------------
    @router.get("/dashboard")
    async def shield_dashboard():
        """Return aggregated dashboard data: catalog stats, audit counters, per-layer stats."""
        shield = shield_getter()
        return shield.get_dashboard_data()

    # ------------------------------------------------------------------
    # GET /audit
    # ------------------------------------------------------------------
    @router.get("/audit")
    async def shield_audit(
        limit: int = Query(100, ge=1, le=1000),
        layer: Optional[str] = Query(None),
    ):
        """Return the raw audit log with optional filtering by layer."""
        shield = shield_getter()
        return {
            "events": shield.get_audit_log(limit=limit, layer=layer),
        }

    return router


# Legacy alias — keep backwards-compat with existing callers
create_shield_router = create_dashboard_router


# =============================================================================
# Per-route decorator
# =============================================================================


def shield_protect(
    shield: Any = None,
    check_body: bool = False,
):
    """
    Decorator that runs ZugaShield perimeter checks on individual FastAPI routes.

    Useful when you don't want to attach global middleware but still want
    protection on specific sensitive endpoints.

    Usage:
        @app.post("/api/sensitive")
        @shield_protect()
        async def sensitive_endpoint(request: Request):
            ...

    Args:
        shield: Optional ZugaShield instance. Defaults to singleton.
        check_body: If True, also read and check the raw request body.
    """
    if not _HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for @shield_protect. "
            "Install with: pip install zugashield[fastapi]"
        )

    def decorator(func: Callable) -> Callable:
        import functools
        import inspect

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            from zugashield import get_zugashield

            _shield = shield or get_zugashield()

            # Attempt to find the Request object in args/kwargs
            request: Optional[Request] = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if request is None:
                for val in kwargs.values():
                    if isinstance(val, Request):
                        request = val
                        break

            if request is not None:
                try:
                    headers = dict(request.headers)
                    client_ip = (
                        request.client.host if request.client else "unknown"
                    )
                    body_text: Optional[str] = None
                    if check_body:
                        raw = await request.body()
                        body_text = raw.decode("utf-8", errors="replace")

                    decision = await _shield.check_request(
                        path=request.url.path,
                        method=request.method,
                        content_length=int(headers.get("content-length", 0)),
                        body=body_text,
                        headers=headers,
                        client_ip=client_ip,
                    )

                    if decision.is_blocked:
                        threat = (
                            decision.threats_detected[0]
                            if decision.threats_detected
                            else None
                        )
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "blocked_by_zugashield",
                                "verdict": decision.verdict.value,
                                "layer": decision.layer,
                                "threat": threat.description if threat else "Unknown threat",
                            },
                        )
                except Exception:
                    logger.exception(
                        "[ZugaShield] @shield_protect error — fail-open for route %s",
                        getattr(request, "url", {}).path if request else "unknown",
                    )

            # Invoke the original route handler
            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

        return wrapper

    return decorator
