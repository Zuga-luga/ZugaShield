"""
ZugaShield - Starlette/ASGI Middleware
=======================================

Pure ASGI middleware that can be used with any ASGI framework
(Starlette, FastAPI, Litestar, Quart, etc.).

This is the base transport layer that ``zugashield.integrations.fastapi``
builds on top of via Starlette's BaseHTTPMiddleware.

Usage (Starlette):
    from starlette.applications import Starlette
    from zugashield import ZugaShield
    from zugashield.integrations.starlette import ZugaShieldMiddleware

    shield = ZugaShield()
    app = Starlette()
    app.add_middleware(ZugaShieldMiddleware, shield=shield)

Usage (raw ASGI wrapping):
    from zugashield.integrations.starlette import ZugaShieldMiddleware

    app = ZugaShieldMiddleware(your_asgi_app)

Usage (FastAPI — prefer the fastapi integration):
    from fastapi import FastAPI
    from zugashield.integrations.starlette import ZugaShieldMiddleware

    app = FastAPI()
    app.add_middleware(ZugaShieldMiddleware)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


class ZugaShieldMiddleware:
    """
    ASGI middleware that checks all HTTP requests through ZugaShield's
    perimeter layer (Layer 1) before they reach the application.

    Non-HTTP scopes (WebSocket, lifespan) are passed through unchanged.

    Blocked requests receive an immediate 403 JSON response:
        {"error": "blocked_by_zugashield", "verdict": "block", ...}

    The middleware is fail-open by default: if ZugaShield raises an
    unexpected exception, the request proceeds to the application.
    This behaviour can be changed by passing ``fail_closed=True``.

    Args:
        app:         The inner ASGI application.
        shield:      Optional ZugaShield instance. Defaults to singleton.
        config:      Optional ShieldConfig. Ignored when ``shield`` is provided.
        fail_closed: Block on unexpected ZugaShield errors instead of passing through.
        exclude_paths: Iterable of path prefixes to bypass (e.g. ["/health"]).
    """

    def __init__(
        self,
        app: Any,
        shield: Any = None,
        config: Any = None,
        fail_closed: bool = False,
        exclude_paths: Optional[tuple] = None,
    ) -> None:
        self.app = app
        self._shield_instance = shield
        self._config = config
        self._fail_closed = fail_closed
        self._exclude_paths: tuple = tuple(exclude_paths or ())

    def _get_shield(self) -> Any:
        """Lazy-initialise the shield singleton on first request."""
        if self._shield_instance is None:
            from zugashield import ZugaShield, get_zugashield

            if self._config is not None:
                self._shield_instance = ZugaShield(config=self._config)
            else:
                self._shield_instance = get_zugashield()
        return self._shield_instance

    async def __call__(self, scope: Dict, receive: Callable, send: Callable) -> None:
        # Only intercept HTTP — let WebSocket and lifespan pass straight through
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "/")

        # Excluded paths bypass the shield entirely
        for prefix in self._exclude_paths:
            if path.startswith(prefix):
                await self.app(scope, receive, send)
                return

        try:
            shield = self._get_shield()

            # Build a minimal headers dict from the ASGI raw headers list
            raw_headers: list = scope.get("headers", [])
            headers: Dict[str, str] = {
                k.decode("latin-1").lower(): v.decode("latin-1")
                for k, v in raw_headers
            }

            method: str = scope.get("method", "GET")
            content_length = int(headers.get("content-length", 0))
            client = scope.get("client")
            client_ip = client[0] if client else "unknown"

            decision = await shield.check_request(
                path=path,
                method=method,
                content_length=content_length,
                body=None,
                headers=headers,
                client_ip=client_ip,
            )

            if decision.is_blocked:
                await self._send_blocked(scope, receive, send, decision)
                return

        except Exception:
            logger.exception(
                "[ZugaShield] ASGI middleware error for %s %s",
                scope.get("method", "?"),
                path,
            )
            if self._fail_closed:
                # Build a synthetic blocked decision for the error response
                await self._send_error_blocked(scope, receive, send)
                return

        await self.app(scope, receive, send)

    async def _send_blocked(
        self,
        scope: Dict,
        receive: Callable,
        send: Callable,
        decision: Any,
    ) -> None:
        """Send a 403 JSON response for a blocked request."""
        threat = (
            decision.threats_detected[0] if decision.threats_detected else None
        )
        body = json.dumps(
            {
                "error": "blocked_by_zugashield",
                "verdict": decision.verdict.value,
                "layer": decision.layer,
                "threat": threat.description if threat else "Request blocked",
                "category": threat.category.value if threat else None,
            }
        ).encode()

        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                    [b"x-zugashield", b"blocked"],
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def _send_error_blocked(
        self,
        scope: Dict,
        receive: Callable,
        send: Callable,
    ) -> None:
        """Send a 503 JSON response when fail_closed=True and an error occurred."""
        body = json.dumps(
            {
                "error": "zugashield_error",
                "detail": "Security check failed; request blocked (fail_closed=True)",
            }
        ).encode()

        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                    [b"x-zugashield", b"error"],
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})
