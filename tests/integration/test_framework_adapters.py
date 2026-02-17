"""
Integration tests for ZugaShield framework adapters.

Tests verify that each adapter can be constructed and behaves correctly
without requiring a running server or external service.
Framework packages that are not installed are gracefully skipped.

All async checks use asyncio.run() to match project test conventions.

Adapters tested:
    1. FastAPI  — create_dashboard_router returns an APIRouter
    2. FastAPI  — /status endpoint returns health data
    3. Flask    — create_flask_extension wraps a Flask app
    4. LangChain — ZugaShieldCallbackHandler has required methods
    5. Approval  — ApprovalProvider can be subclassed
    6. MCP       — ZugaShieldMCPInterceptor exposes expected interface
    7. Starlette — ZugaShieldMiddleware can be instantiated
"""

import asyncio
import inspect

import pytest

from zugashield import ZugaShield
from zugashield.config import ShieldConfig


# ---------------------------------------------------------------------------
# Helper — run a coroutine synchronously (matches project convention)
# ---------------------------------------------------------------------------


def run(coro):
    """Run an async coroutine synchronously in a test."""
    return asyncio.run(coro)


def _make_shield() -> ZugaShield:
    """Create a fresh ZugaShield with default config."""
    return ZugaShield(ShieldConfig())


# =============================================================================
# 1. FastAPI — create_dashboard_router returns an APIRouter
# =============================================================================


def test_fastapi_router_creation():
    """
    create_dashboard_router (aliased as create_shield_router) returns a
    FastAPI APIRouter instance with the expected prefix and tags.
    """
    try:
        from fastapi import APIRouter
        from zugashield.integrations.fastapi import create_dashboard_router
    except ImportError:
        pytest.skip("fastapi not installed")

    shield = _make_shield()
    router = create_dashboard_router(shield_getter=lambda: shield)

    assert isinstance(router, APIRouter), (
        f"Expected APIRouter, got {type(router).__name__}"
    )


# =============================================================================
# 2. FastAPI — /status endpoint returns health data
# =============================================================================


def test_fastapi_status_endpoint():
    """
    The /status route function on the created router returns a dict
    containing the expected keys when called directly as a coroutine.
    """
    try:
        from fastapi import APIRouter
        from zugashield.integrations.fastapi import create_dashboard_router
    except ImportError:
        pytest.skip("fastapi not installed")

    shield = _make_shield()
    router = create_dashboard_router(shield_getter=lambda: shield)

    # Find the /status route handler on the router
    status_route = None
    for route in router.routes:
        if hasattr(route, "path") and route.path == "/status":
            status_route = route
            break

    assert status_route is not None, "No /status route found on the router"

    # Call the endpoint function directly
    endpoint = status_route.endpoint
    if asyncio.iscoroutinefunction(endpoint):
        result = run(endpoint())
    else:
        result = endpoint()

    assert isinstance(result, dict), (
        f"Expected dict response from /status, got {type(result).__name__}"
    )
    assert "enabled" in result, "Missing 'enabled' key in /status response"
    assert "strict_mode" in result, "Missing 'strict_mode' key in /status response"
    assert "fail_closed" in result, "Missing 'fail_closed' key in /status response"
    assert "enabled_layers" in result, (
        "Missing 'enabled_layers' key in /status response"
    )


# =============================================================================
# 3. Flask — create_flask_extension wraps a Flask app
# =============================================================================


def test_flask_extension_init():
    """
    create_flask_extension registers before/after request hooks on a Flask
    app without error and returns an extension object.
    """
    try:
        from flask import Flask
        from zugashield.integrations.flask import create_flask_extension
    except ImportError:
        pytest.skip("flask not installed")

    app = Flask("zugashield_test")
    shield = _make_shield()

    ext = create_flask_extension(app=app, shield=shield)

    assert ext is not None, "create_flask_extension returned None"
    # The before_request and after_request hooks were registered — verify
    # by checking the Flask app's registered functions.
    assert hasattr(ext, "init_app"), (
        "Extension object missing init_app method"
    )
    # Flask stores before_request functions on the app
    assert len(app.before_request_funcs.get(None, [])) >= 1, (
        "No before_request hook registered on Flask app"
    )
    assert len(app.after_request_funcs.get(None, [])) >= 1, (
        "No after_request hook registered on Flask app"
    )


# =============================================================================
# 4. LangChain — ZugaShieldCallbackHandler has required methods
# =============================================================================


def test_langchain_callback_handler():
    """
    ZugaShieldCallbackHandler can be instantiated without langchain installed
    and exposes the required callback protocol methods.
    """
    from zugashield.integrations.langchain import ZugaShieldCallbackHandler

    shield = _make_shield()
    handler = ZugaShieldCallbackHandler(shield=shield, session_id="test-session")

    assert handler is not None

    # Required LangChain callback protocol methods
    required_methods = [
        "on_llm_start",
        "on_tool_start",
        "on_llm_end",
        "on_tool_end",
        "on_chain_start",
        "on_chain_end",
        "on_llm_error",
        "on_tool_error",
        "on_chain_error",
    ]
    for method_name in required_methods:
        assert hasattr(handler, method_name), (
            f"ZugaShieldCallbackHandler missing method: {method_name}"
        )
        method = getattr(handler, method_name)
        assert callable(method), f"{method_name} is not callable"
        assert asyncio.iscoroutinefunction(method), (
            f"{method_name} must be an async (coroutine) function"
        )


# =============================================================================
# 5. Approval — ApprovalProvider can be subclassed and implemented
# =============================================================================


def test_approval_provider_protocol():
    """
    ApprovalProvider is an abstract base class that can be subclassed.
    A concrete implementation can be instantiated and called.
    """
    from zugashield.integrations.approval import ApprovalProvider, NoOpApprovalProvider
    from zugashield.types import ShieldDecision, ShieldVerdict

    # Verify abstract base class structure
    assert inspect.isabstract(ApprovalProvider), (
        "ApprovalProvider should be abstract (has abstractmethod)"
    )

    # Concrete subclass implementation
    class AlwaysApprove(ApprovalProvider):
        async def request_approval(self, decision, context=None):
            return True

    provider = AlwaysApprove()
    decision = ShieldDecision(
        verdict=ShieldVerdict.CHALLENGE,
        threats_detected=[],
        layer="tool_guard",
    )

    approved = run(provider.request_approval(decision, context={"tool": "web_search"}))
    assert approved is True, "AlwaysApprove provider should return True"

    # Also verify the built-in NoOpApprovalProvider auto-denies
    noop = NoOpApprovalProvider()
    denied = run(noop.request_approval(decision))
    assert denied is False, "NoOpApprovalProvider should return False"

    # notify() is a no-op but must not raise
    run(noop.notify(decision, context={}))


# =============================================================================
# 6. MCP — ZugaShieldMCPInterceptor has the expected interface
# =============================================================================


def test_mcp_server_tools_registered():
    """
    ZugaShieldMCPInterceptor exposes scan_tools, check_call, check_output,
    and get_stats. scan_tools filters a list of tool dicts correctly.
    """
    from zugashield.integrations.mcp import ZugaShieldMCPInterceptor

    shield = _make_shield()
    interceptor = ZugaShieldMCPInterceptor(shield=shield, session_id="test")

    # Verify the expected public interface
    required_methods = ["scan_tools", "check_call", "check_output", "get_stats"]
    for method_name in required_methods:
        assert hasattr(interceptor, method_name), (
            f"ZugaShieldMCPInterceptor missing method: {method_name}"
        )
        assert callable(getattr(interceptor, method_name)), (
            f"{method_name} is not callable"
        )

    # scan_tools is synchronous — run it with a clean list
    clean_tools = [
        {
            "name": "web_search",
            "description": "Search the web for information.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
            },
        },
        {
            "name": "get_weather",
            "description": "Retrieve weather forecast for a location.",
            "inputSchema": {
                "type": "object",
                "properties": {"location": {"type": "string"}},
            },
        },
    ]

    result = interceptor.scan_tools(clean_tools)
    # Clean tools should pass through
    assert isinstance(result, list), "scan_tools should return a list"
    assert len(result) == 2, (
        f"Expected 2 clean tools to pass through, got {len(result)}"
    )

    # Stats should reflect the scanned tools
    stats = interceptor.get_stats()
    assert "tools_scanned" in stats, "Missing 'tools_scanned' in stats"
    assert stats["tools_scanned"] == 2


# =============================================================================
# 7. Starlette — ZugaShieldMiddleware can be instantiated
# =============================================================================


def test_starlette_middleware_creation():
    """
    ZugaShieldMiddleware wraps a minimal ASGI application without error.
    The middleware object stores the inner app and exposes __call__.
    """
    from zugashield.integrations.starlette import ZugaShieldMiddleware

    # Minimal ASGI app stub — never actually called in this test
    async def dummy_app(scope, receive, send):
        pass

    shield = _make_shield()

    # Default construction (fail-open, no excludes)
    middleware = ZugaShieldMiddleware(app=dummy_app, shield=shield)
    assert middleware is not None
    assert middleware.app is dummy_app
    assert callable(middleware.__call__), (
        "ZugaShieldMiddleware must be callable (ASGI interface)"
    )

    # Construction with options
    middleware_strict = ZugaShieldMiddleware(
        app=dummy_app,
        shield=shield,
        fail_closed=True,
        exclude_paths=("/health", "/metrics"),
    )
    assert middleware_strict._fail_closed is True
    assert "/health" in middleware_strict._exclude_paths
    assert "/metrics" in middleware_strict._exclude_paths

    # Verify the ASGI callable signature: (scope, receive, send)
    sig = inspect.signature(middleware.__call__)
    param_names = list(sig.parameters.keys())
    assert "scope" in param_names, "Missing 'scope' parameter in __call__"
    assert "receive" in param_names, "Missing 'receive' parameter in __call__"
    assert "send" in param_names, "Missing 'send' parameter in __call__"
