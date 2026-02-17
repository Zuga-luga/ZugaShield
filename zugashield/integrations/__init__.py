"""
ZugaShield integration plugins.

Lazy imports — each integration is only loaded when explicitly accessed,
so importing this package does not pull in FastAPI, Flask, LangChain, etc.

Available integrations:

    fastapi    — Middleware, dashboard router, @shield_protect decorator
    starlette  — Raw ASGI middleware (ZugaShieldMiddleware)
    flask      — Flask extension + Blueprint
    langchain  — LangChain AsyncCallbackHandler
    llamaindex — LlamaIndex CallbackHandler
    crewai     — Tool wrapper + crew-level protection
    mcp        — MCP tool definition scanner + call interceptor
    approval   — Abstract approval provider (Human-in-the-Loop)
"""

from __future__ import annotations

# Approval provider is always available (zero dependencies)
from zugashield.integrations.approval import ApprovalProvider, NoOpApprovalProvider

__all__ = [
    # Zero-dependency (always available)
    "ApprovalProvider",
    "NoOpApprovalProvider",
    # FastAPI / Starlette
    "create_shield_middleware",
    "create_dashboard_router",
    "create_shield_router",   # legacy alias
    "shield_protect",
    "ZugaShieldMiddleware",
    # Flask
    "create_flask_extension",
    "create_dashboard_blueprint",
    # LangChain
    "ZugaShieldCallbackHandler",
    # LlamaIndex (imported via sub-module to avoid name collision)
    "llamaindex",
    # CrewAI
    "shield_wrap_tool",
    "shield_wrap_crew",
    "ZugaShieldToolMixin",
    # MCP
    "ZugaShieldMCPInterceptor",
    "shield_wrap_mcp_client",
]


def __getattr__(name: str):
    """
    Lazy loader — only imports a sub-module's symbols when first accessed.
    This keeps import time fast and avoids ImportError for missing optional
    dependencies when other integrations are used.
    """
    # FastAPI
    if name in ("create_shield_middleware", "create_dashboard_router", "create_shield_router", "shield_protect"):
        from zugashield.integrations import fastapi as _fastapi
        if name == "create_shield_middleware":
            return _fastapi.create_shield_middleware
        if name == "create_dashboard_router":
            return _fastapi.create_dashboard_router
        if name == "create_shield_router":
            return _fastapi.create_shield_router
        if name == "shield_protect":
            return _fastapi.shield_protect

    # Starlette
    if name == "ZugaShieldMiddleware":
        from zugashield.integrations.starlette import ZugaShieldMiddleware
        return ZugaShieldMiddleware

    # Flask
    if name in ("create_flask_extension", "create_dashboard_blueprint"):
        from zugashield.integrations import flask as _flask
        if name == "create_flask_extension":
            return _flask.create_flask_extension
        if name == "create_dashboard_blueprint":
            return _flask.create_dashboard_blueprint

    # LangChain
    if name == "ZugaShieldCallbackHandler":
        from zugashield.integrations.langchain import ZugaShieldCallbackHandler
        return ZugaShieldCallbackHandler

    # LlamaIndex (return the module itself to avoid collision with LangChain's handler)
    if name == "llamaindex":
        from zugashield.integrations import llamaindex as _llamaindex
        return _llamaindex

    # CrewAI
    if name == "shield_wrap_tool":
        from zugashield.integrations.crewai import shield_wrap_tool
        return shield_wrap_tool
    if name == "shield_wrap_crew":
        from zugashield.integrations.crewai import shield_wrap_crew
        return shield_wrap_crew
    if name == "ZugaShieldToolMixin":
        from zugashield.integrations.crewai import ZugaShieldToolMixin
        return ZugaShieldToolMixin

    # MCP
    if name == "ZugaShieldMCPInterceptor":
        from zugashield.integrations.mcp import ZugaShieldMCPInterceptor
        return ZugaShieldMCPInterceptor
    if name == "shield_wrap_mcp_client":
        from zugashield.integrations.mcp import shield_wrap_mcp_client
        return shield_wrap_mcp_client

    raise AttributeError(f"module 'zugashield.integrations' has no attribute {name!r}")
