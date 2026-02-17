"""
ZugaShield - FastAPI Integration
==================================

Optional FastAPI router for the security dashboard.

Usage:
    from zugashield import ZugaShield
    from zugashield.integrations.fastapi import create_shield_router

    shield = ZugaShield()
    router = create_shield_router(lambda: shield)
    app.include_router(router, prefix="/api/shield")
"""

from __future__ import annotations

from typing import Callable, Optional

try:
    from fastapi import APIRouter, Query

    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False


def create_shield_router(
    shield_getter: Callable,
    prefix: str = "",
) -> "APIRouter":
    """
    Create a FastAPI router for the ZugaShield dashboard API.

    Args:
        shield_getter: Callable that returns the ZugaShield instance
        prefix: Optional URL prefix

    Returns:
        FastAPI APIRouter with shield endpoints
    """
    if not _HAS_FASTAPI:
        raise ImportError("FastAPI is required for the shield dashboard. Install with: pip install zugashield[fastapi]")

    router = APIRouter(prefix=prefix, tags=["ZugaShield"])

    @router.get("/status")
    async def shield_status():
        """Get overall shield status and dashboard data."""
        shield = shield_getter()
        return shield.get_dashboard_data()

    @router.get("/audit")
    async def shield_audit(
        limit: int = Query(100, ge=1, le=1000),
        layer: Optional[str] = Query(None),
    ):
        """Get recent audit events."""
        shield = shield_getter()
        return {"events": shield.get_audit_log(limit=limit, layer=layer)}

    @router.get("/config")
    async def shield_config():
        """Get current shield configuration."""
        shield = shield_getter()
        return shield.get_version_state()

    @router.get("/catalog/stats")
    async def catalog_stats():
        """Get threat catalog statistics."""
        shield = shield_getter()
        return shield.catalog.get_stats()

    return router
