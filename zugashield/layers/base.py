"""
ZugaShield - Base Layer Protocol
==================================

Defines the interface all security layers must implement.
Use this to create custom layers:

    from zugashield.layers.base import BaseLayer

    class MyComplianceLayer(BaseLayer):
        LAYER_NAME = "compliance"

        async def check(self, text: str, **kwargs) -> ShieldDecision:
            # Your logic here
            return allow_decision(self.LAYER_NAME)

    shield.register_layer(MyComplianceLayer(config, catalog))
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from zugashield.config import ShieldConfig
    from zugashield.threat_catalog import ThreatCatalog
    from zugashield.types import ShieldDecision


class BaseLayer(ABC):
    """
    Abstract base class for all ZugaShield security layers.

    Every layer must:
    - Define a unique ``LAYER_NAME`` class attribute
    - Implement an async ``check()`` method
    - Implement ``get_stats()`` for observability
    """

    LAYER_NAME: str = ""

    @abstractmethod
    async def check(self, *args: Any, **kwargs: Any) -> ShieldDecision:
        """
        Run this layer's security checks.

        The signature varies by layer type. All layers return a ShieldDecision.
        """
        ...

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Return layer statistics for dashboard/observability."""
        ...
