"""
ZugaShield - Abstract Approval Provider
=========================================

Abstract base class for Human-in-the-Loop (HIL) integration.
Implement this to connect ZugaShield to your approval system
(Slack, Discord, web UI, CLI prompt, etc.)

Usage:
    from zugashield.integrations.approval import ApprovalProvider
    from zugashield import set_approval_provider

    class MyApprovalProvider(ApprovalProvider):
        async def request_approval(self, decision, context):
            # Show to user, wait for response
            return True  # or False

    set_approval_provider(MyApprovalProvider())
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from zugashield.types import ShieldDecision


class ApprovalProvider(ABC):
    """Abstract base class for human-in-the-loop approval."""

    @abstractmethod
    async def request_approval(
        self,
        decision: ShieldDecision,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Request human approval for a challenged action.

        Args:
            decision: The ShieldDecision requiring approval
            context: Additional context (tool name, session ID, etc.)

        Returns:
            True if approved, False if denied
        """
        ...

    async def notify(
        self,
        decision: ShieldDecision,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Notify about a security event (no approval needed).

        Override this to send alerts for BLOCK/QUARANTINE events.
        Default implementation is a no-op.
        """
        pass


class NoOpApprovalProvider(ApprovalProvider):
    """Default approval provider that auto-denies all requests."""

    async def request_approval(
        self,
        decision: ShieldDecision,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        return False
