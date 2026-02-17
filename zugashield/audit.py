"""
ZugaShield - Audit Logger
===========================

Security event logging and forensics.
Records all shield decisions for:
- Real-time dashboard display
- Post-incident forensics
- False positive analysis
- Performance monitoring

Uses in-memory ring buffer with optional database persistence.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from zugashield.types import (
    ShieldDecision,
    ShieldVerdict,
)

logger = logging.getLogger(__name__)

# Maximum events in memory
_MAX_EVENTS = 10000


@dataclass
class AuditEvent:
    """A single audit log entry."""

    timestamp: str
    layer: str
    verdict: str
    threat_count: int
    max_level: str
    elapsed_ms: float
    details: Dict[str, Any]

    def to_dict(self) -> Dict:
        return asdict(self)


class ShieldAuditLogger:
    """
    Audit logger for ZugaShield events.

    Maintains an in-memory ring buffer of recent events
    and provides query/filter capabilities for the dashboard.
    """

    def __init__(self, max_events: int = _MAX_EVENTS) -> None:
        self._events: deque = deque(maxlen=max_events)
        self._counters = {
            "total_checks": 0,
            "total_blocks": 0,
            "total_challenges": 0,
            "total_sanitizations": 0,
            "total_allows": 0,
        }
        self._layer_stats: Dict[str, Dict[str, int]] = {}

    def log(self, decision: ShieldDecision, context: Optional[Dict] = None) -> None:
        """
        Log a shield decision.

        Args:
            decision: The ShieldDecision from any layer
            context: Optional additional context (session_id, user_id, etc.)
        """
        self._counters["total_checks"] += 1

        if decision.verdict == ShieldVerdict.BLOCK:
            self._counters["total_blocks"] += 1
        elif decision.verdict == ShieldVerdict.QUARANTINE:
            self._counters["total_blocks"] += 1
        elif decision.verdict == ShieldVerdict.CHALLENGE:
            self._counters["total_challenges"] += 1
        elif decision.verdict == ShieldVerdict.SANITIZE:
            self._counters["total_sanitizations"] += 1
        else:
            self._counters["total_allows"] += 1

        # Track per-layer stats
        layer = decision.layer
        if layer not in self._layer_stats:
            self._layer_stats[layer] = {"checks": 0, "blocks": 0, "threats": 0}
        self._layer_stats[layer]["checks"] += 1
        self._layer_stats[layer]["threats"] += decision.threat_count
        if decision.is_blocked:
            self._layer_stats[layer]["blocks"] += 1

        # Only log non-allow events to the ring buffer (saves space)
        if decision.verdict != ShieldVerdict.ALLOW:
            details = {
                "threats": [
                    {
                        "category": t.category.value,
                        "level": t.level.value,
                        "description": t.description,
                        "evidence": t.evidence[:100],
                        "confidence": t.confidence,
                        "signature_id": t.signature_id,
                    }
                    for t in decision.threats_detected
                ],
            }
            if context:
                details["context"] = context

            event = AuditEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                layer=layer,
                verdict=decision.verdict.value,
                threat_count=decision.threat_count,
                max_level=decision.max_threat_level.value,
                elapsed_ms=round(decision.elapsed_ms, 2),
                details=details,
            )
            self._events.append(event)

            # Log to standard logger for syslog/file collection
            if decision.is_blocked:
                logger.warning(
                    "[ShieldAudit] BLOCKED by %s: %s (threats=%d, %.1fms)",
                    layer, decision.threats_detected[0].description if decision.threats_detected else "unknown",
                    decision.threat_count, decision.elapsed_ms,
                )

    def get_recent(self, limit: int = 100, layer: Optional[str] = None) -> List[Dict]:
        """Get recent audit events."""
        events = list(self._events)
        if layer:
            events = [e for e in events if e.layer == layer]
        return [e.to_dict() for e in events[-limit:]]

    def get_stats(self) -> Dict:
        """Get overall audit statistics."""
        return {
            "counters": dict(self._counters),
            "layer_stats": dict(self._layer_stats),
            "buffer_size": len(self._events),
            "buffer_capacity": self._events.maxlen,
        }
