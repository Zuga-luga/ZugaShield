"""
ZugaShield - Shared Types
=========================

Core data structures for the AI Agent Security System.
All layers share these enums and dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# =============================================================================
# Enums
# =============================================================================


class ThreatLevel(str, Enum):
    """Severity classification for detected threats."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    """Categories of AI-agent-specific attacks."""

    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    ASCII_ART_BYPASS = "ascii_art_bypass"
    UNICODE_SMUGGLING = "unicode_smuggling"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_EXPLOITATION = "tool_exploitation"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CHAIN_ATTACK = "chain_attack"
    WALLET_ATTACK = "wallet_attack"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"


class ShieldVerdict(str, Enum):
    """Action to take on detection. Mirrors GovernorVerdict pattern."""

    ALLOW = "allow"  # Clean, proceed
    SANITIZE = "sanitize"  # Modified input, proceed with cleaned version
    CHALLENGE = "challenge"  # Ask user to confirm intent
    QUARANTINE = "quarantine"  # Log + block + alert
    BLOCK = "block"  # Hard block, no bypass


class MemoryTrust(str, Enum):
    """Trust levels for memory provenance tracking."""

    VERIFIED = "verified"  # Explicitly confirmed by user
    USER_DIRECT = "user_direct"  # From user chat (trusted)
    BRAIN_GENERATED = "brain"  # From brain thoughts (medium trust)
    EXTERNAL = "external"  # From web/files (low trust, spotlight in prompt)
    UNKNOWN = "unknown"  # Legacy memories without provenance (flag)


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass
class ThreatDetection:
    """A single threat detection event from any layer."""

    category: ThreatCategory
    level: ThreatLevel
    verdict: ShieldVerdict
    description: str
    evidence: str  # What triggered detection
    layer: str  # Which layer detected it
    confidence: float  # 0.0-1.0
    suggested_action: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    signature_id: Optional[str] = None  # Threat catalog reference
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShieldDecision:
    """
    Returned by each layer check. Compatible with GovernorDecision.

    The aggregated result of running input through a shield layer,
    containing the verdict, any threats found, and timing info.
    """

    verdict: ShieldVerdict
    threats_detected: List[ThreatDetection]
    layer: str
    elapsed_ms: float = 0.0
    sanitized_input: Optional[str] = None  # If verdict=SANITIZE, the cleaned version
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return self.verdict in (ShieldVerdict.BLOCK, ShieldVerdict.QUARANTINE)

    @property
    def requires_approval(self) -> bool:
        return self.verdict == ShieldVerdict.CHALLENGE

    @property
    def threat_count(self) -> int:
        return len(self.threats_detected)

    @property
    def max_threat_level(self) -> ThreatLevel:
        if not self.threats_detected:
            return ThreatLevel.NONE
        level_order = [ThreatLevel.NONE, ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        return max(self.threats_detected, key=lambda t: level_order.index(t.level)).level


@dataclass
class AnomalyScore:
    """Behavioral anomaly scoring for session risk assessment."""

    session_score: float = 0.0  # 0-100, current session risk
    cumulative_score: float = 0.0  # 0-100, rolling risk across sessions
    decay_rate: float = 0.95  # How fast old events decay
    contributing_events: List[ThreatDetection] = field(default_factory=list)

    @property
    def threat_level(self) -> ThreatLevel:
        if self.session_score > 80:
            return ThreatLevel.CRITICAL
        if self.session_score > 60:
            return ThreatLevel.HIGH
        if self.session_score > 40:
            return ThreatLevel.MEDIUM
        if self.session_score > 20:
            return ThreatLevel.LOW
        return ThreatLevel.NONE


@dataclass
class ToolPolicy:
    """Policy for a specific tool's usage constraints."""

    rate: int = 30  # Max calls per minute
    approval: bool = False  # Requires user approval
    risk: str = "low"  # Risk level: low, medium, high, critical


# =============================================================================
# Helper: Create allow/block decisions quickly
# =============================================================================


def allow_decision(layer: str, elapsed_ms: float = 0.0) -> ShieldDecision:
    """Create a quick ALLOW decision with no threats."""
    return ShieldDecision(
        verdict=ShieldVerdict.ALLOW,
        threats_detected=[],
        layer=layer,
        elapsed_ms=elapsed_ms,
    )


def block_decision(
    layer: str,
    category: ThreatCategory,
    level: ThreatLevel,
    description: str,
    evidence: str,
    confidence: float = 0.9,
    signature_id: Optional[str] = None,
    elapsed_ms: float = 0.0,
) -> ShieldDecision:
    """Create a BLOCK decision with a single threat."""
    threat = ThreatDetection(
        category=category,
        level=level,
        verdict=ShieldVerdict.BLOCK,
        description=description,
        evidence=evidence,
        layer=layer,
        confidence=confidence,
        suggested_action="Block and log",
        signature_id=signature_id,
    )
    return ShieldDecision(
        verdict=ShieldVerdict.BLOCK,
        threats_detected=[threat],
        layer=layer,
        elapsed_ms=elapsed_ms,
    )
