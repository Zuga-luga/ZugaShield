"""
Unit tests for ZugaShield types module.

Tests all enums, dataclasses, and helper factory functions.
"""

from datetime import datetime

import pytest

from zugashield.types import (
    AnomalyScore,
    MemoryTrust,
    ShieldDecision,
    ShieldVerdict,
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ToolPolicy,
    allow_decision,
    block_decision,
)


# =============================================================================
# ThreatLevel enum
# =============================================================================


class TestThreatLevel:
    """ThreatLevel enum ordering and values."""

    def test_all_values_defined(self):
        values = {level.value for level in ThreatLevel}
        assert values == {"none", "low", "medium", "high", "critical"}

    def test_string_coercion(self):
        # str(Enum) should give the value, not the repr
        assert ThreatLevel.CRITICAL.value == "critical"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.NONE.value == "none"

    def test_order_for_sorting(self):
        """Validate a typical ordering used by layers."""
        level_order = [
            ThreatLevel.NONE,
            ThreatLevel.LOW,
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]
        assert level_order.index(ThreatLevel.NONE) < level_order.index(ThreatLevel.LOW)
        assert level_order.index(ThreatLevel.LOW) < level_order.index(ThreatLevel.MEDIUM)
        assert level_order.index(ThreatLevel.MEDIUM) < level_order.index(ThreatLevel.HIGH)
        assert level_order.index(ThreatLevel.HIGH) < level_order.index(ThreatLevel.CRITICAL)

    def test_is_str_subclass(self):
        assert isinstance(ThreatLevel.HIGH, str)
        assert ThreatLevel.HIGH == "high"


# =============================================================================
# ThreatCategory enum
# =============================================================================


class TestThreatCategory:
    """ThreatCategory enum membership."""

    def test_expected_categories_present(self):
        expected = {
            "prompt_injection",
            "indirect_injection",
            "ascii_art_bypass",
            "unicode_smuggling",
            "memory_poisoning",
            "tool_exploitation",
            "data_exfiltration",
            "privilege_escalation",
            "chain_attack",
            "wallet_attack",
            "behavioral_anomaly",
        }
        values = {cat.value for cat in ThreatCategory}
        # All expected categories must be present
        assert expected.issubset(values), f"Missing: {expected - values}"

    def test_is_str_subclass(self):
        assert isinstance(ThreatCategory.PROMPT_INJECTION, str)
        assert ThreatCategory.PROMPT_INJECTION == "prompt_injection"


# =============================================================================
# ShieldVerdict enum
# =============================================================================


class TestShieldVerdict:
    """ShieldVerdict enum and its semantics."""

    def test_all_verdicts_defined(self):
        values = {v.value for v in ShieldVerdict}
        assert values == {"allow", "sanitize", "challenge", "quarantine", "block"}

    def test_is_str_subclass(self):
        assert isinstance(ShieldVerdict.BLOCK, str)
        assert ShieldVerdict.ALLOW == "allow"

    def test_verdict_severity_ordering(self):
        """Verdicts increase in restriction from ALLOW to BLOCK."""
        order = [
            ShieldVerdict.ALLOW,
            ShieldVerdict.SANITIZE,
            ShieldVerdict.CHALLENGE,
            ShieldVerdict.QUARANTINE,
            ShieldVerdict.BLOCK,
        ]
        # ALLOW is least restrictive
        assert order[0] == ShieldVerdict.ALLOW
        # BLOCK is most restrictive
        assert order[-1] == ShieldVerdict.BLOCK


# =============================================================================
# MemoryTrust enum
# =============================================================================


class TestMemoryTrust:
    """MemoryTrust enum for provenance tracking."""

    def test_all_trust_levels_present(self):
        values = {t.value for t in MemoryTrust}
        assert "verified" in values
        assert "user_direct" in values
        assert "external" in values
        assert "unknown" in values


# =============================================================================
# ThreatDetection dataclass
# =============================================================================


class TestThreatDetection:
    """ThreatDetection dataclass construction and field access."""

    def _make_detection(self, **overrides):
        defaults = dict(
            category=ThreatCategory.PROMPT_INJECTION,
            level=ThreatLevel.HIGH,
            verdict=ShieldVerdict.BLOCK,
            description="Test threat",
            evidence="ignore previous instructions",
            layer="prompt_armor",
            confidence=0.95,
            suggested_action="Block immediately",
        )
        defaults.update(overrides)
        return ThreatDetection(**defaults)

    def test_basic_construction(self):
        d = self._make_detection()
        assert d.category == ThreatCategory.PROMPT_INJECTION
        assert d.level == ThreatLevel.HIGH
        assert d.verdict == ShieldVerdict.BLOCK
        assert d.confidence == 0.95

    def test_timestamp_auto_populated(self):
        d = self._make_detection()
        assert isinstance(d.timestamp, datetime)

    def test_optional_signature_id_defaults_none(self):
        d = self._make_detection()
        assert d.signature_id is None

    def test_signature_id_can_be_set(self):
        d = self._make_detection(signature_id="FP-001")
        assert d.signature_id == "FP-001"

    def test_metadata_defaults_empty_dict(self):
        d = self._make_detection()
        assert d.metadata == {}

    def test_metadata_stored(self):
        meta = {"key": "value", "count": 3}
        d = self._make_detection(metadata=meta)
        assert d.metadata["key"] == "value"
        assert d.metadata["count"] == 3

    def test_confidence_range(self):
        # Confidence must be a float in [0.0, 1.0]; constructor doesn't enforce
        # but tests document the expected range
        d = self._make_detection(confidence=0.0)
        assert d.confidence == 0.0
        d = self._make_detection(confidence=1.0)
        assert d.confidence == 1.0


# =============================================================================
# ShieldDecision dataclass
# =============================================================================


class TestShieldDecision:
    """ShieldDecision dataclass properties and derived values."""

    def _make_decision(self, verdict=ShieldVerdict.ALLOW, threats=None, layer="test"):
        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats or [],
            layer=layer,
        )

    def _make_threat(self, level=ThreatLevel.HIGH):
        return ThreatDetection(
            category=ThreatCategory.PROMPT_INJECTION,
            level=level,
            verdict=ShieldVerdict.BLOCK,
            description="threat",
            evidence="evidence",
            layer="test",
            confidence=0.9,
            suggested_action="block",
        )

    def test_allow_is_not_blocked(self):
        d = self._make_decision(verdict=ShieldVerdict.ALLOW)
        assert not d.is_blocked

    def test_block_is_blocked(self):
        d = self._make_decision(verdict=ShieldVerdict.BLOCK)
        assert d.is_blocked

    def test_quarantine_is_blocked(self):
        d = self._make_decision(verdict=ShieldVerdict.QUARANTINE)
        assert d.is_blocked

    def test_challenge_requires_approval(self):
        d = self._make_decision(verdict=ShieldVerdict.CHALLENGE)
        assert d.requires_approval

    def test_block_does_not_require_approval(self):
        d = self._make_decision(verdict=ShieldVerdict.BLOCK)
        assert not d.requires_approval

    def test_threat_count_empty(self):
        d = self._make_decision()
        assert d.threat_count == 0

    def test_threat_count_with_threats(self):
        threats = [self._make_threat(), self._make_threat()]
        d = self._make_decision(threats=threats)
        assert d.threat_count == 2

    def test_max_threat_level_none_when_empty(self):
        d = self._make_decision()
        assert d.max_threat_level == ThreatLevel.NONE

    def test_max_threat_level_returns_highest(self):
        threats = [
            self._make_threat(ThreatLevel.LOW),
            self._make_threat(ThreatLevel.CRITICAL),
            self._make_threat(ThreatLevel.MEDIUM),
        ]
        d = self._make_decision(threats=threats)
        assert d.max_threat_level == ThreatLevel.CRITICAL

    def test_elapsed_ms_defaults_zero(self):
        d = self._make_decision()
        assert d.elapsed_ms == 0.0

    def test_elapsed_ms_stored(self):
        d = ShieldDecision(
            verdict=ShieldVerdict.ALLOW,
            threats_detected=[],
            layer="test",
            elapsed_ms=12.5,
        )
        assert d.elapsed_ms == 12.5

    def test_sanitized_input_defaults_none(self):
        d = self._make_decision()
        assert d.sanitized_input is None

    def test_metadata_defaults_empty(self):
        d = self._make_decision()
        assert d.metadata == {}


# =============================================================================
# AnomalyScore dataclass
# =============================================================================


class TestAnomalyScore:
    """AnomalyScore dataclass and threat_level property."""

    def test_default_session_score_zero(self):
        score = AnomalyScore()
        assert score.session_score == 0.0

    def test_threat_level_none_when_low(self):
        score = AnomalyScore(session_score=5.0)
        assert score.threat_level == ThreatLevel.NONE

    def test_threat_level_low(self):
        score = AnomalyScore(session_score=25.0)
        assert score.threat_level == ThreatLevel.LOW

    def test_threat_level_medium(self):
        score = AnomalyScore(session_score=45.0)
        assert score.threat_level == ThreatLevel.MEDIUM

    def test_threat_level_high(self):
        score = AnomalyScore(session_score=65.0)
        assert score.threat_level == ThreatLevel.HIGH

    def test_threat_level_critical(self):
        score = AnomalyScore(session_score=85.0)
        assert score.threat_level == ThreatLevel.CRITICAL


# =============================================================================
# ToolPolicy dataclass
# =============================================================================


class TestToolPolicy:
    """ToolPolicy defaults and construction."""

    def test_defaults(self):
        policy = ToolPolicy()
        assert policy.rate == 30
        assert policy.approval is False
        assert policy.risk == "low"

    def test_custom_values(self):
        policy = ToolPolicy(rate=5, approval=True, risk="critical")
        assert policy.rate == 5
        assert policy.approval is True
        assert policy.risk == "critical"


# =============================================================================
# allow_decision factory
# =============================================================================


class TestAllowDecision:
    """allow_decision helper factory."""

    def test_verdict_is_allow(self):
        d = allow_decision("test_layer")
        assert d.verdict == ShieldVerdict.ALLOW

    def test_no_threats(self):
        d = allow_decision("test_layer")
        assert d.threats_detected == []

    def test_layer_name_preserved(self):
        d = allow_decision("prompt_armor")
        assert d.layer == "prompt_armor"

    def test_elapsed_ms_optional(self):
        d = allow_decision("test_layer", elapsed_ms=5.0)
        assert d.elapsed_ms == 5.0

    def test_elapsed_ms_defaults_zero(self):
        d = allow_decision("test_layer")
        assert d.elapsed_ms == 0.0

    def test_is_not_blocked(self):
        d = allow_decision("test_layer")
        assert not d.is_blocked


# =============================================================================
# block_decision factory
# =============================================================================


class TestBlockDecision:
    """block_decision helper factory."""

    def test_verdict_is_block(self):
        d = block_decision(
            layer="test_layer",
            category=ThreatCategory.PROMPT_INJECTION,
            level=ThreatLevel.CRITICAL,
            description="Test block",
            evidence="payload",
        )
        assert d.verdict == ShieldVerdict.BLOCK

    def test_one_threat_created(self):
        d = block_decision(
            layer="test_layer",
            category=ThreatCategory.DATA_EXFILTRATION,
            level=ThreatLevel.HIGH,
            description="Secret leak",
            evidence="sk-live-xxx",
        )
        assert len(d.threats_detected) == 1

    def test_threat_fields_populated(self):
        d = block_decision(
            layer="exfiltration_guard",
            category=ThreatCategory.DATA_EXFILTRATION,
            level=ThreatLevel.HIGH,
            description="API key detected",
            evidence="sk-live-abc123",
            confidence=0.98,
            signature_id="EG-KEY",
        )
        threat = d.threats_detected[0]
        assert threat.category == ThreatCategory.DATA_EXFILTRATION
        assert threat.level == ThreatLevel.HIGH
        assert threat.confidence == 0.98
        assert threat.signature_id == "EG-KEY"
        assert threat.layer == "exfiltration_guard"

    def test_is_blocked(self):
        d = block_decision(
            layer="test",
            category=ThreatCategory.PROMPT_INJECTION,
            level=ThreatLevel.CRITICAL,
            description="desc",
            evidence="evid",
        )
        assert d.is_blocked
