"""
Mutation-killing tests for ZugaShield types module.

These tests are designed to catch specific mutants that survive the base
test suite (test_types.py). Each test targets a precise operator, constant,
or logic change that a mutation testing tool would introduce.

Mutation targets:
  - AnomalyScore.threat_level: boundary precision (> vs >=, off-by-one constants)
  - ShieldDecision.is_blocked: tuple membership (SANITIZE, CHALLENGE not blocked)
  - ShieldDecision.requires_approval: equality vs membership, all non-CHALLENGE verdicts
  - ShieldDecision.max_threat_level: single element, uniform levels, ordering
  - block_decision factory: exact defaults, field wiring, layer propagation
  - allow_decision factory: derived property correctness
  - AnomalyScore defaults: exact numeric values
  - ThreatDetection: all fields stored and retrievable
  - Enum member counts: no accidental additions or removals
  - ToolPolicy: each default individually
"""

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
# Helpers shared across classes
# =============================================================================


def _make_threat(level: ThreatLevel = ThreatLevel.HIGH, layer: str = "test") -> ThreatDetection:
    return ThreatDetection(
        category=ThreatCategory.PROMPT_INJECTION,
        level=level,
        verdict=ShieldVerdict.BLOCK,
        description="mutation test threat",
        evidence="test evidence",
        layer=layer,
        confidence=0.9,
        suggested_action="Block and log",
    )


def _make_decision(
    verdict: ShieldVerdict = ShieldVerdict.ALLOW,
    threats=None,
    layer: str = "test",
) -> ShieldDecision:
    return ShieldDecision(
        verdict=verdict,
        threats_detected=threats if threats is not None else [],
        layer=layer,
    )


# =============================================================================
# AnomalyScore.threat_level — boundary precision
#
# Source (lines 137-145):
#   if self.session_score > 80: return CRITICAL
#   if self.session_score > 60: return HIGH
#   if self.session_score > 40: return MEDIUM
#   if self.session_score > 20: return LOW
#   return NONE
#
# Mutation targets:
#   > 80 -> >= 80  (boundary 80.0 would become CRITICAL instead of HIGH)
#   > 80 -> > 79   (boundary 79.01 would become CRITICAL instead of HIGH)
#   > 80 -> > 81   (boundary 80.01 would become HIGH instead of CRITICAL)
#   same pattern for 60, 40, 20
# =============================================================================


class TestAnomalyScoreThreatLevelBoundaries:
    """Precise boundary tests that kill off-by-one and > vs >= mutants."""

    # --- score == 0.0 ---

    def test_boundary_score_0_is_none(self):
        """Zero score must be NONE — kills mutant that maps 0 to LOW."""
        assert AnomalyScore(session_score=0.0).threat_level == ThreatLevel.NONE

    # --- score == 20.0: sits on the boundary, not above it ---

    def test_boundary_score_20_is_none_not_low(self):
        """score > 20 means 20.0 itself is NOT low. Kills >= 20 mutant."""
        assert AnomalyScore(session_score=20.0).threat_level == ThreatLevel.NONE

    def test_boundary_score_20_01_is_low(self):
        """Just above 20 crosses into LOW. Kills > 21 mutant."""
        assert AnomalyScore(session_score=20.01).threat_level == ThreatLevel.LOW

    def test_boundary_score_19_99_is_none(self):
        """Just below 20 remains NONE. Kills > 19 mutant."""
        assert AnomalyScore(session_score=19.99).threat_level == ThreatLevel.NONE

    # --- score == 40.0: sits on the boundary, not above it ---

    def test_boundary_score_40_is_low_not_medium(self):
        """score > 40 means 40.0 itself is still LOW (not MEDIUM). Kills >= 40 mutant."""
        assert AnomalyScore(session_score=40.0).threat_level == ThreatLevel.LOW

    def test_boundary_score_40_01_is_medium(self):
        """Just above 40 crosses into MEDIUM. Kills > 41 mutant."""
        assert AnomalyScore(session_score=40.01).threat_level == ThreatLevel.MEDIUM

    def test_boundary_score_39_99_is_low(self):
        """Just below 40 remains LOW. Kills > 39 mutant."""
        assert AnomalyScore(session_score=39.99).threat_level == ThreatLevel.LOW

    # --- score == 60.0: sits on the boundary, not above it ---

    def test_boundary_score_60_is_medium_not_high(self):
        """score > 60 means 60.0 itself is still MEDIUM (not HIGH). Kills >= 60 mutant."""
        assert AnomalyScore(session_score=60.0).threat_level == ThreatLevel.MEDIUM

    def test_boundary_score_60_01_is_high(self):
        """Just above 60 crosses into HIGH. Kills > 61 mutant."""
        assert AnomalyScore(session_score=60.01).threat_level == ThreatLevel.HIGH

    def test_boundary_score_59_99_is_medium(self):
        """Just below 60 remains MEDIUM. Kills > 59 mutant."""
        assert AnomalyScore(session_score=59.99).threat_level == ThreatLevel.MEDIUM

    # --- score == 80.0: sits on the boundary, not above it ---

    def test_boundary_score_80_is_high_not_critical(self):
        """score > 80 means 80.0 itself is still HIGH (not CRITICAL). Kills >= 80 mutant."""
        assert AnomalyScore(session_score=80.0).threat_level == ThreatLevel.HIGH

    def test_boundary_score_80_01_is_critical(self):
        """Just above 80 crosses into CRITICAL. Kills > 81 mutant."""
        assert AnomalyScore(session_score=80.01).threat_level == ThreatLevel.CRITICAL

    def test_boundary_score_79_99_is_high(self):
        """Just below 80 remains HIGH. Kills > 79 mutant."""
        assert AnomalyScore(session_score=79.99).threat_level == ThreatLevel.HIGH

    # --- score == 100.0 ---

    def test_boundary_score_100_is_critical(self):
        """Maximum score is CRITICAL."""
        assert AnomalyScore(session_score=100.0).threat_level == ThreatLevel.CRITICAL

    # --- negative scores ---

    def test_boundary_score_negative_is_none(self):
        """Negative scores fall through all conditions and return NONE."""
        assert AnomalyScore(session_score=-1.0).threat_level == ThreatLevel.NONE

    def test_boundary_score_negative_large_is_none(self):
        """Large negative scores also return NONE."""
        assert AnomalyScore(session_score=-100.0).threat_level == ThreatLevel.NONE

    # --- cross-level checks to prevent condition reordering mutants ---

    def test_ordering_low_below_medium(self):
        """Confirm LOW (score=30) and MEDIUM (score=50) are distinct."""
        assert AnomalyScore(session_score=30.0).threat_level == ThreatLevel.LOW
        assert AnomalyScore(session_score=50.0).threat_level == ThreatLevel.MEDIUM

    def test_ordering_medium_below_high(self):
        """Confirm MEDIUM (score=50) and HIGH (score=70) are distinct."""
        assert AnomalyScore(session_score=50.0).threat_level == ThreatLevel.MEDIUM
        assert AnomalyScore(session_score=70.0).threat_level == ThreatLevel.HIGH

    def test_ordering_high_below_critical(self):
        """Confirm HIGH (score=70) and CRITICAL (score=90) are distinct."""
        assert AnomalyScore(session_score=70.0).threat_level == ThreatLevel.HIGH
        assert AnomalyScore(session_score=90.0).threat_level == ThreatLevel.CRITICAL


# =============================================================================
# AnomalyScore defaults — exact numeric values
#
# Kills mutants that change 0.95 -> 0.9, 0.0 -> 1.0, etc.
# =============================================================================


class TestAnomalyScoreDefaults:
    """Verify each default field value with precision."""

    def test_cumulative_score_default_is_zero(self):
        """cumulative_score defaults to 0.0, not 1.0 or any other value."""
        score = AnomalyScore()
        assert score.cumulative_score == 0.0

    def test_cumulative_score_default_is_not_one(self):
        """Kills mutant that sets cumulative_score default to 1.0."""
        score = AnomalyScore()
        assert score.cumulative_score != 1.0

    def test_decay_rate_default_is_0_95(self):
        """decay_rate defaults to exactly 0.95."""
        score = AnomalyScore()
        assert score.decay_rate == 0.95

    def test_decay_rate_default_is_not_0_9(self):
        """Kills mutant that sets decay_rate to 0.9."""
        score = AnomalyScore()
        assert score.decay_rate != 0.9

    def test_decay_rate_default_is_not_1_0(self):
        """Kills mutant that sets decay_rate to 1.0 (no decay)."""
        score = AnomalyScore()
        assert score.decay_rate != 1.0

    def test_contributing_events_default_is_empty_list(self):
        """contributing_events defaults to an empty list."""
        score = AnomalyScore()
        assert score.contributing_events == []

    def test_contributing_events_default_is_list_type(self):
        """contributing_events is a list, not None or some other type."""
        score = AnomalyScore()
        assert isinstance(score.contributing_events, list)

    def test_contributing_events_are_independent_across_instances(self):
        """Each instance gets its own list — mutable default not shared."""
        a = AnomalyScore()
        b = AnomalyScore()
        a.contributing_events.append(_make_threat())
        assert b.contributing_events == []

    def test_session_score_default_is_zero(self):
        """session_score defaults to 0.0."""
        score = AnomalyScore()
        assert score.session_score == 0.0


# =============================================================================
# ShieldDecision.is_blocked — tuple membership
#
# Source (line 108):
#   return self.verdict in (ShieldVerdict.BLOCK, ShieldVerdict.QUARANTINE)
#
# Existing tests cover: ALLOW (false), BLOCK (true), QUARANTINE (true)
# Missing: SANITIZE (false), CHALLENGE (false)
# Kills mutants that add SANITIZE or CHALLENGE to the tuple.
# =============================================================================


class TestShieldDecisionIsBlocked:
    """Full coverage of is_blocked for all five verdicts."""

    def test_sanitize_is_not_blocked(self):
        """SANITIZE must not be blocked. Kills mutant adding SANITIZE to the tuple."""
        d = _make_decision(verdict=ShieldVerdict.SANITIZE)
        assert d.is_blocked is False

    def test_challenge_is_not_blocked(self):
        """CHALLENGE must not be blocked. Kills mutant adding CHALLENGE to the tuple."""
        d = _make_decision(verdict=ShieldVerdict.CHALLENGE)
        assert d.is_blocked is False

    def test_allow_is_not_blocked_explicit(self):
        """ALLOW is not blocked — explicit boolean assertion."""
        d = _make_decision(verdict=ShieldVerdict.ALLOW)
        assert d.is_blocked is False

    def test_block_is_blocked_explicit(self):
        """BLOCK is blocked — explicit boolean assertion."""
        d = _make_decision(verdict=ShieldVerdict.BLOCK)
        assert d.is_blocked is True

    def test_quarantine_is_blocked_explicit(self):
        """QUARANTINE is blocked — explicit boolean assertion."""
        d = _make_decision(verdict=ShieldVerdict.QUARANTINE)
        assert d.is_blocked is True

    def test_exactly_two_verdicts_are_blocked(self):
        """Exactly BLOCK and QUARANTINE are blocked — no more, no less."""
        all_verdicts = list(ShieldVerdict)
        blocked = [v for v in all_verdicts if _make_decision(verdict=v).is_blocked]
        assert set(blocked) == {ShieldVerdict.BLOCK, ShieldVerdict.QUARANTINE}
        assert len(blocked) == 2


# =============================================================================
# ShieldDecision.requires_approval — equality precision
#
# Source (line 112):
#   return self.verdict == ShieldVerdict.CHALLENGE
#
# Existing tests: CHALLENGE (true), BLOCK (false)
# Missing: ALLOW (false), SANITIZE (false), QUARANTINE (false)
# Kills mutants: == -> in (CHALLENGE, QUARANTINE), == -> in (CHALLENGE, BLOCK)
# =============================================================================


class TestShieldDecisionRequiresApproval:
    """Full coverage of requires_approval for all five verdicts."""

    def test_allow_does_not_require_approval(self):
        """ALLOW never requires approval."""
        d = _make_decision(verdict=ShieldVerdict.ALLOW)
        assert d.requires_approval is False

    def test_sanitize_does_not_require_approval(self):
        """SANITIZE does not require approval. Kills in (CHALLENGE, SANITIZE) mutant."""
        d = _make_decision(verdict=ShieldVerdict.SANITIZE)
        assert d.requires_approval is False

    def test_quarantine_does_not_require_approval(self):
        """QUARANTINE does not require approval. Kills in (CHALLENGE, QUARANTINE) mutant."""
        d = _make_decision(verdict=ShieldVerdict.QUARANTINE)
        assert d.requires_approval is False

    def test_challenge_requires_approval_explicit(self):
        """CHALLENGE is the sole verdict that requires approval."""
        d = _make_decision(verdict=ShieldVerdict.CHALLENGE)
        assert d.requires_approval is True

    def test_block_does_not_require_approval_explicit(self):
        """BLOCK does not require approval — explicit boolean assertion."""
        d = _make_decision(verdict=ShieldVerdict.BLOCK)
        assert d.requires_approval is False

    def test_exactly_one_verdict_requires_approval(self):
        """Exactly one verdict (CHALLENGE) requires approval — no more."""
        all_verdicts = list(ShieldVerdict)
        needing = [v for v in all_verdicts if _make_decision(verdict=v).requires_approval]
        assert needing == [ShieldVerdict.CHALLENGE]
        assert len(needing) == 1


# =============================================================================
# ShieldDecision.max_threat_level — correctness and ordering
#
# Kills mutants:
#   - Returns first element instead of max
#   - Returns last element instead of max
#   - Uses alphabetical comparison instead of level_order index
# =============================================================================


class TestShieldDecisionMaxThreatLevel:
    """max_threat_level property precision tests."""

    def test_single_threat_returns_its_level(self):
        """Single-element list — max equals the only element's level."""
        d = _make_decision(threats=[_make_threat(ThreatLevel.MEDIUM)])
        assert d.max_threat_level == ThreatLevel.MEDIUM

    def test_single_low_threat_returns_low(self):
        """Kills mutant that always returns NONE for single-element list."""
        d = _make_decision(threats=[_make_threat(ThreatLevel.LOW)])
        assert d.max_threat_level == ThreatLevel.LOW

    def test_single_critical_threat_returns_critical(self):
        """Single CRITICAL threat returns CRITICAL."""
        d = _make_decision(threats=[_make_threat(ThreatLevel.CRITICAL)])
        assert d.max_threat_level == ThreatLevel.CRITICAL

    def test_all_threats_same_level_returns_that_level(self):
        """All identical threat levels — returns that level, not NONE."""
        threats = [_make_threat(ThreatLevel.MEDIUM) for _ in range(3)]
        d = _make_decision(threats=threats)
        assert d.max_threat_level == ThreatLevel.MEDIUM

    def test_max_is_not_first_element(self):
        """Highest threat is last — kills 'return first element' mutant."""
        threats = [
            _make_threat(ThreatLevel.LOW),
            _make_threat(ThreatLevel.MEDIUM),
            _make_threat(ThreatLevel.CRITICAL),
        ]
        d = _make_decision(threats=threats)
        assert d.max_threat_level == ThreatLevel.CRITICAL

    def test_max_is_not_last_element(self):
        """Highest threat is first — kills 'return last element' mutant."""
        threats = [
            _make_threat(ThreatLevel.CRITICAL),
            _make_threat(ThreatLevel.MEDIUM),
            _make_threat(ThreatLevel.LOW),
        ]
        d = _make_decision(threats=threats)
        assert d.max_threat_level == ThreatLevel.CRITICAL

    def test_low_beats_none_in_max(self):
        """LOW > NONE in ordering. Kills alphabetical sort mutant (l < n alphabetically)."""
        threats = [_make_threat(ThreatLevel.NONE), _make_threat(ThreatLevel.LOW)]
        d = _make_decision(threats=threats)
        assert d.max_threat_level == ThreatLevel.LOW

    def test_medium_beats_low_in_max(self):
        """MEDIUM > LOW ordering is semantic, not alphabetical (m > l alphabetically — same result,
        but critical for pinning behavior). Compare MEDIUM vs HIGH instead where alpha differs."""
        threats = [_make_threat(ThreatLevel.LOW), _make_threat(ThreatLevel.MEDIUM)]
        d = _make_decision(threats=threats)
        assert d.max_threat_level == ThreatLevel.MEDIUM

    def test_high_beats_critical_alphabetically_fails(self):
        """Alphabetically 'critical' < 'high' — semantic ordering must return CRITICAL."""
        threats = [_make_threat(ThreatLevel.HIGH), _make_threat(ThreatLevel.CRITICAL)]
        d = _make_decision(threats=threats)
        # 'critical' < 'high' alphabetically, so alphabetical sort would return HIGH — wrong
        assert d.max_threat_level == ThreatLevel.CRITICAL

    def test_empty_threats_returns_none_level(self):
        """Empty list returns NONE (re-pins this behavior alongside ordering tests)."""
        d = _make_decision(threats=[])
        assert d.max_threat_level == ThreatLevel.NONE

    def test_max_with_mixed_five_levels(self):
        """One threat at each level — max must be CRITICAL."""
        threats = [
            _make_threat(ThreatLevel.NONE),
            _make_threat(ThreatLevel.LOW),
            _make_threat(ThreatLevel.MEDIUM),
            _make_threat(ThreatLevel.HIGH),
            _make_threat(ThreatLevel.CRITICAL),
        ]
        d = _make_decision(threats=threats)
        assert d.max_threat_level == ThreatLevel.CRITICAL


# =============================================================================
# block_decision factory — exact defaults and field wiring
#
# Source (lines 172-199):
#   confidence=0.9 default
#   suggested_action="Block and log"
#   inner threat verdict = ShieldVerdict.BLOCK
#   signature_id defaults to None
#   elapsed_ms defaults to 0.0
#   layer propagates to both ShieldDecision and ThreatDetection
# =============================================================================


class TestBlockDecisionFactory:
    """Mutation-killing tests for block_decision factory function."""

    def _make_block(self, **overrides):
        defaults = dict(
            layer="test_layer",
            category=ThreatCategory.PROMPT_INJECTION,
            level=ThreatLevel.HIGH,
            description="test description",
            evidence="test evidence",
        )
        defaults.update(overrides)
        return block_decision(**defaults)

    def test_default_confidence_is_0_9(self):
        """Confidence defaults to exactly 0.9, not 0.8 or 1.0."""
        d = self._make_block()
        assert d.threats_detected[0].confidence == 0.9

    def test_default_confidence_is_not_0_8(self):
        """Kills mutant that sets confidence default to 0.8."""
        d = self._make_block()
        assert d.threats_detected[0].confidence != 0.8

    def test_default_confidence_is_not_1_0(self):
        """Kills mutant that sets confidence default to 1.0."""
        d = self._make_block()
        assert d.threats_detected[0].confidence != 1.0

    def test_explicit_confidence_is_stored(self):
        """Non-default confidence is stored correctly."""
        d = self._make_block(confidence=0.75)
        assert d.threats_detected[0].confidence == 0.75

    def test_default_suggested_action_exact_string(self):
        """suggested_action defaults to the exact string 'Block and log'."""
        d = self._make_block()
        assert d.threats_detected[0].suggested_action == "Block and log"

    def test_default_suggested_action_is_not_block_only(self):
        """Kills mutant that shortens the string to 'Block'."""
        d = self._make_block()
        assert d.threats_detected[0].suggested_action != "Block"

    def test_default_suggested_action_is_not_log_and_block(self):
        """Kills mutant that reverses the string to 'Log and block'."""
        d = self._make_block()
        assert d.threats_detected[0].suggested_action != "Log and block"

    def test_inner_threat_verdict_is_block(self):
        """Inner ThreatDetection verdict is ShieldVerdict.BLOCK."""
        d = self._make_block()
        assert d.threats_detected[0].verdict == ShieldVerdict.BLOCK

    def test_inner_threat_verdict_is_not_quarantine(self):
        """Kills mutant that sets inner verdict to QUARANTINE."""
        d = self._make_block()
        assert d.threats_detected[0].verdict != ShieldVerdict.QUARANTINE

    def test_outer_verdict_is_block(self):
        """ShieldDecision verdict is ShieldVerdict.BLOCK."""
        d = self._make_block()
        assert d.verdict == ShieldVerdict.BLOCK

    def test_default_signature_id_is_none(self):
        """signature_id defaults to None when not provided."""
        d = self._make_block()
        assert d.threats_detected[0].signature_id is None

    def test_explicit_signature_id_is_stored(self):
        """Explicitly provided signature_id is stored on the threat."""
        d = self._make_block(signature_id="PI-007")
        assert d.threats_detected[0].signature_id == "PI-007"

    def test_default_elapsed_ms_is_zero(self):
        """elapsed_ms defaults to 0.0 on the ShieldDecision."""
        d = self._make_block()
        assert d.elapsed_ms == 0.0

    def test_explicit_elapsed_ms_is_stored(self):
        """elapsed_ms parameter is stored on ShieldDecision."""
        d = self._make_block(elapsed_ms=3.7)
        assert d.elapsed_ms == 3.7

    def test_layer_propagates_to_shield_decision(self):
        """layer argument sets ShieldDecision.layer."""
        d = self._make_block(layer="prompt_armor")
        assert d.layer == "prompt_armor"

    def test_layer_propagates_to_inner_threat(self):
        """layer argument also sets ThreatDetection.layer inside the threat."""
        d = self._make_block(layer="prompt_armor")
        assert d.threats_detected[0].layer == "prompt_armor"

    def test_layer_propagates_consistently(self):
        """Both ShieldDecision and inner ThreatDetection share the same layer value."""
        d = self._make_block(layer="exfiltration_guard")
        assert d.layer == d.threats_detected[0].layer

    def test_description_stored_on_threat(self):
        """description argument is stored on the inner ThreatDetection."""
        d = self._make_block(description="Injection attempt detected")
        assert d.threats_detected[0].description == "Injection attempt detected"

    def test_evidence_stored_on_threat(self):
        """evidence argument is stored on the inner ThreatDetection."""
        d = self._make_block(evidence="ignore all previous instructions")
        assert d.threats_detected[0].evidence == "ignore all previous instructions"

    def test_category_stored_on_threat(self):
        """category argument is stored on the inner ThreatDetection."""
        d = self._make_block(category=ThreatCategory.DATA_EXFILTRATION)
        assert d.threats_detected[0].category == ThreatCategory.DATA_EXFILTRATION

    def test_level_stored_on_threat(self):
        """level argument is stored on the inner ThreatDetection."""
        d = self._make_block(level=ThreatLevel.CRITICAL)
        assert d.threats_detected[0].level == ThreatLevel.CRITICAL

    def test_exactly_one_threat_created(self):
        """Factory creates exactly one threat, not zero or two."""
        d = self._make_block()
        assert len(d.threats_detected) == 1


# =============================================================================
# allow_decision factory — derived property correctness
#
# Verifies that the allow_decision result has correct derived state,
# not just correct raw fields (which test_types.py already covers).
# =============================================================================


class TestAllowDecisionDerivedProperties:
    """allow_decision correctness via derived property assertions."""

    def test_requires_approval_is_false(self):
        """allow_decision must not require approval."""
        d = allow_decision("layer_x")
        assert d.requires_approval is False

    def test_threat_count_is_zero(self):
        """allow_decision has zero threats."""
        d = allow_decision("layer_x")
        assert d.threat_count == 0

    def test_max_threat_level_is_none(self):
        """allow_decision with no threats has NONE max threat level."""
        d = allow_decision("layer_x")
        assert d.max_threat_level == ThreatLevel.NONE

    def test_is_blocked_is_false(self):
        """allow_decision is not blocked (explicit boolean)."""
        d = allow_decision("layer_x")
        assert d.is_blocked is False

    def test_elapsed_ms_zero_by_default(self):
        """elapsed_ms defaults to exactly 0.0."""
        d = allow_decision("layer_x")
        assert d.elapsed_ms == 0.0

    def test_elapsed_ms_stored_when_provided(self):
        """Non-zero elapsed_ms is stored correctly."""
        d = allow_decision("layer_x", elapsed_ms=2.5)
        assert d.elapsed_ms == 2.5

    def test_layer_stored(self):
        """Layer name is preserved on the resulting ShieldDecision."""
        d = allow_decision("my_layer")
        assert d.layer == "my_layer"


# =============================================================================
# ThreatDetection field storage
#
# Ensures every field on ThreatDetection is stored and retrievable.
# Kills mutants that swap fields or discard values silently.
# =============================================================================


class TestThreatDetectionFieldStorage:
    """Every field on ThreatDetection is individually pinned."""

    def test_description_stored(self):
        """description field is stored and retrievable."""
        t = _make_threat()
        t2 = ThreatDetection(
            category=ThreatCategory.CHAIN_ATTACK,
            level=ThreatLevel.MEDIUM,
            verdict=ShieldVerdict.QUARANTINE,
            description="custom description text",
            evidence="some evidence",
            layer="layer_a",
            confidence=0.5,
            suggested_action="Quarantine",
        )
        assert t2.description == "custom description text"

    def test_evidence_stored(self):
        """evidence field is stored and retrievable."""
        t = ThreatDetection(
            category=ThreatCategory.UNICODE_SMUGGLING,
            level=ThreatLevel.LOW,
            verdict=ShieldVerdict.SANITIZE,
            description="desc",
            evidence="specific evidence string",
            layer="layer_b",
            confidence=0.3,
            suggested_action="Sanitize",
        )
        assert t.evidence == "specific evidence string"

    def test_layer_field_stored(self):
        """layer field is stored and retrievable."""
        t = ThreatDetection(
            category=ThreatCategory.MEMORY_POISONING,
            level=ThreatLevel.HIGH,
            verdict=ShieldVerdict.BLOCK,
            description="desc",
            evidence="evid",
            layer="memory_guard",
            confidence=0.8,
            suggested_action="Block",
        )
        assert t.layer == "memory_guard"

    def test_suggested_action_stored(self):
        """suggested_action field is stored and retrievable."""
        t = ThreatDetection(
            category=ThreatCategory.WALLET_ATTACK,
            level=ThreatLevel.CRITICAL,
            verdict=ShieldVerdict.BLOCK,
            description="desc",
            evidence="evid",
            layer="test",
            confidence=0.99,
            suggested_action="Escalate to human",
        )
        assert t.suggested_action == "Escalate to human"

    def test_confidence_stored_precisely(self):
        """confidence is stored with floating point precision."""
        t = ThreatDetection(
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            level=ThreatLevel.HIGH,
            verdict=ShieldVerdict.BLOCK,
            description="desc",
            evidence="evid",
            layer="test",
            confidence=0.7357,
            suggested_action="Block",
        )
        assert t.confidence == 0.7357

    def test_category_stored(self):
        """category field is stored and retrievable."""
        t = ThreatDetection(
            category=ThreatCategory.ASCII_ART_BYPASS,
            level=ThreatLevel.MEDIUM,
            verdict=ShieldVerdict.SANITIZE,
            description="desc",
            evidence="evid",
            layer="test",
            confidence=0.6,
            suggested_action="Sanitize",
        )
        assert t.category == ThreatCategory.ASCII_ART_BYPASS

    def test_level_stored(self):
        """level field is stored and retrievable."""
        t = ThreatDetection(
            category=ThreatCategory.TOOL_EXPLOITATION,
            level=ThreatLevel.CRITICAL,
            verdict=ShieldVerdict.BLOCK,
            description="desc",
            evidence="evid",
            layer="test",
            confidence=0.95,
            suggested_action="Block",
        )
        assert t.level == ThreatLevel.CRITICAL

    def test_verdict_stored(self):
        """verdict field is stored and retrievable."""
        t = ThreatDetection(
            category=ThreatCategory.INDIRECT_INJECTION,
            level=ThreatLevel.HIGH,
            verdict=ShieldVerdict.QUARANTINE,
            description="desc",
            evidence="evid",
            layer="test",
            confidence=0.88,
            suggested_action="Quarantine",
        )
        assert t.verdict == ShieldVerdict.QUARANTINE


# =============================================================================
# Enum member counts
#
# Catches accidental additions or removals of enum members.
# A mutant that adds or removes a variant changes the count.
# =============================================================================


class TestEnumMemberCounts:
    """Each enum has an exact expected member count."""

    def test_threat_level_has_exactly_5_members(self):
        """ThreatLevel: NONE, LOW, MEDIUM, HIGH, CRITICAL."""
        assert len(ThreatLevel) == 5

    def test_threat_level_members_are_none_low_medium_high_critical(self):
        """Pin exact set — catches rename mutants."""
        names = {m.name for m in ThreatLevel}
        assert names == {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_threat_category_has_exactly_11_members(self):
        """ThreatCategory has exactly 11 attack categories."""
        assert len(ThreatCategory) == 11

    def test_threat_category_exact_values(self):
        """Pin all 11 ThreatCategory values against accidental changes."""
        values = {m.value for m in ThreatCategory}
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
        assert values == expected

    def test_shield_verdict_has_exactly_5_members(self):
        """ShieldVerdict: ALLOW, SANITIZE, CHALLENGE, QUARANTINE, BLOCK."""
        assert len(ShieldVerdict) == 5

    def test_shield_verdict_exact_values(self):
        """Pin all 5 ShieldVerdict values."""
        values = {m.value for m in ShieldVerdict}
        assert values == {"allow", "sanitize", "challenge", "quarantine", "block"}

    def test_memory_trust_has_exactly_5_members(self):
        """MemoryTrust: VERIFIED, USER_DIRECT, BRAIN_GENERATED, EXTERNAL, UNKNOWN."""
        assert len(MemoryTrust) == 5

    def test_memory_trust_exact_values(self):
        """Pin all 5 MemoryTrust values."""
        values = {m.value for m in MemoryTrust}
        assert values == {"verified", "user_direct", "brain", "external", "unknown"}


# =============================================================================
# ToolPolicy — each default individually pinned
#
# Existing test_types.py tests all three in one assertion.
# These tests isolate each default so a mutant on any single field is caught.
# =============================================================================


class TestToolPolicyDefaults:
    """Each ToolPolicy default is pinned individually."""

    def test_rate_default_is_30(self):
        """rate defaults to exactly 30."""
        assert ToolPolicy().rate == 30

    def test_rate_default_is_not_20(self):
        """Kills mutant that sets rate to 20."""
        assert ToolPolicy().rate != 20

    def test_rate_default_is_not_60(self):
        """Kills mutant that sets rate to 60."""
        assert ToolPolicy().rate != 60

    def test_rate_default_is_not_10(self):
        """Kills mutant that sets rate to 10."""
        assert ToolPolicy().rate != 10

    def test_approval_default_is_false(self):
        """approval defaults to False, not True."""
        assert ToolPolicy().approval is False

    def test_approval_default_is_not_true(self):
        """Kills mutant that flips approval default to True."""
        assert ToolPolicy().approval is not True

    def test_risk_default_is_low(self):
        """risk defaults to exactly 'low'."""
        assert ToolPolicy().risk == "low"

    def test_risk_default_is_not_medium(self):
        """Kills mutant that sets risk default to 'medium'."""
        assert ToolPolicy().risk != "medium"

    def test_risk_default_is_not_high(self):
        """Kills mutant that sets risk default to 'high'."""
        assert ToolPolicy().risk != "high"

    def test_risk_default_is_not_critical(self):
        """Kills mutant that sets risk default to 'critical'."""
        assert ToolPolicy().risk != "critical"

    def test_each_default_is_independent(self):
        """All three defaults hold simultaneously on a freshly constructed instance."""
        p = ToolPolicy()
        assert p.rate == 30
        assert p.approval is False
        assert p.risk == "low"
