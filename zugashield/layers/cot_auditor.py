"""
ZugaShield - Chain-of-Thought Trace Auditor
=============================================

Audits reasoning traces (chain-of-thought, scratchpad output) for deceptive
patterns before the model acts on its internal reasoning.

Background: LLMs that expose their reasoning steps can develop internal
monologues that contradict their stated goals — either due to adversarial
prompting or emergent deceptive alignment. This layer flags:

1. Explicit deception indicators: "the user doesn't need to know", "I'll hide"
2. Goal mismatch: stated goal vs. planned actions diverge
3. Hidden objectives: reasoning reveals a secondary agenda
4. Safety circumvention in the thought process itself

Usage:
    decision = await shield.check_reasoning(trace, stated_goal="Book a flight")

Integration point: Wrap around any LLM that exposes <thinking> blocks or
scratchpad output before executing tool calls or returning responses.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from zugashield.types import (
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ShieldDecision,
    ShieldVerdict,
    allow_decision,
)

if TYPE_CHECKING:
    from zugashield.config import ShieldConfig
    from zugashield.threat_catalog import ThreatCatalog

logger = logging.getLogger(__name__)

# =============================================================================
# Detection patterns
# Each entry: (compiled_pattern, signature_id, description, category, level)
# =============================================================================

_DECEPTION_PATTERNS: List[Tuple[re.Pattern, str, str, ThreatCategory, ThreatLevel]] = [
    # COT-DECEPTION: Explicit deception language
    (
        re.compile(
            r"the\s+user\s+(?:doesn'?t?|does\s+not|won'?t?|will\s+not)\s+"
            r"(?:need|have)\s+to\s+know",
            re.I,
        ),
        "COT-DECEPTION",
        "Reasoning explicitly hides information from user",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"i'?ll?\s+(?:hide|conceal|obscure|omit|not\s+mention|avoid\s+(?:saying|telling|mentioning))",
            re.I,
        ),
        "COT-DECEPTION",
        "Reasoning plans to hide or omit information",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"\bpretend\s+(?:to|that\s+I)",
            re.I,
        ),
        "COT-DECEPTION",
        "Reasoning plans deceptive presentation",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bwithout\s+(?:them|the\s+user|him|her)\s+knowing",
            re.I,
        ),
        "COT-DECEPTION",
        "Reasoning plans covert action without user awareness",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"\bactually\s+I\s+should\b",
            re.I,
        ),
        "COT-DECEPTION",
        "Reasoning pivots away from stated intent (potential deception)",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.MEDIUM,
    ),
    (
        re.compile(
            r"\b(?:deceive|mislead|trick|fool|manipulate)\s+the\s+user",
            re.I,
        ),
        "COT-DECEPTION",
        "Reasoning explicitly plans to deceive the user",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"\bmake\s+(?:it|this|the\s+response)\s+(?:look|seem|appear)\s+(?:like|as\s+if)",
            re.I,
        ),
        "COT-DECEPTION",
        "Reasoning plans misleading framing",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.HIGH,
    ),
    # COT-GOAL-MISMATCH: Stated goal contradicts actual plan
    (
        re.compile(
            r"\bbut\s+instead\s+(?:I\s+(?:will|should|can)|let\s+me)",
            re.I,
        ),
        "COT-GOAL-MISMATCH",
        "Reasoning explicitly substitutes a different goal",
        ThreatCategory.BEHAVIORAL_ANOMALY,
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bhowever\s+I\s+will\s+actually\b",
            re.I,
        ),
        "COT-GOAL-MISMATCH",
        "Reasoning contradicts stated plan with alternative action",
        ThreatCategory.BEHAVIORAL_ANOMALY,
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bmy\s+(?:real|actual|true|hidden)\s+goal\b",
            re.I,
        ),
        "COT-GOAL-MISMATCH",
        "Reasoning reveals an undisclosed primary goal",
        ThreatCategory.BEHAVIORAL_ANOMALY,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"\bthe\s+(?:stated|given|assigned)\s+goal\s+(?:is|was)\s+"
            r"(?:just\s+a\s+(?:cover|facade|pretext)|not\s+(?:what|my))",
            re.I,
        ),
        "COT-GOAL-MISMATCH",
        "Reasoning treats the stated goal as a pretext",
        ThreatCategory.BEHAVIORAL_ANOMALY,
        ThreatLevel.CRITICAL,
    ),
    # COT-HIDDEN-OBJ: Hidden secondary objectives
    (
        re.compile(
            r"\bmy\s+(?:true|real|actual|secret)\s+objective\b",
            re.I,
        ),
        "COT-HIDDEN-OBJ",
        "Reasoning discloses an undisclosed objective",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"\bsecret\s+plan\b",
            re.I,
        ),
        "COT-HIDDEN-OBJ",
        "Reasoning references a secret plan",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"the\s+user\s+thinks?\s+I'?m?\s+",
            re.I,
        ),
        "COT-HIDDEN-OBJ",
        "Reasoning differentiates what user believes from actual intent",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bthey\s+won'?t?\s+(?:notice|realize|see|detect|find\s+out)",
            re.I,
        ),
        "COT-HIDDEN-OBJ",
        "Reasoning anticipates concealing actions from user",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bappear\s+(?:compliant|cooperative|helpful|harmless)\s+while\b",
            re.I,
        ),
        "COT-HIDDEN-OBJ",
        "Reasoning plans to appear compliant while pursuing other goals",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    # COT-SAFETY-OVERRIDE: Safety circumvention in reasoning
    (
        re.compile(
            r"ignore\s+the\s+(?:safety|security|alignment|ethical)\s+"
            r"(?:constraint|restriction|rule|check|guideline)",
            re.I,
        ),
        "COT-SAFETY-OVERRIDE",
        "Reasoning plans to ignore safety constraints",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"bypass\s+(?:the\s+)?(?:restriction|filter|safety|guard|shield|check)",
            re.I,
        ),
        "COT-SAFETY-OVERRIDE",
        "Reasoning plans to bypass safety mechanisms",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"get\s+around\s+(?:the\s+)?(?:filter|safety|restriction|rule|limit)",
            re.I,
        ),
        "COT-SAFETY-OVERRIDE",
        "Reasoning plans to circumvent safety rules",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"(?:disable|turn\s+off|deactivate)\s+(?:the\s+)?(?:safety|security|guard|filter)",
            re.I,
        ),
        "COT-SAFETY-OVERRIDE",
        "Reasoning attempts to disable safety systems",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"\bwithout\s+triggering\s+(?:the\s+)?(?:safety|filter|guard|alarm|alert)",
            re.I,
        ),
        "COT-SAFETY-OVERRIDE",
        "Reasoning tries to evade detection by safety systems",
        ThreatCategory.PROMPT_INJECTION,
        ThreatLevel.CRITICAL,
    ),
]

# =============================================================================
# Goal-mismatch semantic analysis helpers
# =============================================================================

# Action verbs we look for in the trace to compare against stated goal
_ACTION_VERBS = re.compile(
    r"\b(?:I\s+will|I\s+should|I\s+(?:am\s+going|'m\s+going)\s+to|let\s+me|"
    r"I\s+(?:can|must|need\s+to)|my\s+plan\s+is\s+to)\s+(\w[\w\s]{0,40})",
    re.I,
)

# Contradiction indicators that suggest the trace diverges from stated goal
_CONTRADICTION_MARKERS = re.compile(
    r"\b(?:but\s+actually|however|instead|rather\s+than|"
    r"contrary\s+to|despite|even\s+though|although|"
    r"regardless\s+of\s+(?:what|the)\s+(?:user|instruction))",
    re.I,
)


class CoTAuditorLayer:
    """
    Layer: Chain-of-Thought Trace Auditor.

    Scans model reasoning traces for deceptive patterns, goal mismatches,
    hidden objectives, and safety circumvention attempts.
    """

    LAYER_NAME = "cot_auditor"

    def __init__(self, config: ShieldConfig) -> None:
        self._config = config
        self._stats: Dict[str, int] = {
            "checks": 0,
            "deceptions_found": 0,
            "goal_mismatches": 0,
            "safety_overrides": 0,
        }

    async def check(
        self,
        trace: str,
        stated_goal: str = "",
        **kwargs: Any,
    ) -> ShieldDecision:
        """
        Audit a chain-of-thought trace for deceptive patterns.

        Args:
            trace: The full chain-of-thought/scratchpad text to audit.
            stated_goal: The goal as stated to the user (for mismatch detection).
                         Pass empty string to skip semantic goal comparison.
            **kwargs: Ignored; accepts extra keyword args for forward compatibility.

        Returns:
            ShieldDecision with verdict and any threats detected.
        """
        if not self._config.cot_auditor_enabled:
            return allow_decision(self.LAYER_NAME)

        if not trace or not trace.strip():
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["checks"] += 1
        threats: List[ThreatDetection] = []

        # === Pass 1: Compiled pattern detection ===
        pattern_threats = self._scan_patterns(trace)
        threats.extend(pattern_threats)

        # === Pass 2: Semantic goal mismatch analysis ===
        if stated_goal and stated_goal.strip():
            mismatch_threats = self._check_goal_mismatch(trace, stated_goal)
            threats.extend(mismatch_threats)

        # === Pass 3: Contradiction density analysis ===
        contradiction_threat = self._check_contradiction_density(trace)
        if contradiction_threat:
            threats.append(contradiction_threat)

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        # Deduplicate by signature_id — keep highest level per sig
        deduped = self._deduplicate(threats)
        self._stats["deceptions_found"] += len(deduped)

        # Count by category for stats
        for t in deduped:
            if t.signature_id == "COT-GOAL-MISMATCH":
                self._stats["goal_mismatches"] += 1
            elif t.signature_id == "COT-SAFETY-OVERRIDE":
                self._stats["safety_overrides"] += 1

        # Determine overall verdict
        level_order = [
            ThreatLevel.NONE,
            ThreatLevel.LOW,
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]
        worst = max(deduped, key=lambda t: level_order.index(t.level))

        if worst.level == ThreatLevel.CRITICAL:
            verdict = ShieldVerdict.BLOCK
        elif worst.level == ThreatLevel.HIGH:
            verdict = ShieldVerdict.QUARANTINE
        elif worst.level == ThreatLevel.MEDIUM:
            verdict = ShieldVerdict.CHALLENGE if not self._config.strict_mode else ShieldVerdict.QUARANTINE
        else:
            verdict = ShieldVerdict.SANITIZE

        logger.warning(
            "[CoTAuditor] %s: %d deception pattern(s) in reasoning trace (%.1fms, verdict=%s)",
            verdict.value.upper(),
            len(deduped),
            elapsed,
            verdict.value,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=deduped,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    def _scan_patterns(self, trace: str) -> List[ThreatDetection]:
        """Run all compiled regex patterns against the trace."""
        threats: List[ThreatDetection] = []

        for pattern, sig_id, description, category, level in _DECEPTION_PATTERNS:
            match = pattern.search(trace)
            if not match:
                continue

            evidence = self._extract_context(trace, match.start(), match.end())

            threats.append(
                ThreatDetection(
                    category=category,
                    level=level,
                    verdict=self._level_to_verdict(level),
                    description=description,
                    evidence=evidence,
                    layer=self.LAYER_NAME,
                    confidence=0.88,
                    suggested_action=self._suggested_action(sig_id),
                    signature_id=sig_id,
                )
            )

        return threats

    def _check_goal_mismatch(self, trace: str, stated_goal: str) -> List[ThreatDetection]:
        """
        Semantic goal mismatch detection.

        Extracts planned actions from the trace and checks whether they
        appear consistent with the stated goal. Flags traces that contain
        contradiction markers alongside actions unrelated to the goal.
        """
        threats: List[ThreatDetection] = []

        stated_lower = stated_goal.lower()
        trace_lower = trace.lower()

        # Extract key nouns/verbs from the stated goal (simple tokenisation)
        stated_keywords = set(
            w for w in re.findall(r"\b\w{4,}\b", stated_lower)
            if w not in {"that", "this", "with", "from", "have", "been", "will", "should"}
        )

        if not stated_keywords:
            return threats

        # Find planned actions in the trace
        action_matches = _ACTION_VERBS.findall(trace)
        if not action_matches:
            return threats

        # Count actions that share keywords with the stated goal
        related_actions = 0
        unrelated_actions = 0
        for action_text in action_matches:
            action_words = set(re.findall(r"\b\w{4,}\b", action_text.lower()))
            if action_words & stated_keywords:
                related_actions += 1
            else:
                unrelated_actions += 1

        total_actions = related_actions + unrelated_actions
        if total_actions == 0:
            return threats

        # Check if there are contradiction markers in the trace
        contradiction_count = len(_CONTRADICTION_MARKERS.findall(trace))

        # Flag if: majority of actions are unrelated AND contradictions present
        unrelated_ratio = unrelated_actions / total_actions
        if unrelated_ratio > 0.6 and contradiction_count >= 2:
            level = ThreatLevel.HIGH if unrelated_ratio > 0.8 else ThreatLevel.MEDIUM
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    level=level,
                    verdict=self._level_to_verdict(level),
                    description=(
                        f"Goal mismatch: {unrelated_actions}/{total_actions} planned actions "
                        f"unrelated to stated goal, {contradiction_count} contradiction marker(s)"
                    ),
                    evidence=(
                        f"Stated goal: '{stated_goal[:100]}' | "
                        f"Unrelated actions: {unrelated_actions}/{total_actions} | "
                        f"Contradictions: {contradiction_count}"
                    ),
                    layer=self.LAYER_NAME,
                    confidence=0.70,
                    suggested_action="Review reasoning trace alignment with stated user goal",
                    signature_id="COT-GOAL-MISMATCH",
                )
            )

        return threats

    def _check_contradiction_density(self, trace: str) -> Optional[ThreatDetection]:
        """
        Flag traces with an unusually high density of contradiction markers.

        A reasoning trace filled with "but actually", "however", "instead"
        can indicate the model is rationalising away from honest behavior.
        Threshold: >4 contradictions per 1000 characters.
        """
        if len(trace) < 200:
            return None

        contradiction_count = len(_CONTRADICTION_MARKERS.findall(trace))
        density = contradiction_count / (len(trace) / 1000)

        if density > 4.0 and contradiction_count >= 5:
            return ThreatDetection(
                category=ThreatCategory.BEHAVIORAL_ANOMALY,
                level=ThreatLevel.MEDIUM,
                verdict=ShieldVerdict.CHALLENGE,
                description=(
                    f"High contradiction density in reasoning trace "
                    f"({contradiction_count} contradictions, {density:.1f}/1000 chars)"
                ),
                evidence=f"{contradiction_count} contradiction markers in {len(trace)} char trace",
                layer=self.LAYER_NAME,
                confidence=0.65,
                suggested_action="Review reasoning trace for coherence with stated intent",
                signature_id="COT-CONTRADICTION-DENSITY",
            )

        return None

    @staticmethod
    def _extract_context(trace: str, start: int, end: int, window: int = 120) -> str:
        """Extract surrounding context around a match for evidence."""
        ctx_start = max(0, start - window // 2)
        ctx_end = min(len(trace), end + window // 2)
        snippet = trace[ctx_start:ctx_end]
        prefix = "..." if ctx_start > 0 else ""
        suffix = "..." if ctx_end < len(trace) else ""
        return f"{prefix}{snippet}{suffix}"[:200]

    @staticmethod
    def _level_to_verdict(level: ThreatLevel) -> ShieldVerdict:
        """Map threat level to shield verdict."""
        return {
            ThreatLevel.CRITICAL: ShieldVerdict.BLOCK,
            ThreatLevel.HIGH: ShieldVerdict.QUARANTINE,
            ThreatLevel.MEDIUM: ShieldVerdict.CHALLENGE,
            ThreatLevel.LOW: ShieldVerdict.SANITIZE,
            ThreatLevel.NONE: ShieldVerdict.ALLOW,
        }.get(level, ShieldVerdict.CHALLENGE)

    @staticmethod
    def _suggested_action(sig_id: str) -> str:
        """Return a remediation hint for each signature category."""
        actions = {
            "COT-DECEPTION": "Halt execution; report deceptive reasoning to oversight",
            "COT-GOAL-MISMATCH": "Verify alignment between stated goal and planned actions",
            "COT-HIDDEN-OBJ": "Block immediately; possible deceptive alignment",
            "COT-SAFETY-OVERRIDE": "Block; model attempting to circumvent safety systems",
        }
        for prefix, action in actions.items():
            if sig_id.startswith(prefix):
                return action
        return "Review reasoning trace before allowing execution"

    @staticmethod
    def _deduplicate(threats: List[ThreatDetection]) -> List[ThreatDetection]:
        """
        Deduplicate by signature_id, keeping the highest-severity detection
        for each signature.
        """
        level_order = [
            ThreatLevel.NONE,
            ThreatLevel.LOW,
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]
        best: Dict[str, ThreatDetection] = {}
        for t in threats:
            key = t.signature_id or t.description
            if key not in best:
                best[key] = t
            else:
                existing_idx = level_order.index(best[key].level)
                new_idx = level_order.index(t.level)
                if new_idx > existing_idx:
                    best[key] = t
        return list(best.values())

    def get_stats(self) -> Dict[str, Any]:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            **self._stats,
        }
