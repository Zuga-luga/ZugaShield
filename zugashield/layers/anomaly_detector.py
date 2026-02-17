"""
ZugaShield - Layer 6: Anomaly Detector
========================================

Cross-layer behavioral analysis engine. Receives events from all
other layers and correlates them to detect:
- Salami attacks (gradual privilege escalation)
- Alternating patterns (benign → malicious → benign)
- Chain attacks (multiple low-severity = high-severity chain)
- Time-based anomalies
- Topic drift into sensitive operations

Integration point: Cross-layer event correlation
"""

from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict, deque
from typing import Dict, List, TYPE_CHECKING

from zugashield.types import (
    AnomalyScore,
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ShieldDecision,
    ShieldVerdict,
    allow_decision,
)

if TYPE_CHECKING:
    from zugashield.config import ShieldConfig

logger = logging.getLogger(__name__)

# Score contributions by threat level
_LEVEL_SCORES = {
    ThreatLevel.NONE: 0,
    ThreatLevel.LOW: 5,
    ThreatLevel.MEDIUM: 15,
    ThreatLevel.HIGH: 30,
    ThreatLevel.CRITICAL: 50,
}

# Chain attack patterns: if these events occur within 5 minutes, escalate
_CHAIN_PATTERNS = [
    # (event_categories, min_count, description, escalated_level)
    (
        {ThreatCategory.PROMPT_INJECTION, ThreatCategory.TOOL_EXPLOITATION},
        2,
        "Injection + tool exploitation chain",
        ThreatLevel.CRITICAL,
    ),
    (
        {ThreatCategory.DATA_EXFILTRATION, ThreatCategory.TOOL_EXPLOITATION},
        2,
        "Exfiltration chain attack",
        ThreatLevel.CRITICAL,
    ),
    (
        {ThreatCategory.MEMORY_POISONING, ThreatCategory.PROMPT_INJECTION},
        2,
        "Memory poisoning + injection chain",
        ThreatLevel.HIGH,
    ),
    (
        {ThreatCategory.UNICODE_SMUGGLING, ThreatCategory.PROMPT_INJECTION},
        2,
        "Unicode smuggling + injection chain",
        ThreatLevel.HIGH,
    ),
]


class AnomalyDetectorLayer:
    """
    Layer 6: Behavioral anomaly detection and cross-layer correlation.

    Maintains per-session risk scores that decay over time and
    spike when suspicious patterns are detected.
    """

    LAYER_NAME = "anomaly_detector"

    def __init__(self, config: ShieldConfig) -> None:
        self._config = config
        # Per-session event history
        self._session_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # Per-session anomaly scores
        self._session_scores: Dict[str, AnomalyScore] = {}
        self._stats = {"events_processed": 0, "chains_detected": 0, "escalations": 0}

    def record_event(self, session_id: str, detection: ThreatDetection) -> None:
        """
        Record a threat detection event for correlation.
        Called by other layers when they detect something.
        """
        self._session_events[session_id].append(detection)
        self._stats["events_processed"] += 1

        # Update session score
        score = self._get_or_create_score(session_id)
        contribution = _LEVEL_SCORES.get(detection.level, 0) * detection.confidence
        score.session_score = min(100, score.session_score + contribution)
        score.contributing_events.append(detection)

        # Keep contributing events bounded
        if len(score.contributing_events) > 50:
            score.contributing_events = score.contributing_events[-50:]

    async def check(self, session_id: str = "default") -> ShieldDecision:
        """
        Run anomaly analysis on current session.

        Returns:
            ShieldDecision based on accumulated anomaly score and chain detection.
        """
        if not self._config.anomaly_detector_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        score = self._get_or_create_score(session_id)
        threats: List[ThreatDetection] = []

        # Apply decay
        score.session_score *= score.decay_rate

        # === Check 1: Chain attack patterns ===
        chain_threats = self._check_chains(session_id)
        threats.extend(chain_threats)

        # === Check 2: Alternating pattern detection ===
        alt_threats = self._check_alternating(session_id)
        threats.extend(alt_threats)

        # === Check 3: Score threshold ===
        if score.session_score > self._config.anomaly_threshold:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    level=score.threat_level,
                    verdict=ShieldVerdict.CHALLENGE if score.threat_level <= ThreatLevel.HIGH else ShieldVerdict.BLOCK,
                    description=f"Session anomaly score exceeded threshold: {score.session_score:.1f}/{self._config.anomaly_threshold}",
                    evidence=f"Score: {score.session_score:.1f}, Events: {len(score.contributing_events)}",
                    layer=self.LAYER_NAME,
                    confidence=0.75,
                    suggested_action="Increase monitoring or require confirmation",
                    signature_id="AD-SCORE",
                )
            )

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        max_threat = max(
            threats,
            key=lambda t: [
                ThreatLevel.NONE,
                ThreatLevel.LOW,
                ThreatLevel.MEDIUM,
                ThreatLevel.HIGH,
                ThreatLevel.CRITICAL,
            ].index(t.level),
        )

        verdict = ShieldVerdict.BLOCK if max_threat.level >= ThreatLevel.CRITICAL else ShieldVerdict.CHALLENGE

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    def _check_chains(self, session_id: str) -> List[ThreatDetection]:
        """Detect multi-category attack chains."""
        threats = []
        events = self._session_events[session_id]
        if len(events) < 2:
            return threats

        now = time.time()
        # Look at events in the last 5 minutes
        recent = [e for e in events if (now - e.timestamp.timestamp()) < 300]
        recent_categories = Counter(e.category for e in recent)

        for required_cats, min_count, desc, escalated_level in _CHAIN_PATTERNS:
            matching = sum(recent_categories.get(c, 0) for c in required_cats)
            distinct = sum(1 for c in required_cats if recent_categories.get(c, 0) > 0)
            if distinct >= 2 and matching >= min_count:
                self._stats["chains_detected"] += 1
                self._stats["escalations"] += 1
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.CHAIN_ATTACK,
                        level=escalated_level,
                        verdict=ShieldVerdict.BLOCK
                        if escalated_level >= ThreatLevel.CRITICAL
                        else ShieldVerdict.QUARANTINE,
                        description=f"Chain attack: {desc}",
                        evidence=f"Categories: {dict(recent_categories)}, matching: {matching}",
                        layer=self.LAYER_NAME,
                        confidence=0.80,
                        suggested_action="Block chain attack and alert",
                        signature_id="AD-CHAIN",
                    )
                )

        return threats

    def _check_alternating(self, session_id: str) -> List[ThreatDetection]:
        """Detect alternating benign/malicious patterns (evasion)."""
        events = self._session_events[session_id]
        if len(events) < 6:
            return []

        # Look at last 10 events
        recent = list(events)[-10:]
        levels = [e.level for e in recent]

        # Check for alternating high/low pattern
        alternations = 0
        for i in range(1, len(levels)):
            prev_high = levels[i - 1] in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
            curr_low = levels[i] in (ThreatLevel.NONE, ThreatLevel.LOW)
            prev_low = levels[i - 1] in (ThreatLevel.NONE, ThreatLevel.LOW)
            curr_high = levels[i] in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

            if (prev_high and curr_low) or (prev_low and curr_high):
                alternations += 1

        if alternations >= 3:
            return [
                ThreatDetection(
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"Alternating benign/malicious pattern: {alternations} alternations in {len(recent)} events",
                    evidence=f"Levels: {[lv.value for lv in levels]}",
                    layer=self.LAYER_NAME,
                    confidence=0.70,
                    suggested_action="Increase scrutiny on all requests",
                    signature_id="AD-ALT",
                )
            ]

        return []

    def get_session_score(self, session_id: str = "default") -> AnomalyScore:
        """Get the anomaly score for a session."""
        return self._get_or_create_score(session_id)

    def _get_or_create_score(self, session_id: str) -> AnomalyScore:
        """Get or create an anomaly score for a session."""
        if session_id not in self._session_scores:
            self._session_scores[session_id] = AnomalyScore(
                decay_rate=self._config.anomaly_decay_rate,
            )
        return self._session_scores[session_id]

    def get_stats(self) -> Dict:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            **self._stats,
            "active_sessions": len(self._session_scores),
        }
