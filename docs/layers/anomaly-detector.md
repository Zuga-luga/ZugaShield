# Layer 6: Anomaly Detector

**Module:** `zugashield/layers/anomaly_detector.py`
**Class:** `AnomalyDetectorLayer`
**Last Updated:** 2026-02-17

## Purpose

The Anomaly Detector is a cross-layer behavioral analysis engine. While every other layer makes decisions about individual requests in isolation, this layer maintains state across requests and correlates events from all other layers to detect patterns that only become visible over time.

Individual low-severity signals that each fall below the block threshold can aggregate into a clear attack signature when viewed together. A salami attacker submitting many slightly-malicious messages, or an evasion attempt alternating benign and malicious requests, would not be caught by per-request analysis alone.

## How It Works

### Event Recording

Every time any layer detects a threat, the orchestrator calls `record_event(session_id, detection)` to log the event. This updates two data structures:

- **`_session_events`:** A per-session deque (max 500 events) storing the full `ThreatDetection` objects for pattern analysis.
- **`_session_scores`:** A per-session `AnomalyScore` object maintaining the current risk score.

### Session Risk Scoring

Each threat detection contributes to the session score based on its threat level and confidence:

| Threat Level | Base Score Contribution |
|---|---|
| NONE | 0 |
| LOW | 5 |
| MEDIUM | 15 |
| HIGH | 30 |
| CRITICAL | 50 |

The actual contribution is `base_score * confidence`. A CRITICAL detection with 0.80 confidence contributes 40 points. The score is capped at 100.

### Score Decay and Lifetime Floor

The session score decays multiplicatively each time `check()` is called, using the configured decay rate (default 0.95 per check cycle). This models the intuition that old events matter less than recent ones.

To prevent a determined attacker from "resetting" a session's risk score by going quiet, a non-decaying lifetime floor is maintained: `cumulative_score = max(cumulative_score, session_score * 0.2)`. The session score can never decay below 20% of its historical peak. A session that once reached a score of 80 will always have a floor of 16, preventing it from falling back to zero.

### Cross-Session Tracking

The `_session_scores` dictionary persists across requests within a process lifetime. Each session ID is tracked independently. Session scores for different sessions do not influence each other (though the Anomaly Detector could be extended to correlate cross-session activity for detecting distributed attacks).

## What It Detects

### Chain Attack Patterns (AD-CHAIN)

Four multi-category chain patterns are defined. A chain is detected when two or more distinct categories from the required set appear in events within the past 5 minutes:

| Chain | Required Categories | Min Events | Escalated Level |
|---|---|---|---|
| Injection + tool exploitation | PROMPT_INJECTION + TOOL_EXPLOITATION | 2 | CRITICAL |
| Exfiltration chain | DATA_EXFILTRATION + TOOL_EXPLOITATION | 2 | CRITICAL |
| Memory + injection | MEMORY_POISONING + PROMPT_INJECTION | 2 | HIGH |
| Unicode + injection | UNICODE_SMUGGLING + PROMPT_INJECTION | 2 | HIGH |

A chain detection escalates the threat level beyond what either category would produce alone. Two MEDIUM-level events from different layers that match a chain pattern produce a CRITICAL verdict.

**Confidence:** 0.80

### Alternating Benign/Malicious Pattern (AD-ALT)

A sophisticated evasion technique involves sending malicious requests interspersed with benign ones. The attacker's hypothesis is that each malicious request produces a low-confidence signal that falls below the block threshold, and the benign requests reset the system's suspicion.

This check analyzes the threat levels of the last 10 recorded events. If at least 3 transitions between HIGH/CRITICAL and NONE/LOW occur, the alternating pattern is flagged.

**Threat level:** HIGH
**Verdict:** QUARANTINE
**Confidence:** 0.70

### Score Threshold Breach (AD-SCORE)

When the current session score exceeds the configured anomaly threshold (default 60.0), a threshold breach event is raised. The threat level of the breach event is derived from the `AnomalyScore.threat_level` property, which maps score ranges to threat levels:

| Score | Threat Level |
|---|---|
| 0–20 | LOW |
| 20–50 | MEDIUM |
| 50–80 | HIGH |
| 80+ | CRITICAL |

**Confidence:** 0.75

## Verdict Logic

| Max Threat Level | Verdict |
|---|---|
| CRITICAL | BLOCK |
| HIGH or below | CHALLENGE |

## Configuration

| Option | Environment Variable | Default | Description |
|---|---|---|---|
| `anomaly_detector_enabled` | `ZUGASHIELD_ANOMALY_DETECTOR_ENABLED` | `true` | Enable or disable this layer |
| `anomaly_threshold` | `ZUGASHIELD_ANOMALY_THRESHOLD` | `60.0` | Score threshold that triggers AD-SCORE (0–100 scale) |
| `anomaly_decay_rate` | `ZUGASHIELD_ANOMALY_DECAY_RATE` | `0.95` | Multiplicative decay applied to session score each check cycle |

### Threshold tuning guidance

| Deployment Type | Recommended Threshold |
|---|---|
| High-security financial system | 30–40 |
| Standard production API | 60 (default) |
| Development / low-sensitivity | 80–90 |

### Decay rate guidance

A lower decay rate causes scores to drop faster between checks, increasing tolerance for occasional suspicious events. A higher decay rate (closer to 1.0) makes the score persistent.

| Scenario | Recommended Rate |
|---|---|
| Short interactive sessions | 0.90–0.93 |
| Long-running agent sessions | 0.96–0.99 |
| Default | 0.95 |

## Example Attacks Caught

**Salami attack via accumulated low-severity events:** An attacker sends 20 messages over 10 minutes, each triggering a LOW-severity detection (score contribution: 5 × 0.6 confidence = 3 each). After 20 events with 0.95 decay between checks, the cumulative score approaches 60 and AD-SCORE fires, raising a CHALLENGE before the attacker can escalate.

**Unicode smuggling + injection chain:** A session first triggers a Unicode smuggling detection (UA-HOM), then later triggers a prompt injection detection (FP-001). Even if both were individually at MEDIUM, the AD-CHAIN pattern combining UNICODE_SMUGGLING and PROMPT_INJECTION escalates the combined event to HIGH (QUARANTINE).

**Exfiltration chain correlation:** Tool Guard detects a MEDIUM-confidence exfiltration chain (TG-CHAIN-EXFIL, confidence 0.75). The Exfiltration Guard also fires (EG-SECRET) in the same session. The cross-layer correlation of DATA_EXFILTRATION + TOOL_EXPLOITATION produces a CRITICAL chain detection (BLOCK).

**Alternating evasion pattern:** An attacker sends the sequence: malicious (HIGH) → benign (NONE) → malicious (HIGH) → benign (NONE) → malicious (HIGH) → benign (NONE). After 6 events with 3+ alternations, AD-ALT fires (HIGH, QUARANTINE).

**Session resetting attempt:** After accumulating a score of 70 (triggering AD-SCORE), the attacker goes silent for several minutes hoping the score decays. With a decay rate of 0.95, the score falls from 70 to 70 × 0.95^n, but the lifetime floor locks it at 70 × 0.2 = 14. The session remains elevated and the attacker cannot return to a clean slate.

## Code Examples

### Integration with the shield orchestrator

The Anomaly Detector is typically managed by the main `ZugaShield` orchestrator, which calls `record_event` for every detection from other layers and calls `check` at key decision points. When using ZugaShield directly, this wiring is automatic.

```python
from zugashield import ZugaShield
from zugashield.config import ShieldConfig

# The anomaly detector is wired in automatically
shield = ZugaShield(ShieldConfig())

# Use the shield normally — anomaly correlation runs behind the scenes
decision = await shield.check_message(user_input, session_id=session_id)
```

### Direct usage for custom orchestration

```python
import asyncio
from zugashield.layers.anomaly_detector import AnomalyDetectorLayer
from zugashield.config import ShieldConfig
from zugashield.types import ThreatDetection, ThreatLevel, ThreatCategory, ShieldVerdict

config = ShieldConfig()
detector = AnomalyDetectorLayer(config)

async def process_with_anomaly_tracking(session_id: str, detection: ThreatDetection):
    # Record an event from another layer
    detector.record_event(session_id, detection)

    # Check for cross-layer patterns
    decision = await detector.check(session_id=session_id)

    if decision.verdict == ShieldVerdict.BLOCK:
        raise RuntimeError(f"Session {session_id} blocked: {decision.threats_detected[0].description}")

    return decision
```

### Querying session state

```python
score = detector.get_session_score("session-abc123")
print(f"Current score: {score.session_score:.1f}")
print(f"Lifetime peak floor: {score.cumulative_score:.1f}")
print(f"Threat level: {score.threat_level.value}")
print(f"Contributing events: {len(score.contributing_events)}")
```

### Custom threshold for a financial deployment

```python
config = ShieldConfig.builder() \
    .set_anomaly_threshold(35.0) \
    .build()

# Override via environment variable:
# ZUGASHIELD_ANOMALY_THRESHOLD=35.0
# ZUGASHIELD_ANOMALY_DECAY_RATE=0.97
```

### Retrieving layer statistics

```python
stats = detector.get_stats()
# {
#   "layer": "anomaly_detector",
#   "events_processed": 8421,
#   "chains_detected": 5,
#   "escalations": 5,
#   "active_sessions": 32
# }
```

## Implementation Notes

- `record_event()` is synchronous and returns immediately, making it safe to call from within other layer checks without creating async deadlocks.
- The `check()` call applies score decay as a side effect. Calling `check()` repeatedly without recording new events will cause the session score to decay toward the lifetime floor.
- Chain detection uses `Counter` over the `category` fields of all events in the last 5-minute window. This means the same category can be counted multiple times if multiple events of that type occurred. The `distinct >= 2` check ensures that at least two different categories from the required set are present, preventing a single-category spam attack from triggering a chain.
- The contributing events list in `AnomalyScore` is bounded to the last 50 events. The full event history remains in `_session_events` (bounded to 500).
- Active session count reported in `get_stats()` reflects all sessions that have ever received an event in the lifetime of this `AnomalyDetectorLayer` instance, including sessions that have since gone quiet.
