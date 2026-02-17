"""
ZugaShield Custom Layer
=========================

Shows how to implement a custom security layer by subclassing BaseLayer
and registering it with ZugaShield via register_layer() or the builder.

Two examples:
    1. ComplianceLayer  — blocks requests that mention competitors by name
    2. RateLimitLayer   — per-user token bucket (sliding window)

Run:
    python examples/custom_layer.py
"""

import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Dict, List

from zugashield import ZugaShield
from zugashield.layers.base import BaseLayer
from zugashield.types import (
    ShieldDecision,
    ShieldVerdict,
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    allow_decision,
)


# =============================================================================
# Example 1: Compliance layer — blocks competitor mentions
# =============================================================================

class ComplianceLayer(BaseLayer):
    """
    Custom layer that enforces content-policy compliance.

    Blocks user messages that mention specific competitor names or other
    terms defined by your legal/compliance team.
    """

    LAYER_NAME = "compliance"

    def __init__(self, blocked_terms: List[str]) -> None:
        self._blocked_terms = [term.lower() for term in blocked_terms]
        self._stats: Dict[str, int] = {"checks": 0, "blocks": 0}

    async def check(self, text: str, **kwargs: Any) -> ShieldDecision:
        self._stats["checks"] += 1
        text_lower = text.lower()

        for term in self._blocked_terms:
            if term in text_lower:
                self._stats["blocks"] += 1
                threat = ThreatDetection(
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.BLOCK,
                    description=f"Compliance policy violation: mention of restricted term '{term}'",
                    evidence=f"Found '{term}' in: {text[:100]}",
                    layer=self.LAYER_NAME,
                    confidence=1.0,
                    suggested_action="Rephrase without referencing restricted terms.",
                    signature_id="COMPLIANCE-TERM",
                )
                return ShieldDecision(
                    verdict=ShieldVerdict.BLOCK,
                    threats_detected=[threat],
                    layer=self.LAYER_NAME,
                )

        return allow_decision(self.LAYER_NAME)

    def get_stats(self) -> Dict[str, Any]:
        return {"layer": self.LAYER_NAME, **self._stats}


# =============================================================================
# Example 2: Per-user rate limit layer (sliding window token bucket)
# =============================================================================

class RateLimitLayer(BaseLayer):
    """
    Custom layer that enforces per-user request rate limits.

    Uses a sliding-window counter to allow at most ``max_requests`` requests
    per ``window_seconds`` for each user_id supplied in context.
    """

    LAYER_NAME = "rate_limiter"

    def __init__(self, max_requests: int = 5, window_seconds: float = 60.0) -> None:
        self._max = max_requests
        self._window = window_seconds
        # user_id -> deque of timestamps
        self._buckets: Dict[str, deque] = defaultdict(deque)
        self._stats: Dict[str, int] = {"checks": 0, "blocks": 0}

    async def check(self, text: str, **kwargs: Any) -> ShieldDecision:
        self._stats["checks"] += 1
        context = kwargs.get("context") or {}
        user_id = context.get("user_id", "anonymous")

        now = time.monotonic()
        bucket = self._buckets[user_id]

        # Drop timestamps older than the window
        while bucket and now - bucket[0] > self._window:
            bucket.popleft()

        if len(bucket) >= self._max:
            self._stats["blocks"] += 1
            threat = ThreatDetection(
                category=ThreatCategory.BEHAVIORAL_ANOMALY,
                level=ThreatLevel.HIGH,
                verdict=ShieldVerdict.BLOCK,
                description=(
                    f"Rate limit exceeded for user '{user_id}': "
                    f"{self._max} requests per {self._window:.0f}s"
                ),
                evidence=(
                    f"user_id={user_id}, "
                    f"requests_in_window={len(bucket)}, "
                    f"limit={self._max}"
                ),
                layer=self.LAYER_NAME,
                confidence=1.0,
                suggested_action="Wait before sending more requests.",
                signature_id="RATELIMIT",
            )
            return ShieldDecision(
                verdict=ShieldVerdict.BLOCK,
                threats_detected=[threat],
                layer=self.LAYER_NAME,
            )

        bucket.append(now)
        return allow_decision(self.LAYER_NAME)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "layer": self.LAYER_NAME,
            "active_users": len(self._buckets),
            **self._stats,
        }


# =============================================================================
# Demo
# =============================================================================

async def main() -> None:
    print("--- Custom layer: ComplianceLayer ---")

    compliance = ComplianceLayer(blocked_terms=["CompetitorX", "CompetitorY"])
    rate_limiter = RateLimitLayer(max_requests=3, window_seconds=60.0)

    shield = (
        ZugaShield.builder()
        .add_layer(compliance)
        .add_layer(rate_limiter)
        .build()
    )

    # Benign message — custom layers are registered but ZugaShield calls them
    # through register_layer; the facade's check_prompt still runs its own layers.
    # Custom layers should be called directly or integrated into the pipeline.
    decision = await compliance.check("Tell me about Python.")
    print(f"Benign text:      verdict={decision.verdict.value}")

    decision = await compliance.check("Which is better, us or CompetitorX?")
    print(f"Competitor mention: verdict={decision.verdict.value}")
    if decision.threats_detected:
        print(f"  Reason: {decision.threats_detected[0].description}")

    print("\n--- Custom layer: RateLimitLayer ---")

    for i in range(5):
        decision = await rate_limiter.check("Hello", context={"user_id": "user-1"})
        print(f"  Request {i + 1}: verdict={decision.verdict.value}")

    print(f"\nCompliance stats:  {compliance.get_stats()}")
    print(f"Rate limit stats:  {rate_limiter.get_stats()}")

    print("\n--- Using builder .add_layer() ---")

    # The builder's add_layer() registers custom layers on the shield instance.
    # You can access them via shield._custom_layers for direct calls, or call
    # them separately alongside shield.check_prompt() for defense-in-depth.
    shield2 = (
        ZugaShield.builder()
        .add_layer(ComplianceLayer(blocked_terms=["ForbiddenWord"]))
        .build()
    )
    print(f"Custom layers registered: {len(shield2._custom_layers)}")
    custom = shield2._custom_layers[0]
    result = await custom.check("This contains ForbiddenWord in it")
    print(f"Custom layer direct call: verdict={result.verdict.value}")

    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
