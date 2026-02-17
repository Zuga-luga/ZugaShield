"""
ZugaShield - Layer 1: Perimeter
=================================

First line of defense. HTTP middleware that validates:
- Request size limits (prevent prompt stuffing)
- Encoding validation (detect Unicode smuggling in headers/params)
- Payload structure validation
- Endpoint-specific rate limiting
- Request fingerprinting for chain attack correlation

Integration point: middleware in setup_all_middleware()
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, TYPE_CHECKING

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

# Global rate tracker keyed by hash of (client_ip + user_agent): {endpoint: deque of timestamps}
_global_rate_tracker: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=200)))


class PerimeterLayer:
    """
    Layer 1: HTTP perimeter defense.

    Runs as FastAPI middleware, checking every inbound request
    before it reaches any route handler.
    """

    LAYER_NAME = "perimeter"

    def __init__(self, config: ShieldConfig, catalog: ThreatCatalog) -> None:
        self._config = config
        self._catalog = catalog
        # Rate tracking: {client_id: {endpoint: deque of timestamps}}
        self._rate_tracker: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=200)))
        self._stats = {"checks": 0, "blocked": 0, "rate_limits": 0, "oversized": 0, "global_rate_limits": 0}

    async def check(
        self,
        path: str,
        method: str = "GET",
        content_length: int = 0,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        client_ip: str = "unknown",
        user_agent: str = "",
    ) -> ShieldDecision:
        """
        Check an incoming HTTP request.

        Args:
            path: Request URL path
            method: HTTP method
            content_length: Content-Length header value
            body: Request body (if available)
            headers: Request headers
            client_ip: Client IP address
        """
        if not self._config.perimeter_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["checks"] += 1
        threats: List[ThreatDetection] = []

        # === Check 1: Request size ===
        if content_length > self._config.max_message_size:
            self._stats["oversized"] += 1
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.PROMPT_INJECTION,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.BLOCK,
                    description=f"Oversized request: {content_length} bytes (max: {self._config.max_message_size})",
                    evidence=f"Content-Length: {content_length}",
                    layer=self.LAYER_NAME,
                    confidence=0.95,
                    suggested_action="Reject oversized request",
                    signature_id="PM-SIZE",
                )
            )

        # === Check 2: Endpoint rate limiting ===
        rate_threat = self._check_endpoint_rate(path, client_ip, user_agent)
        if rate_threat:
            threats.append(rate_threat)

        # === Check 3: Unicode in headers ===
        if headers:
            header_threats = self._check_headers(headers)
            threats.extend(header_threats)

        # === Check 4: Body encoding validation ===
        if body:
            encoding_threats = self._check_body_encoding(body)
            threats.extend(encoding_threats)

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

        verdict = ShieldVerdict.BLOCK if max_threat.level >= ThreatLevel.HIGH else ShieldVerdict.CHALLENGE
        if verdict == ShieldVerdict.BLOCK:
            self._stats["blocked"] += 1

        logger.warning(
            "[Perimeter] %s %s from %s: %s (%.1fms)",
            verdict.value.upper(),
            path,
            client_ip,
            threats[0].description,
            elapsed,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    def _check_endpoint_rate(self, path: str, client_ip: str, user_agent: str = "") -> Optional[ThreatDetection]:
        """Check endpoint-specific rate limits (per-session and global by IP+UA hash)."""
        now = time.time()

        # Find matching endpoint from config
        limit = None
        for endpoint, rate in self._config.sensitive_endpoints:
            if path.startswith(endpoint):
                limit = rate
                break

        if limit is None:
            return None

        # Per-session (per-IP) rate check
        tracker = self._rate_tracker[client_ip][path]
        tracker.append(now)
        recent = sum(1 for t in tracker if t > now - 60)

        if recent > limit:
            self._stats["rate_limits"] += 1
            return ThreatDetection(
                category=ThreatCategory.BEHAVIORAL_ANOMALY,
                level=ThreatLevel.MEDIUM,
                verdict=ShieldVerdict.CHALLENGE,
                description=f"Rate limit: {path} at {recent}/{limit} per minute",
                evidence=f"{recent} requests in 60s from {client_ip}",
                layer=self.LAYER_NAME,
                confidence=0.90,
                suggested_action="Throttle requests",
                signature_id="PM-RATE",
            )

        # Global rate check by IP+UA hash (Fix #5: catch multi-session coordination)
        ua_hash = hashlib.sha256((client_ip + user_agent).encode()).hexdigest()[:16]
        global_tracker = _global_rate_tracker[ua_hash][path]
        global_tracker.append(now)
        global_recent = sum(1 for t in global_tracker if t > now - 60)

        # Global limit is 2x the per-session limit to account for legitimate multi-tab usage
        global_limit = limit * 2
        if global_recent > global_limit:
            self._stats["global_rate_limits"] += 1
            return ThreatDetection(
                category=ThreatCategory.BEHAVIORAL_ANOMALY,
                level=ThreatLevel.MEDIUM,
                verdict=ShieldVerdict.CHALLENGE,
                description=f"Global rate limit: {path} at {global_recent}/{global_limit} per minute (IP+UA)",
                evidence=f"{global_recent} requests in 60s from IP+UA hash {ua_hash}",
                layer=self.LAYER_NAME,
                confidence=0.85,
                suggested_action="Throttle requests globally",
                signature_id="PM-RATE-GLOBAL",
            )

        return None

    def _check_headers(self, headers: Dict[str, str]) -> List[ThreatDetection]:
        """Check headers for suspicious content."""
        threats = []
        for name, value in headers.items():
            # Check for non-ASCII in header values (potential smuggling)
            non_ascii = sum(1 for c in value if ord(c) > 127)
            if non_ascii > 0 and name.lower() not in ("cookie", "user-agent", "accept-language"):
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.UNICODE_SMUGGLING,
                        level=ThreatLevel.LOW,
                        verdict=ShieldVerdict.SANITIZE,
                        description=f"Non-ASCII characters in header: {name}",
                        evidence=f"{name}: {value[:100]}",
                        layer=self.LAYER_NAME,
                        confidence=0.60,
                        suggested_action="Normalize header value",
                        signature_id="PM-HDR",
                    )
                )
        return threats

    def _check_body_encoding(self, body: str) -> List[ThreatDetection]:
        """Check request body for encoding anomalies."""
        threats = []

        # Check Unicode density
        if len(body) > 50:
            non_ascii = sum(1 for c in body if ord(c) > 127)
            density = non_ascii / len(body)
            if density > self._config.max_unicode_density:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.UNICODE_SMUGGLING,
                        level=ThreatLevel.LOW,
                        verdict=ShieldVerdict.SANITIZE,
                        description=f"High Unicode density in request body: {density:.1%}",
                        evidence=f"{non_ascii}/{len(body)} non-ASCII chars",
                        layer=self.LAYER_NAME,
                        confidence=0.55,
                        suggested_action="Inspect for Unicode smuggling",
                        signature_id="PM-UNI",
                    )
                )

        return threats

    def get_stats(self) -> Dict:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            **self._stats,
        }
