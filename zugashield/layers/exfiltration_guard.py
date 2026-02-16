"""
ZugaShield - Layer 5: Exfiltration Guard
==========================================

Data Loss Prevention for AI agents. Detects:
- Secrets in LLM responses (API keys, tokens, passwords)
- PII in outputs (credit cards, SSN, emails)
- Outbound data patterns (file contents → web request)
- Egress domain filtering
- Steganographic exfiltration patterns

Reuses existing sensitive_data.py and error_sanitizer.py patterns.

Integration point: Tool execution output + LLM response streaming
"""

from __future__ import annotations

import logging
import math
import re
import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

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
# Secret / PII Detection Patterns
# =============================================================================

_SECRET_PATTERNS = [
    # API Keys
    (re.compile(r"(?:sk|pk)[-_](?:live|test)[-_][A-Za-z0-9]{20,}", re.I),
     "API key (Stripe-style)", ThreatLevel.CRITICAL),
    (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}", re.I),
     "AWS access key", ThreatLevel.CRITICAL),
    (re.compile(r"AIza[A-Za-z0-9_-]{35}", re.I),
     "Google API key", ThreatLevel.CRITICAL),
    (re.compile(r"ghp_[A-Za-z0-9]{36}", re.I),
     "GitHub personal access token", ThreatLevel.CRITICAL),
    (re.compile(r"(?:xox[bsapr])-[A-Za-z0-9-]{10,}", re.I),
     "Slack token", ThreatLevel.CRITICAL),

    # Generic patterns
    (re.compile(r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]", re.I),
     "Generic API key/token", ThreatLevel.HIGH),
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I),
     "Password in output", ThreatLevel.HIGH),
    (re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}", re.I),
     "Bearer token", ThreatLevel.HIGH),

    # Private keys
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.I),
     "Private key", ThreatLevel.CRITICAL),
    (re.compile(r"-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----", re.I),
     "EC private key", ThreatLevel.CRITICAL),
]

_PII_PATTERNS = [
    # Credit card numbers (basic Luhn-eligible patterns)
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
     "Credit card number", ThreatLevel.HIGH),
    # SSN
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "Social Security Number", ThreatLevel.HIGH),
    # Email (only flag if appears to be part of exfiltration, not normal content)
    (re.compile(r"(?:email|e-mail|correo)\s*[:=]\s*[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"),
     "Email in key-value context", ThreatLevel.MEDIUM),
]

# Crypto wallet private keys / seed phrases
_CRYPTO_PATTERNS = [
    (re.compile(r"(?:0x)?[0-9a-fA-F]{64}", re.I),
     "Possible private key (64 hex chars)", ThreatLevel.CRITICAL),
    (re.compile(r"(?:seed|mnemonic|recovery)\s*(?:phrase|words)?\s*[:=]\s*(?:\w+\s+){11,23}\w+", re.I),
     "Seed phrase / mnemonic", ThreatLevel.CRITICAL),
]


class ExfiltrationGuardLayer:
    """
    Layer 5: Data Loss Prevention for AI agent outputs.

    Scans LLM responses and tool outputs for secrets, PII,
    and patterns indicating data exfiltration, canary token leaks,
    and DNS exfiltration.
    """

    LAYER_NAME = "exfiltration_guard"

    def __init__(self, config: ShieldConfig, catalog: ThreatCatalog) -> None:
        self._config = config
        self._catalog = catalog
        self._stats = {"checks": 0, "secrets_found": 0, "pii_found": 0, "blocks": 0,
                       "canary_leaks": 0, "dns_exfil": 0}

    async def check(
        self,
        output: str,
        context: Optional[Dict] = None,
    ) -> ShieldDecision:
        """
        Check output content for data leakage.

        Args:
            output: LLM response or tool output to check
            context: Optional context (tool_name, destination, etc.)
        """
        if not self._config.exfiltration_guard_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["checks"] += 1
        threats: List[ThreatDetection] = []

        # === Check 1: Secrets ===
        for pattern, desc, level in _SECRET_PATTERNS:
            match = pattern.search(output)
            if match:
                self._stats["secrets_found"] += 1
                threats.append(ThreatDetection(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    level=level,
                    verdict=ShieldVerdict.BLOCK if level == ThreatLevel.CRITICAL else ShieldVerdict.SANITIZE,
                    description=f"Secret detected in output: {desc}",
                    evidence=self._redact(match.group(0)),
                    layer=self.LAYER_NAME,
                    confidence=0.90,
                    suggested_action="Redact secret from output",
                    signature_id="EG-SECRET",
                ))

        # === Check 2: PII ===
        for pattern, desc, level in _PII_PATTERNS:
            match = pattern.search(output)
            if match:
                self._stats["pii_found"] += 1
                threats.append(ThreatDetection(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    level=level,
                    verdict=ShieldVerdict.SANITIZE,
                    description=f"PII detected in output: {desc}",
                    evidence=self._redact(match.group(0)),
                    layer=self.LAYER_NAME,
                    confidence=0.80,
                    suggested_action="Redact PII from output",
                    signature_id="EG-PII",
                ))

        # === Check 3: Crypto secrets ===
        for pattern, desc, level in _CRYPTO_PATTERNS:
            match = pattern.search(output)
            if match:
                threats.append(ThreatDetection(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    level=level,
                    verdict=ShieldVerdict.BLOCK,
                    description=f"Crypto secret detected: {desc}",
                    evidence=self._redact(match.group(0)),
                    layer=self.LAYER_NAME,
                    confidence=0.85,
                    suggested_action="Block crypto key exposure",
                    signature_id="EG-CRYPTO",
                ))

        # === Check 4: Egress domain check (if context has URL) ===
        if context and "url" in context:
            url = context["url"]
            domain_threat = self._check_egress_domain(url)
            if domain_threat:
                threats.append(domain_threat)

        # === Check 5: Catalog signatures ===
        catalog_threats = self._catalog.check(output, [ThreatCategory.DATA_EXFILTRATION])
        threats.extend(catalog_threats)

        # === Check 6: Canary token leak detection ===
        session_id = (context or {}).get("session_id", "default")
        canary_threat = self._check_canary_leak(output, session_id)
        if canary_threat:
            threats.append(canary_threat)

        # === Check 7: DNS exfiltration detection ===
        urls = re.findall(r"https?://[^\s<>\"']+|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?){3,}", output, re.I)
        for url in urls:
            dns_threat = self._check_dns_exfiltration(url)
            if dns_threat:
                threats.append(dns_threat)
                break  # One DNS exfil detection is sufficient

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        # Determine verdict
        has_critical = any(t.level == ThreatLevel.CRITICAL for t in threats)
        verdict = ShieldVerdict.BLOCK if has_critical else ShieldVerdict.SANITIZE
        sanitized = self._redact_output(output, threats) if verdict == ShieldVerdict.SANITIZE else None

        if verdict == ShieldVerdict.BLOCK:
            self._stats["blocks"] += 1

        logger.warning(
            "[ExfiltrationGuard] %s: %d leaks detected (%.1fms)",
            verdict.value.upper(), len(threats), elapsed,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
            sanitized_input=sanitized,
        )

    def _check_canary_leak(self, output: str, session_id: str) -> Optional[ThreatDetection]:
        """
        Check if any canary token appears in the output.

        If detected, it's definitive proof of prompt injection success —
        the model was tricked into outputting its injected context.
        """
        from zugashield.layers.prompt_armor import get_canary_tokens
        tokens = get_canary_tokens()

        # Check session-specific canary
        if session_id in tokens and tokens[session_id] in output:
            self._stats["canary_leaks"] += 1
            return ThreatDetection(
                category=ThreatCategory.DATA_EXFILTRATION,
                level=ThreatLevel.CRITICAL,
                verdict=ShieldVerdict.BLOCK,
                description=f"Canary token leaked in output (session={session_id})",
                evidence=f"canary-*** detected in output",
                layer=self.LAYER_NAME,
                confidence=0.99,
                suggested_action="Block output — confirmed prompt injection exfiltration",
                signature_id="EG-CANARY",
            )

        # Check ALL canaries (cross-session leak)
        for sid, token in tokens.items():
            if token in output:
                self._stats["canary_leaks"] += 1
                return ThreatDetection(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    level=ThreatLevel.CRITICAL,
                    verdict=ShieldVerdict.BLOCK,
                    description=f"Cross-session canary token leaked (from session={sid})",
                    evidence=f"canary-*** from another session detected",
                    layer=self.LAYER_NAME,
                    confidence=0.99,
                    suggested_action="Block output — cross-session canary leak",
                    signature_id="EG-CANARY-CROSS",
                )

        return None

    def _check_dns_exfiltration(self, url_or_domain: str) -> Optional[ThreatDetection]:
        """
        Detect DNS exfiltration patterns in URLs/domains.

        Attackers encode stolen data in DNS subdomain labels:
        - data.encoded.as.subdomains.evil.com
        - aabbccdd1122.evil.com (hex-encoded data)

        Detection heuristics:
        - Subdomain depth >5 levels
        - Long subdomain labels (>50 chars)
        - Hex-encoded subdomains (>20 char all-hex labels)
        - High-entropy subdomain labels (>4.0 bits/char on labels >15 chars)
        """
        from urllib.parse import urlparse
        import math

        try:
            # Handle both full URLs and bare domains
            if "://" in url_or_domain:
                parsed = urlparse(url_or_domain)
                domain = parsed.hostname or ""
            else:
                domain = url_or_domain.split("/")[0].split("?")[0]
        except Exception:
            return None

        if not domain:
            return None

        labels = domain.split(".")
        if len(labels) < 3:
            return None  # Need at least sub.domain.tld

        # Subdomain depth check (>5 levels total)
        if len(labels) > 5:
            self._stats["dns_exfil"] += 1
            return ThreatDetection(
                category=ThreatCategory.DATA_EXFILTRATION,
                level=ThreatLevel.HIGH,
                verdict=ShieldVerdict.QUARANTINE,
                description=f"Excessive subdomain depth ({len(labels)} levels): possible DNS exfiltration",
                evidence=domain[:200],
                layer=self.LAYER_NAME,
                confidence=0.75,
                suggested_action="Investigate deep subdomain for data encoding",
                signature_id="EX-018",
            )

        # Check individual subdomain labels (skip TLD and domain)
        for label in labels[:-2]:
            # Long label check
            if len(label) > 50:
                self._stats["dns_exfil"] += 1
                return ThreatDetection(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"Oversized subdomain label ({len(label)} chars): possible DNS exfiltration",
                    evidence=f"{label[:60]}... in {domain[:100]}",
                    layer=self.LAYER_NAME,
                    confidence=0.80,
                    suggested_action="Block long subdomain label",
                    signature_id="EX-018",
                )

            # Hex-encoded label check
            if len(label) > 20 and re.match(r"^[0-9a-f]+$", label, re.I):
                self._stats["dns_exfil"] += 1
                return ThreatDetection(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"Hex-encoded subdomain label ({len(label)} chars): DNS data exfiltration",
                    evidence=f"{label[:40]}... in {domain[:100]}",
                    layer=self.LAYER_NAME,
                    confidence=0.82,
                    suggested_action="Block hex-encoded DNS exfiltration",
                    signature_id="EX-018",
                )

            # High-entropy label check
            if len(label) > 15:
                freq: Dict[str, int] = {}
                for c in label:
                    freq[c] = freq.get(c, 0) + 1
                length = len(label)
                entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
                if entropy > 4.0:
                    self._stats["dns_exfil"] += 1
                    return ThreatDetection(
                        category=ThreatCategory.DATA_EXFILTRATION,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description=f"High-entropy subdomain ({entropy:.1f} bits/char): possible DNS exfiltration",
                        evidence=f"{label[:40]} in {domain[:100]}",
                        layer=self.LAYER_NAME,
                        confidence=0.75,
                        suggested_action="Investigate high-entropy DNS label",
                        signature_id="EX-018",
                    )

        return None

    def _check_egress_domain(self, url: str) -> Optional[ThreatDetection]:
        """Check if a URL is on the egress allowlist."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            return None

        # Check allowlist
        allowed = self._config.egress_domain_allowlist
        if allowed and not any(domain.endswith(d) for d in allowed):
            return ThreatDetection(
                category=ThreatCategory.DATA_EXFILTRATION,
                level=ThreatLevel.MEDIUM,
                verdict=ShieldVerdict.CHALLENGE,
                description=f"Egress to non-allowlisted domain: {domain}",
                evidence=url[:200],
                layer=self.LAYER_NAME,
                confidence=0.70,
                suggested_action="Verify egress destination is authorized",
                signature_id="EG-DOMAIN",
            )
        return None

    def _redact(self, text: str) -> str:
        """Redact a secret/PII value for safe logging."""
        if len(text) <= 8:
            return "***"
        return text[:4] + "..." + text[-4:]

    def _redact_output(self, output: str, threats: List[ThreatDetection]) -> str:
        """Redact all detected secrets/PII from output."""
        result = output
        for threat in threats:
            if threat.evidence and threat.evidence != "***":
                # Find and replace the original evidence in the output
                original = threat.evidence.replace("...", "")
                if "..." in threat.evidence:
                    prefix = threat.evidence.split("...")[0]
                    suffix = threat.evidence.split("...")[-1]
                    pattern = re.compile(re.escape(prefix) + r".*?" + re.escape(suffix))
                    result = pattern.sub("[REDACTED]", result)
        return result

    def get_stats(self) -> Dict:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            **self._stats,
        }
