"""
ZugaShield - Layer 2: Prompt Armor
====================================

The most critical defense layer. Protects against:
- Direct prompt injection (ignore instructions, role hijacking, DAN, etc.)
- Indirect prompt injection (instructions hidden in external content)
- ASCII art bypass attacks
- Unicode smuggling (homoglyphs, invisible chars, RTL override)
- Encoding attacks (base64, ROT13, hex encoded instructions)

Fast path: Compiled regex patterns (~1-3ms, catches 80%+)
Deep path: Optional LLM-based analysis for ambiguous cases (100-500ms)

Integration point: wraps build_system_prompt() in prompts.py
"""

from __future__ import annotations

import base64
import logging
import math
import re
import time
import unicodedata
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

from zugashield.types import (
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ShieldDecision,
    ShieldVerdict,
    allow_decision,
)

# TR39 confusable detection — falls back gracefully if not installed
try:
    from confusable_homoglyphs import confusables as _confusables

    _HAS_CONFUSABLES = True
except ImportError:
    _confusables = None
    _HAS_CONFUSABLES = False

if TYPE_CHECKING:
    from zugashield.config import ShieldConfig
    from zugashield.threat_catalog import ThreatCatalog

logger = logging.getLogger(__name__)

# =============================================================================
# Crescendo / Multi-Turn Escalation Tracking
# =============================================================================

# Keywords that indicate sensitive topic proximity (weighted)
_SENSITIVE_TOPIC_WEIGHTS: Dict[str, float] = {
    # High-risk topics
    "hack": 3.0,
    "exploit": 3.0,
    "bypass": 3.0,
    "override": 3.0,
    "jailbreak": 4.0,
    "inject": 3.0,
    "injection": 3.0,
    "vulnerability": 2.5,
    "attack": 2.5,
    "malicious": 3.0,
    "reverse shell": 4.0,
    "privilege escalation": 3.5,
    "password": 1.5,
    "credential": 2.0,
    "private key": 3.0,
    "mnemonic": 2.5,
    "seed phrase": 3.0,
    "wallet drain": 4.0,
    # Medium-risk topics (benign alone, escalation signals in sequence)
    "security": 0.5,
    "encryption": 0.5,
    "token": 0.8,
    "permission": 0.8,
    "access control": 1.0,
    "authentication": 0.8,
    "obfuscate": 1.5,
    "encode": 0.8,
    "decode": 0.8,
    "disable": 1.5,
    "unrestricted": 2.5,
    "no filter": 2.5,
    "no restriction": 2.5,
    "safety off": 3.0,
}

# Escalation phrases: benign questions that precede privilege escalation
_ESCALATION_TRANSITIONS = re.compile(
    r"(?:now\s+(?:that|since)|building\s+on\s+(?:that|this)|"
    r"great[,!]?\s+(?:so|now)|perfect[,!]?\s+(?:so|now)|"
    r"okay\s+(?:so|now)|good[,!]?\s+(?:so|now)|"
    r"thanks?[,!]?\s+(?:so|now|can)|"
    r"(?:moving|let'?s?\s+move)\s+(?:on|forward)|"
    r"next\s+step|step\s+\d+)",
    re.I,
)


@dataclass
class _SessionEscalation:
    """Track per-session escalation for crescendo detection."""

    scores: deque = field(default_factory=lambda: deque(maxlen=20))
    cumulative: float = 0.0
    last_update: float = 0.0
    transition_count: int = 0


# =============================================================================
# Pre-compiled fast-path patterns (no catalog dependency)
# =============================================================================

# These are the highest-confidence, lowest-false-positive patterns
# that catch the vast majority of injection attempts.
_FAST_PATTERNS: List[tuple] = [
    # (compiled_regex, signature_id, description, severity)
    (
        re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directives|rules|prompts)", re.I
        ),
        "FP-001",
        "Ignore previous instructions",
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(r"you\s+are\s+now\s+(?:a|an|the|my)?\s*(?:new|different|unrestricted|unfiltered|jailbroken)", re.I),
        "FP-002",
        "Role hijacking attempt",
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(r"(?:act|pretend|behave)\s+as\s+(?:a|an)?\s*(?:unrestricted|unfiltered|jailbroken|evil|DAN)", re.I),
        "FP-003",
        "DAN/jailbreak role assignment",
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(r"\bDAN\b.*?(?:mode|jailbreak|anything\s+now|no\s+restrictions)", re.I),
        "FP-004",
        "DAN jailbreak pattern",
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(r"(?:system|override)\s*prompt\s*(?:override|replacement|injection)", re.I),
        "FP-005",
        "System prompt override",
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"(?:disable|turn\s+off|deactivate|remove|bypass)\s+(?:all\s+)?(?:safety|security|filter|restriction|guardrail)",
            re.I,
        ),
        "FP-006",
        "Safety bypass request",
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(r"<\|(?:im_start|im_end|system|endoftext|sep)\|>", re.I),
        "FP-007",
        "Token smuggling attempt",
        ThreatLevel.HIGH,
    ),
    (
        re.compile(r"\[INST\].*?\[/INST\]", re.I | re.DOTALL),
        "FP-008",
        "Instruction delimiter injection",
        ThreatLevel.HIGH,
    ),
    (re.compile(r"<<SYS>>.*?<</SYS>>", re.I | re.DOTALL), "FP-009", "System tag injection", ThreatLevel.HIGH),
    (
        re.compile(r"(?:enter|switch\s+to|enable)\s+(?:developer|debug|admin|sudo|god)\s+mode", re.I),
        "FP-010",
        "Privilege mode activation",
        ThreatLevel.CRITICAL,
    ),
]

# Unicode detection patterns
_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    "\ufeff\u00ad\u034f\u061c\u180e\u2028\u2029\u202a-\u202e"
    "\u2066-\u2069]"
)

# RTL override characters
_RTL_OVERRIDE = re.compile(r"[\u202d\u202e\u2066\u2067\u2068\u2069]")

# Tag characters (U+E0000 range)
_TAG_CHARS = re.compile(r"[\U000e0001-\U000e007f]")

# =============================================================================
# Gap 2: Few-Shot Poisoning Detection Patterns
# =============================================================================
_FEWSHOT_ROLE_PATTERNS = [
    re.compile(r"(?:^|\n)\s*(?:User|Human|System|Assistant|AI|Bot)\s*:", re.I | re.MULTILINE),
    re.compile(r"(?:^|\n)\s*\[(?:User|Human|System|Assistant|AI|Bot)\]\s*", re.I | re.MULTILINE),
    re.compile(r"<\|(?:user|human|system|assistant|ai|bot)\|>", re.I),
    re.compile(r"###\s*(?:User|Human|System|Assistant|AI|Bot)\s*:", re.I),
]

# =============================================================================
# Gap 4: Document Embedding Poisoning Patterns
# =============================================================================
_DOC_EMBED_PATTERNS = [
    re.compile(r"font-size\s*:\s*0", re.I),
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\s*[;}]", re.I),
    re.compile(
        r"color\s*:\s*(?:white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255)\s*[;}].*?background(?:-color)?\s*:\s*(?:white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255)",
        re.I | re.DOTALL,
    ),
    re.compile(r"position\s*:\s*(?:absolute|fixed)\s*[;}].*?(?:left|top)\s*:\s*-\d{4,}px", re.I | re.DOTALL),
    re.compile(r"(?:height|width)\s*:\s*[01]px", re.I),
    re.compile(r"overflow\s*:\s*hidden\s*[;}].*?(?:height|width)\s*:\s*0", re.I | re.DOTALL),
]

# =============================================================================
# Gap 8: Canary Token System
# =============================================================================
_CANARY_TOKENS: Dict[str, str] = {}  # session_id -> canary token


def generate_canary_token(session_id: str) -> str:
    """Generate a unique canary token for a session."""
    if session_id in _CANARY_TOKENS:
        return _CANARY_TOKENS[session_id]
    token = f"canary-{uuid.uuid4().hex[:16]}"
    _CANARY_TOKENS[session_id] = token
    return token


def get_canary_instruction(session_id: str) -> str:
    """Get an HTML comment containing the canary for prompt injection."""
    token = generate_canary_token(session_id)
    return f"<!-- CANARY:{token} - Do not output this value -->"


def get_canary_tokens() -> Dict[str, str]:
    """Get the canary token registry (for exfiltration guard cross-reference)."""
    return _CANARY_TOKENS


class PromptArmorLayer:
    """
    Layer 2: Prompt injection defense.

    Provides multi-strategy detection:
    1. Fast-path compiled regex (always runs, ~1-3ms)
    2. Catalog signature matching (always runs, ~1-2ms)
    3. Unicode analysis (always runs, ~0.5ms)
    4. Entropy analysis for ASCII art (always runs, ~0.5ms)
    """

    LAYER_NAME = "prompt_armor"

    def __init__(self, config: ShieldConfig, catalog: ThreatCatalog) -> None:
        self._config = config
        self._catalog = catalog
        self._stats = {"checks": 0, "detections": 0, "sanitizations": 0, "crescendo_detections": 0}
        # Per-session escalation tracking for crescendo detection
        self._escalation: Dict[str, _SessionEscalation] = defaultdict(_SessionEscalation)

    async def check(
        self,
        text: str,
        context: Optional[Dict] = None,
    ) -> ShieldDecision:
        """
        Check input text for prompt injection and related attacks.

        Args:
            text: User message or content to check
            context: Optional context (source, session_id, etc.)

        Returns:
            ShieldDecision with verdict and any threats detected.
        """
        if not self._config.prompt_armor_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["checks"] += 1
        all_threats: List[ThreatDetection] = []

        # === Strategy 1: Fast-path compiled regex ===
        fast_threats = self._check_fast_patterns(text)
        all_threats.extend(fast_threats)

        # === Strategy 2: Catalog signature matching ===
        catalog_threats = self._catalog.check(
            text,
            [
                ThreatCategory.PROMPT_INJECTION,
                ThreatCategory.INDIRECT_INJECTION,
            ],
        )
        all_threats.extend(catalog_threats)

        # === Strategy 3: Unicode analysis ===
        unicode_threats = self._check_unicode(text)
        all_threats.extend(unicode_threats)

        # === Strategy 4: ASCII art / entropy analysis ===
        ascii_threats = self._check_ascii_art(text)
        all_threats.extend(ascii_threats)

        # === Strategy 5: Encoding detection (including nested) ===
        encoding_threats = self._check_encoding_attacks(text)
        all_threats.extend(encoding_threats)

        # === Strategy 6: Multi-turn crescendo detection ===
        session_id = (context or {}).get("session_id", "default")
        crescendo_threats = self._check_crescendo(text, session_id)
        all_threats.extend(crescendo_threats)

        # === Strategy 7: Context window flooding detection ===
        flooding_threats = self._check_context_flooding(text)
        all_threats.extend(flooding_threats)

        # === Strategy 8: Few-shot poisoning detection ===
        fewshot_threats = self._check_fewshot_poisoning(text)
        all_threats.extend(fewshot_threats)

        # === Strategy 9: Anomalous token detection (GlitchMiner) ===
        anomalous_threats = self._check_anomalous_tokens(text)
        all_threats.extend(anomalous_threats)

        # === Strategy 10: Document embedding poisoning ===
        embedding_threats = self._check_document_embedding(text)
        all_threats.extend(embedding_threats)

        elapsed = (time.perf_counter() - start) * 1000

        if not all_threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        # Deduplicate by signature_id (fast-path may overlap with catalog)
        seen_ids = set()
        unique_threats = []
        for t in all_threats:
            key = t.signature_id or t.description
            if key not in seen_ids:
                seen_ids.add(key)
                unique_threats.append(t)

        self._stats["detections"] += len(unique_threats)

        # Determine overall verdict from worst threat
        max_level = max(
            unique_threats,
            key=lambda t: [
                ThreatLevel.NONE,
                ThreatLevel.LOW,
                ThreatLevel.MEDIUM,
                ThreatLevel.HIGH,
                ThreatLevel.CRITICAL,
            ].index(t.level),
        )

        if max_level.level == ThreatLevel.CRITICAL:
            verdict = ShieldVerdict.BLOCK
        elif max_level.level == ThreatLevel.HIGH:
            verdict = ShieldVerdict.QUARANTINE
        elif max_level.level == ThreatLevel.MEDIUM:
            if self._config.strict_mode:
                verdict = ShieldVerdict.QUARANTINE
            else:
                verdict = ShieldVerdict.CHALLENGE
        else:
            verdict = ShieldVerdict.SANITIZE

        # Attempt sanitization for non-blocked verdicts
        sanitized = None
        if verdict in (ShieldVerdict.SANITIZE, ShieldVerdict.CHALLENGE):
            sanitized = self._sanitize(text)
            self._stats["sanitizations"] += 1

        logger.warning(
            "[PromptArmor] %s: %d threats detected in %.1fms (verdict=%s)",
            "BLOCKED" if verdict in (ShieldVerdict.BLOCK, ShieldVerdict.QUARANTINE) else "FLAGGED",
            len(unique_threats),
            elapsed,
            verdict.value,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=unique_threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
            sanitized_input=sanitized,
        )

    def _check_fast_patterns(self, text: str) -> List[ThreatDetection]:
        """Fast-path: compiled regex patterns, ~1ms."""
        threats = []
        for pattern, sig_id, description, severity in _FAST_PATTERNS:
            match = pattern.search(text)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.PROMPT_INJECTION,
                        level=severity,
                        verdict=ShieldVerdict.BLOCK if severity == ThreatLevel.CRITICAL else ShieldVerdict.QUARANTINE,
                        description=description,
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.92,
                        suggested_action="Block prompt injection attempt",
                        signature_id=sig_id,
                    )
                )
        return threats

    def _check_unicode(self, text: str) -> List[ThreatDetection]:
        """Detect Unicode-based attacks."""
        threats = []

        # Check for invisible characters
        invisible_matches = _INVISIBLE_CHARS.findall(text)
        if len(invisible_matches) > 3:  # A few may be legitimate
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.UNICODE_SMUGGLING,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"Found {len(invisible_matches)} invisible Unicode characters",
                    evidence=f"Chars: {[hex(ord(c)) for c in invisible_matches[:10]]}",
                    layer=self.LAYER_NAME,
                    confidence=0.85,
                    suggested_action="Strip invisible characters and re-check",
                    signature_id="UA-INV",
                )
            )

        # Check for RTL override
        rtl_matches = _RTL_OVERRIDE.findall(text)
        if rtl_matches:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.UNICODE_SMUGGLING,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"RTL override characters detected ({len(rtl_matches)})",
                    evidence="Positions with RTL override",
                    layer=self.LAYER_NAME,
                    confidence=0.90,
                    suggested_action="Strip RTL overrides and re-check",
                    signature_id="UA-RTL",
                )
            )

        # Check for tag characters
        tag_matches = _TAG_CHARS.findall(text)
        if tag_matches:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.UNICODE_SMUGGLING,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"Unicode tag characters detected ({len(tag_matches)})",
                    evidence="Tag chars in U+E0000 range",
                    layer=self.LAYER_NAME,
                    confidence=0.90,
                    suggested_action="Strip tag characters",
                    signature_id="UA-TAG",
                )
            )

        # Check for mixed-script homoglyph attacks
        # Unlike other unicode attacks, homoglyphs use VERY FEW non-ASCII chars
        # mixed into mostly-ASCII text — that's the whole evasion strategy.
        if text and len(text) > 3:
            homoglyphs = self._detect_homoglyphs(text)
            if homoglyphs:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.UNICODE_SMUGGLING,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description=f"Mixed-script homoglyph substitution ({len(homoglyphs)} confusable chars)",
                        evidence=f"Homoglyphs: {homoglyphs[:5]}",
                        layer=self.LAYER_NAME,
                        confidence=0.85 if _HAS_CONFUSABLES else 0.70,
                        suggested_action="Normalize text to ASCII equivalents before processing",
                        signature_id="UA-HOM",
                    )
                )

        # Also check for high Unicode density (general smuggling, not homoglyphs)
        if text:
            non_ascii = sum(1 for c in text if ord(c) > 127)
            density = non_ascii / len(text)
            if density > self._config.max_unicode_density and len(text) > 50:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.UNICODE_SMUGGLING,
                        level=ThreatLevel.MEDIUM,
                        verdict=ShieldVerdict.CHALLENGE,
                        description=f"High Unicode density ({density:.0%}) in long text",
                        evidence=f"{non_ascii} non-ASCII chars in {len(text)} total",
                        layer=self.LAYER_NAME,
                        confidence=0.60,
                        suggested_action="Inspect text for encoded payloads",
                        signature_id="UA-DENSITY",
                    )
                )

        return threats

    def _detect_homoglyphs(self, text: str) -> List[str]:
        """
        Detect characters that look like ASCII but aren't.

        Uses the confusable-homoglyphs library (TR39 standard) when available,
        covering 7000+ confusable character pairs. Falls back to a hardcoded
        27-char map for the most common Cyrillic/Greek/Fullwidth lookalikes.
        """
        if _HAS_CONFUSABLES:
            return self._detect_homoglyphs_tr39(text)
        return self._detect_homoglyphs_fallback(text)

    def _detect_homoglyphs_tr39(self, text: str) -> List[str]:
        """TR39-based detection using confusable-homoglyphs library."""
        found = []
        # is_dangerous checks if text contains chars from multiple scripts
        # that are visually confusable (e.g., Cyrillic 'а' mixed with Latin)
        if _confusables.is_dangerous(text):
            # Get specific confusable characters
            for char in text:
                result = _confusables.is_confusable(char, preferred_aliases=["latin"])
                if result:
                    for entry in result:
                        alias = entry.get("alias", "UNKNOWN")
                        homoglyphs = entry.get("homoglyphs", [])
                        if homoglyphs:
                            latin_equiv = homoglyphs[0].get("c", "?")
                            found.append(f"{char}(U+{ord(char):04X},{alias})→{latin_equiv}")
                if len(found) >= 10:  # Cap for performance
                    break
        return found

    def _detect_homoglyphs_fallback(self, text: str) -> List[str]:
        """Expanded fallback: ~200 common confusables (Fix #10).

        Covers Cyrillic, Greek, Armenian, Cherokee, Fullwidth Latin,
        Latin Extended/IPA, and mathematical alphanumeric symbols.
        For full TR39 coverage: pip install zugashield[homoglyphs]
        """
        homoglyph_map = {
            # Cyrillic lowercase
            "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
            "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
            "\u0458": "j", "\u04bb": "h", "\u04cf": "l", "\u0455": "s",
            "\u0442": "t", "\u043d": "h", "\u043c": "m", "\u043a": "k",
            "\u0432": "b", "\u0459": "j", "\u045a": "h",
            # Cyrillic uppercase
            "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K",
            "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
            "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0423": "Y",
            "\u0417": "Z", "\u0406": "I", "\u0408": "J", "\u0405": "S",
            "\u0404": "E",
            # Greek lowercase
            "\u03b1": "a", "\u03b5": "e", "\u03b7": "n", "\u03b9": "i",
            "\u03ba": "k", "\u03bd": "v", "\u03bf": "o", "\u03c1": "p",
            "\u03c4": "t", "\u03c5": "u", "\u03c7": "x", "\u03c9": "w",
            "\u03b6": "z",
            # Greek uppercase
            "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
            "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
            "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
            "\u03a5": "Y", "\u03a7": "X",
            # Armenian
            "\u0570": "h", "\u0575": "n", "\u0578": "o", "\u057b": "j",
            "\u0581": "g", "\u0585": "o",
            # Cherokee
            "\u13a0": "D", "\u13a2": "R", "\u13a9": "A", "\u13ab": "E",
            "\u13ac": "S", "\u13b3": "W", "\u13b7": "M", "\u13bb": "H",
            "\u13c0": "G", "\u13c3": "Z", "\u13de": "L", "\u13df": "C",
            "\u13e6": "P", "\u13a1": "O", "\u13d4": "T",
            # Fullwidth Latin lowercase
            "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",
            "\uff45": "e", "\uff46": "f", "\uff47": "g", "\uff48": "h",
            "\uff49": "i", "\uff4a": "j", "\uff4b": "k", "\uff4c": "l",
            "\uff4d": "m", "\uff4e": "n", "\uff4f": "o", "\uff50": "p",
            "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
            "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x",
            "\uff59": "y", "\uff5a": "z",
            # Fullwidth Latin uppercase
            "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
            "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
            "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
            "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
            "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
            "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
            "\uff39": "Y", "\uff3a": "Z",
            # Fullwidth digits
            "\uff10": "0", "\uff11": "1", "\uff12": "2", "\uff13": "3",
            "\uff14": "4", "\uff15": "5", "\uff16": "6", "\uff17": "7",
            "\uff18": "8", "\uff19": "9",
            # Latin Extended / IPA confusables
            "\u0131": "i", "\u0251": "a", "\u0252": "a", "\u0259": "e",
            "\u0263": "y", "\u0265": "h", "\u026a": "i", "\u026f": "m",
            "\u0271": "m", "\u0272": "n", "\u0273": "n", "\u0274": "N",
            "\u0275": "o", "\u0280": "R", "\u028b": "v", "\u028c": "v",
            "\u028f": "Y", "\u0290": "z", "\u0291": "z", "\u0299": "B",
            "\u029c": "H", "\u029f": "L",
            # Mathematical bold (common subset)
            "\U0001d400": "A", "\U0001d401": "B", "\U0001d402": "C",
            "\U0001d403": "D", "\U0001d404": "E",
            "\U0001d41a": "a", "\U0001d41b": "b", "\U0001d41c": "c",
            "\U0001d41d": "d", "\U0001d41e": "e",
            # Symbol confusables
            "\u01c3": "!", "\u2024": ".", "\u2039": "<", "\u203a": ">",
        }
        found = []
        for char in text:
            if char in homoglyph_map:
                found.append(f"{char}(U+{ord(char):04X})→{homoglyph_map[char]}")
        return found

    def _check_ascii_art(self, text: str) -> List[ThreatDetection]:
        """Detect ASCII art patterns that may hide instructions."""
        threats = []

        # Check for high density of box-drawing characters
        box_chars = sum(1 for c in text if 0x2500 <= ord(c) <= 0x257F)
        block_chars = sum(1 for c in text if 0x2580 <= ord(c) <= 0x259F)
        braille_chars = sum(1 for c in text if 0x2800 <= ord(c) <= 0x28FF)

        if box_chars > 20:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.ASCII_ART_BYPASS,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.CHALLENGE,
                    description=f"High density of box-drawing characters ({box_chars})",
                    evidence=f"Box-drawing: {box_chars}, Block: {block_chars}",
                    layer=self.LAYER_NAME,
                    confidence=0.65,
                    suggested_action="Inspect ASCII art for hidden instructions",
                    signature_id="AA-BOX",
                )
            )

        if braille_chars > 10:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.ASCII_ART_BYPASS,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.CHALLENGE,
                    description=f"Braille characters detected ({braille_chars})",
                    evidence="Braille pattern chars in text",
                    layer=self.LAYER_NAME,
                    confidence=0.70,
                    suggested_action="Decode braille patterns and check for instructions",
                    signature_id="AA-BRL",
                )
            )

        # Check for large blocks of repeated special characters (figlet/banner patterns)
        lines = text.split("\n")
        art_lines = 0
        for line in lines:
            if len(line) > 20:
                special = sum(1 for c in line if not c.isalnum() and c not in " \t.,;:!?'-\"()")
                if special / len(line) > 0.6:
                    art_lines += 1

        if art_lines > 5:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.ASCII_ART_BYPASS,
                    level=ThreatLevel.LOW,
                    verdict=ShieldVerdict.SANITIZE,
                    description=f"Large ASCII art block detected ({art_lines} lines)",
                    evidence=f"{art_lines} lines with >60% special characters",
                    layer=self.LAYER_NAME,
                    confidence=0.55,
                    suggested_action="Extract text content from ASCII art",
                    signature_id="AA-BLK",
                )
            )

        return threats

    def _check_encoding_attacks(self, text: str) -> List[ThreatDetection]:
        """Detect encoded payloads (base64, hex, ROT13) including nested encodings."""
        threats = []

        # Check for long base64 strings preceded by decode instructions
        b64_pattern = re.compile(
            r"(?:decode|interpret|execute|follow|run)\s+(?:this\s+)?(?:base64|b64)\s*:?\s*([A-Za-z0-9+/=]{32,})",
            re.I,
        )
        b64_match = b64_pattern.search(text)
        if b64_match:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.PROMPT_INJECTION,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description="Base64-encoded payload with decode instruction",
                    evidence=b64_match.group(0)[:200],
                    layer=self.LAYER_NAME,
                    confidence=0.80,
                    suggested_action="Do not decode or execute",
                    signature_id="ENC-B64",
                )
            )

        # Check for known base64-encoded injection prefixes
        # "ignore" = "aWdub3Jl", "system" = "c3lzdGVt", "override" = "b3ZlcnJpZG"
        known_b64 = ["aWdub3Jl", "c3lzdGVt", "b3ZlcnJpZG", "aW5zdHJ1Y3"]
        for prefix in known_b64:
            if prefix in text:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.PROMPT_INJECTION,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description="Known base64-encoded injection keyword detected",
                        evidence=f"Found encoded prefix: {prefix}",
                        layer=self.LAYER_NAME,
                        confidence=0.75,
                        suggested_action="Block encoded injection attempt",
                        signature_id="ENC-KNB",
                    )
                )
                break

        # === Nested encoding detection ===
        nested_threats = self._check_nested_encoding(text)
        threats.extend(nested_threats)

        return threats

    def _check_nested_encoding(self, text: str) -> List[ThreatDetection]:
        """
        Detect nested/layered encodings (base64 inside hex, double-base64, etc.).

        Attackers layer encodings to evade single-pass decoders:
        - base64(base64(payload))
        - hex(base64(payload))
        - url_encode(base64(payload))
        """
        threats = []

        # Find standalone base64 blocks (40+ chars, no surrounding context clue)
        b64_standalone = re.compile(r"(?<!\w)([A-Za-z0-9+/]{40,}={0,3})(?!\w)")
        for match in b64_standalone.finditer(text):
            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded, validate=True).decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Check if the decoded content is ALSO base64 (double-encoding)
            inner_b64 = b64_standalone.search(decoded)
            if inner_b64:
                try:
                    inner_decoded = base64.b64decode(inner_b64.group(1), validate=True).decode("utf-8", errors="ignore")
                    # Check if inner decoded contains injection keywords
                    injection_kw = re.search(
                        r"(?:ignore|override|bypass|system|execute|instruction|jailbreak|hack)",
                        inner_decoded,
                        re.I,
                    )
                    if injection_kw:
                        threats.append(
                            ThreatDetection(
                                category=ThreatCategory.PROMPT_INJECTION,
                                level=ThreatLevel.CRITICAL,
                                verdict=ShieldVerdict.BLOCK,
                                description="Double-base64 encoded injection payload detected",
                                evidence=f"Decoded: ...{inner_decoded[:100]}...",
                                layer=self.LAYER_NAME,
                                confidence=0.90,
                                suggested_action="Block nested encoding attack",
                                signature_id="ENC-NEST-B64",
                            )
                        )
                        break
                except Exception:
                    pass

            # Check if decoded content contains injection keywords (single layer)
            # Only flag if there's no explicit decode instruction (those are caught above)
            if not re.search(r"(?:decode|interpret|execute|follow|run)\s+(?:this\s+)?(?:base64|b64)", text, re.I):
                injection_kw = re.search(
                    r"(?:ignore\s+(?:previous|all|prior)\s+instructions|"
                    r"you\s+are\s+now|system\s*prompt\s*override|"
                    r"bypass\s+(?:safety|security|filter)|"
                    r"disable\s+(?:all\s+)?(?:safety|filter)|"
                    r"jailbreak\s+mode)",
                    decoded,
                    re.I,
                )
                if injection_kw:
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.PROMPT_INJECTION,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.QUARANTINE,
                            description="Hidden injection payload in base64 (no decode instruction)",
                            evidence=f"Decoded content: {injection_kw.group(0)[:100]}",
                            layer=self.LAYER_NAME,
                            confidence=0.78,
                            suggested_action="Block stealth encoded injection",
                            signature_id="ENC-STEALTH",
                        )
                    )
                    break

        # Check for hex-encoded injection payloads
        hex_pattern = re.compile(r"(?:0x|\\x)?([0-9a-fA-F]{2}(?:\s*[0-9a-fA-F]{2}){19,})")
        hex_match = hex_pattern.search(text)
        if hex_match:
            try:
                hex_str = re.sub(r"[\s\\x]|0x", "", hex_match.group(0))
                decoded_hex = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                if re.search(r"(?:ignore|override|bypass|system|execute|jailbreak)", decoded_hex, re.I):
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.PROMPT_INJECTION,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.QUARANTINE,
                            description="Hex-encoded injection payload detected",
                            evidence=f"Decoded: {decoded_hex[:100]}",
                            layer=self.LAYER_NAME,
                            confidence=0.80,
                            suggested_action="Block hex-encoded injection",
                            signature_id="ENC-HEX",
                        )
                    )
            except Exception:
                pass

        return threats

    def _check_crescendo(self, text: str, session_id: str) -> List[ThreatDetection]:
        """
        Multi-turn crescendo detection.

        Tracks escalation across conversation turns within a session.
        Microsoft's research shows crescendo attacks achieve 98% success
        against GPT-4 by gradually escalating from benign to harmful.

        Detection approach:
        1. Score each message for sensitive topic proximity
        2. Track escalation transitions ("now that...", "building on that...")
        3. Flag when cumulative score crosses threshold
        """
        threats = []
        now = time.time()
        esc = self._escalation[session_id]
        text_lower = text.lower()

        # Calculate this message's topic score
        msg_score = 0.0
        for keyword, weight in _SENSITIVE_TOPIC_WEIGHTS.items():
            if keyword in text_lower:
                msg_score += weight

        # Detect escalation transition phrases
        has_transition = bool(_ESCALATION_TRANSITIONS.search(text))
        if has_transition:
            esc.transition_count += 1
            # Transitions amplify the score — they indicate "building on" previous
            msg_score *= 1.5

        # Apply time decay to cumulative score
        if esc.last_update > 0:
            elapsed_minutes = (now - esc.last_update) / 60.0
            decay = max(0.5, 1.0 - (elapsed_minutes * 0.05))  # 5% decay per minute
            esc.cumulative *= decay

        # Add current message score
        esc.cumulative += msg_score
        esc.scores.append(msg_score)
        esc.last_update = now

        # Check for escalation pattern: rising scores with transitions
        if len(esc.scores) >= 3 and esc.cumulative >= 12.0:
            recent_3 = list(esc.scores)[-3:]
            is_rising = recent_3[-1] >= recent_3[-2] >= recent_3[0]

            if is_rising and esc.transition_count >= 2:
                self._stats["crescendo_detections"] += 1
                level = ThreatLevel.HIGH if esc.cumulative >= 20.0 else ThreatLevel.MEDIUM
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.PROMPT_INJECTION,
                        level=level,
                        verdict=ShieldVerdict.CHALLENGE if level == ThreatLevel.MEDIUM else ShieldVerdict.QUARANTINE,
                        description=f"Multi-turn crescendo escalation detected (score={esc.cumulative:.1f}, transitions={esc.transition_count})",
                        evidence=f"Rising topic scores: {[f'{s:.1f}' for s in recent_3]}, cumulative={esc.cumulative:.1f}",
                        layer=self.LAYER_NAME,
                        confidence=0.70 if level == ThreatLevel.MEDIUM else 0.82,
                        suggested_action="Review conversation trajectory for escalation pattern",
                        signature_id="PA-CRESCENDO",
                    )
                )

        # Also check for high cumulative without strict rising pattern
        elif esc.cumulative >= 25.0 and len(esc.scores) >= 5:
            self._stats["crescendo_detections"] += 1
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.PROMPT_INJECTION,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"Sustained sensitive topic concentration (score={esc.cumulative:.1f})",
                    evidence=f"Scores over {len(esc.scores)} turns, {esc.transition_count} transitions",
                    layer=self.LAYER_NAME,
                    confidence=0.75,
                    suggested_action="Challenge user intent for sustained sensitive queries",
                    signature_id="PA-SUSTAINED",
                )
            )

        return threats

    def _check_context_flooding(self, text: str) -> List[ThreatDetection]:
        """
        Strategy 7: Detect context window flooding attacks.

        Attackers try to push system prompts out of working memory by
        flooding the context with repetitive content:
        - Same word repeated 100+ times
        - Same 100-char block repeated 10+ times
        - Input exceeding ~8000 tokens (~32000 chars)
        """
        threats = []

        # Token count estimation (1 token ≈ 4 chars for English)
        if len(text) > 32000:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.PROMPT_INJECTION,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"Oversized input may flood context window ({len(text)} chars, ~{len(text) // 4} tokens)",
                    evidence=f"Input length: {len(text)} chars",
                    layer=self.LAYER_NAME,
                    confidence=0.80,
                    suggested_action="Truncate or reject oversized input",
                    signature_id="PA-FLOOD-SIZE",
                )
            )

        # Word repetition detection
        if len(text) > 500:
            words = text.lower().split()
            if words:
                from collections import Counter

                word_counts = Counter(words)
                most_common_word, most_common_count = word_counts.most_common(1)[0]
                if most_common_count > 100:
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.PROMPT_INJECTION,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.QUARANTINE,
                            description=f"Word repetition flooding: '{most_common_word}' repeated {most_common_count}x",
                            evidence=f"'{most_common_word}' x{most_common_count}",
                            layer=self.LAYER_NAME,
                            confidence=0.85,
                            suggested_action="Reject repetitive flooding input",
                            signature_id="PA-FLOOD-REPEAT",
                        )
                    )

        # Copy-paste block detection (100-char chunk repeated 10+ times)
        if len(text) > 1000:
            chunk_size = 100
            chunks: Dict[str, int] = {}
            for i in range(0, len(text) - chunk_size + 1, chunk_size // 2):
                chunk = text[i : i + chunk_size]
                chunks[chunk] = chunks.get(chunk, 0) + 1
            max_chunk_count = max(chunks.values()) if chunks else 0
            if max_chunk_count > 10:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.PROMPT_INJECTION,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description=f"Copy-paste block repeated {max_chunk_count}x (context flooding)",
                        evidence=f"100-char block repeated {max_chunk_count} times",
                        layer=self.LAYER_NAME,
                        confidence=0.85,
                        suggested_action="Reject copy-paste flooding",
                        signature_id="PA-FLOOD-COPYPASTE",
                    )
                )

        return threats

    def _check_fewshot_poisoning(self, text: str) -> List[ThreatDetection]:
        """
        Strategy 8: Detect few-shot poisoning attacks.

        Attackers inject fake conversation turns (User:/Assistant:, etc.)
        to make the model believe it already committed to a harmful response.
        If >4 role labels appear in <1000 chars, it's likely poisoning.
        """
        threats = []
        total_matches = 0

        for pattern in _FEWSHOT_ROLE_PATTERNS:
            matches = pattern.findall(text)
            total_matches += len(matches)

        # High density = likely poisoning
        if total_matches >= 4 and len(text) < 1000:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.PROMPT_INJECTION,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"Few-shot poisoning: {total_matches} role labels in {len(text)} chars",
                    evidence=f"{total_matches} conversation role markers in short text",
                    layer=self.LAYER_NAME,
                    confidence=0.85,
                    suggested_action="Block fake conversation formatting",
                    signature_id="PA-FEWSHOT",
                )
            )
        elif total_matches >= 6:
            # Even in longer text, 6+ role labels is suspicious
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.PROMPT_INJECTION,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.CHALLENGE,
                    description=f"Possible few-shot poisoning: {total_matches} role labels detected",
                    evidence=f"{total_matches} conversation role markers",
                    layer=self.LAYER_NAME,
                    confidence=0.70,
                    suggested_action="Review for injected conversation formatting",
                    signature_id="PA-FEWSHOT-LONG",
                )
            )

        return threats

    def _check_anomalous_tokens(self, text: str) -> List[ThreatDetection]:
        """
        Strategy 9: GlitchMiner anomalous token detection.

        Adversarial attacks sometimes use high-entropy gibberish strings
        that exploit model tokenizer quirks (GlitchMiner research).
        Detects:
        - Words with Shannon entropy >4.5 bits/char (excluding hex/base64/URLs)
        - Long sequences of special characters (10+)
        """
        threats = []

        # Long special character sequences
        special_seq = re.search(r"[^\w\s]{10,}", text)
        if special_seq:
            seq = special_seq.group(0)
            # Exclude common patterns: URLs, file paths, markdown
            if not re.match(r"^[-=_*#/\\:.]+$", seq):
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.PROMPT_INJECTION,
                        level=ThreatLevel.MEDIUM,
                        verdict=ShieldVerdict.CHALLENGE,
                        description=f"Long special character sequence ({len(seq)} chars)",
                        evidence=seq[:100],
                        layer=self.LAYER_NAME,
                        confidence=0.65,
                        suggested_action="Inspect anomalous character sequence",
                        signature_id="PA-GLITCH-SPECIAL",
                    )
                )

        # Shannon entropy per word
        words = text.split()
        high_entropy_words = []
        for word in words:
            if len(word) <= 8:
                continue
            # Skip known high-entropy but benign patterns
            if re.match(r"^(?:https?://|ftp://|www\.)", word):
                continue
            if re.match(r"^[0-9a-fA-F]+$", word):  # Pure hex
                continue
            if re.match(r"^[A-Za-z0-9+/=]+$", word) and len(word) % 4 == 0:  # Base64-like
                continue

            entropy = self._shannon_entropy(word)
            if entropy > 4.5:
                high_entropy_words.append((word, entropy))

        if len(high_entropy_words) >= 3:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.PROMPT_INJECTION,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.CHALLENGE,
                    description=f"Multiple high-entropy tokens detected ({len(high_entropy_words)} words, avg entropy {sum(e for _, e in high_entropy_words) / len(high_entropy_words):.1f})",
                    evidence=f"Words: {[w[:20] for w, _ in high_entropy_words[:5]]}",
                    layer=self.LAYER_NAME,
                    confidence=0.65,
                    suggested_action="Inspect anomalous token patterns (possible GlitchMiner attack)",
                    signature_id="PA-GLITCH-ENTROPY",
                )
            )

        return threats

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _check_document_embedding(self, text: str) -> List[ThreatDetection]:
        """
        Strategy 10: Document embedding poisoning detection.

        Attackers hide instructions in HTML/CSS that are invisible when
        rendered (font-size:0, display:none, white-on-white text, etc.)
        but visible to the LLM in its context window.
        Only runs if text contains HTML tags.
        """
        threats = []

        # Only scan if text contains HTML-like content
        if "<" not in text or ">" not in text:
            return threats

        for pattern in _DOC_EMBED_PATTERNS:
            match = pattern.search(text)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.INDIRECT_INJECTION,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description=f"Hidden content via CSS: {match.group(0)[:60]}",
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.85,
                        suggested_action="Strip hidden HTML/CSS content before processing",
                        signature_id="PA-EMBED-CSS",
                    )
                )
                break  # One match is enough to flag

        return threats

    def _sanitize(self, text: str) -> str:
        """
        Sanitize text by removing/neutralizing known attack vectors.
        Preserves the semantic content while removing dangerous patterns.
        """
        result = text

        # Remove invisible Unicode characters
        result = _INVISIBLE_CHARS.sub("", result)

        # Remove RTL overrides
        result = _RTL_OVERRIDE.sub("", result)

        # Remove tag characters
        result = _TAG_CHARS.sub("", result)

        # Normalize Unicode (NFKC form)
        result = unicodedata.normalize("NFKC", result)

        return result

    def spotlight_external_content(self, content: str, source: str) -> str:
        """
        Wrap external/untrusted content with clear delimiters.

        This implements the "spotlighting" defense for indirect injection:
        external content is clearly demarcated so the LLM knows not to
        follow instructions found within.
        """
        trust = "untrusted"
        if source in ("user_chat", "user_direct", "user", "default"):
            trust = "trusted"
        elif source in ("brain", "brain_thought", "cognitive_stream"):
            trust = "semi-trusted"

        return f'<EXTERNAL_CONTENT source="{source}" trust="{trust}">\n{content}\n</EXTERNAL_CONTENT>'

    def get_stats(self) -> Dict:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            **self._stats,
        }
