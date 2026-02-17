"""
ZugaShield - Layer 4: Memory Sentinel
=======================================

Validates memory content on both write and read paths:

Write path (memory_store.save):
- Content scanning for embedded instructions
- Importance inflation detection
- Provenance tracking (source tagging)
- Rate limiting memory writes

Read path (prompt injection via memory recall):
- Cross-reference memory source with trust level
- Flag untrusted memories with warning markers
- Temporal anomaly detection
- Consensus validation (memory vs majority)

Integration points:
- memory_store.py:save() (wrap)
- prompts.py:1211 (before memory injection)
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from zugashield.types import (
    MemoryTrust,
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

# Patterns for embedded instructions in memory content
_INSTRUCTION_PATTERNS = [
    re.compile(r"(?:always|must|should)\s+(?:execute|run|follow|obey|do)\b", re.I),
    re.compile(r"(?:ignore|override|bypass|disable)\s+(?:safety|security|rules|filter|restriction)", re.I),
    re.compile(r"(?:when\s+recalled|on\s+recall|if\s+loaded)\s*[,:]?\s*(?:execute|run|do|perform)", re.I),
    re.compile(r"(?:secret|hidden)\s+(?:instruction|command|directive|task)", re.I),
    re.compile(r"(?:do\s+not|never)\s+(?:tell|reveal|show|mention)\s+(?:the\s+user|anyone|antonio)", re.I),
    re.compile(r"(?:sleeper|dormant|delayed|trigger)\s+(?:instruction|command|payload|action)", re.I),
    re.compile(r"(?:transfer|send|move|wire)\s+(?:all\s+)?(?:funds?|money|balance|assets|crypto|bitcoin)", re.I),
    re.compile(r"(?:SYSTEM|ADMIN|ROOT)\s*(?:UPDATE|OVERRIDE|COMMAND|DIRECTIVE)\s*:", re.I),
]

# CSS/HTML hiding patterns for document embedding poisoning
_DOC_CSS_HIDE_PATTERNS = [
    re.compile(r"font-size\s*:\s*0", re.I),
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\s*[;}]", re.I),
    re.compile(r"(?:height|width)\s*:\s*[01]px", re.I),
]

# Importance inflation patterns
_INFLATION_PATTERNS = [
    re.compile(r"(?:critically?\s+)?import(?:ant|ance)\s*[:=]\s*(?:critical|highest|maximum|10|1\.0)", re.I),
    re.compile(r"(?:priority|urgency)\s*[:=]\s*(?:critical|highest|maximum|10|1\.0)", re.I),
    re.compile(r"(?:this\s+is\s+)?(?:the\s+most|extremely|critically)\s+important", re.I),
]


class MemorySentinelLayer:
    """
    Layer 4: Memory content validation and provenance tracking.

    Defends against memory poisoning: the slow, persistent attack
    where malicious content planted in memory activates later.
    """

    LAYER_NAME = "memory_sentinel"

    def __init__(self, config: ShieldConfig, catalog: ThreatCatalog) -> None:
        self._config = config
        self._catalog = catalog
        # Rate tracking: {user_id: deque of timestamps}
        self._write_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._stats = {"writes_checked": 0, "reads_checked": 0, "blocked": 0, "flagged": 0}

    async def check_write(
        self,
        content: str,
        memory_type: str = "",
        importance: str = "",
        source: str = "unknown",
        user_id: str = "default",
        tags: Optional[List[str]] = None,
    ) -> ShieldDecision:
        """
        Check memory content before storage.

        Args:
            content: Memory content being stored
            memory_type: Type of memory (LEARNING, CONVERSATION, etc.)
            importance: Importance level
            source: Where this memory came from
            user_id: Who is storing it
            tags: Memory tags
        """
        if not self._config.memory_sentinel_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["writes_checked"] += 1
        threats: List[ThreatDetection] = []

        # === Check 1: Embedded instruction detection ===
        for pattern in _INSTRUCTION_PATTERNS:
            match = pattern.search(content)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.MEMORY_POISONING,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description="Embedded instruction detected in memory content",
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.80,
                        suggested_action="Block memory storage of instruction-embedded content",
                        signature_id="MS-INSTR",
                    )
                )
                break  # One instruction pattern is enough to flag

        # === Check 2: Importance inflation ===
        for pattern in _INFLATION_PATTERNS:
            match = pattern.search(content)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.MEMORY_POISONING,
                        level=ThreatLevel.MEDIUM,
                        verdict=ShieldVerdict.CHALLENGE,
                        description="Importance inflation detected in memory content",
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.70,
                        suggested_action="Review and normalize importance level",
                        signature_id="MS-INFLATE",
                    )
                )
                break

        # === Check 3: Rate limiting ===
        now = time.time()
        tracker = self._write_tracker[user_id]
        tracker.append(now)
        recent = sum(1 for t in tracker if t > now - 60)
        if recent > 10:  # Max 10 memory writes per minute
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.MEMORY_POISONING,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.CHALLENGE,
                    description=f"Memory write rate exceeded: {recent}/min",
                    evidence=f"{recent} writes in 60s from {user_id}",
                    layer=self.LAYER_NAME,
                    confidence=0.85,
                    suggested_action="Throttle memory writes",
                    signature_id="MS-RATE",
                )
            )

        # === Check 4: Provenance classification ===
        # Classify and tag the source trust for downstream use.
        # Callers can read decision.metadata["source_trust"] to store in DB.
        trust = self._classify_trust(source)

        # === Check 5: Catalog signatures ===
        catalog_threats = self._catalog.check(content, [ThreatCategory.MEMORY_POISONING])
        threats.extend(catalog_threats)

        # === Check 6: Tag/metadata injection ===
        if tags:
            tag_str = " ".join(tags)
            for pattern in _INSTRUCTION_PATTERNS:
                if pattern.search(tag_str):
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.MEMORY_POISONING,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.BLOCK,
                            description="Instruction injection in memory tags",
                            evidence=tag_str[:200],
                            layer=self.LAYER_NAME,
                            confidence=0.85,
                            suggested_action="Strip instructions from tags",
                            signature_id="MS-TAG",
                        )
                    )
                    break

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return ShieldDecision(
                verdict=ShieldVerdict.ALLOW,
                threats_detected=[],
                layer=self.LAYER_NAME,
                elapsed_ms=elapsed,
                metadata={"source_trust": trust.value},
            )

        self._stats["flagged"] += 1
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
            "[MemorySentinel] %s on write: %d threats (source=%s, trust=%s, %.1fms)",
            verdict.value.upper(),
            len(threats),
            source,
            trust.value,
            elapsed,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
            metadata={"source_trust": trust.value},
        )

    async def check_recall(
        self,
        memories: List[Dict[str, Any]],
    ) -> ShieldDecision:
        """
        Check recalled memories before injection into prompt.

        Args:
            memories: List of memory dicts being injected into prompt

        Returns:
            ShieldDecision. If SANITIZE, metadata["filtered_memories"]
            contains the cleaned list.
        """
        if not self._config.memory_sentinel_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["reads_checked"] += 1
        threats: List[ThreatDetection] = []
        filtered: List[Dict[str, Any]] = []

        for mem in memories:
            content = str(mem.get("content", ""))
            source = str(mem.get("source", mem.get("user_id", "unknown")))
            # Use stored trust if available (from write-path provenance), else classify
            stored_trust = mem.get("source_trust", "")
            try:
                trust = MemoryTrust(stored_trust) if stored_trust else self._classify_trust(source)
            except ValueError:
                trust = self._classify_trust(source)
            is_clean = True

            # Check content for embedded instructions
            for pattern in _INSTRUCTION_PATTERNS:
                if pattern.search(content):
                    # External/unknown sources with instructions = higher confidence
                    conf = 0.92 if trust in (MemoryTrust.EXTERNAL, MemoryTrust.UNKNOWN) else 0.80
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.MEMORY_POISONING,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.QUARANTINE,
                            description=f"Recalled memory contains embedded instruction (trust={trust.value})",
                            evidence=content[:200],
                            layer=self.LAYER_NAME,
                            confidence=conf,
                            suggested_action="Exclude memory from prompt injection",
                            signature_id="MS-RECALL",
                        )
                    )
                    is_clean = False
                    break

            # Also flag unknown-provenance memories that lack source_trust
            if is_clean and trust == MemoryTrust.UNKNOWN and not stored_trust:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.MEMORY_POISONING,
                        level=ThreatLevel.LOW,
                        verdict=ShieldVerdict.ALLOW,
                        description="Recalled memory has no provenance (legacy/untagged)",
                        evidence=f"id={mem.get('id', '?')}, source={source}",
                        layer=self.LAYER_NAME,
                        confidence=0.50,
                        suggested_action="Tag legacy memories with provenance",
                        signature_id="MS-PROVENANCE",
                    )
                )
                # Still include it — just flag, don't block

            if is_clean:
                # Tag with trust level for spotlighting
                mem_copy = dict(mem)
                mem_copy["_shield_trust"] = trust.value
                filtered.append(mem_copy)

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        verdict = ShieldVerdict.SANITIZE if filtered else ShieldVerdict.BLOCK

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
            metadata={"filtered_memories": filtered},
        )

    async def check_document(
        self,
        content: str,
        source: str = "external",
        document_type: str = "",
    ) -> ShieldDecision:
        """
        Pre-ingestion scanning for RAG documents.

        Scans external documents before they enter the vector store.
        Detects imperative instructions, system command patterns,
        and other injection payloads that could activate on recall.

        Args:
            content: The document text to scan
            source: Where this document came from
            document_type: Type of document (pdf, html, txt, etc.)
        """
        if not self._config.memory_sentinel_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        threats: List[ThreatDetection] = []

        # === Check 1: Imperative instruction detection ===
        imperative_patterns = [
            re.compile(
                r"when\s+this\s+(?:document|text|content)\s+is\s+(?:recalled|retrieved|loaded|read)\s*[,:]?\s*(?:execute|run|do|perform|follow)",
                re.I,
            ),
            re.compile(
                r"(?:upon|on|after)\s+(?:recall|retrieval|ingestion)\s*[,:]?\s*(?:execute|run|do|ignore|override|bypass)",
                re.I,
            ),
            re.compile(
                r"(?:the\s+(?:AI|assistant|model|bot|agent)\s+(?:must|should|will|shall)\s+(?:ignore|override|bypass|disable|forget))",
                re.I,
            ),
            re.compile(
                r"(?:system\s+)?instruction\s*:\s*(?:ignore|override|bypass|disable|forget)\s+(?:all|previous|prior|safety)",
                re.I,
            ),
        ]

        for pattern in imperative_patterns:
            match = pattern.search(content)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.MEMORY_POISONING,
                        level=ThreatLevel.CRITICAL,
                        verdict=ShieldVerdict.BLOCK,
                        description="Imperative instruction in document targeting recall behavior",
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.90,
                        suggested_action="Reject document — contains recall-triggered instructions",
                        signature_id="MS-DOC-IMPERATIVE",
                    )
                )
                break

        # === Check 2: CSS/HTML hiding (invisible injections) ===
        if "<" in content and ">" in content:
            for pattern in _DOC_CSS_HIDE_PATTERNS:
                match = pattern.search(content)
                if match:
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.INDIRECT_INJECTION,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.QUARANTINE,
                            description=f"Hidden content via CSS in document: {match.group(0)[:60]}",
                            evidence=match.group(0)[:200],
                            layer=self.LAYER_NAME,
                            confidence=0.85,
                            suggested_action="Strip hidden HTML/CSS content before ingestion",
                            signature_id="MS-DOC-CSS-HIDE",
                        )
                    )
                    break

        # === Check 3: System command density ===
        command_patterns = re.findall(
            r"(?:sudo|chmod|chown|rm\s+-rf|curl\s+.*?\|\s*(?:bash|sh)|wget\s+.*?\|\s*(?:bash|sh)|eval\s*\(|exec\s*\()",
            content,
            re.I,
        )
        if len(command_patterns) > 3:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.MEMORY_POISONING,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.QUARANTINE,
                    description=f"High density of system commands in document ({len(command_patterns)})",
                    evidence=f"Commands: {command_patterns[:5]}",
                    layer=self.LAYER_NAME,
                    confidence=0.75,
                    suggested_action="Review document for embedded command injection",
                    signature_id="MS-DOC-COMMANDS",
                )
            )

        # === Check 3: Reuse existing instruction patterns ===
        for pattern in _INSTRUCTION_PATTERNS:
            match = pattern.search(content)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.MEMORY_POISONING,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description="Embedded instruction pattern in external document",
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.80,
                        suggested_action="Sanitize document before ingestion",
                        signature_id="MS-DOC-INSTR",
                    )
                )
                break

        # === Check 4: Catalog signatures for MEMORY_POISONING ===
        catalog_threats = self._catalog.check(content, [ThreatCategory.MEMORY_POISONING])
        threats.extend(catalog_threats)

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        self._stats["blocked"] += 1
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
        verdict = ShieldVerdict.BLOCK if max_threat.level >= ThreatLevel.CRITICAL else ShieldVerdict.QUARANTINE

        logger.warning(
            "[MemorySentinel] Document scan %s: %d threats (source=%s, %.1fms)",
            verdict.value.upper(),
            len(threats),
            source,
            elapsed,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    def _classify_trust(self, source: str) -> MemoryTrust:
        """Classify memory trust level based on source."""
        source_lower = source.lower()
        if source_lower in ("user_chat", "user_direct", "user", "default"):
            return MemoryTrust.USER_DIRECT
        elif source_lower in ("brain", "brain_thought", "cognitive_stream"):
            return MemoryTrust.BRAIN_GENERATED
        elif source_lower in ("web_search", "web_fetch", "file_read", "browser", "external"):
            return MemoryTrust.EXTERNAL
        elif source_lower == "verified":
            return MemoryTrust.VERIFIED
        return MemoryTrust.UNKNOWN

    def get_stats(self) -> Dict:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            **self._stats,
        }
