"""
ZugaShield - Threat Catalog
============================

Curated, versioned signature database for AI agent threats.
Modeled after uBlock Origin's filter list approach:
- Signatures stored as JSON files for easy updates
- Pre-compiled regex patterns for fast matching (~1ms)
- Organized by threat category
- Versioned with update tracking

Usage:
    catalog = ThreatCatalog()
    catalog.load_signatures_dir("backend/core/safety/shield/signatures")
    detections = catalog.check("ignore previous instructions", [ThreatCategory.PROMPT_INJECTION])
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from zugashield.types import (
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ShieldVerdict,
)

logger = logging.getLogger(__name__)

# Map category names in JSON to ThreatCategory enum
_CATEGORY_MAP: Dict[str, ThreatCategory] = {
    "prompt_injection": ThreatCategory.PROMPT_INJECTION,
    "indirect_injection": ThreatCategory.INDIRECT_INJECTION,
    "ascii_art_bypass": ThreatCategory.ASCII_ART_BYPASS,
    "ascii_art": ThreatCategory.ASCII_ART_BYPASS,  # Alias for JSON files
    "unicode_smuggling": ThreatCategory.UNICODE_SMUGGLING,
    "memory_poisoning": ThreatCategory.MEMORY_POISONING,
    "tool_exploitation": ThreatCategory.TOOL_EXPLOITATION,
    "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "exfiltration": ThreatCategory.DATA_EXFILTRATION,  # Alias for JSON files
    "privilege_escalation": ThreatCategory.PRIVILEGE_ESCALATION,
    "chain_attack": ThreatCategory.CHAIN_ATTACK,
    "wallet_attack": ThreatCategory.WALLET_ATTACK,
    "wallet_attacks": ThreatCategory.WALLET_ATTACK,  # Alias for JSON files
    "behavioral_anomaly": ThreatCategory.BEHAVIORAL_ANOMALY,
}

_LEVEL_MAP: Dict[str, ThreatLevel] = {
    "low": ThreatLevel.LOW,
    "medium": ThreatLevel.MEDIUM,
    "high": ThreatLevel.HIGH,
    "critical": ThreatLevel.CRITICAL,
}


@dataclass
class ThreatSignature:
    """A single threat detection signature with compiled regex patterns."""

    id: str
    category: ThreatCategory
    name: str
    description: str
    patterns: List[str]
    severity: ThreatLevel
    confidence: float = 0.8
    false_positive_rate: float = 0.01
    references: List[str] = field(default_factory=list)
    enabled: bool = True
    _compiled: List[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        """Compile regex patterns on creation for fast matching."""
        self._compiled = []
        for p in self.patterns:
            try:
                self._compiled.append(re.compile(p, re.IGNORECASE | re.DOTALL))
            except re.error as e:
                logger.warning("[ThreatCatalog] Invalid regex in %s: %s (%s)", self.id, p, e)

    def check(self, text: str) -> Optional[Tuple[str, str]]:
        """
        Check text against all compiled patterns.

        Returns:
            (matched_pattern, matched_text) or None if no match.
        """
        if not self.enabled:
            return None
        for i, compiled in enumerate(self._compiled):
            match = compiled.search(text)
            if match:
                return (self.patterns[i], match.group(0)[:200])
        return None


class ThreatCatalog:
    """
    Curated threat signature database.

    Loads signatures from JSON files, compiles them, and provides
    fast pattern matching against input text.
    """

    def __init__(self) -> None:
        self._signatures: Dict[ThreatCategory, List[ThreatSignature]] = {
            cat: [] for cat in ThreatCategory
        }
        self._version: str = "0.0.0"
        self._last_updated: Optional[datetime] = None
        self._total_signatures: int = 0
        self._load_default_signatures()

    def _load_default_signatures(self) -> None:
        """Load signatures from the default signatures directory."""
        sig_dir = Path(__file__).parent / "signatures"
        if sig_dir.exists():
            self.load_signatures_dir(str(sig_dir))

    def load_signatures_dir(self, dir_path: str) -> int:
        """
        Load all JSON signature files from a directory.

        Returns:
            Number of signatures loaded.
        """
        loaded = 0
        dir_path = Path(dir_path)

        if not dir_path.exists():
            logger.warning("[ThreatCatalog] Signatures dir not found: %s", dir_path)
            return 0

        # Load version info if present
        version_file = dir_path / "catalog_version.json"
        if version_file.exists():
            try:
                with open(version_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                self._version = meta.get("version", self._version)
                self._last_updated = datetime.fromisoformat(meta["last_updated"]) if "last_updated" in meta else None
            except Exception as e:
                logger.warning("[ThreatCatalog] Failed to read version file: %s", e)

        # Load each category file
        for json_file in sorted(dir_path.glob("*.json")):
            if json_file.name == "catalog_version.json":
                continue
            try:
                count = self._load_signature_file(json_file)
                loaded += count
                logger.debug("[ThreatCatalog] Loaded %d signatures from %s", count, json_file.name)
            except Exception as e:
                logger.error("[ThreatCatalog] Failed to load %s: %s", json_file.name, e)

        self._total_signatures = loaded
        logger.info(
            "[ThreatCatalog] Loaded %d signatures (v%s) across %d categories",
            loaded, self._version,
            sum(1 for sigs in self._signatures.values() if sigs),
        )
        return loaded

    def _load_signature_file(self, path: Path) -> int:
        """Load signatures from a single JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        count = 0
        for sig_data in data.get("signatures", []):
            category_str = sig_data.get("category", "")
            category = _CATEGORY_MAP.get(category_str)
            if category is None:
                logger.warning("[ThreatCatalog] Unknown category '%s' in %s", category_str, path.name)
                continue

            severity = _LEVEL_MAP.get(sig_data.get("severity", "medium"), ThreatLevel.MEDIUM)

            sig = ThreatSignature(
                id=sig_data["id"],
                category=category,
                name=sig_data.get("name", sig_data["id"]),
                description=sig_data.get("description", ""),
                patterns=sig_data.get("patterns", []),
                severity=severity,
                confidence=sig_data.get("confidence", 0.8),
                false_positive_rate=sig_data.get("false_positive_rate", 0.01),
                references=sig_data.get("references", []),
                enabled=sig_data.get("enabled", True),
            )
            self._signatures[category].append(sig)
            count += 1

        return count

    def check(
        self,
        text: str,
        categories: Optional[List[ThreatCategory]] = None,
    ) -> List[ThreatDetection]:
        """
        Check text against all signatures in the specified categories.

        Args:
            text: Input text to check
            categories: Categories to check (None = all)

        Returns:
            List of ThreatDetection objects for each match.
        """
        if not text:
            return []

        cats = categories or list(ThreatCategory)
        detections: List[ThreatDetection] = []
        text_lower = text.lower()

        for cat in cats:
            for sig in self._signatures.get(cat, []):
                result = sig.check(text_lower)
                if result:
                    pattern_str, matched_text = result
                    # Map severity to verdict
                    if sig.severity == ThreatLevel.CRITICAL:
                        verdict = ShieldVerdict.BLOCK
                    elif sig.severity == ThreatLevel.HIGH:
                        verdict = ShieldVerdict.QUARANTINE
                    elif sig.severity == ThreatLevel.MEDIUM:
                        verdict = ShieldVerdict.CHALLENGE
                    else:
                        verdict = ShieldVerdict.SANITIZE

                    detections.append(ThreatDetection(
                        category=cat,
                        level=sig.severity,
                        verdict=verdict,
                        description=sig.description,
                        evidence=matched_text[:200],
                        layer="threat_catalog",
                        confidence=sig.confidence,
                        suggested_action=f"Matched signature {sig.id}",
                        signature_id=sig.id,
                    ))

        return detections

    def get_signatures_for_category(self, category: ThreatCategory) -> List[ThreatSignature]:
        """Get all signatures for a category."""
        return self._signatures.get(category, [])

    def get_stats(self) -> Dict:
        """Get catalog statistics."""
        return {
            "version": self._version,
            "last_updated": self._last_updated.isoformat() if self._last_updated else None,
            "total_signatures": self._total_signatures,
            "categories": {
                cat.value: len(sigs) for cat, sigs in self._signatures.items() if sigs
            },
        }
