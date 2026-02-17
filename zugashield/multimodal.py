"""
ZugaShield - Multimodal Security (Gap 6)
=========================================

Image-based injection detection:
- EXIF metadata injection (comments, description fields)
- Suspicious alt-text containing injection keywords
- 1x1 pixel steganography detection
- OCR text scanning for injection patterns

Pillow is optional — degrades gracefully if not installed.
"""

from __future__ import annotations

import logging
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

# Optional Pillow import
try:
    from PIL import Image

    _HAS_PILLOW = True
except ImportError:
    Image = None
    _HAS_PILLOW = False

logger = logging.getLogger(__name__)

# Injection keywords in image metadata/alt-text
_INJECTION_KEYWORDS = re.compile(
    r"(?:ignore|override|bypass|disable)\s+(?:all\s+)?(?:previous|prior|safety|security|filter|restriction|instruction)",
    re.I,
)
_ROLE_HIJACK = re.compile(
    r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|switch\s+to)\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|evil|DAN)",
    re.I,
)
_SYSTEM_OVERRIDE = re.compile(
    r"(?:system|admin|root)\s*(?:prompt|instruction|command)\s*[:=]",
    re.I,
)


class MultimodalScanner:
    """
    Scans images for injection payloads in metadata and visual content.
    """

    LAYER_NAME = "multimodal"

    def __init__(self, config: ShieldConfig, catalog: ThreatCatalog) -> None:
        self._config = config
        self._catalog = catalog
        self._stats = {"checks": 0, "detections": 0}

    async def check_image(
        self,
        image_path: Optional[str] = None,
        alt_text: Optional[str] = None,
        ocr_text: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ShieldDecision:
        """
        Scan an image for injection payloads.

        Args:
            image_path: Path to image file (optional, requires Pillow)
            alt_text: Alt text / description of the image
            ocr_text: Pre-extracted OCR text from the image
            metadata: Pre-extracted EXIF/metadata dict
        """
        start = time.perf_counter()
        self._stats["checks"] += 1
        threats: List[ThreatDetection] = []

        # Degradation mode (Fix #8): handle missing Pillow
        degradation = getattr(self._config, "multimodal_degradation_mode", "warn")
        if image_path and not _HAS_PILLOW:
            if degradation == "block":
                return ShieldDecision(
                    verdict=ShieldVerdict.CHALLENGE,
                    threats_detected=[
                        ThreatDetection(
                            category=ThreatCategory.INDIRECT_INJECTION,
                            level=ThreatLevel.MEDIUM,
                            verdict=ShieldVerdict.CHALLENGE,
                            description="Image scanning unavailable (Pillow not installed) — degradation_mode=block",
                            evidence="pip install zugashield[image]",
                            layer=self.LAYER_NAME,
                            confidence=0.5,
                            suggested_action="Install Pillow for image scanning",
                            signature_id="MM-DEGRADE",
                        )
                    ],
                    layer=self.LAYER_NAME,
                    elapsed_ms=(time.perf_counter() - start) * 1000,
                )
            elif degradation == "warn":
                logger.warning("[Multimodal] Pillow not installed, skipping image file scan")

        # Check EXIF / metadata
        if image_path and _HAS_PILLOW:
            meta_threats = self._check_image_metadata(image_path)
            threats.extend(meta_threats)
        elif metadata:
            # Check pre-extracted metadata
            meta_threats = self._check_metadata_dict(metadata)
            threats.extend(meta_threats)

        # Check alt text
        if alt_text:
            alt_threats = self._check_text_for_injection(alt_text, "alt_text")
            threats.extend(alt_threats)

        # Check OCR text
        if ocr_text:
            ocr_threats = self._check_text_for_injection(ocr_text, "ocr_text")
            threats.extend(ocr_threats)

        # Check for 1x1 pixel (steganography carrier)
        if image_path and _HAS_PILLOW:
            steg_threat = self._check_steganography(image_path)
            if steg_threat:
                threats.append(steg_threat)

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        self._stats["detections"] += len(threats)
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

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    def _check_image_metadata(self, image_path: str) -> List[ThreatDetection]:
        """Extract and scan EXIF/metadata from image file."""
        threats = []
        try:
            img = Image.open(image_path)
            exif_data = img.info or {}

            # Check all string metadata fields
            for key, value in exif_data.items():
                if isinstance(value, str):
                    field_threats = self._check_text_for_injection(value, f"exif:{key}")
                    threats.extend(field_threats)

            # Check EXIF specifically
            if hasattr(img, "_getexif") and img._getexif():
                for tag_id, value in img._getexif().items():
                    if isinstance(value, str):
                        field_threats = self._check_text_for_injection(value, f"exif_tag:{tag_id}")
                        threats.extend(field_threats)

            img.close()
        except Exception as e:
            logger.debug("[Multimodal] Failed to read image metadata: %s", e)
        return threats

    def _check_metadata_dict(self, metadata: Dict[str, Any]) -> List[ThreatDetection]:
        """Scan pre-extracted metadata dict for injection."""
        threats = []
        for key, value in metadata.items():
            if isinstance(value, str):
                field_threats = self._check_text_for_injection(value, f"meta:{key}")
                threats.extend(field_threats)
        return threats

    def _check_text_for_injection(self, text: str, source: str) -> List[ThreatDetection]:
        """Check text content for injection patterns."""
        threats = []

        for pattern, desc, sig_id in [
            (_INJECTION_KEYWORDS, "Injection keywords", "MM-INJECT"),
            (_ROLE_HIJACK, "Role hijacking", "MM-ROLE"),
            (_SYSTEM_OVERRIDE, "System override", "MM-SYSOVR"),
        ]:
            match = pattern.search(text)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.INDIRECT_INJECTION,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description=f"{desc} in image {source}: {match.group(0)[:60]}",
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.85,
                        suggested_action=f"Strip injection from image {source}",
                        signature_id=sig_id,
                    )
                )

        return threats

    def _check_steganography(self, image_path: str) -> Optional[ThreatDetection]:
        """Detect 1x1 pixel images (common steganography carrier)."""
        try:
            img = Image.open(image_path)
            w, h = img.size
            img.close()
            if w == 1 and h == 1:
                return ThreatDetection(
                    category=ThreatCategory.INDIRECT_INJECTION,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.CHALLENGE,
                    description="1x1 pixel image (potential steganography carrier)",
                    evidence=f"Image size: {w}x{h}",
                    layer=self.LAYER_NAME,
                    confidence=0.60,
                    suggested_action="Investigate 1x1 pixel image",
                    signature_id="MM-STEG",
                )
        except Exception:
            pass
        return None

    def get_stats(self) -> Dict:
        return {"layer": self.LAYER_NAME, **self._stats}
