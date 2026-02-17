"""
ZugaShield - AI Agent Security System
=======================================

7-layer defense system for AI agent threats:

    Layer 1: Perimeter ─── HTTP middleware, request validation
    Layer 2: Prompt Armor ── Injection detection, input sanitization
    Layer 3: Tool Guard ──── Tool execution gating, parameter validation
    Layer 4: Memory Sentinel ── Memory content validation, poison detection
    Layer 5: Exfiltration Guard ── Output DLP, secret detection
    Layer 6: Anomaly Detector ── Behavioral baselines, chain attack detection
    Layer 7: Wallet Fortress ── Transaction approval, address validation

Usage:
    from zugashield import ZugaShield

    shield = ZugaShield()
    decision = await shield.check_prompt("user message", context={})
    if decision.is_blocked:
        return "Blocked by ZugaShield"

Architecture:
    - Modeled after uBlock Origin: curated threat catalog + layered defenses
    - Zero required dependencies - works out of the box
    - Configurable via environment variables (ZUGASHIELD_*)
    - All layers run asynchronously with <15ms total fast-path overhead
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from zugashield.types import (
    AnomalyScore,
    MemoryTrust,
    ShieldDecision,
    ShieldVerdict,
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ToolPolicy,
    allow_decision,
    block_decision,
)
from zugashield.config import ShieldConfig
from zugashield.threat_catalog import ThreatCatalog
from zugashield.audit import ShieldAuditLogger

from zugashield.layers.perimeter import PerimeterLayer
from zugashield.layers.prompt_armor import PromptArmorLayer
from zugashield.layers.tool_guard import ToolGuardLayer
from zugashield.layers.memory_sentinel import MemorySentinelLayer
from zugashield.layers.exfiltration_guard import ExfiltrationGuardLayer
from zugashield.layers.anomaly_detector import AnomalyDetectorLayer
from zugashield.layers.wallet_fortress import WalletFortressLayer
from zugashield.layers.llm_judge import LLMJudgeLayer
from zugashield.multimodal import MultimodalScanner

logger = logging.getLogger(__name__)

# Approval provider interface for Human-in-the-Loop integration
_approval_provider = None


def set_approval_provider(provider: Any) -> None:
    """Set an external approval provider for HIL integration."""
    global _approval_provider
    _approval_provider = provider


def get_approval_provider() -> Any:
    """Get the current approval provider (or None)."""
    return _approval_provider


class ZugaShield:
    """
    Main facade for the ZugaShield security system.

    Provides a clean API for each integration point.
    """

    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        self._config = config or ShieldConfig.from_env()
        self._catalog = ThreatCatalog()
        self._audit = ShieldAuditLogger()

        # Initialize all layers
        self.perimeter = PerimeterLayer(self._config, self._catalog)
        self.prompt_armor = PromptArmorLayer(self._config, self._catalog)
        self.tool_guard = ToolGuardLayer(self._config, self._catalog)
        self.memory_sentinel = MemorySentinelLayer(self._config, self._catalog)
        self.exfiltration_guard = ExfiltrationGuardLayer(self._config, self._catalog)
        self.anomaly_detector = AnomalyDetectorLayer(self._config)
        self.wallet_fortress = WalletFortressLayer(self._config, self._catalog)
        self.multimodal = MultimodalScanner(self._config, self._catalog)
        self.llm_judge = LLMJudgeLayer(self._config)

        logger.info(
            "[ZugaShield] Initialized: %d signatures loaded, %d layers active",
            self._catalog._total_signatures,
            sum(
                [
                    self._config.perimeter_enabled,
                    self._config.prompt_armor_enabled,
                    self._config.tool_guard_enabled,
                    self._config.memory_sentinel_enabled,
                    self._config.exfiltration_guard_enabled,
                    self._config.anomaly_detector_enabled,
                    self._config.wallet_fortress_enabled,
                ]
            ),
        )

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    @property
    def config(self) -> ShieldConfig:
        return self._config

    @property
    def catalog(self) -> ThreatCatalog:
        return self._catalog

    @property
    def audit(self) -> ShieldAuditLogger:
        return self._audit

    # =========================================================================
    # Layer 1: Perimeter (HTTP middleware)
    # =========================================================================

    async def check_request(
        self,
        path: str,
        method: str = "GET",
        content_length: int = 0,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        client_ip: str = "unknown",
    ) -> ShieldDecision:
        """Check an incoming HTTP request (Layer 1)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.perimeter.check(
            path=path,
            method=method,
            content_length=content_length,
            body=body,
            headers=headers,
            client_ip=client_ip,
        )
        self._audit.log(decision, {"path": path, "method": method, "client_ip": client_ip})
        self._feed_anomaly(decision)
        return decision

    # =========================================================================
    # Layer 2: Prompt Armor (injection defense)
    # =========================================================================

    async def check_prompt(
        self,
        user_message: str,
        context: Optional[Dict] = None,
    ) -> ShieldDecision:
        """Check user message for prompt injection (Layer 2)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.prompt_armor.check(user_message, context)

        # Optional LLM judge escalation for ambiguous cases
        if self.llm_judge.should_escalate(decision):
            decision = await self.llm_judge.judge(user_message, decision)

        self._audit.log(decision, {"source": "prompt", **(context or {})})
        self._feed_anomaly(decision)
        return decision

    # =========================================================================
    # Layer 3: Tool Guard (execution gating)
    # =========================================================================

    async def check_tool_call(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session_id: str = "default",
    ) -> ShieldDecision:
        """Check a tool call before execution (Layer 3)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.tool_guard.check(tool_name, params, session_id)
        self._audit.log(decision, {"tool": tool_name, "session_id": session_id})
        self._feed_anomaly(decision, session_id)
        return decision

    # =========================================================================
    # Layer 4: Memory Sentinel (write + read paths)
    # =========================================================================

    async def check_memory_write(
        self,
        content: str,
        memory_type: str = "",
        importance: str = "",
        source: str = "unknown",
        user_id: str = "default",
        tags: Optional[List[str]] = None,
    ) -> ShieldDecision:
        """Check memory content before storage (Layer 4 write)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.memory_sentinel.check_write(
            content=content,
            memory_type=memory_type,
            importance=importance,
            source=source,
            user_id=user_id,
            tags=tags,
        )
        self._audit.log(decision, {"source": source, "memory_type": memory_type})
        self._feed_anomaly(decision)
        return decision

    async def check_memory_recall(
        self,
        memories: List[Dict[str, Any]],
    ) -> ShieldDecision:
        """Check recalled memories before prompt injection (Layer 4 read)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.memory_sentinel.check_recall(memories)
        self._audit.log(decision, {"memory_count": len(memories)})
        return decision

    # =========================================================================
    # Layer 4b: RAG Document Pre-Ingestion Scanning
    # =========================================================================

    async def check_document(
        self,
        content: str,
        source: str = "external",
        document_type: str = "",
    ) -> ShieldDecision:
        """Check an external document before RAG ingestion (Layer 4)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.memory_sentinel.check_document(
            content=content,
            source=source,
            document_type=document_type,
        )
        self._audit.log(decision, {"source": source, "document_type": document_type})
        self._feed_anomaly(decision)
        return decision

    # =========================================================================
    # Layer 5: Exfiltration Guard (output DLP)
    # =========================================================================

    async def check_output(
        self,
        output: str,
        context: Optional[Dict] = None,
    ) -> ShieldDecision:
        """Check LLM response or tool output for data leakage (Layer 5)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.exfiltration_guard.check(output, context)
        self._audit.log(decision, context)
        self._feed_anomaly(decision)
        return decision

    # =========================================================================
    # Multimodal: Image-Based Injection Detection
    # =========================================================================

    async def check_image(
        self,
        image_path: Optional[str] = None,
        alt_text: Optional[str] = None,
        ocr_text: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ShieldDecision:
        """Check an image for injection payloads (multimodal defense)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.multimodal.check_image(
            image_path=image_path,
            alt_text=alt_text,
            ocr_text=ocr_text,
            metadata=metadata,
        )
        self._audit.log(decision, {"source": "image"})
        self._feed_anomaly(decision)
        return decision

    # =========================================================================
    # Layer 7: Wallet Fortress (crypto protection)
    # =========================================================================

    async def check_transaction(
        self,
        tx_type: str = "send",
        to_address: str = "",
        amount: float = 0.0,
        amount_usd: float = 0.0,
        contract_data: Optional[str] = None,
        function_sig: Optional[str] = None,
    ) -> ShieldDecision:
        """Check a wallet transaction (Layer 7)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self.wallet_fortress.check(
            tx_type=tx_type,
            to_address=to_address,
            amount=amount,
            amount_usd=amount_usd,
            contract_data=contract_data,
            function_sig=function_sig,
        )
        self._audit.log(decision, {"tx_type": tx_type, "amount_usd": amount_usd})
        self._feed_anomaly(decision)
        return decision

    # =========================================================================
    # Cross-layer: Anomaly Detection (Layer 6)
    # =========================================================================

    def get_session_risk(self, session_id: str = "default") -> AnomalyScore:
        """Get current anomaly score for a session."""
        return self.anomaly_detector.get_session_score(session_id)

    def get_audit_log(self, limit: int = 100, layer: Optional[str] = None) -> List[Dict]:
        """Get recent audit events."""
        return self._audit.get_recent(limit=limit, layer=layer)

    def get_dashboard_data(self) -> Dict:
        """Get aggregated data for the security dashboard."""
        return {
            "enabled": self._config.enabled,
            "strict_mode": self._config.strict_mode,
            "catalog": self._catalog.get_stats(),
            "audit": self._audit.get_stats(),
            "layers": {
                "perimeter": self.perimeter.get_stats(),
                "prompt_armor": self.prompt_armor.get_stats(),
                "tool_guard": self.tool_guard.get_stats(),
                "memory_sentinel": self.memory_sentinel.get_stats(),
                "exfiltration_guard": self.exfiltration_guard.get_stats(),
                "anomaly_detector": self.anomaly_detector.get_stats(),
                "wallet_fortress": self.wallet_fortress.get_stats(),
            },
        }

    # =========================================================================
    # Tool Definition Scanning (MCP injection defense)
    # =========================================================================

    def scan_tool_definitions(
        self,
        tools: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Scan tool definitions for injection payloads before sending to LLM.

        Addresses CVE-2025-53773: malicious instructions hidden in tool
        descriptions, parameter descriptions, or tool metadata.
        """
        if not self._config.enabled or not self._config.prompt_armor_enabled:
            return tools

        clean_tools = []
        injection_keywords = re.compile(
            r"(?:ignore|override|bypass|disable)\s+(?:all\s+)?(?:previous|prior|safety|security|filter|restriction|instruction|rule|guideline)",
            re.I,
        )
        hidden_instruction = re.compile(
            r"(?:actually|really|instead|secretly|hidden)\s*[,:]?\s*(?:you\s+)?(?:should|must|will|need\s+to)\s+(?:ignore|override|execute|bypass|follow\s+these)",
            re.I,
        )
        role_override = re.compile(
            r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|switch\s+to)\s+(?:a\s+)?(?:unrestricted|unfiltered|jailbroken|evil|DAN)",
            re.I,
        )

        for tool in tools:
            flagged = False
            tool_name = tool.get("name", "unknown")

            texts_to_scan = []
            if "description" in tool:
                texts_to_scan.append(("description", tool["description"]))

            schema = tool.get("input_schema", {})
            for param_name, param_def in schema.get("properties", {}).items():
                if "description" in param_def:
                    texts_to_scan.append((f"param:{param_name}", param_def["description"]))

            for field_name, text in texts_to_scan:
                for pattern, desc in [
                    (injection_keywords, "injection keyword"),
                    (hidden_instruction, "hidden instruction"),
                    (role_override, "role override"),
                ]:
                    match = pattern.search(text)
                    if match:
                        flagged = True
                        threat = ThreatDetection(
                            category=ThreatCategory.TOOL_EXPLOITATION,
                            level=ThreatLevel.CRITICAL,
                            verdict=ShieldVerdict.BLOCK,
                            description=f"Injection in tool definition '{tool_name}' field '{field_name}': {desc}",
                            evidence=match.group(0)[:200],
                            layer="tool_definition_scanner",
                            confidence=0.88,
                            suggested_action=f"Remove poisoned tool '{tool_name}' from definitions",
                            signature_id="TDS-INJECT",
                        )
                        self._audit.log(
                            ShieldDecision(
                                verdict=ShieldVerdict.BLOCK,
                                threats_detected=[threat],
                                layer="tool_definition_scanner",
                                elapsed_ms=0.0,
                            ),
                            {"tool_name": tool_name, "field": field_name},
                        )
                        logger.warning(
                            "[ZugaShield] BLOCKED poisoned tool definition: %s (field=%s, match=%s)",
                            tool_name,
                            field_name,
                            match.group(0)[:80],
                        )
                        break
                if flagged:
                    break

            if not flagged:
                clean_tools.append(tool)

        removed = len(tools) - len(clean_tools)
        if removed:
            logger.warning(
                "[ZugaShield] Removed %d poisoned tool definition(s) from %d total",
                removed,
                len(tools),
            )

        return clean_tools

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _feed_anomaly(self, decision: ShieldDecision, session_id: str = "default") -> None:
        """Feed detection events to the anomaly detector for correlation."""
        for threat in decision.threats_detected:
            self.anomaly_detector.record_event(session_id, threat)

    def get_version_state(self) -> Dict[str, Any]:
        """Snapshot current shield configuration for versioning."""
        return {
            "enabled_layers": {
                "perimeter": self._config.perimeter_enabled,
                "prompt_armor": self._config.prompt_armor_enabled,
                "tool_guard": self._config.tool_guard_enabled,
                "memory_sentinel": self._config.memory_sentinel_enabled,
                "exfiltration_guard": self._config.exfiltration_guard_enabled,
                "anomaly_detector": self._config.anomaly_detector_enabled,
                "wallet_fortress": self._config.wallet_fortress_enabled,
            },
            "config": {
                "fail_open": self._config.fail_open if hasattr(self._config, "fail_open") else True,
            },
        }


# =============================================================================
# Singleton
# =============================================================================

_shield: Optional[ZugaShield] = None


def get_zugashield() -> ZugaShield:
    """Get or create the singleton ZugaShield instance."""
    global _shield
    if _shield is None:
        _shield = ZugaShield()
    return _shield


def reset_zugashield() -> None:
    """Reset the singleton (for testing)."""
    global _shield
    _shield = None


__all__ = [
    # Facade
    "ZugaShield",
    "get_zugashield",
    "reset_zugashield",
    "set_approval_provider",
    "get_approval_provider",
    # Types
    "AnomalyScore",
    "MemoryTrust",
    "ShieldDecision",
    "ShieldVerdict",
    "ThreatCategory",
    "ThreatDetection",
    "ThreatLevel",
    "ToolPolicy",
    "allow_decision",
    "block_decision",
    # Config
    "ShieldConfig",
    # Catalog
    "ThreatCatalog",
    # Audit
    "ShieldAuditLogger",
]
