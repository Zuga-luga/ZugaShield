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

Optional layers:
    LLM Judge ──── Provider-agnostic deep analysis for ambiguous cases
    Code Scanner ── LLM-generated code safety validation
    CoT Auditor ─── Chain-of-thought trace deception detection
    MCP Guard ──── MCP protocol security (tool definition integrity)

Usage:
    # Zero-config (2 lines)
    from zugashield import ZugaShield
    decision = await ZugaShield().check_prompt("user input")

    # Builder pattern
    shield = (ZugaShield.builder()
        .fail_closed()
        .enable_layers("prompt_armor", "tool_guard")
        .build())

    # Sync wrapper
    decision = shield.check_prompt_sync("user input")
"""

from __future__ import annotations

import asyncio
import functools
import logging
import re
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional

from zugashield._version import __version__
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


# =============================================================================
# Event hooks
# =============================================================================

ThreatHandler = Callable[[ShieldDecision], Coroutine[Any, Any, None]]


class _EventHooks:
    """Registry for event hooks."""

    def __init__(self) -> None:
        self._on_threat: List[tuple[str, ThreatHandler]] = []  # (min_level, handler)
        self._on_block: List[ThreatHandler] = []

    def add_threat_handler(self, handler: ThreatHandler, min_level: str = "low") -> None:
        self._on_threat.append((min_level, handler))

    def add_block_handler(self, handler: ThreatHandler) -> None:
        self._on_block.append(handler)

    async def fire_threat(self, decision: ShieldDecision) -> None:
        if not decision.threats_detected:
            return
        level_order = ["none", "low", "medium", "high", "critical"]
        max_level = decision.max_threat_level.value
        for min_level, handler in self._on_threat:
            if level_order.index(max_level) >= level_order.index(min_level):
                try:
                    await handler(decision)
                except Exception as e:
                    logger.warning("[ZugaShield] Event hook error: %s", e)

    async def fire_block(self, decision: ShieldDecision) -> None:
        for handler in self._on_block:
            try:
                await handler(decision)
            except Exception as e:
                logger.warning("[ZugaShield] Block hook error: %s", e)


# =============================================================================
# Sync wrapper helper
# =============================================================================

def _run_sync(coro: Coroutine) -> Any:
    """Run an async coroutine synchronously."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We're inside an async context — use a thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


# =============================================================================
# Main facade
# =============================================================================


class ZugaShield:
    """
    Main facade for the ZugaShield security system.

    Provides a clean API for each integration point. Supports both
    async and sync usage, builder pattern configuration, and event hooks.
    """

    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        self._config = config or ShieldConfig.from_env()
        self._catalog = ThreatCatalog(
            verify_integrity=self._config.verify_signatures,
        )
        self._audit = ShieldAuditLogger()
        self._hooks = _EventHooks()
        self._custom_layers: List[Any] = []

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

        # New optional layers (lazy init — only if enabled)
        self._code_scanner = None
        self._cot_auditor = None
        self._mcp_guard = None
        self._init_optional_layers()

        logger.info(
            "[ZugaShield] v%s initialized: %d signatures, fail_closed=%s",
            __version__,
            self._catalog._total_signatures,
            self._config.fail_closed,
        )

    def _init_optional_layers(self) -> None:
        """Initialize optional layers if enabled and available."""
        if self._config.code_scanner_enabled:
            try:
                from zugashield.layers.code_scanner import CodeScannerLayer
                self._code_scanner = CodeScannerLayer(self._config)
            except ImportError:
                pass

        if self._config.cot_auditor_enabled:
            try:
                from zugashield.layers.cot_auditor import CoTAuditorLayer
                self._cot_auditor = CoTAuditorLayer(self._config)
            except ImportError:
                pass

        if self._config.mcp_guard_enabled:
            try:
                from zugashield.layers.mcp_guard import MCPGuardLayer
                self._mcp_guard = MCPGuardLayer(self._config)
            except ImportError:
                pass

    # =========================================================================
    # Builder pattern
    # =========================================================================

    @classmethod
    def builder(cls) -> _ZugaShieldBuilder:
        """Create a builder for fluent shield configuration."""
        return _ZugaShieldBuilder()

    # =========================================================================
    # Event hooks
    # =========================================================================

    def on_threat(self, min_level: str = "low") -> Callable:
        """Decorator to register a threat event handler.

        Usage::

            @shield.on_threat(min_level="high")
            async def alert_slack(decision):
                ...
        """
        def decorator(fn: ThreatHandler) -> ThreatHandler:
            self._hooks.add_threat_handler(fn, min_level)
            return fn
        return decorator

    def on_block(self, fn: ThreatHandler) -> ThreatHandler:
        """Decorator to register a block event handler.

        Usage::

            @shield.on_block
            async def log_to_siem(decision):
                ...
        """
        self._hooks.add_block_handler(fn)
        return fn

    # =========================================================================
    # Custom layer registration
    # =========================================================================

    def register_layer(self, layer: Any) -> None:
        """Register a custom layer for inclusion in checks."""
        self._custom_layers.append(layer)

    # =========================================================================
    # Properties
    # =========================================================================

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

    @property
    def version(self) -> str:
        return __version__

    # =========================================================================
    # Fail-closed layer runner (Fix #1)
    # =========================================================================

    async def _run_layer(
        self,
        layer_name: str,
        coro: Coroutine[Any, Any, ShieldDecision],
        *,
        always_fail_closed: bool = False,
    ) -> ShieldDecision:
        """
        Run a layer check with fail-closed exception handling.

        If ``fail_closed`` is True in config (or ``always_fail_closed`` is set),
        any exception from the layer returns BLOCK instead of ALLOW.
        Wallet and tool execution layers always fail closed.
        """
        try:
            decision = await coro
            # Fire event hooks
            if decision.threats_detected:
                await self._hooks.fire_threat(decision)
            if decision.is_blocked:
                await self._hooks.fire_block(decision)
            return decision
        except Exception as e:
            fail_closed = always_fail_closed or self._config.fail_closed
            if fail_closed:
                logger.error(
                    "[ZugaShield] Layer '%s' threw %s — BLOCKING (fail-closed): %s",
                    layer_name, type(e).__name__, e,
                )
                return block_decision(
                    layer=layer_name,
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    level=ThreatLevel.HIGH,
                    description=f"Layer '{layer_name}' failed — blocked under fail-closed policy",
                    evidence=f"{type(e).__name__}: {str(e)[:200]}",
                    signature_id="SYS-FAIL-CLOSED",
                )
            else:
                logger.warning(
                    "[ZugaShield] Layer '%s' threw %s — allowing (fail-open): %s",
                    layer_name, type(e).__name__, e,
                )
                return allow_decision(layer_name)

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

        decision = await self._run_layer(
            "perimeter",
            self.perimeter.check(
                path=path, method=method, content_length=content_length,
                body=body, headers=headers, client_ip=client_ip,
            ),
        )
        self._audit.log(decision, {"path": path, "method": method, "client_ip": client_ip})
        self._feed_anomaly(decision)
        return decision

    def check_request_sync(self, **kwargs: Any) -> ShieldDecision:
        """Synchronous wrapper for check_request."""
        return _run_sync(self.check_request(**kwargs))

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

        decision = await self._run_layer(
            "prompt_armor",
            self.prompt_armor.check(user_message, context),
        )

        # Optional LLM judge escalation for ambiguous cases
        if self.llm_judge.should_escalate(decision):
            decision = await self._run_layer(
                "llm_judge",
                self.llm_judge.judge(user_message, decision),
            )

        self._audit.log(decision, {"source": "prompt", **(context or {})})
        self._feed_anomaly(decision)
        return decision

    def check_prompt_sync(self, user_message: str, context: Optional[Dict] = None) -> ShieldDecision:
        """Synchronous wrapper for check_prompt."""
        return _run_sync(self.check_prompt(user_message, context))

    # =========================================================================
    # Layer 3: Tool Guard (execution gating)
    # =========================================================================

    async def check_tool_call(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session_id: str = "default",
    ) -> ShieldDecision:
        """Check a tool call before execution (Layer 3). Always fail-closed."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self._run_layer(
            "tool_guard",
            self.tool_guard.check(tool_name, params, session_id),
            always_fail_closed=True,
        )
        self._audit.log(decision, {"tool": tool_name, "session_id": session_id})
        self._feed_anomaly(decision, session_id)
        return decision

    def check_tool_call_sync(self, tool_name: str, params: Dict[str, Any], session_id: str = "default") -> ShieldDecision:
        """Synchronous wrapper for check_tool_call."""
        return _run_sync(self.check_tool_call(tool_name, params, session_id))

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

        decision = await self._run_layer(
            "memory_sentinel",
            self.memory_sentinel.check_write(
                content=content, memory_type=memory_type, importance=importance,
                source=source, user_id=user_id, tags=tags,
            ),
        )
        self._audit.log(decision, {"source": source, "memory_type": memory_type})
        self._feed_anomaly(decision)
        return decision

    def check_memory_write_sync(self, **kwargs: Any) -> ShieldDecision:
        """Synchronous wrapper for check_memory_write."""
        return _run_sync(self.check_memory_write(**kwargs))

    async def check_memory_recall(
        self,
        memories: List[Dict[str, Any]],
    ) -> ShieldDecision:
        """Check recalled memories before prompt injection (Layer 4 read)."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self._run_layer(
            "memory_sentinel",
            self.memory_sentinel.check_recall(memories),
        )
        self._audit.log(decision, {"memory_count": len(memories)})
        return decision

    def check_memory_recall_sync(self, memories: List[Dict[str, Any]]) -> ShieldDecision:
        """Synchronous wrapper for check_memory_recall."""
        return _run_sync(self.check_memory_recall(memories))

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

        decision = await self._run_layer(
            "memory_sentinel",
            self.memory_sentinel.check_document(
                content=content, source=source, document_type=document_type,
            ),
        )
        self._audit.log(decision, {"source": source, "document_type": document_type})
        self._feed_anomaly(decision)
        return decision

    def check_document_sync(self, content: str, source: str = "external", document_type: str = "") -> ShieldDecision:
        """Synchronous wrapper for check_document."""
        return _run_sync(self.check_document(content, source, document_type))

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

        decision = await self._run_layer(
            "exfiltration_guard",
            self.exfiltration_guard.check(output, context),
        )
        self._audit.log(decision, context)
        self._feed_anomaly(decision)
        return decision

    def check_output_sync(self, output: str, context: Optional[Dict] = None) -> ShieldDecision:
        """Synchronous wrapper for check_output."""
        return _run_sync(self.check_output(output, context))

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

        decision = await self._run_layer(
            "multimodal",
            self.multimodal.check_image(
                image_path=image_path, alt_text=alt_text,
                ocr_text=ocr_text, metadata=metadata,
            ),
        )
        self._audit.log(decision, {"source": "image"})
        self._feed_anomaly(decision)
        return decision

    def check_image_sync(self, **kwargs: Any) -> ShieldDecision:
        """Synchronous wrapper for check_image."""
        return _run_sync(self.check_image(**kwargs))

    # =========================================================================
    # Layer 7: Wallet Fortress (crypto protection). Always fail-closed.
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
        """Check a wallet transaction (Layer 7). Always fail-closed."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")

        decision = await self._run_layer(
            "wallet_fortress",
            self.wallet_fortress.check(
                tx_type=tx_type, to_address=to_address, amount=amount,
                amount_usd=amount_usd, contract_data=contract_data,
                function_sig=function_sig,
            ),
            always_fail_closed=True,
        )
        self._audit.log(decision, {"tx_type": tx_type, "amount_usd": amount_usd})
        self._feed_anomaly(decision)
        return decision

    def check_transaction_sync(self, **kwargs: Any) -> ShieldDecision:
        """Synchronous wrapper for check_transaction."""
        return _run_sync(self.check_transaction(**kwargs))

    # =========================================================================
    # NEW: Code Scanner (LLM-generated code safety)
    # =========================================================================

    async def check_code(
        self,
        code: str,
        language: str = "python",
    ) -> ShieldDecision:
        """Check LLM-generated code for security vulnerabilities."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")
        if self._code_scanner is None:
            return allow_decision("code_scanner_not_available")

        decision = await self._run_layer(
            "code_scanner",
            self._code_scanner.check(code, language=language),
        )
        self._audit.log(decision, {"language": language})
        self._feed_anomaly(decision)
        return decision

    def check_code_sync(self, code: str, language: str = "python") -> ShieldDecision:
        """Synchronous wrapper for check_code."""
        return _run_sync(self.check_code(code, language))

    # =========================================================================
    # NEW: CoT Auditor (chain-of-thought trace analysis)
    # =========================================================================

    async def check_reasoning(
        self,
        trace: str,
        stated_goal: str = "",
    ) -> ShieldDecision:
        """Audit a chain-of-thought trace for deceptive patterns."""
        if not self._config.enabled:
            return allow_decision("shield_disabled")
        if self._cot_auditor is None:
            return allow_decision("cot_auditor_not_available")

        decision = await self._run_layer(
            "cot_auditor",
            self._cot_auditor.check(trace, stated_goal=stated_goal),
        )
        self._audit.log(decision, {"stated_goal": stated_goal[:100]})
        self._feed_anomaly(decision)
        return decision

    def check_reasoning_sync(self, trace: str, stated_goal: str = "") -> ShieldDecision:
        """Synchronous wrapper for check_reasoning."""
        return _run_sync(self.check_reasoning(trace, stated_goal))

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
        data: Dict[str, Any] = {
            "version": __version__,
            "enabled": self._config.enabled,
            "strict_mode": self._config.strict_mode,
            "fail_closed": self._config.fail_closed,
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
                "llm_judge": self.llm_judge.get_stats(),
            },
        }
        if self._code_scanner:
            data["layers"]["code_scanner"] = self._code_scanner.get_stats()
        if self._cot_auditor:
            data["layers"]["cot_auditor"] = self._cot_auditor.get_stats()
        if self._mcp_guard:
            data["layers"]["mcp_guard"] = self._mcp_guard.get_stats()
        return data

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

        If the MCP Guard layer is available, delegates to it for richer analysis.
        Otherwise falls back to inline regex scanning.
        """
        if not self._config.enabled or not self._config.prompt_armor_enabled:
            return tools

        # Prefer MCPGuardLayer if available
        if self._mcp_guard is not None:
            clean_tools, threats = self._mcp_guard.scan_definitions(tools)
            for threat in threats:
                self._audit.log(
                    ShieldDecision(
                        verdict=ShieldVerdict.BLOCK,
                        threats_detected=[threat],
                        layer="mcp_guard",
                        elapsed_ms=0.0,
                    ),
                    {"source": "tool_definition_scan"},
                )
            return clean_tools

        # Fallback: inline regex scanning
        return self._scan_tool_definitions_inline(tools)

    def _scan_tool_definitions_inline(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Inline tool definition scanning (fallback when MCPGuardLayer unavailable)."""
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
                            "[ZugaShield] BLOCKED poisoned tool: %s (field=%s)",
                            tool_name, field_name,
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
                removed, len(tools),
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
            "version": __version__,
            "enabled_layers": {
                "perimeter": self._config.perimeter_enabled,
                "prompt_armor": self._config.prompt_armor_enabled,
                "tool_guard": self._config.tool_guard_enabled,
                "memory_sentinel": self._config.memory_sentinel_enabled,
                "exfiltration_guard": self._config.exfiltration_guard_enabled,
                "anomaly_detector": self._config.anomaly_detector_enabled,
                "wallet_fortress": self._config.wallet_fortress_enabled,
                "code_scanner": self._config.code_scanner_enabled,
                "cot_auditor": self._config.cot_auditor_enabled,
                "mcp_guard": self._config.mcp_guard_enabled,
            },
            "config": {
                "fail_closed": self._config.fail_closed,
                "strict_mode": self._config.strict_mode,
            },
        }


# =============================================================================
# Builder
# =============================================================================


class _ZugaShieldBuilder:
    """Fluent builder for ZugaShield instances."""

    def __init__(self) -> None:
        self._config_builder = ShieldConfig.builder()

    def fail_closed(self, value: bool = True) -> _ZugaShieldBuilder:
        self._config_builder.fail_closed(value)
        return self

    def strict_mode(self, value: bool = True) -> _ZugaShieldBuilder:
        self._config_builder.strict_mode(value)
        return self

    def enable_layers(self, *layers: str) -> _ZugaShieldBuilder:
        self._config_builder.enable_layers(*layers)
        return self

    def disable_layers(self, *layers: str) -> _ZugaShieldBuilder:
        self._config_builder.disable_layers(*layers)
        return self

    def set_tool_policy(
        self, tool_name: str, rate: int = 15, approval: bool = False, risk: str = "medium"
    ) -> _ZugaShieldBuilder:
        self._config_builder.set_tool_policy(tool_name, rate, approval, risk)
        return self

    def add_sensitive_endpoint(self, path: str, rate_limit: int = 10) -> _ZugaShieldBuilder:
        self._config_builder.add_sensitive_endpoint(path, rate_limit)
        return self

    def set_egress_allowlist(self, *domains: str) -> _ZugaShieldBuilder:
        self._config_builder.set_egress_allowlist(*domains)
        return self

    def set_wallet_limits(
        self, tx_limit: float = 100.0, hourly_limit: float = 500.0, daily_limit: float = 2000.0
    ) -> _ZugaShieldBuilder:
        self._config_builder.set_wallet_limits(tx_limit, hourly_limit, daily_limit)
        return self

    def set_llm_provider(self, provider: str, model: Optional[str] = None) -> _ZugaShieldBuilder:
        self._config_builder.set_llm_provider(provider, model)
        return self

    def add_layer(self, layer: Any) -> _ZugaShieldBuilder:
        """Register a custom layer to add after build."""
        if not hasattr(self, "_custom_layers"):
            self._custom_layers: list = []
        self._custom_layers.append(layer)
        return self

    def build(self) -> ZugaShield:
        config = self._config_builder.build()
        shield = ZugaShield(config)
        for layer in getattr(self, "_custom_layers", []):
            shield.register_layer(layer)
        return shield


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
    # Version
    "__version__",
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
