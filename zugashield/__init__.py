"""
ZugaShield — AI Agent Security System
======================================

Public API facade that orchestrates all security layers.

Usage::

    from zugashield import ZugaShield, get_zugashield

    # Zero-config
    shield = ZugaShield()
    decision = await shield.check_prompt("user input here")

    if decision.is_blocked:
        print(f"Blocked: {decision.threats_detected[0].description}")

    # Builder pattern
    shield = (ZugaShield.builder()
        .fail_closed(True)
        .strict_mode(True)
        .set_tool_policy("web_search", rate=10)
        .build())

    # Singleton
    shield = get_zugashield()

    # Sync (Flask, Django, scripts)
    decision = shield.check_prompt_sync("user input")
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from zugashield._version import __version__
from zugashield.audit import ShieldAuditLogger
from zugashield.config import ShieldConfig
from zugashield.threat_catalog import ThreatCatalog
from zugashield.types import (
    AnomalyScore,
    ShieldDecision,
    ShieldVerdict,
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    allow_decision,
    block_decision,
)

# Core layers (always importable)
from zugashield.layers import (
    BaseLayer,
    PerimeterLayer,
    PromptArmorLayer,
    ToolGuardLayer,
    MemorySentinelLayer,
    ExfiltrationGuardLayer,
    AnomalyDetectorLayer,
    WalletFortressLayer,
    LLMJudgeLayer,
)

# Optional layers — degrade gracefully if dependencies are missing
try:
    from zugashield.layers import CodeScannerLayer

    _HAS_CODE_SCANNER = True
except ImportError:
    _HAS_CODE_SCANNER = False

try:
    from zugashield.layers import CoTAuditorLayer

    _HAS_COT_AUDITOR = True
except ImportError:
    _HAS_COT_AUDITOR = False

try:
    from zugashield.layers import MCPGuardLayer

    _HAS_MCP_GUARD = True
except ImportError:
    _HAS_MCP_GUARD = False

try:
    from zugashield.layers import MLDetectorLayer

    _HAS_ML_DETECTOR = True
except ImportError:
    _HAS_ML_DETECTOR = False

logger = logging.getLogger(__name__)


def _run_sync(coro):
    """Run a coroutine synchronously, even from inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


# Module-level singleton
_singleton: Optional[ZugaShield] = None
_approval_provider: Optional[Callable] = None

# Layers that ALWAYS fail closed regardless of the config setting
_ALWAYS_FAIL_CLOSED = {"tool_guard", "wallet_fortress"}


# ===================================================================
# Main facade
# ===================================================================


class ZugaShield:
    """Main facade for the ZugaShield AI Agent Security System."""

    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        self._config = config or ShieldConfig.from_env()
        self._catalog = ThreatCatalog(verify_integrity=self._config.verify_signatures)
        self._audit = ShieldAuditLogger()
        self._threat_hooks: List[Tuple[str, Callable]] = []
        self._block_hooks: List[Callable] = []
        self._layers: Dict[str, Any] = {}
        self._updater = None
        self._init_layers()
        self._init_feed()

        logger.info(
            "[ZugaShield] v%s initialized: %d layers active, %d signatures loaded",
            self.version,
            len(self._layers),
            self._catalog.get_stats()["total_signatures"],
        )

    # ---------------------------------------------------------------
    # Layer initialization
    # ---------------------------------------------------------------

    def _init_layers(self) -> None:
        cfg, cat = self._config, self._catalog

        # Core layers (always importable)
        if cfg.perimeter_enabled:
            self._layers["perimeter"] = PerimeterLayer(cfg, cat)
        if cfg.prompt_armor_enabled:
            self._layers["prompt_armor"] = PromptArmorLayer(cfg, cat)
        if cfg.tool_guard_enabled:
            self._layers["tool_guard"] = ToolGuardLayer(cfg, cat)
        if cfg.memory_sentinel_enabled:
            self._layers["memory_sentinel"] = MemorySentinelLayer(cfg, cat)
        if cfg.exfiltration_guard_enabled:
            self._layers["exfiltration_guard"] = ExfiltrationGuardLayer(cfg, cat)
        if cfg.anomaly_detector_enabled:
            self._layers["anomaly_detector"] = AnomalyDetectorLayer(cfg)
        if cfg.wallet_fortress_enabled:
            self._layers["wallet_fortress"] = WalletFortressLayer(cfg, cat)
        if cfg.llm_judge_enabled:
            self._layers["llm_judge"] = LLMJudgeLayer(cfg)

        # Optional layers (may not be installable)
        _optional = [
            ("ml_detector", cfg.ml_detector_enabled, _HAS_ML_DETECTOR, lambda: MLDetectorLayer(cfg)),
            ("code_scanner", cfg.code_scanner_enabled, _HAS_CODE_SCANNER, lambda: CodeScannerLayer(cfg)),
            ("cot_auditor", cfg.cot_auditor_enabled, _HAS_COT_AUDITOR, lambda: CoTAuditorLayer(cfg)),
            ("mcp_guard", cfg.mcp_guard_enabled, _HAS_MCP_GUARD, lambda: MCPGuardLayer(cfg)),
        ]
        for name, enabled, available, factory in _optional:
            if enabled and available:
                try:
                    self._layers[name] = factory()
                except Exception as e:
                    logger.warning("[ZugaShield] %s init failed (degrading gracefully): %s", name, e)

    def _init_feed(self) -> None:
        """Start the signature auto-updater daemon if feed is enabled."""
        if not self._config.feed_enabled:
            return
        try:
            from zugashield.feed.updater import SignatureUpdater

            self._updater = SignatureUpdater(self._catalog, self._config)
            self._updater.start()
            logger.info("[ZugaShield] Signature feed updater started")
        except ImportError:
            logger.debug("[ZugaShield] Feed module not available, skipping auto-update")
        except Exception as e:
            logger.warning("[ZugaShield] Feed updater init failed: %s", e)

    # ---------------------------------------------------------------
    # Properties
    # ---------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    @property
    def config(self) -> ShieldConfig:
        return self._config

    @property
    def version(self) -> str:
        return __version__

    @property
    def catalog(self) -> ThreatCatalog:
        return self._catalog

    @property
    def audit(self) -> ShieldAuditLogger:
        return self._audit

    # Layer accessors — used by tests and advanced callers
    @property
    def perimeter(self):
        return self._layers.get("perimeter")

    @property
    def prompt_armor(self):
        return self._layers.get("prompt_armor")

    @property
    def tool_guard(self):
        return self._layers.get("tool_guard")

    @property
    def memory_sentinel(self):
        return self._layers.get("memory_sentinel")

    @property
    def exfiltration_guard(self):
        return self._layers.get("exfiltration_guard")

    @property
    def anomaly_detector(self):
        return self._layers.get("anomaly_detector")

    @property
    def wallet_fortress(self):
        return self._layers.get("wallet_fortress")

    # ---------------------------------------------------------------
    # Core check methods
    # ---------------------------------------------------------------

    async def check_request(
        self,
        path: str,
        method: str = "GET",
        content_length: int = 0,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        client_ip: str = "unknown",
    ) -> ShieldDecision:
        """Check an incoming HTTP request through the perimeter layer (L1)."""
        if not self.enabled:
            return allow_decision("perimeter")

        start = time.perf_counter()
        layer = self._layers.get("perimeter")
        if not layer:
            return allow_decision("perimeter")

        try:
            decision = await layer.check(
                path=path,
                method=method,
                content_length=content_length,
                body=body,
                headers=headers,
                client_ip=client_ip,
            )
        except Exception as e:
            decision = self._handle_layer_error("perimeter", e)

        decision.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(decision)
        await self._fire_hooks(decision)
        return decision

    async def check_prompt(
        self,
        text: str,
        context: Optional[Dict] = None,
    ) -> ShieldDecision:
        """Check a prompt through prompt armor (L2), ML detector, and anomaly gate (L6)."""
        if not self.enabled:
            return allow_decision("prompt_armor")

        start = time.perf_counter()
        ctx = context or {}
        session_id = ctx.get("session_id", "default")

        # L2 — Prompt Armor (signature-based, fast regex scan)
        layer = self._layers.get("prompt_armor")
        if layer:
            try:
                decision = await layer.check(text, context=ctx)
            except Exception as e:
                decision = self._handle_layer_error("prompt_armor", e)
            if decision.is_blocked:
                decision.elapsed_ms = (time.perf_counter() - start) * 1000
                self._record_anomaly(session_id, decision)
                self._audit.log(decision, context=ctx)
                await self._fire_hooks(decision)
                return decision

        # ML Detector (optional — neural injection detection)
        ml = self._layers.get("ml_detector")
        if ml:
            try:
                decision = await ml.check(text)
            except Exception as e:
                decision = self._handle_layer_error("ml_detector", e)
            if decision.is_blocked:
                decision.elapsed_ms = (time.perf_counter() - start) * 1000
                self._record_anomaly(session_id, decision)
                self._audit.log(decision, context=ctx)
                await self._fire_hooks(decision)
                return decision

        # L6 — Anomaly score gate (cumulative session risk)
        anomaly = self._layers.get("anomaly_detector")
        if anomaly:
            try:
                decision = await anomaly.check(session_id=session_id)
            except Exception as e:
                decision = self._handle_layer_error("anomaly_detector", e)
            if decision.is_blocked:
                decision.elapsed_ms = (time.perf_counter() - start) * 1000
                self._audit.log(decision, context=ctx)
                await self._fire_hooks(decision)
                return decision

        result = allow_decision("prompt_armor")
        result.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(result, context=ctx)
        return result

    async def check_output(
        self,
        text: str,
        context: Optional[Dict] = None,
    ) -> ShieldDecision:
        """Check AI output through exfiltration guard (L5) and CoT auditor."""
        if not self.enabled:
            return allow_decision("exfiltration_guard")

        start = time.perf_counter()
        ctx = context or {}

        # L5 — Exfiltration Guard
        layer = self._layers.get("exfiltration_guard")
        if layer:
            try:
                decision = await layer.check(text, context=ctx)
            except Exception as e:
                decision = self._handle_layer_error("exfiltration_guard", e)
            if decision.is_blocked:
                decision.elapsed_ms = (time.perf_counter() - start) * 1000
                self._audit.log(decision, context=ctx)
                await self._fire_hooks(decision)
                return decision

        # CoT Auditor (optional — checks reasoning traces for deception)
        cot = self._layers.get("cot_auditor")
        if cot:
            try:
                decision = await cot.check(trace=text, stated_goal=ctx.get("task", ""))
            except Exception as e:
                decision = self._handle_layer_error("cot_auditor", e)
            if decision.is_blocked:
                decision.elapsed_ms = (time.perf_counter() - start) * 1000
                self._audit.log(decision, context=ctx)
                await self._fire_hooks(decision)
                return decision

        result = allow_decision("exfiltration_guard")
        result.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(result, context=ctx)
        return result

    async def check_tool_call(
        self,
        name: str,
        args: Optional[Dict[str, Any]] = None,
        session_id: str = "default",
    ) -> ShieldDecision:
        """Check a tool invocation through tool guard (L3) and anomaly detector (L6)."""
        if not self.enabled:
            return allow_decision("tool_guard")

        start = time.perf_counter()
        params = args or {}

        # L3 — Tool Guard (ALWAYS fail-closed regardless of config)
        layer = self._layers.get("tool_guard")
        if layer:
            try:
                decision = await layer.check(name, params, session_id=session_id)
            except Exception as e:
                decision = self._handle_layer_error("tool_guard", e, force_block=True)
            if decision.is_blocked:
                decision.elapsed_ms = (time.perf_counter() - start) * 1000
                self._record_anomaly(session_id, decision)
                self._audit.log(decision)
                await self._fire_hooks(decision)
                return decision

        # L6 — Anomaly score gate
        anomaly = self._layers.get("anomaly_detector")
        if anomaly:
            try:
                decision = await anomaly.check(session_id=session_id)
            except Exception as e:
                decision = self._handle_layer_error("anomaly_detector", e)
            if decision.is_blocked:
                decision.elapsed_ms = (time.perf_counter() - start) * 1000
                self._audit.log(decision)
                await self._fire_hooks(decision)
                return decision

        result = allow_decision("tool_guard")
        result.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(result)
        return result

    async def check_memory_write(
        self,
        content: str,
        memory_type: str = "",
        source: str = "unknown",
        tags: Optional[List[str]] = None,
    ) -> ShieldDecision:
        """Check a memory write through memory sentinel (L4)."""
        if not self.enabled:
            return allow_decision("memory_sentinel")

        start = time.perf_counter()
        layer = self._layers.get("memory_sentinel")
        if not layer:
            return allow_decision("memory_sentinel")

        try:
            decision = await layer.check_write(
                content, memory_type=memory_type, source=source, tags=tags,
            )
        except Exception as e:
            decision = self._handle_layer_error("memory_sentinel", e)

        decision.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(decision)
        await self._fire_hooks(decision)
        return decision

    async def check_memory_recall(
        self,
        memories: List[Dict[str, Any]],
    ) -> ShieldDecision:
        """Check recalled memories through memory sentinel (L4)."""
        if not self.enabled:
            return allow_decision("memory_sentinel")

        start = time.perf_counter()
        layer = self._layers.get("memory_sentinel")
        if not layer:
            return allow_decision("memory_sentinel")

        try:
            decision = await layer.check_recall(memories)
        except Exception as e:
            decision = self._handle_layer_error("memory_sentinel", e)

        decision.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(decision)
        await self._fire_hooks(decision)
        return decision

    async def check_transaction(
        self,
        tx_type: str = "send",
        to_address: str = "",
        amount: float = 0.0,
        amount_usd: float = 0.0,
        contract_data: Optional[str] = None,
        function_sig: Optional[str] = None,
    ) -> ShieldDecision:
        """Check a crypto transaction through wallet fortress (L7). Always fail-closed."""
        if not self.enabled:
            return allow_decision("wallet_fortress")

        start = time.perf_counter()
        layer = self._layers.get("wallet_fortress")
        if not layer:
            return allow_decision("wallet_fortress")

        try:
            decision = await layer.check(
                tx_type=tx_type,
                to_address=to_address,
                amount=amount,
                amount_usd=amount_usd,
                contract_data=contract_data,
                function_sig=function_sig,
            )
        except Exception as e:
            decision = self._handle_layer_error("wallet_fortress", e, force_block=True)

        decision.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(decision)
        await self._fire_hooks(decision)
        return decision

    async def check_code(
        self,
        code: str,
        language: str = "python",
    ) -> ShieldDecision:
        """Check code through the code scanner layer."""
        if not self.enabled:
            return allow_decision("code_scanner")

        start = time.perf_counter()
        layer = self._layers.get("code_scanner")
        if not layer:
            return allow_decision("code_scanner")

        try:
            decision = await layer.check(code, language=language)
        except Exception as e:
            decision = self._handle_layer_error("code_scanner", e)

        decision.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(decision)
        await self._fire_hooks(decision)
        return decision

    async def check_reasoning(
        self,
        trace: str,
        stated_goal: str = "",
    ) -> ShieldDecision:
        """Check a reasoning trace through the CoT auditor layer."""
        if not self.enabled:
            return allow_decision("cot_auditor")

        start = time.perf_counter()
        layer = self._layers.get("cot_auditor")
        if not layer:
            return allow_decision("cot_auditor")

        try:
            decision = await layer.check(trace=trace, stated_goal=stated_goal)
        except Exception as e:
            decision = self._handle_layer_error("cot_auditor", e)

        decision.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(decision)
        await self._fire_hooks(decision)
        return decision

    async def check_document(
        self,
        content: str,
        source: str = "external",
        document_type: str = "",
    ) -> ShieldDecision:
        """Check an external document (RAG) through memory sentinel (L4)."""
        if not self.enabled:
            return allow_decision("memory_sentinel")

        start = time.perf_counter()
        layer = self._layers.get("memory_sentinel")
        if not layer:
            return allow_decision("memory_sentinel")

        try:
            decision = await layer.check_document(content, source=source, document_type=document_type)
        except Exception as e:
            decision = self._handle_layer_error("memory_sentinel", e)

        decision.elapsed_ms = (time.perf_counter() - start) * 1000
        self._audit.log(decision)
        await self._fire_hooks(decision)
        return decision

    async def check_image(
        self,
        alt_text: str = "",
        **kwargs: Any,
    ) -> ShieldDecision:
        """Check image metadata (alt text) for injection through prompt armor (L2)."""
        if not self.enabled:
            return allow_decision("prompt_armor")

        if alt_text:
            return await self.check_prompt(alt_text, context={"source": "image_alt_text"})

        return allow_decision("prompt_armor")

    def scan_tool_definitions(
        self,
        tools: List[Dict[str, Any]],
        server_id: str = "default",
    ) -> List[Dict[str, Any]]:
        """Strip poisoned MCP tool definitions. Returns the clean list only."""
        layer = self._layers.get("mcp_guard")
        if not layer or not self.enabled:
            return tools
        clean, _threats = layer.scan_definitions(tools, server_id=server_id)
        return clean

    # ---------------------------------------------------------------
    # Query / dashboard
    # ---------------------------------------------------------------

    def get_session_risk(self, session_id: str = "default") -> AnomalyScore:
        """Get the anomaly score for a session."""
        layer = self._layers.get("anomaly_detector")
        if layer:
            return layer.get_session_score(session_id)
        return AnomalyScore()

    def get_audit_log(self, limit: int = 100, layer: Optional[str] = None) -> List[Dict]:
        """Get recent audit events, optionally filtered by layer."""
        return self._audit.get_recent(limit=limit, layer=layer)

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Aggregated stats for the security dashboard."""
        layer_stats = {}
        for name, lyr in self._layers.items():
            if hasattr(lyr, "get_stats"):
                layer_stats[name] = lyr.get_stats()
        data: Dict[str, Any] = {
            "version": self.version,
            "enabled": self.enabled,
            "strict_mode": self._config.strict_mode,
            "fail_closed": self._config.fail_closed,
            "catalog": self._catalog.get_stats(),
            "audit": self._audit.get_stats(),
            "layers": layer_stats,
        }
        # Feed stats (if updater is running)
        if self._updater is not None:
            data["feed"] = {
                "running": self._updater.is_alive(),
                "updates_applied": getattr(self._updater, "_updates_applied", 0),
                "last_error": getattr(self._updater, "_last_error", None),
            }
        return data

    def get_version_state(self) -> Dict[str, Any]:
        """Version, config summary, and which layers are active."""
        return {
            "version": self.version,
            "enabled": self.enabled,
            "enabled_layers": list(self._layers.keys()),
            "config": {
                "strict_mode": self._config.strict_mode,
                "fail_closed": self._config.fail_closed,
            },
        }

    # ---------------------------------------------------------------
    # Event hooks
    # ---------------------------------------------------------------

    def on_threat(self, min_level: str = "high") -> Callable:
        """Decorator: fire callback when a threat >= min_level is detected."""
        def decorator(fn: Callable) -> Callable:
            self._threat_hooks.append((min_level, fn))
            return fn
        return decorator

    def on_block(self, fn: Callable) -> Callable:
        """Decorator: fire callback on every BLOCK or QUARANTINE verdict."""
        self._block_hooks.append(fn)
        return fn

    async def _fire_hooks(self, decision: ShieldDecision) -> None:
        """Invoke registered event hooks for this decision."""
        if decision.is_blocked:
            for hook in self._block_hooks:
                try:
                    result = hook(decision)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception:
                    logger.exception("[ZugaShield] Block hook error")

        _LEVELS = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        max_lvl = _LEVELS.get(decision.max_threat_level.value, 0)
        for min_level_str, hook in self._threat_hooks:
            if max_lvl >= _LEVELS.get(min_level_str, 3):
                try:
                    result = hook(decision)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception:
                    logger.exception("[ZugaShield] Threat hook error")

    # ---------------------------------------------------------------
    # Sync wrappers (Flask / Django / scripts)
    # ---------------------------------------------------------------

    def check_prompt_sync(self, text: str, context: Optional[Dict] = None) -> ShieldDecision:
        """Synchronous check_prompt."""
        return _run_sync(self.check_prompt(text, context=context))

    def check_output_sync(self, text: str, context: Optional[Dict] = None) -> ShieldDecision:
        """Synchronous check_output."""
        return _run_sync(self.check_output(text, context=context))

    def check_tool_call_sync(
        self, name: str, args: Optional[Dict[str, Any]] = None, session_id: str = "default",
    ) -> ShieldDecision:
        """Synchronous check_tool_call."""
        return _run_sync(self.check_tool_call(name, args, session_id=session_id))

    def check_memory_write_sync(self, content: str, **kwargs: Any) -> ShieldDecision:
        """Synchronous check_memory_write."""
        return _run_sync(self.check_memory_write(content, **kwargs))

    def check_transaction_sync(self, **kwargs: Any) -> ShieldDecision:
        """Synchronous check_transaction."""
        return _run_sync(self.check_transaction(**kwargs))

    def check_code_sync(self, code: str, language: str = "python") -> ShieldDecision:
        """Synchronous check_code."""
        return _run_sync(self.check_code(code, language=language))

    def check_reasoning_sync(self, trace: str, stated_goal: str = "") -> ShieldDecision:
        """Synchronous check_reasoning."""
        return _run_sync(self.check_reasoning(trace, stated_goal=stated_goal))

    # ---------------------------------------------------------------
    # Internals
    # ---------------------------------------------------------------

    def _record_anomaly(self, session_id: str, decision: ShieldDecision) -> None:
        """Feed threat detections into the anomaly detector for session scoring."""
        anomaly = self._layers.get("anomaly_detector")
        if anomaly and decision.threats_detected:
            for threat in decision.threats_detected:
                anomaly.record_event(session_id, threat)

    def _handle_layer_error(
        self, layer_name: str, error: Exception, *, force_block: bool = False,
    ) -> ShieldDecision:
        """On layer error: BLOCK if fail_closed or force_block, else ALLOW."""
        logger.exception("[ZugaShield] Layer '%s' error", layer_name)
        should_block = force_block or self._config.fail_closed or layer_name in _ALWAYS_FAIL_CLOSED
        if should_block:
            return block_decision(
                layer=layer_name,
                category=ThreatCategory.BEHAVIORAL_ANOMALY,
                level=ThreatLevel.HIGH,
                description=f"Internal error in {layer_name} (fail-closed)",
                evidence=str(error)[:100],
                confidence=0.5,
                signature_id="SYS-FAIL-CLOSED",
            )
        return allow_decision(layer_name)

    # ---------------------------------------------------------------
    # Builder
    # ---------------------------------------------------------------

    @classmethod
    def builder(cls) -> ZugaShieldBuilder:
        """Create a fluent builder for ZugaShield."""
        return ZugaShieldBuilder()


# ===================================================================
# Builder
# ===================================================================


class ZugaShieldBuilder:
    """Fluent builder that wraps ShieldConfig.builder() and produces a ZugaShield."""

    def __init__(self) -> None:
        self._config_builder = ShieldConfig.builder()
        self._custom_layers: List[BaseLayer] = []

    def fail_closed(self, value: bool = True) -> ZugaShieldBuilder:
        self._config_builder.fail_closed(value)
        return self

    def strict_mode(self, value: bool = True) -> ZugaShieldBuilder:
        self._config_builder.strict_mode(value)
        return self

    def enable_layers(self, *layers: str) -> ZugaShieldBuilder:
        self._config_builder.enable_layers(*layers)
        return self

    def disable_layers(self, *layers: str) -> ZugaShieldBuilder:
        self._config_builder.disable_layers(*layers)
        return self

    def set_tool_policy(
        self, name: str, rate: int = 15, approval: bool = False, risk: str = "medium",
    ) -> ZugaShieldBuilder:
        self._config_builder.set_tool_policy(name, rate, approval, risk)
        return self

    def set_egress_allowlist(self, *domains: str) -> ZugaShieldBuilder:
        self._config_builder.set_egress_allowlist(*domains)
        return self

    def set_wallet_limits(
        self, tx_limit: float = 100.0, hourly_limit: float = 500.0, daily_limit: float = 2000.0,
    ) -> ZugaShieldBuilder:
        self._config_builder.set_wallet_limits(tx_limit, hourly_limit, daily_limit)
        return self

    def add_sensitive_endpoint(self, path: str, rate_limit: int = 10) -> ZugaShieldBuilder:
        self._config_builder.add_sensitive_endpoint(path, rate_limit)
        return self

    def enable_feed(
        self, url: Optional[str] = None, interval: int = 3600,
    ) -> ZugaShieldBuilder:
        self._config_builder.enable_feed(url=url, interval=interval)
        return self

    def add_layer(self, layer: BaseLayer) -> ZugaShieldBuilder:
        """Register a custom layer to be added after build."""
        self._custom_layers.append(layer)
        return self

    def build(self) -> ZugaShield:
        config = self._config_builder.build()
        shield = ZugaShield(config=config)
        for layer in self._custom_layers:
            name = getattr(layer, "name", type(layer).__name__.lower())
            shield._layers[name] = layer
        return shield


# ===================================================================
# Module-level singleton + helpers
# ===================================================================


def get_zugashield() -> ZugaShield:
    """Get or create the module-level ZugaShield singleton."""
    global _singleton
    if _singleton is None:
        _singleton = ZugaShield()
    return _singleton


def set_zugashield(instance: ZugaShield) -> None:
    """Replace the module-level singleton (use for custom initialization)."""
    global _singleton
    _singleton = instance


def reset_zugashield() -> None:
    """Reset the singleton to None (useful for tests)."""
    global _singleton
    _singleton = None


def set_approval_provider(provider: Callable) -> None:
    """Set the human-in-the-loop approval provider for CHALLENGE verdicts."""
    global _approval_provider
    _approval_provider = provider


# ===================================================================
# Re-exports for convenience
# ===================================================================

__all__ = [
    # Facade
    "ZugaShield",
    "ZugaShieldBuilder",
    "get_zugashield",
    "set_zugashield",
    "reset_zugashield",
    "set_approval_provider",
    # Config
    "ShieldConfig",
    # Catalog
    "ThreatCatalog",
    # Types
    "ShieldDecision",
    "ShieldVerdict",
    "ThreatLevel",
    "ThreatCategory",
    "ThreatDetection",
    "AnomalyScore",
    # Version
    "__version__",
]
