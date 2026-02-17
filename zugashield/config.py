"""
ZugaShield - Configuration
==========================

Immutable, environment-driven configuration for all shield layers.
All settings have sensible defaults so ZugaShield works out of the box.

The config is frozen after creation to prevent runtime mutation attacks.
Use the builder pattern or `from_env()` to construct.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Optional, Tuple

logger = logging.getLogger(__name__)


def _env_bool(key: str, default: bool = True) -> bool:
    return os.getenv(key, str(default)).lower() in ("true", "1", "yes")


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class ShieldConfig:
    """
    Central configuration for all ZugaShield layers.

    Frozen after creation to prevent runtime config mutation attacks (Fix #2).
    Use ``ShieldConfig.from_env()`` or ``ShieldConfig.builder()`` to construct.
    """

    # Master toggle
    enabled: bool = True
    log_level: str = "INFO"
    strict_mode: bool = False  # true = block on medium threats

    # Fail-closed mode (Fix #1): if a layer throws, BLOCK instead of ALLOW
    fail_closed: bool = True

    # Layer toggles
    perimeter_enabled: bool = True
    prompt_armor_enabled: bool = True
    tool_guard_enabled: bool = True
    memory_sentinel_enabled: bool = True
    exfiltration_guard_enabled: bool = True
    anomaly_detector_enabled: bool = True
    wallet_fortress_enabled: bool = True
    llm_judge_enabled: bool = False
    code_scanner_enabled: bool = True
    cot_auditor_enabled: bool = True
    mcp_guard_enabled: bool = True

    # Perimeter thresholds
    max_message_size: int = 51200  # 50KB
    max_unicode_density: float = 0.3  # Flag if >30% non-ASCII

    # Parameterized sensitive endpoints (Fix: was hardcoded Zugabot paths)
    # Maps endpoint prefix -> requests per minute
    sensitive_endpoints: Tuple[Tuple[str, int], ...] = (
        ("/api/admin", 10),
        ("/admin", 10),
        ("/api/auth", 20),
    )

    # Tool guard
    tool_rate_limit: int = 30  # Global calls per minute
    sensitive_paths: Tuple[str, ...] = (
        ".ssh", ".env", ".git/config", "credentials",
        "secrets", "id_rsa", "id_ed25519", ".aws",
        ".kube", "token",
    )

    # Parameterized tool risk matrix (Fix: was hardcoded Zugabot tool names)
    # Maps tool_name -> (rate, requires_approval, risk_level)
    tool_risk_overrides: Tuple[Tuple[str, int, bool, str], ...] = ()

    # Anomaly detector
    anomaly_threshold: float = 60.0  # Score 0-100
    anomaly_decay_rate: float = 0.95

    # Wallet limits (in USD)
    wallet_tx_limit: float = 100.0
    wallet_hourly_limit: float = 500.0
    wallet_daily_limit: float = 2000.0
    wallet_approval_cooldown: int = 60  # seconds

    # Exfiltration guard
    egress_domain_allowlist: Tuple[str, ...] = ()

    # Multimodal scanner
    multimodal_degradation_mode: str = "warn"  # "warn" | "block" | "allow"

    # LLM Judge provider config
    llm_provider: Optional[str] = None  # "anthropic" | "openai" | "litellm" | None (auto-detect)
    llm_model: Optional[str] = None  # Override model name

    # Signature integrity verification (Fix #12)
    verify_signatures: bool = True

    # Config lock — prevents even builder from creating new configs at runtime
    _locked: bool = False

    @classmethod
    def from_env(cls) -> ShieldConfig:
        """Load configuration from environment variables."""
        # Parse sensitive endpoints from env
        endpoints_env = os.getenv("ZUGASHIELD_SENSITIVE_ENDPOINTS")
        endpoints: Tuple[Tuple[str, int], ...] = cls.__dataclass_fields__["sensitive_endpoints"].default
        if endpoints_env:
            parsed = []
            for item in endpoints_env.split(","):
                parts = item.strip().split(":")
                if len(parts) == 2:
                    parsed.append((parts[0].strip(), int(parts[1].strip())))
            if parsed:
                endpoints = tuple(parsed)

        # Parse sensitive paths from env
        paths_env = os.getenv("ZUGASHIELD_SENSITIVE_PATHS")
        paths = cls.__dataclass_fields__["sensitive_paths"].default
        if paths_env:
            paths = tuple(p.strip() for p in paths_env.split(","))

        # Parse egress allowlist from env
        egress_env = os.getenv("ZUGASHIELD_EGRESS_ALLOWLIST")
        egress: Tuple[str, ...] = ()
        if egress_env:
            egress = tuple(d.strip() for d in egress_env.split(","))

        config = cls(
            enabled=_env_bool("ZUGASHIELD_ENABLED", True),
            log_level=os.getenv("ZUGASHIELD_LOG_LEVEL", "INFO"),
            strict_mode=_env_bool("ZUGASHIELD_STRICT_MODE", False),
            fail_closed=_env_bool("ZUGASHIELD_FAIL_CLOSED", True),
            perimeter_enabled=_env_bool("ZUGASHIELD_PERIMETER_ENABLED", True),
            prompt_armor_enabled=_env_bool("ZUGASHIELD_PROMPT_ARMOR_ENABLED", True),
            tool_guard_enabled=_env_bool("ZUGASHIELD_TOOL_GUARD_ENABLED", True),
            memory_sentinel_enabled=_env_bool("ZUGASHIELD_MEMORY_SENTINEL_ENABLED", True),
            exfiltration_guard_enabled=_env_bool("ZUGASHIELD_EXFILTRATION_GUARD_ENABLED", True),
            anomaly_detector_enabled=_env_bool("ZUGASHIELD_ANOMALY_DETECTOR_ENABLED", True),
            wallet_fortress_enabled=_env_bool("ZUGASHIELD_WALLET_FORTRESS_ENABLED", True),
            llm_judge_enabled=_env_bool("ZUGASHIELD_LLM_JUDGE_ENABLED", False),
            code_scanner_enabled=_env_bool("ZUGASHIELD_CODE_SCANNER_ENABLED", True),
            cot_auditor_enabled=_env_bool("ZUGASHIELD_COT_AUDITOR_ENABLED", True),
            mcp_guard_enabled=_env_bool("ZUGASHIELD_MCP_GUARD_ENABLED", True),
            max_message_size=_env_int("ZUGASHIELD_MAX_MESSAGE_SIZE", 51200),
            max_unicode_density=_env_float("ZUGASHIELD_MAX_UNICODE_DENSITY", 0.3),
            tool_rate_limit=_env_int("ZUGASHIELD_TOOL_RATE_LIMIT", 30),
            anomaly_threshold=_env_float("ZUGASHIELD_ANOMALY_THRESHOLD", 60.0),
            anomaly_decay_rate=_env_float("ZUGASHIELD_ANOMALY_DECAY_RATE", 0.95),
            wallet_tx_limit=_env_float("ZUGASHIELD_WALLET_TX_LIMIT", 100.0),
            wallet_hourly_limit=_env_float("ZUGASHIELD_WALLET_HOURLY_LIMIT", 500.0),
            wallet_daily_limit=_env_float("ZUGASHIELD_WALLET_DAILY_LIMIT", 2000.0),
            wallet_approval_cooldown=_env_int("ZUGASHIELD_WALLET_APPROVAL_COOLDOWN", 60),
            sensitive_endpoints=endpoints,
            sensitive_paths=paths,
            egress_domain_allowlist=egress,
            multimodal_degradation_mode=os.getenv("ZUGASHIELD_MULTIMODAL_DEGRADATION", "warn"),
            llm_provider=os.getenv("ZUGASHIELD_LLM_PROVIDER"),
            llm_model=os.getenv("ZUGASHIELD_LLM_MODEL"),
            verify_signatures=_env_bool("ZUGASHIELD_VERIFY_SIGNATURES", True),
            _locked=_env_bool("ZUGASHIELD_LOCK_CONFIG", False),
        )

        logger.info(
            "[ZugaShield] Config loaded: enabled=%s, strict=%s, fail_closed=%s",
            config.enabled,
            config.strict_mode,
            config.fail_closed,
        )
        return config

    @classmethod
    def builder(cls) -> _ShieldConfigBuilder:
        """Create a builder for fluent configuration."""
        return _ShieldConfigBuilder()


class _ShieldConfigBuilder:
    """Fluent builder for ShieldConfig."""

    def __init__(self) -> None:
        self._kwargs: Dict[str, Any] = {}
        self._tool_overrides: list = []
        self._endpoints: list = []

    def fail_closed(self, value: bool = True) -> _ShieldConfigBuilder:
        self._kwargs["fail_closed"] = value
        return self

    def strict_mode(self, value: bool = True) -> _ShieldConfigBuilder:
        self._kwargs["strict_mode"] = value
        return self

    def enable_layers(self, *layers: str) -> _ShieldConfigBuilder:
        all_layers = [
            "perimeter", "prompt_armor", "tool_guard", "memory_sentinel",
            "exfiltration_guard", "anomaly_detector", "wallet_fortress",
            "llm_judge", "code_scanner", "cot_auditor", "mcp_guard",
        ]
        for layer in all_layers:
            key = f"{layer}_enabled"
            self._kwargs[key] = layer in layers
        return self

    def disable_layers(self, *layers: str) -> _ShieldConfigBuilder:
        for layer in layers:
            key = f"{layer}_enabled"
            self._kwargs[key] = False
        return self

    def set_tool_policy(
        self, tool_name: str, rate: int = 15, approval: bool = False, risk: str = "medium"
    ) -> _ShieldConfigBuilder:
        self._tool_overrides.append((tool_name, rate, approval, risk))
        return self

    def add_sensitive_endpoint(
        self, path: str, rate_limit: int = 10
    ) -> _ShieldConfigBuilder:
        self._endpoints.append((path, rate_limit))
        return self

    def set_egress_allowlist(self, *domains: str) -> _ShieldConfigBuilder:
        self._kwargs["egress_domain_allowlist"] = tuple(domains)
        return self

    def set_wallet_limits(
        self,
        tx_limit: float = 100.0,
        hourly_limit: float = 500.0,
        daily_limit: float = 2000.0,
    ) -> _ShieldConfigBuilder:
        self._kwargs["wallet_tx_limit"] = tx_limit
        self._kwargs["wallet_hourly_limit"] = hourly_limit
        self._kwargs["wallet_daily_limit"] = daily_limit
        return self

    def set_llm_provider(
        self, provider: str, model: Optional[str] = None
    ) -> _ShieldConfigBuilder:
        self._kwargs["llm_provider"] = provider
        self._kwargs["llm_judge_enabled"] = True
        if model:
            self._kwargs["llm_model"] = model
        return self

    def set_anomaly_threshold(self, threshold: float) -> _ShieldConfigBuilder:
        self._kwargs["anomaly_threshold"] = threshold
        return self

    def set_degradation_mode(self, mode: str) -> _ShieldConfigBuilder:
        self._kwargs["multimodal_degradation_mode"] = mode
        return self

    def build(self) -> ShieldConfig:
        if self._tool_overrides:
            self._kwargs["tool_risk_overrides"] = tuple(self._tool_overrides)
        if self._endpoints:
            # Merge with defaults
            defaults = list(ShieldConfig.__dataclass_fields__["sensitive_endpoints"].default)
            self._kwargs["sensitive_endpoints"] = tuple(defaults + self._endpoints)
        return ShieldConfig(**self._kwargs)
