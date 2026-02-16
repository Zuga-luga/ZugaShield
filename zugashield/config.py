"""
ZugaShield - Configuration
==========================

Environment-driven configuration for all shield layers.
All settings have sensible defaults so ZugaShield works out of the box.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field

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


@dataclass
class ShieldConfig:
    """Central configuration for all ZugaShield layers."""

    # Master toggle
    enabled: bool = True
    log_level: str = "INFO"
    strict_mode: bool = False  # true = block on medium threats

    # Layer toggles
    perimeter_enabled: bool = True
    prompt_armor_enabled: bool = True
    tool_guard_enabled: bool = True
    memory_sentinel_enabled: bool = True
    exfiltration_guard_enabled: bool = True
    anomaly_detector_enabled: bool = True
    wallet_fortress_enabled: bool = True

    # LLM Judge (optional deep analysis)
    llm_judge_enabled: bool = False

    # Perimeter thresholds
    max_message_size: int = 51200  # 50KB
    max_unicode_density: float = 0.3  # Flag if >30% non-ASCII

    # Tool guard
    tool_rate_limit: int = 30  # Global calls per minute
    sensitive_paths: list = field(default_factory=lambda: [
        ".ssh", ".env", ".git/config", "credentials", "secrets",
        "id_rsa", "id_ed25519", ".aws", ".kube", "token",
    ])

    # Anomaly detector
    anomaly_threshold: float = 60.0  # Score 0-100
    anomaly_decay_rate: float = 0.95

    # Wallet limits (in USD)
    wallet_tx_limit: float = 100.0
    wallet_hourly_limit: float = 500.0
    wallet_daily_limit: float = 2000.0
    wallet_approval_cooldown: int = 60  # seconds

    # Exfiltration guard
    egress_domain_allowlist: list = field(default_factory=list)

    @classmethod
    def from_env(cls) -> ShieldConfig:
        """Load configuration from environment variables."""
        config = cls(
            enabled=_env_bool("ZUGASHIELD_ENABLED", True),
            log_level=os.getenv("ZUGASHIELD_LOG_LEVEL", "INFO"),
            strict_mode=_env_bool("ZUGASHIELD_STRICT_MODE", False),
            perimeter_enabled=_env_bool("ZUGASHIELD_PERIMETER_ENABLED", True),
            prompt_armor_enabled=_env_bool("ZUGASHIELD_PROMPT_ARMOR_ENABLED", True),
            tool_guard_enabled=_env_bool("ZUGASHIELD_TOOL_GUARD_ENABLED", True),
            memory_sentinel_enabled=_env_bool("ZUGASHIELD_MEMORY_SENTINEL_ENABLED", True),
            exfiltration_guard_enabled=_env_bool("ZUGASHIELD_EXFILTRATION_GUARD_ENABLED", True),
            anomaly_detector_enabled=_env_bool("ZUGASHIELD_ANOMALY_DETECTOR_ENABLED", True),
            wallet_fortress_enabled=_env_bool("ZUGASHIELD_WALLET_FORTRESS_ENABLED", True),
            llm_judge_enabled=_env_bool("ZUGASHIELD_LLM_JUDGE_ENABLED", False),
            max_message_size=_env_int("ZUGASHIELD_MAX_MESSAGE_SIZE", 51200),
            tool_rate_limit=_env_int("ZUGASHIELD_TOOL_RATE_LIMIT", 30),
            anomaly_threshold=_env_float("ZUGASHIELD_ANOMALY_THRESHOLD", 60.0),
            wallet_tx_limit=_env_float("ZUGASHIELD_WALLET_TX_LIMIT", 100.0),
            wallet_hourly_limit=_env_float("ZUGASHIELD_WALLET_HOURLY_LIMIT", 500.0),
            wallet_daily_limit=_env_float("ZUGASHIELD_WALLET_DAILY_LIMIT", 2000.0),
            wallet_approval_cooldown=_env_int("ZUGASHIELD_WALLET_APPROVAL_COOLDOWN", 60),
        )

        # Allow environment override for sensitive paths
        sensitive_paths_env = os.getenv("ZUGASHIELD_SENSITIVE_PATHS")
        if sensitive_paths_env:
            config.sensitive_paths = [path.strip() for path in sensitive_paths_env.split(",")]

        logger.info(
            "[ZugaShield] Config loaded: enabled=%s, strict=%s, layers=%s",
            config.enabled,
            config.strict_mode,
            sum([
                config.perimeter_enabled, config.prompt_armor_enabled,
                config.tool_guard_enabled, config.memory_sentinel_enabled,
                config.exfiltration_guard_enabled, config.anomaly_detector_enabled,
                config.wallet_fortress_enabled,
            ]),
        )
        return config
