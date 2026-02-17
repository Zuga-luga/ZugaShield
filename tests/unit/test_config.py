"""
Unit tests for ShieldConfig.

Tests:
- Default values
- from_env() reads environment variables
- Frozen dataclass — mutation raises FrozenInstanceError
- Builder pattern constructs valid configs
"""

import dataclasses

import pytest

from zugashield.config import ShieldConfig


# =============================================================================
# Default values
# =============================================================================


class TestShieldConfigDefaults:
    """Default ShieldConfig values are sane for production use."""

    def test_enabled_by_default(self):
        cfg = ShieldConfig()
        assert cfg.enabled is True

    def test_fail_closed_by_default(self):
        """fail_closed must default True — never silently open on errors."""
        cfg = ShieldConfig()
        assert cfg.fail_closed is True

    def test_strict_mode_off_by_default(self):
        cfg = ShieldConfig()
        assert cfg.strict_mode is False

    def test_all_core_layers_enabled_by_default(self):
        cfg = ShieldConfig()
        assert cfg.perimeter_enabled is True
        assert cfg.prompt_armor_enabled is True
        assert cfg.tool_guard_enabled is True
        assert cfg.memory_sentinel_enabled is True
        assert cfg.exfiltration_guard_enabled is True
        assert cfg.anomaly_detector_enabled is True
        assert cfg.wallet_fortress_enabled is True

    def test_llm_judge_disabled_by_default(self):
        """LLM judge requires an API key — must be opt-in."""
        cfg = ShieldConfig()
        assert cfg.llm_judge_enabled is False

    def test_new_optional_layers_enabled_by_default(self):
        cfg = ShieldConfig()
        assert cfg.code_scanner_enabled is True
        assert cfg.cot_auditor_enabled is True
        assert cfg.mcp_guard_enabled is True

    def test_max_message_size_reasonable(self):
        """50 KB default keeps huge payloads from flooding context."""
        cfg = ShieldConfig()
        assert cfg.max_message_size == 51200

    def test_max_unicode_density_thirty_percent(self):
        cfg = ShieldConfig()
        assert cfg.max_unicode_density == pytest.approx(0.3)

    def test_wallet_tx_limit_conservative(self):
        cfg = ShieldConfig()
        assert cfg.wallet_tx_limit == pytest.approx(100.0)

    def test_wallet_hourly_limit(self):
        cfg = ShieldConfig()
        assert cfg.wallet_hourly_limit == pytest.approx(500.0)

    def test_wallet_daily_limit(self):
        cfg = ShieldConfig()
        assert cfg.wallet_daily_limit == pytest.approx(2000.0)

    def test_sensitive_paths_non_empty(self):
        cfg = ShieldConfig()
        assert len(cfg.sensitive_paths) > 0
        # Must include SSH key path and .env
        paths_str = " ".join(cfg.sensitive_paths)
        assert ".ssh" in paths_str or "id_rsa" in paths_str
        assert ".env" in paths_str or "credentials" in paths_str

    def test_sensitive_endpoints_non_empty(self):
        cfg = ShieldConfig()
        assert len(cfg.sensitive_endpoints) > 0

    def test_verify_signatures_on_by_default(self):
        cfg = ShieldConfig()
        assert cfg.verify_signatures is True

    def test_tool_rate_limit_positive(self):
        cfg = ShieldConfig()
        assert cfg.tool_rate_limit > 0


# =============================================================================
# from_env() reads environment variables
# =============================================================================


class TestShieldConfigFromEnv:
    """from_env() reads and applies all ZUGASHIELD_* env vars."""

    def test_from_env_returns_config(self):
        cfg = ShieldConfig.from_env()
        assert isinstance(cfg, ShieldConfig)

    def test_env_disabled(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_ENABLED", "false")
        cfg = ShieldConfig.from_env()
        assert cfg.enabled is False

    def test_env_strict_mode(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_STRICT_MODE", "true")
        cfg = ShieldConfig.from_env()
        assert cfg.strict_mode is True

    def test_env_fail_closed_false(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_FAIL_CLOSED", "false")
        cfg = ShieldConfig.from_env()
        assert cfg.fail_closed is False

    def test_env_prompt_armor_disabled(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_PROMPT_ARMOR_ENABLED", "0")
        cfg = ShieldConfig.from_env()
        assert cfg.prompt_armor_enabled is False

    def test_env_wallet_tx_limit(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_WALLET_TX_LIMIT", "250.0")
        cfg = ShieldConfig.from_env()
        assert cfg.wallet_tx_limit == pytest.approx(250.0)

    def test_env_max_message_size(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_MAX_MESSAGE_SIZE", "102400")
        cfg = ShieldConfig.from_env()
        assert cfg.max_message_size == 102400

    def test_env_egress_allowlist(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_EGRESS_ALLOWLIST", "api.openai.com,api.anthropic.com")
        cfg = ShieldConfig.from_env()
        assert "api.openai.com" in cfg.egress_domain_allowlist
        assert "api.anthropic.com" in cfg.egress_domain_allowlist

    def test_env_sensitive_paths(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_SENSITIVE_PATHS", "/etc/passwd,/etc/shadow,.ssh")
        cfg = ShieldConfig.from_env()
        assert "/etc/passwd" in cfg.sensitive_paths
        assert ".ssh" in cfg.sensitive_paths

    def test_env_llm_judge_enabled(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_LLM_JUDGE_ENABLED", "true")
        cfg = ShieldConfig.from_env()
        assert cfg.llm_judge_enabled is True

    def test_env_anomaly_threshold(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_ANOMALY_THRESHOLD", "45.0")
        cfg = ShieldConfig.from_env()
        assert cfg.anomaly_threshold == pytest.approx(45.0)

    def test_env_code_scanner_disabled(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_CODE_SCANNER_ENABLED", "false")
        cfg = ShieldConfig.from_env()
        assert cfg.code_scanner_enabled is False

    def test_env_cot_auditor_disabled(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_COT_AUDITOR_ENABLED", "false")
        cfg = ShieldConfig.from_env()
        assert cfg.cot_auditor_enabled is False

    def test_env_mcp_guard_disabled(self, monkeypatch):
        monkeypatch.setenv("ZUGASHIELD_MCP_GUARD_ENABLED", "false")
        cfg = ShieldConfig.from_env()
        assert cfg.mcp_guard_enabled is False

    def test_env_boolean_truthy_values(self, monkeypatch):
        """'1' and 'yes' should also be treated as True."""
        monkeypatch.setenv("ZUGASHIELD_ENABLED", "1")
        cfg = ShieldConfig.from_env()
        assert cfg.enabled is True

        monkeypatch.setenv("ZUGASHIELD_STRICT_MODE", "yes")
        cfg = ShieldConfig.from_env()
        assert cfg.strict_mode is True


# =============================================================================
# Frozen dataclass — mutation raises FrozenInstanceError
# =============================================================================


class TestShieldConfigFrozen:
    """ShieldConfig is frozen — no runtime mutation allowed."""

    def test_cannot_set_enabled(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.enabled = False  # type: ignore[misc]

    def test_cannot_set_fail_closed(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.fail_closed = False  # type: ignore[misc]

    def test_cannot_set_strict_mode(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.strict_mode = True  # type: ignore[misc]

    def test_cannot_set_wallet_tx_limit(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.wallet_tx_limit = 99999.0  # type: ignore[misc]

    def test_cannot_add_new_attribute(self):
        cfg = ShieldConfig()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            cfg.new_field = "injected"  # type: ignore[attr-defined]

    def test_config_is_hashable(self):
        """Frozen dataclasses are hashable by default."""
        cfg = ShieldConfig()
        # Should not raise
        h = hash(cfg)
        assert isinstance(h, int)

    def test_two_identical_configs_are_equal(self):
        cfg1 = ShieldConfig()
        cfg2 = ShieldConfig()
        assert cfg1 == cfg2


# =============================================================================
# Builder pattern
# =============================================================================


class TestShieldConfigBuilder:
    """Builder constructs valid, customised ShieldConfig objects."""

    def test_builder_returns_shield_config(self):
        cfg = ShieldConfig.builder().build()
        assert isinstance(cfg, ShieldConfig)

    def test_builder_fail_closed(self):
        cfg = ShieldConfig.builder().fail_closed(True).build()
        assert cfg.fail_closed is True

    def test_builder_fail_open(self):
        cfg = ShieldConfig.builder().fail_closed(False).build()
        assert cfg.fail_closed is False

    def test_builder_strict_mode(self):
        cfg = ShieldConfig.builder().strict_mode(True).build()
        assert cfg.strict_mode is True

    def test_builder_enable_layers_restricts_to_listed(self):
        """enable_layers disables layers NOT listed."""
        cfg = (
            ShieldConfig.builder()
            .enable_layers("prompt_armor", "tool_guard")
            .build()
        )
        assert cfg.prompt_armor_enabled is True
        assert cfg.tool_guard_enabled is True
        assert cfg.perimeter_enabled is False
        assert cfg.memory_sentinel_enabled is False
        assert cfg.wallet_fortress_enabled is False

    def test_builder_disable_specific_layer(self):
        cfg = (
            ShieldConfig.builder()
            .disable_layers("wallet_fortress", "llm_judge")
            .build()
        )
        assert cfg.wallet_fortress_enabled is False
        assert cfg.llm_judge_enabled is False
        # Other layers are unaffected
        assert cfg.prompt_armor_enabled is True
        assert cfg.tool_guard_enabled is True

    def test_builder_set_wallet_limits(self):
        cfg = (
            ShieldConfig.builder()
            .set_wallet_limits(tx_limit=50.0, hourly_limit=200.0, daily_limit=800.0)
            .build()
        )
        assert cfg.wallet_tx_limit == pytest.approx(50.0)
        assert cfg.wallet_hourly_limit == pytest.approx(200.0)
        assert cfg.wallet_daily_limit == pytest.approx(800.0)

    def test_builder_set_egress_allowlist(self):
        cfg = (
            ShieldConfig.builder()
            .set_egress_allowlist("api.example.com", "cdn.example.com")
            .build()
        )
        assert "api.example.com" in cfg.egress_domain_allowlist
        assert "cdn.example.com" in cfg.egress_domain_allowlist

    def test_builder_set_tool_policy(self):
        cfg = (
            ShieldConfig.builder()
            .set_tool_policy("local_bash", rate=5, approval=True, risk="critical")
            .build()
        )
        assert len(cfg.tool_risk_overrides) == 1
        tool_entry = cfg.tool_risk_overrides[0]
        assert tool_entry[0] == "local_bash"
        assert tool_entry[1] == 5
        assert tool_entry[2] is True
        assert tool_entry[3] == "critical"

    def test_builder_add_sensitive_endpoint(self):
        cfg = (
            ShieldConfig.builder()
            .add_sensitive_endpoint("/api/wallet", rate_limit=5)
            .build()
        )
        endpoint_paths = [ep[0] for ep in cfg.sensitive_endpoints]
        assert "/api/wallet" in endpoint_paths

    def test_builder_set_llm_provider(self):
        cfg = (
            ShieldConfig.builder()
            .set_llm_provider("anthropic", model="claude-3-5-haiku-20241022")
            .build()
        )
        assert cfg.llm_provider == "anthropic"
        assert cfg.llm_model == "claude-3-5-haiku-20241022"
        assert cfg.llm_judge_enabled is True

    def test_builder_result_is_frozen(self):
        """Built config must also be frozen."""
        cfg = ShieldConfig.builder().build()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.enabled = False  # type: ignore[misc]

    def test_builder_chaining_is_fluent(self):
        """All builder methods return the builder for chaining."""
        builder = ShieldConfig.builder()
        result = builder.fail_closed(True).strict_mode(False).disable_layers("llm_judge")
        assert result is builder

    def test_builder_default_equals_direct_construction_mostly(self):
        """An empty builder should yield equivalent config to plain defaults."""
        direct = ShieldConfig()
        built = ShieldConfig.builder().build()
        # Core safety-critical fields must match
        assert built.enabled == direct.enabled
        assert built.fail_closed == direct.fail_closed
        assert built.prompt_armor_enabled == direct.prompt_armor_enabled
        assert built.tool_guard_enabled == direct.tool_guard_enabled
