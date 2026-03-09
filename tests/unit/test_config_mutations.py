"""
Mutation tests for zugashield/config.py.

Each test is written to kill a specific mutant — a plausible single-line
change a mutation tool (e.g. mutmut, cosmic-ray) would introduce.
The file is intentionally exhaustive: every constant, comparison operator,
boolean default, and branch in config.py has at least one test that would
fail if that value were changed.

Coverage targets
----------------
_env_bool       — truthy set membership, case folding, default passthrough
_env_int        — normal path, default passthrough, ValueError recovery
_env_float      — normal path, default passthrough, ValueError recovery
ShieldConfig    — every default field value
from_env()      — env-var → field mapping, clamp logic, parsing branches
builder         — all mutating methods, chaining, merge logic
frozen          — immutability after construction
"""

import dataclasses
import os
from unittest.mock import patch

import pytest

from zugashield.config import ShieldConfig, _ShieldConfigBuilder, _env_bool, _env_int, _env_float


# =============================================================================
# _env_bool — kills mutants on tuple membership and .lower()
# =============================================================================


class TestEnvBool:
    """Every truthy token and the lower() call must survive mutation."""

    # --- Explicit truthy tokens ---

    def test_env_bool_true_lowercase(self):
        with patch.dict(os.environ, {"_ZS_TEST": "true"}, clear=False):
            assert _env_bool("_ZS_TEST", False) is True

    def test_env_bool_one_is_truthy(self):
        """Kills mutant: removes '1' from the membership tuple."""
        with patch.dict(os.environ, {"_ZS_TEST": "1"}, clear=False):
            assert _env_bool("_ZS_TEST", False) is True

    def test_env_bool_yes_is_truthy(self):
        """Kills mutant: removes 'yes' from the membership tuple."""
        with patch.dict(os.environ, {"_ZS_TEST": "yes"}, clear=False):
            assert _env_bool("_ZS_TEST", False) is True

    # --- Case-insensitive: kills mutant removing .lower() ---

    def test_env_bool_True_capital(self):
        """Kills mutant: removes .lower(), so 'True' != 'true'."""
        with patch.dict(os.environ, {"_ZS_TEST": "True"}, clear=False):
            assert _env_bool("_ZS_TEST", False) is True

    def test_env_bool_TRUE_uppercase(self):
        with patch.dict(os.environ, {"_ZS_TEST": "TRUE"}, clear=False):
            assert _env_bool("_ZS_TEST", False) is True

    def test_env_bool_Yes_mixed(self):
        with patch.dict(os.environ, {"_ZS_TEST": "Yes"}, clear=False):
            assert _env_bool("_ZS_TEST", False) is True

    def test_env_bool_YES_uppercase(self):
        with patch.dict(os.environ, {"_ZS_TEST": "YES"}, clear=False):
            assert _env_bool("_ZS_TEST", False) is True

    def test_env_bool_ONE_uppercase_not_in_tuple(self):
        """'1' has no case variant — still truthy regardless of .lower()."""
        with patch.dict(os.environ, {"_ZS_TEST": "1"}, clear=False):
            assert _env_bool("_ZS_TEST", False) is True

    # --- Explicit falsy tokens ---

    def test_env_bool_false_string_is_falsy(self):
        with patch.dict(os.environ, {"_ZS_TEST": "false"}, clear=False):
            assert _env_bool("_ZS_TEST", True) is False

    def test_env_bool_zero_string_is_falsy(self):
        with patch.dict(os.environ, {"_ZS_TEST": "0"}, clear=False):
            assert _env_bool("_ZS_TEST", True) is False

    def test_env_bool_no_string_is_falsy(self):
        with patch.dict(os.environ, {"_ZS_TEST": "no"}, clear=False):
            assert _env_bool("_ZS_TEST", True) is False

    def test_env_bool_empty_string_is_falsy(self):
        with patch.dict(os.environ, {"_ZS_TEST": ""}, clear=False):
            assert _env_bool("_ZS_TEST", True) is False

    def test_env_bool_random_string_is_falsy(self):
        with patch.dict(os.environ, {"_ZS_TEST": "enabled"}, clear=False):
            assert _env_bool("_ZS_TEST", True) is False

    # --- Default passthrough (no env var set) ---

    def test_env_bool_default_true_returns_true(self):
        """Kills mutant: default=True stringified to 'True', which lowercases to 'true'."""
        env = {k: v for k, v in os.environ.items() if k != "_ZS_TEST"}
        with patch.dict(os.environ, env, clear=True):
            assert _env_bool("_ZS_TEST", True) is True

    def test_env_bool_default_false_returns_false(self):
        """Kills mutant: default=False stringified to 'False', lowercased 'false' not in tuple."""
        env = {k: v for k, v in os.environ.items() if k != "_ZS_TEST"}
        with patch.dict(os.environ, env, clear=True):
            assert _env_bool("_ZS_TEST", False) is False

    def test_env_bool_default_true_not_using_default_false(self):
        """Ensures default parameter is used, not a hardcoded fallback."""
        env = {k: v for k, v in os.environ.items() if k != "_ZS_TEST"}
        with patch.dict(os.environ, env, clear=True):
            # default=True returns True; if mutant replaces default with False it would fail
            result_true = _env_bool("_ZS_TEST", True)
            result_false = _env_bool("_ZS_TEST", False)
            assert result_true is not result_false


# =============================================================================
# _env_int — kills mutants on return value in ValueError branch
# =============================================================================


class TestEnvInt:
    """Kills mutant: ValueError handler returns 0 instead of default."""

    def test_env_int_parses_valid_string(self):
        with patch.dict(os.environ, {"_ZS_INT": "42"}, clear=False):
            assert _env_int("_ZS_INT", 99) == 42

    def test_env_int_returns_default_when_unset(self):
        env = {k: v for k, v in os.environ.items() if k != "_ZS_INT"}
        with patch.dict(os.environ, env, clear=True):
            assert _env_int("_ZS_INT", 99) == 99

    def test_env_int_default_not_zero_when_unset(self):
        """Kills mutant: returns 0 instead of default when key missing."""
        env = {k: v for k, v in os.environ.items() if k != "_ZS_INT"}
        with patch.dict(os.environ, env, clear=True):
            assert _env_int("_ZS_INT", 77) == 77

    def test_env_int_returns_default_on_value_error(self):
        """Kills mutant: ValueError branch returns 0 not default."""
        with patch.dict(os.environ, {"_ZS_INT": "abc"}, clear=False):
            assert _env_int("_ZS_INT", 55) == 55

    def test_env_int_value_error_does_not_return_zero(self):
        """Distinct default ensures '0 vs default' is caught."""
        with patch.dict(os.environ, {"_ZS_INT": "not_a_number"}, clear=False):
            assert _env_int("_ZS_INT", 123) == 123

    def test_env_int_value_error_does_not_raise(self):
        """ValueError must be swallowed, not re-raised."""
        with patch.dict(os.environ, {"_ZS_INT": "!!!"}, clear=False):
            result = _env_int("_ZS_INT", 7)
            assert result == 7

    def test_env_int_negative_value(self):
        with patch.dict(os.environ, {"_ZS_INT": "-5"}, clear=False):
            assert _env_int("_ZS_INT", 0) == -5

    def test_env_int_zero_value(self):
        with patch.dict(os.environ, {"_ZS_INT": "0"}, clear=False):
            assert _env_int("_ZS_INT", 99) == 0


# =============================================================================
# _env_float — same pattern as _env_int, for floats
# =============================================================================


class TestEnvFloat:
    """Kills mutant: ValueError handler returns 0.0 instead of default."""

    def test_env_float_parses_valid_string(self):
        with patch.dict(os.environ, {"_ZS_FLT": "3.14"}, clear=False):
            assert _env_float("_ZS_FLT", 0.0) == pytest.approx(3.14)

    def test_env_float_returns_default_when_unset(self):
        env = {k: v for k, v in os.environ.items() if k != "_ZS_FLT"}
        with patch.dict(os.environ, env, clear=True):
            assert _env_float("_ZS_FLT", 9.9) == pytest.approx(9.9)

    def test_env_float_default_not_zero_when_unset(self):
        """Kills mutant: returns 0.0 instead of default when key missing."""
        env = {k: v for k, v in os.environ.items() if k != "_ZS_FLT"}
        with patch.dict(os.environ, env, clear=True):
            assert _env_float("_ZS_FLT", 7.7) == pytest.approx(7.7)

    def test_env_float_returns_default_on_value_error(self):
        """Kills mutant: ValueError branch returns 0.0 not default."""
        with patch.dict(os.environ, {"_ZS_FLT": "not_float"}, clear=False):
            assert _env_float("_ZS_FLT", 2.5) == pytest.approx(2.5)

    def test_env_float_value_error_does_not_return_zero_float(self):
        """Distinct non-zero default ensures 0.0 substitution is caught."""
        with patch.dict(os.environ, {"_ZS_FLT": "???"}, clear=False):
            assert _env_float("_ZS_FLT", 8.8) == pytest.approx(8.8)

    def test_env_float_value_error_does_not_raise(self):
        with patch.dict(os.environ, {"_ZS_FLT": "abc"}, clear=False):
            result = _env_float("_ZS_FLT", 1.1)
            assert result == pytest.approx(1.1)

    def test_env_float_integer_string_parsed_as_float(self):
        with patch.dict(os.environ, {"_ZS_FLT": "42"}, clear=False):
            assert _env_float("_ZS_FLT", 0.0) == pytest.approx(42.0)

    def test_env_float_negative_value(self):
        with patch.dict(os.environ, {"_ZS_FLT": "-0.5"}, clear=False):
            assert _env_float("_ZS_FLT", 0.0) == pytest.approx(-0.5)


# =============================================================================
# ShieldConfig defaults — kills off-by-one and wrong-default mutants
# =============================================================================


class TestShieldConfigDefaultValues:
    """
    Each assertion targets a specific literal in config.py.
    An off-by-one or sign flip in that literal kills the test.
    """

    # --- Master flags ---

    def test_default_enabled_is_true(self):
        """Kills mutant: enabled=False."""
        assert ShieldConfig().enabled is True

    def test_default_fail_closed_is_true(self):
        """Kills mutant: fail_closed=False (security regression)."""
        assert ShieldConfig().fail_closed is True

    def test_default_strict_mode_is_false(self):
        """Kills mutant: strict_mode=True (would block medium threats by default)."""
        assert ShieldConfig().strict_mode is False

    # --- Layer toggles ---

    def test_default_perimeter_enabled_true(self):
        assert ShieldConfig().perimeter_enabled is True

    def test_default_prompt_armor_enabled_true(self):
        assert ShieldConfig().prompt_armor_enabled is True

    def test_default_tool_guard_enabled_true(self):
        assert ShieldConfig().tool_guard_enabled is True

    def test_default_memory_sentinel_enabled_true(self):
        assert ShieldConfig().memory_sentinel_enabled is True

    def test_default_exfiltration_guard_enabled_true(self):
        assert ShieldConfig().exfiltration_guard_enabled is True

    def test_default_anomaly_detector_enabled_true(self):
        assert ShieldConfig().anomaly_detector_enabled is True

    def test_default_wallet_fortress_enabled_true(self):
        assert ShieldConfig().wallet_fortress_enabled is True

    def test_default_llm_judge_enabled_is_false(self):
        """Kills mutant: llm_judge_enabled=True (requires API key, unsafe default)."""
        assert ShieldConfig().llm_judge_enabled is False

    def test_default_code_scanner_enabled_true(self):
        assert ShieldConfig().code_scanner_enabled is True

    def test_default_cot_auditor_enabled_true(self):
        assert ShieldConfig().cot_auditor_enabled is True

    def test_default_mcp_guard_enabled_true(self):
        assert ShieldConfig().mcp_guard_enabled is True

    # --- ML detector ---

    def test_default_ml_detector_enabled_true(self):
        assert ShieldConfig().ml_detector_enabled is True

    def test_default_ml_confidence_threshold_exact(self):
        """Kills mutant: 0.5 or 0.9 instead of 0.7."""
        assert ShieldConfig().ml_confidence_threshold == pytest.approx(0.7)

    def test_default_ml_confidence_threshold_not_below_0_7(self):
        assert ShieldConfig().ml_confidence_threshold >= 0.7

    def test_default_ml_confidence_threshold_not_above_0_7(self):
        assert ShieldConfig().ml_confidence_threshold <= 0.7

    # --- Perimeter thresholds ---

    def test_default_max_message_size_exact(self):
        """Kills mutant: 50000 or 52000 instead of 51200 (50 KB)."""
        assert ShieldConfig().max_message_size == 51200

    def test_default_max_message_size_not_50000(self):
        assert ShieldConfig().max_message_size != 50000

    def test_default_max_message_size_not_52000(self):
        assert ShieldConfig().max_message_size != 52000

    def test_default_max_unicode_density_exact(self):
        """Kills mutant: 0.1 or 0.5 instead of 0.3."""
        assert ShieldConfig().max_unicode_density == pytest.approx(0.3)

    # --- Tool guard ---

    def test_default_tool_rate_limit_exact(self):
        """Kills mutant: 20 or 60 instead of 30."""
        assert ShieldConfig().tool_rate_limit == 30

    # --- Anomaly detector ---

    def test_default_anomaly_threshold_exact(self):
        """Kills mutant: 50.0 or 70.0 instead of 60.0."""
        assert ShieldConfig().anomaly_threshold == pytest.approx(60.0)

    def test_default_anomaly_decay_rate_exact(self):
        """Kills mutant: 0.9 or 0.99 instead of 0.95."""
        assert ShieldConfig().anomaly_decay_rate == pytest.approx(0.95)

    # --- Wallet limits ---

    def test_default_wallet_tx_limit_exact(self):
        """Kills mutant: 10.0 or 1000.0 instead of 100.0."""
        assert ShieldConfig().wallet_tx_limit == pytest.approx(100.0)

    def test_default_wallet_hourly_limit_exact(self):
        """Kills mutant: 200.0 or 5000.0 instead of 500.0."""
        assert ShieldConfig().wallet_hourly_limit == pytest.approx(500.0)

    def test_default_wallet_daily_limit_exact(self):
        """Kills mutant: 1000.0 or 20000.0 instead of 2000.0."""
        assert ShieldConfig().wallet_daily_limit == pytest.approx(2000.0)

    def test_default_wallet_approval_cooldown_exact(self):
        """Kills mutant: 30 or 120 instead of 60 seconds."""
        assert ShieldConfig().wallet_approval_cooldown == 60

    # --- Feed ---

    def test_default_feed_enabled_is_false(self):
        """Kills mutant: feed_enabled=True (opt-in must be explicit)."""
        assert ShieldConfig().feed_enabled is False

    def test_default_feed_poll_interval_exact(self):
        """Kills mutant: 1800 or 7200 instead of 3600."""
        assert ShieldConfig().feed_poll_interval == 3600

    def test_default_feed_startup_jitter_exact(self):
        """Kills mutant: 0 or 600 instead of 300."""
        assert ShieldConfig().feed_startup_jitter == 300

    def test_default_feed_timeout_exact(self):
        """Kills mutant: 10 or 60 instead of 30."""
        assert ShieldConfig().feed_timeout == 30

    # --- Signature integrity ---

    def test_default_verify_signatures_is_true(self):
        """Kills mutant: verify_signatures=False (security regression)."""
        assert ShieldConfig().verify_signatures is True

    # --- Sensitive endpoints: exactly 3 default entries ---

    def test_default_sensitive_endpoints_count(self):
        """Kills mutant: adds or removes an entry from the default tuple."""
        assert len(ShieldConfig().sensitive_endpoints) == 3

    def test_default_sensitive_endpoints_has_api_admin(self):
        paths = [ep[0] for ep in ShieldConfig().sensitive_endpoints]
        assert "/api/admin" in paths

    def test_default_sensitive_endpoints_has_admin(self):
        paths = [ep[0] for ep in ShieldConfig().sensitive_endpoints]
        assert "/admin" in paths

    def test_default_sensitive_endpoints_has_api_auth(self):
        paths = [ep[0] for ep in ShieldConfig().sensitive_endpoints]
        assert "/api/auth" in paths

    def test_default_sensitive_endpoints_api_admin_rate(self):
        """Kills mutant: rate 5 or 20 instead of 10 for /api/admin."""
        rates = {ep[0]: ep[1] for ep in ShieldConfig().sensitive_endpoints}
        assert rates["/api/admin"] == 10

    def test_default_sensitive_endpoints_admin_rate(self):
        rates = {ep[0]: ep[1] for ep in ShieldConfig().sensitive_endpoints}
        assert rates["/admin"] == 10

    def test_default_sensitive_endpoints_api_auth_rate(self):
        """Kills mutant: rate 10 or 30 instead of 20 for /api/auth."""
        rates = {ep[0]: ep[1] for ep in ShieldConfig().sensitive_endpoints}
        assert rates["/api/auth"] == 20

    # --- Sensitive paths ---

    def test_default_sensitive_paths_contains_ssh(self):
        assert ".ssh" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_env(self):
        assert ".env" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_git_config(self):
        assert ".git/config" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_credentials(self):
        assert "credentials" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_secrets(self):
        assert "secrets" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_id_rsa(self):
        assert "id_rsa" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_id_ed25519(self):
        assert "id_ed25519" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_aws(self):
        assert ".aws" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_kube(self):
        assert ".kube" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_contains_token(self):
        assert "token" in ShieldConfig().sensitive_paths

    def test_default_sensitive_paths_total_count(self):
        """Kills mutant: adding or removing entries silently."""
        assert len(ShieldConfig().sensitive_paths) == 10


# =============================================================================
# ShieldConfig.from_env() — kills env-var mapping and clamp mutants
# =============================================================================


class TestShieldConfigFromEnv:
    """
    Every ZUGASHIELD_* variable is tested against its field.
    Uses patch.dict with clear=True to guarantee isolation.
    """

    def _base_env(self) -> dict:
        """Return a minimal env dict that overrides nothing but keeps PATH."""
        return {"PATH": os.environ.get("PATH", "")}

    def test_from_env_enabled_false(self):
        """Kills mutant: ENABLED env var mapped to wrong field."""
        with patch.dict(os.environ, {**self._base_env(), "ZUGASHIELD_ENABLED": "false"}, clear=True):
            cfg = ShieldConfig.from_env()
        assert cfg.enabled is False

    def test_from_env_enabled_true_explicit(self):
        with patch.dict(os.environ, {**self._base_env(), "ZUGASHIELD_ENABLED": "true"}, clear=True):
            cfg = ShieldConfig.from_env()
        assert cfg.enabled is True

    def test_from_env_strict_mode_true(self):
        """Kills mutant: STRICT_MODE mapped to fail_closed or another field."""
        with patch.dict(os.environ, {**self._base_env(), "ZUGASHIELD_STRICT_MODE": "true"}, clear=True):
            cfg = ShieldConfig.from_env()
        assert cfg.strict_mode is True

    def test_from_env_fail_closed_false(self):
        """Kills mutant: FAIL_CLOSED mapped to wrong field or default ignored."""
        with patch.dict(os.environ, {**self._base_env(), "ZUGASHIELD_FAIL_CLOSED": "false"}, clear=True):
            cfg = ShieldConfig.from_env()
        assert cfg.fail_closed is False

    def test_from_env_max_message_size(self):
        with patch.dict(os.environ, {**self._base_env(), "ZUGASHIELD_MAX_MESSAGE_SIZE": "1024"}, clear=True):
            cfg = ShieldConfig.from_env()
        assert cfg.max_message_size == 1024

    def test_from_env_sensitive_endpoints_custom(self):
        """Kills mutant: custom endpoints not parsed or split on wrong delimiter."""
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_SENSITIVE_ENDPOINTS": "/custom:5,/api/v2:15"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        paths = [ep[0] for ep in cfg.sensitive_endpoints]
        rates = {ep[0]: ep[1] for ep in cfg.sensitive_endpoints}
        assert "/custom" in paths
        assert "/api/v2" in paths
        assert rates["/custom"] == 5
        assert rates["/api/v2"] == 15

    def test_from_env_sensitive_endpoints_replaces_defaults(self):
        """When env provides endpoints, defaults are NOT merged — they are replaced."""
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_SENSITIVE_ENDPOINTS": "/only:1"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        paths = [ep[0] for ep in cfg.sensitive_endpoints]
        assert paths == ["/only"]
        # Default entries must be absent
        assert "/api/admin" not in paths

    def test_from_env_sensitive_paths_custom(self):
        """Kills mutant: paths not parsed or split on wrong delimiter."""
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_SENSITIVE_PATHS": ".env,.ssh"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.sensitive_paths == (".env", ".ssh")

    def test_from_env_egress_allowlist(self):
        """Kills mutant: allowlist not split correctly."""
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_EGRESS_ALLOWLIST": "example.com,api.test.com"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.egress_domain_allowlist == ("example.com", "api.test.com")

    def test_from_env_feed_poll_interval_clamp_below_min(self):
        """Kills mutant: clamp uses < instead of max(), or uses wrong floor (e.g. 600)."""
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_FEED_POLL_INTERVAL": "100"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        # 100 < 900 → clamped to 900
        assert cfg.feed_poll_interval == 900

    def test_from_env_feed_poll_interval_clamp_at_exact_min(self):
        """Kills mutant: strict > instead of >= in max(), excluding exactly 900."""
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_FEED_POLL_INTERVAL": "900"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.feed_poll_interval == 900

    def test_from_env_feed_poll_interval_above_min_passes_through(self):
        """Values above the minimum floor must NOT be clamped."""
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_FEED_POLL_INTERVAL": "7200"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.feed_poll_interval == 7200

    def test_from_env_malformed_sensitive_endpoints_keeps_defaults(self):
        """Malformed items (no ':') are skipped; if all fail, defaults are kept."""
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_SENSITIVE_ENDPOINTS": "nodivider,alsonodivider"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        # Parsed list is empty → defaults preserved
        default_paths = {ep[0] for ep in ShieldConfig().sensitive_endpoints}
        actual_paths = {ep[0] for ep in cfg.sensitive_endpoints}
        assert actual_paths == default_paths

    def test_from_env_llm_judge_enabled_true(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_LLM_JUDGE_ENABLED": "true"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.llm_judge_enabled is True

    def test_from_env_anomaly_threshold(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_ANOMALY_THRESHOLD": "75.0"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.anomaly_threshold == pytest.approx(75.0)

    def test_from_env_ml_confidence_threshold(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_ML_CONFIDENCE_THRESHOLD": "0.85"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.ml_confidence_threshold == pytest.approx(0.85)

    def test_from_env_wallet_tx_limit(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_WALLET_TX_LIMIT": "50.0"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.wallet_tx_limit == pytest.approx(50.0)

    def test_from_env_wallet_hourly_limit(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_WALLET_HOURLY_LIMIT": "200.0"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.wallet_hourly_limit == pytest.approx(200.0)

    def test_from_env_wallet_daily_limit(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_WALLET_DAILY_LIMIT": "1000.0"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.wallet_daily_limit == pytest.approx(1000.0)

    def test_from_env_verify_signatures_false(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_VERIFY_SIGNATURES": "false"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.verify_signatures is False

    def test_from_env_feed_enabled_true(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_FEED_ENABLED": "true"},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert cfg.feed_enabled is True

    def test_from_env_egress_allowlist_empty_when_unset(self):
        """Kills mutant: non-empty default tuple for egress_domain_allowlist."""
        with patch.dict(os.environ, self._base_env(), clear=True):
            cfg = ShieldConfig.from_env()
        assert cfg.egress_domain_allowlist == ()

    def test_from_env_egress_allowlist_strips_whitespace(self):
        with patch.dict(
            os.environ,
            {**self._base_env(), "ZUGASHIELD_EGRESS_ALLOWLIST": " a.com , b.com "},
            clear=True,
        ):
            cfg = ShieldConfig.from_env()
        assert "a.com" in cfg.egress_domain_allowlist
        assert "b.com" in cfg.egress_domain_allowlist


# =============================================================================
# Builder — kills mutants in method logic and merge behavior
# =============================================================================


class TestBuilderReturnsBuilderInstance:
    """builder() class method returns the correct type."""

    def test_builder_returns_shield_config_builder_type(self):
        b = ShieldConfig.builder()
        assert isinstance(b, _ShieldConfigBuilder)

    def test_builder_build_returns_shield_config_type(self):
        cfg = ShieldConfig.builder().build()
        assert isinstance(cfg, ShieldConfig)


class TestBuilderFailClosed:
    def test_builder_fail_closed_false(self):
        """Kills mutant: fail_closed(False) sets True instead."""
        cfg = ShieldConfig.builder().fail_closed(False).build()
        assert cfg.fail_closed is False

    def test_builder_fail_closed_true_explicit(self):
        cfg = ShieldConfig.builder().fail_closed(True).build()
        assert cfg.fail_closed is True

    def test_builder_fail_closed_default_param_is_true(self):
        """Default arg of fail_closed() is True — calling it bare enables it."""
        cfg = ShieldConfig.builder().fail_closed().build()
        assert cfg.fail_closed is True


class TestBuilderStrictMode:
    def test_builder_strict_mode_true(self):
        cfg = ShieldConfig.builder().strict_mode(True).build()
        assert cfg.strict_mode is True

    def test_builder_strict_mode_false(self):
        cfg = ShieldConfig.builder().strict_mode(False).build()
        assert cfg.strict_mode is False

    def test_builder_strict_mode_default_param_is_true(self):
        cfg = ShieldConfig.builder().strict_mode().build()
        assert cfg.strict_mode is True


class TestBuilderEnableLayers:
    """enable_layers enables ONLY the listed layers; all others become False."""

    def test_enable_layers_only_listed_are_true(self):
        cfg = ShieldConfig.builder().enable_layers("perimeter", "prompt_armor").build()
        assert cfg.perimeter_enabled is True
        assert cfg.prompt_armor_enabled is True

    def test_enable_layers_unlisted_are_disabled(self):
        cfg = ShieldConfig.builder().enable_layers("perimeter", "prompt_armor").build()
        assert cfg.tool_guard_enabled is False
        assert cfg.memory_sentinel_enabled is False
        assert cfg.exfiltration_guard_enabled is False
        assert cfg.anomaly_detector_enabled is False
        assert cfg.wallet_fortress_enabled is False
        assert cfg.llm_judge_enabled is False
        assert cfg.code_scanner_enabled is False
        assert cfg.cot_auditor_enabled is False
        assert cfg.mcp_guard_enabled is False
        assert cfg.ml_detector_enabled is False

    def test_enable_layers_single_layer(self):
        cfg = ShieldConfig.builder().enable_layers("wallet_fortress").build()
        assert cfg.wallet_fortress_enabled is True
        assert cfg.perimeter_enabled is False

    def test_enable_layers_empty_disables_all(self):
        """Kills mutant: empty layers() call keeps defaults instead of disabling all."""
        cfg = ShieldConfig.builder().enable_layers().build()
        assert cfg.perimeter_enabled is False
        assert cfg.prompt_armor_enabled is False
        assert cfg.wallet_fortress_enabled is False


class TestBuilderDisableLayers:
    def test_disable_layers_perimeter(self):
        """Kills mutant: sets True instead of False."""
        cfg = ShieldConfig.builder().disable_layers("perimeter").build()
        assert cfg.perimeter_enabled is False

    def test_disable_layers_leaves_others_at_defaults(self):
        cfg = ShieldConfig.builder().disable_layers("perimeter").build()
        # Other layers must still be at their default (True for most)
        assert cfg.prompt_armor_enabled is True
        assert cfg.tool_guard_enabled is True
        assert cfg.wallet_fortress_enabled is True

    def test_disable_layers_multiple(self):
        cfg = ShieldConfig.builder().disable_layers("perimeter", "wallet_fortress").build()
        assert cfg.perimeter_enabled is False
        assert cfg.wallet_fortress_enabled is False
        assert cfg.prompt_armor_enabled is True


class TestBuilderSetToolPolicy:
    def test_set_tool_policy_stored_in_overrides(self):
        cfg = (
            ShieldConfig.builder()
            .set_tool_policy("exec", rate=5, approval=True, risk="critical")
            .build()
        )
        assert len(cfg.tool_risk_overrides) == 1

    def test_set_tool_policy_tool_name(self):
        cfg = ShieldConfig.builder().set_tool_policy("exec", rate=5, approval=True, risk="critical").build()
        assert cfg.tool_risk_overrides[0][0] == "exec"

    def test_set_tool_policy_rate(self):
        """Kills mutant: rate stored in wrong tuple position."""
        cfg = ShieldConfig.builder().set_tool_policy("exec", rate=5, approval=True, risk="critical").build()
        assert cfg.tool_risk_overrides[0][1] == 5

    def test_set_tool_policy_approval_flag(self):
        """Kills mutant: approval stored in wrong position or negated."""
        cfg = ShieldConfig.builder().set_tool_policy("exec", rate=5, approval=True, risk="critical").build()
        assert cfg.tool_risk_overrides[0][2] is True

    def test_set_tool_policy_risk_level(self):
        """Kills mutant: risk stored in wrong position."""
        cfg = ShieldConfig.builder().set_tool_policy("exec", rate=5, approval=True, risk="critical").build()
        assert cfg.tool_risk_overrides[0][3] == "critical"

    def test_set_tool_policy_no_overrides_stays_default(self):
        """Kills mutant: build() always sets tool_risk_overrides even when empty."""
        cfg = ShieldConfig.builder().build()
        assert cfg.tool_risk_overrides == ()

    def test_set_tool_policy_multiple_entries(self):
        cfg = (
            ShieldConfig.builder()
            .set_tool_policy("exec", rate=5, approval=True, risk="critical")
            .set_tool_policy("read", rate=20, approval=False, risk="low")
            .build()
        )
        assert len(cfg.tool_risk_overrides) == 2


class TestBuilderAddSensitiveEndpoint:
    def test_add_sensitive_endpoint_merges_with_defaults(self):
        """Kills mutant: custom endpoint replaces defaults instead of merging."""
        cfg = ShieldConfig.builder().add_sensitive_endpoint("/custom", 5).build()
        paths = [ep[0] for ep in cfg.sensitive_endpoints]
        # Default 3 + custom 1 = 4 total
        assert len(cfg.sensitive_endpoints) == 4
        assert "/custom" in paths
        assert "/api/admin" in paths

    def test_add_sensitive_endpoint_rate_stored(self):
        """Kills mutant: rate not stored or stored at wrong index."""
        cfg = ShieldConfig.builder().add_sensitive_endpoint("/custom", 7).build()
        rates = {ep[0]: ep[1] for ep in cfg.sensitive_endpoints}
        assert rates["/custom"] == 7

    def test_no_add_endpoint_keeps_defaults(self):
        """Kills mutant: build() always overrides sensitive_endpoints."""
        cfg = ShieldConfig.builder().build()
        assert cfg.sensitive_endpoints == ShieldConfig().sensitive_endpoints


class TestBuilderSetEgressAllowlist:
    def test_set_egress_allowlist_two_domains(self):
        cfg = ShieldConfig.builder().set_egress_allowlist("a.com", "b.com").build()
        assert cfg.egress_domain_allowlist == ("a.com", "b.com")

    def test_set_egress_allowlist_order_preserved(self):
        """Kills mutant: tuple order scrambled."""
        cfg = ShieldConfig.builder().set_egress_allowlist("first.com", "second.com", "third.com").build()
        assert cfg.egress_domain_allowlist[0] == "first.com"
        assert cfg.egress_domain_allowlist[1] == "second.com"
        assert cfg.egress_domain_allowlist[2] == "third.com"

    def test_set_egress_allowlist_is_tuple_not_list(self):
        cfg = ShieldConfig.builder().set_egress_allowlist("x.com").build()
        assert isinstance(cfg.egress_domain_allowlist, tuple)


class TestBuilderSetWalletLimits:
    def test_set_wallet_limits_tx_only(self):
        """Kills mutant: tx_limit mapped to hourly or daily field."""
        cfg = ShieldConfig.builder().set_wallet_limits(tx_limit=50.0).build()
        assert cfg.wallet_tx_limit == pytest.approx(50.0)

    def test_set_wallet_limits_hourly_only(self):
        """Kills mutant: hourly_limit mapped to daily field."""
        cfg = ShieldConfig.builder().set_wallet_limits(hourly_limit=150.0).build()
        assert cfg.wallet_hourly_limit == pytest.approx(150.0)

    def test_set_wallet_limits_daily_only(self):
        cfg = ShieldConfig.builder().set_wallet_limits(daily_limit=800.0).build()
        assert cfg.wallet_daily_limit == pytest.approx(800.0)

    def test_set_wallet_limits_all_three(self):
        cfg = (
            ShieldConfig.builder()
            .set_wallet_limits(tx_limit=10.0, hourly_limit=50.0, daily_limit=200.0)
            .build()
        )
        assert cfg.wallet_tx_limit == pytest.approx(10.0)
        assert cfg.wallet_hourly_limit == pytest.approx(50.0)
        assert cfg.wallet_daily_limit == pytest.approx(200.0)

    def test_set_wallet_limits_no_cross_contamination(self):
        """tx_limit change must not bleed into hourly or daily."""
        cfg = ShieldConfig.builder().set_wallet_limits(tx_limit=1.0).build()
        assert cfg.wallet_hourly_limit == pytest.approx(500.0)
        assert cfg.wallet_daily_limit == pytest.approx(2000.0)


class TestBuilderSetLlmProvider:
    def test_set_llm_provider_enables_judge(self):
        """Kills mutant: llm_judge_enabled not set to True."""
        cfg = ShieldConfig.builder().set_llm_provider("anthropic", model="claude-3").build()
        assert cfg.llm_judge_enabled is True

    def test_set_llm_provider_stores_provider(self):
        """Kills mutant: provider stored in model field or vice versa."""
        cfg = ShieldConfig.builder().set_llm_provider("anthropic", model="claude-3").build()
        assert cfg.llm_provider == "anthropic"

    def test_set_llm_provider_stores_model(self):
        cfg = ShieldConfig.builder().set_llm_provider("anthropic", model="claude-3").build()
        assert cfg.llm_model == "claude-3"

    def test_set_llm_provider_without_model_leaves_model_none(self):
        """Kills mutant: model set to provider name or empty string when omitted."""
        cfg = ShieldConfig.builder().set_llm_provider("openai").build()
        assert cfg.llm_model is None

    def test_set_llm_provider_without_model_still_enables_judge(self):
        cfg = ShieldConfig.builder().set_llm_provider("openai").build()
        assert cfg.llm_judge_enabled is True


class TestBuilderSetAnomalyThreshold:
    def test_set_anomaly_threshold_stored(self):
        """Kills mutant: threshold stored in wrong field."""
        cfg = ShieldConfig.builder().set_anomaly_threshold(80.0).build()
        assert cfg.anomaly_threshold == pytest.approx(80.0)

    def test_set_anomaly_threshold_does_not_affect_decay(self):
        cfg = ShieldConfig.builder().set_anomaly_threshold(80.0).build()
        assert cfg.anomaly_decay_rate == pytest.approx(0.95)


class TestBuilderEnableMl:
    def test_enable_ml_sets_detector_enabled(self):
        """Kills mutant: ml_detector_enabled not set to True."""
        cfg = ShieldConfig.builder().enable_ml(model_dir="/tmp/models", threshold=0.5).build()
        assert cfg.ml_detector_enabled is True

    def test_enable_ml_stores_model_dir(self):
        """Kills mutant: model_dir mapped to wrong field."""
        cfg = ShieldConfig.builder().enable_ml(model_dir="/tmp/models", threshold=0.5).build()
        assert cfg.ml_model_dir == "/tmp/models"

    def test_enable_ml_stores_threshold(self):
        """Kills mutant: threshold mapped to anomaly_threshold or ignored."""
        cfg = ShieldConfig.builder().enable_ml(model_dir="/tmp/models", threshold=0.5).build()
        assert cfg.ml_confidence_threshold == pytest.approx(0.5)

    def test_enable_ml_threshold_not_stored_as_anomaly_threshold(self):
        """Cross-field contamination check."""
        cfg = ShieldConfig.builder().enable_ml(threshold=0.5).build()
        assert cfg.anomaly_threshold == pytest.approx(60.0)


class TestBuilderEnableFeed:
    def test_enable_feed_sets_feed_enabled_true(self):
        """Kills mutant: feed_enabled not set or set to False."""
        cfg = ShieldConfig.builder().enable_feed().build()
        assert cfg.feed_enabled is True

    def test_enable_feed_default_interval_clamped(self):
        """Default interval 3600 >= 900, must pass through unchanged."""
        cfg = ShieldConfig.builder().enable_feed().build()
        assert cfg.feed_poll_interval == 3600

    def test_enable_feed_interval_below_min_clamped_to_900(self):
        """Kills mutant: clamp uses wrong floor value."""
        cfg = ShieldConfig.builder().enable_feed(interval=100).build()
        assert cfg.feed_poll_interval == 900

    def test_enable_feed_interval_exactly_900_not_clamped(self):
        cfg = ShieldConfig.builder().enable_feed(interval=900).build()
        assert cfg.feed_poll_interval == 900

    def test_enable_feed_interval_above_min_passes_through(self):
        cfg = ShieldConfig.builder().enable_feed(interval=7200).build()
        assert cfg.feed_poll_interval == 7200

    def test_enable_feed_with_custom_url(self):
        """Kills mutant: url stored in wrong field or ignored."""
        cfg = ShieldConfig.builder().enable_feed(url="https://custom.example.com").build()
        assert cfg.feed_url == "https://custom.example.com"

    def test_enable_feed_without_url_keeps_default_url(self):
        """Kills mutant: feed_url set to None or empty when url omitted."""
        default_url = ShieldConfig().feed_url
        cfg = ShieldConfig.builder().enable_feed().build()
        assert cfg.feed_url == default_url

    def test_enable_feed_without_url_does_not_set_url_key(self):
        """Kills mutant: feed_url always written even when None."""
        cfg = ShieldConfig.builder().enable_feed(url=None).build()
        # Must equal the dataclass default, not None
        assert cfg.feed_url is not None
        assert cfg.feed_url != ""


class TestBuilderChaining:
    def test_all_builder_methods_return_self(self):
        """Kills mutant: any method returns None or a new builder."""
        b = ShieldConfig.builder()
        assert b.fail_closed(True) is b
        assert b.strict_mode(True) is b
        assert b.enable_layers("perimeter") is b
        assert b.disable_layers("llm_judge") is b
        assert b.set_tool_policy("x") is b
        assert b.add_sensitive_endpoint("/x") is b
        assert b.set_egress_allowlist("a.com") is b
        assert b.set_wallet_limits() is b
        assert b.set_llm_provider("openai") is b
        assert b.set_anomaly_threshold(70.0) is b
        assert b.set_degradation_mode("warn") is b
        assert b.enable_ml() is b
        assert b.enable_feed() is b

    def test_builder_chain_strict_mode_and_fail_closed(self):
        """Full chain produces config with all settings applied."""
        cfg = (
            ShieldConfig.builder()
            .strict_mode(True)
            .fail_closed(False)
            .build()
        )
        assert cfg.strict_mode is True
        assert cfg.fail_closed is False

    def test_builder_chain_later_call_overrides_earlier(self):
        """Kills mutant: first value is kept instead of last."""
        cfg = (
            ShieldConfig.builder()
            .strict_mode(False)
            .strict_mode(True)
            .build()
        )
        assert cfg.strict_mode is True


# =============================================================================
# Frozen config — immutability after construction
# =============================================================================


class TestShieldConfigFrozen:
    """Config must be immutable after creation to prevent runtime mutation attacks."""

    def test_cannot_mutate_enabled(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.enabled = False  # type: ignore[misc]

    def test_cannot_mutate_fail_closed(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.fail_closed = False  # type: ignore[misc]

    def test_cannot_mutate_strict_mode(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.strict_mode = True  # type: ignore[misc]

    def test_cannot_mutate_max_message_size(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.max_message_size = 999  # type: ignore[misc]

    def test_cannot_mutate_wallet_tx_limit(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.wallet_tx_limit = 1_000_000.0  # type: ignore[misc]

    def test_cannot_mutate_sensitive_endpoints(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.sensitive_endpoints = ()  # type: ignore[misc]

    def test_cannot_mutate_sensitive_paths(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.sensitive_paths = ()  # type: ignore[misc]

    def test_cannot_mutate_verify_signatures(self):
        cfg = ShieldConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.verify_signatures = False  # type: ignore[misc]

    def test_cannot_add_arbitrary_attribute(self):
        cfg = ShieldConfig()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            cfg.injected_field = "evil"  # type: ignore[attr-defined]

    def test_built_config_is_also_frozen(self):
        """Frozen must apply to builder-produced configs too."""
        cfg = ShieldConfig.builder().strict_mode(True).build()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.strict_mode = False  # type: ignore[misc]

    def test_from_env_config_is_frozen(self):
        """Frozen must apply to from_env()-produced configs too."""
        cfg = ShieldConfig.from_env()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.enabled = False  # type: ignore[misc]
