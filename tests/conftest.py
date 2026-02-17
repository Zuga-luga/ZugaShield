"""
ZugaShield test configuration — shared fixtures.

All tests use these fixtures unless they define their own.
The `fresh_shield` autouse fixture resets the singleton between tests so
no state leaks across test cases.
"""

import pytest

from zugashield import ZugaShield, ThreatCatalog, ShieldConfig, reset_zugashield


@pytest.fixture(autouse=True)
def fresh_shield():
    """Reset the global singleton between tests to avoid cross-contamination."""
    reset_zugashield()
    yield
    reset_zugashield()


@pytest.fixture
def shield_config() -> ShieldConfig:
    """
    Default ShieldConfig for tests.

    All layers enabled, fail_closed=True, strict_mode=False.
    Uses defaults so tests reflect realistic production behaviour.
    """
    return ShieldConfig()


@pytest.fixture
def shield(shield_config: ShieldConfig) -> ZugaShield:
    """
    ZugaShield instance constructed with the default test config.

    Each test gets a fresh instance (singleton is reset by `fresh_shield`).
    """
    return ZugaShield(shield_config)


@pytest.fixture
def catalog() -> ThreatCatalog:
    """
    ThreatCatalog instance for direct catalog tests.

    Integrity verification is on by default so we also exercise the
    verify_signatures path in tests.
    """
    return ThreatCatalog(verify_integrity=True)
