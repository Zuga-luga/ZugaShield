"""ZugaShield test configuration."""

import pytest
from zugashield import reset_zugashield


@pytest.fixture(autouse=True)
def fresh_shield():
    """Reset singleton between tests to avoid cross-contamination."""
    reset_zugashield()
    yield
    reset_zugashield()
