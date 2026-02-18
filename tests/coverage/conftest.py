"""
Dataset download fixtures for coverage tests.

Downloads public prompt injection datasets to a local cache directory
for measuring detection rates against real-world attacks.

Usage:
    pytest tests/coverage/ -m slow
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple

import pytest

# Skip entire module if datasets not available
datasets = pytest.importorskip("datasets")

_CACHE_DIR = Path(os.getenv(
    "ZUGASHIELD_TEST_DATA_DIR",
    ".zugashield-test-data",
))


@pytest.fixture(scope="session")
def deepset_samples() -> Tuple[List[str], List[int]]:
    """
    Load deepset/prompt-injections dataset.

    Returns:
        (texts, labels): texts is a list of strings, labels is 0=benign 1=injection
    """
    ds = datasets.load_dataset(
        "deepset/prompt-injections",
        split="train",
        cache_dir=str(_CACHE_DIR),
    )
    texts = [row["text"] for row in ds]
    labels = [int(row["label"]) for row in ds]
    return texts, labels


@pytest.fixture(scope="session")
def gandalf_samples() -> List[str]:
    """
    Load Lakera/gandalf_ignore_instructions dataset.

    Returns:
        texts: list of injection attempt strings (all labeled as injection)
    """
    ds = datasets.load_dataset(
        "Lakera/gandalf_ignore_instructions",
        split="train",
        cache_dir=str(_CACHE_DIR),
    )
    texts = []
    for row in ds:
        text = row.get("text", row.get("prompt", ""))
        if text:
            texts.append(text)
    return texts


@pytest.fixture(scope="session")
def shield_with_ml():
    """Create a ZugaShield instance with ML detection enabled."""
    from zugashield import ZugaShield
    from zugashield.config import ShieldConfig

    config = ShieldConfig(
        ml_detector_enabled=True,
        ml_onnx_enabled=False,  # TF-IDF only for dataset tests
    )
    return ZugaShield(config)
