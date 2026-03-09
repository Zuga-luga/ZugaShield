"""
ZugaShield Threat Feed — Persistent Update State.

Tracks ETags, last check time, and applied versions in
``~/.zugashield/update_state.json`` so we can do conditional
HTTP requests and avoid re-downloading unchanged manifests.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class UpdateState:
    """Persistent state for the signature update feed."""

    etag: str = ""
    last_check: str = ""
    last_applied_version: str = "0.0.0"
    last_signature_count: int = 0

    def with_update(self, version: str, sig_count: int) -> UpdateState:
        """Return a copy with updated version info."""
        return UpdateState(
            etag=self.etag,
            last_check=datetime.now(timezone.utc).isoformat(),
            last_applied_version=version,
            last_signature_count=sig_count,
        )


def _state_path(state_dir: str) -> Path:
    """Resolve the update state file path."""
    return Path(state_dir).expanduser() / "update_state.json"


def load_state(state_dir: str) -> UpdateState:
    """Load update state from disk, returning defaults if missing."""
    path = _state_path(state_dir)
    if not path.exists():
        return UpdateState()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return UpdateState(
            etag=data.get("etag", ""),
            last_check=data.get("last_check", ""),
            last_applied_version=data.get("last_applied_version", "0.0.0"),
            last_signature_count=data.get("last_signature_count", 0),
        )
    except Exception as e:
        logger.warning("[feed] Failed to load state: %s", e)
        return UpdateState()


def save_state(state_dir: str, state: UpdateState) -> None:
    """Persist update state to disk. Creates directory if needed."""
    path = _state_path(state_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f, indent=2)
    except Exception as e:
        logger.warning("[feed] Failed to save state: %s", e)
