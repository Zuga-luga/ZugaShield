"""
ZugaShield Threat Feed — Signature Updater Daemon.

Background daemon thread that periodically checks for new signature
releases, downloads and verifies them, and hot-reloads the catalog.

Design principles:
    - **Never crash**: all exceptions caught, logged, and swallowed.
    - **Never block startup**: runs as a daemon thread with startup jitter.
    - **Fail-open**: update failures leave existing signatures untouched.
    - **Zero cost on no-update**: ETag conditional HTTP returns 304.
"""

from __future__ import annotations

import logging
import random
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from zugashield.config import ShieldConfig
    from zugashield.threat_catalog import ThreatCatalog

logger = logging.getLogger(__name__)


class SignatureUpdater(threading.Thread):
    """Background daemon that checks for and applies signature updates."""

    def __init__(
        self,
        catalog: ThreatCatalog,
        config: ShieldConfig,
    ) -> None:
        super().__init__(daemon=True, name="zugashield-updater")
        self.catalog = catalog
        self.config = config
        self._stop_event = threading.Event()
        self._updates_applied = 0
        self._last_error: Optional[str] = None

    def stop(self) -> None:
        """Signal the updater to stop."""
        self._stop_event.set()

    def run(self) -> None:
        """Main loop: jitter → poll → sleep → repeat."""
        # Startup jitter: random delay to avoid thundering herd
        jitter = random.uniform(0, self.config.feed_startup_jitter)
        logger.debug("[feed] Updater starting with %.1fs jitter", jitter)
        if self._stop_event.wait(timeout=jitter):
            return

        # First check immediately after jitter
        self._safe_check()

        # Then poll at the configured interval
        while not self._stop_event.wait(timeout=self.config.feed_poll_interval):
            self._safe_check()

    def _safe_check(self) -> None:
        """Run check_and_apply with full exception protection."""
        try:
            self._check_and_apply()
        except Exception as e:
            self._last_error = str(e)
            logger.exception("[feed] Update check failed")

    def _check_and_apply(self) -> None:
        """Check for updates and apply if available."""
        from zugashield.feed.checker import check_for_update
        from zugashield.feed.downloader import download_and_verify
        from zugashield.feed.state import load_state, save_state

        state = load_state(self.config.feed_state_dir)
        manifest = check_for_update(self.config, state)

        if manifest is None:
            return  # No update or ETag match

        # Update ETag in state regardless of download outcome
        state.etag = manifest.etag

        sig_dir = download_and_verify(manifest, self.config, self.config.feed_state_dir)
        if sig_dir is None:
            # Download/verify failed — save ETag to avoid re-checking
            save_state(self.config.feed_state_dir, state)
            return

        count = self.catalog.hot_reload(str(sig_dir))
        new_state = state.with_update(manifest.version, count)
        new_state.etag = manifest.etag
        save_state(self.config.feed_state_dir, new_state)

        self._updates_applied += 1
        logger.info(
            "[feed] Updated to v%s (%d signatures)",
            manifest.version,
            count,
        )

    def get_stats(self) -> dict:
        """Return updater status for dashboard."""
        return {
            "running": self.is_alive(),
            "updates_applied": self._updates_applied,
            "last_error": self._last_error,
            "poll_interval": self.config.feed_poll_interval,
        }
