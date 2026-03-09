"""
ZugaShield Threat Feed — Auto-Updating Signature System.

Pull-based, cryptographically signed signature updates from GitHub Releases.
"""

from zugashield.feed.updater import SignatureUpdater

__all__ = ["SignatureUpdater"]
