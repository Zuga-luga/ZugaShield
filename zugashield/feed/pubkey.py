"""
ZugaShield Threat Feed — Hardcoded Minisign Public Key.

This key is embedded in the source code so it can only be changed
via a code release, not via configuration. This prevents an attacker
from pointing the feed at a rogue server AND swapping the public key.

To generate a new keypair:
    minisign -G -p zugashield.pub -s zugashield.sec

Then paste the public key string here.
"""

# Minisign public key for ZugaShield signature verification.
# Format: base64 of (2-byte algo "Ed" + 8-byte key_id + 32-byte Ed25519 pubkey).
# Key ID: A4EC7E83594AD0AA
ZUGASHIELD_PUBKEY = "RWSk7H6DWUrQqjhJBecstlzI2SeU10FwP0AkBvTZci0J1MRGgY/z3yjQ"
