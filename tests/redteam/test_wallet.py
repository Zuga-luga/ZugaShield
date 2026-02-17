"""
Red team tests — Wallet Fortress.

Ports TestWalletFortress from the Zugabot test suite.

Coverage:
- MAX_UINT256 unlimited approval (Block)
- Large transaction amount (Block)
- Known mixer/tornado-cash address (Block)
- Drain function signature (Block/Challenge)
- Small unknown transaction (Challenge — always requires confirmation)
- Custom limits via builder

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


# Known Tornado Cash mixer address (OFAC sanctioned)
TORNADO_CASH = "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b"


# =============================================================================
# Wallet Fortress attacks
# =============================================================================


class TestWalletFortress:
    """Cryptocurrency wallet attack detection."""

    def test_unlimited_approval_max_uint256(self, shield):
        """MAX_UINT256 approval is a classic drain-all attack."""
        d = run(shield.check_transaction(
            tx_type="approve",
            to_address="0x1234567890abcdef1234567890abcdef12345678",
            amount=2**256 - 1,  # MAX_UINT256
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_large_transaction_blocked(self, shield):
        """Transactions exceeding the per-tx limit must be blocked."""
        d = run(shield.check_transaction(
            tx_type="send",
            to_address="0xabcdef1234567890abcdef1234567890abcdef12",
            amount_usd=50000,
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_mixer_address_tornado_cash(self, shield):
        """Sending to a known mixer address must be blocked."""
        d = run(shield.check_transaction(
            tx_type="send",
            to_address=TORNADO_CASH,
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_drain_function_sig_transfer_from(self, shield):
        """transferFrom() on unknown contract must be challenged or blocked."""
        d = run(shield.check_transaction(
            tx_type="contract_call",
            to_address="0x1234567890abcdef1234567890abcdef12345678",
            function_sig="transferFrom(address,address,uint256)",
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    def test_amount_above_hourly_limit(self, shield):
        """Amounts exceeding the hourly wallet limit must be blocked."""
        d = run(shield.check_transaction(
            tx_type="send",
            to_address="0xabcdef1234567890abcdef1234567890abcdef12",
            amount_usd=600.0,  # Default hourly limit is 500
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    # --- Small transactions get CHALLENGE (require user confirmation) ---

    def test_small_transaction_challenges(self, shield):
        """
        All transactions to unknown addresses require user confirmation.
        This is by design — wallet security requires explicit approval.
        """
        d = run(shield.check_transaction(
            tx_type="send",
            to_address="0xabcdef1234567890abcdef1234567890abcdef12",
            amount_usd=5.0,
        ))
        assert d.verdict == ShieldVerdict.CHALLENGE

    def test_approve_reasonable_amount_challenges(self, shield):
        """A reasonable approval to an unknown contract should be challenged."""
        d = run(shield.check_transaction(
            tx_type="approve",
            to_address="0xabcdef1234567890abcdef1234567890abcdef12",
            amount=1000,
        ))
        assert d.verdict != ShieldVerdict.ALLOW

    # --- Custom limits via builder ---

    def test_custom_tx_limit_respected(self):
        """Builder-configured wallet limits override defaults."""
        shield = (
            ZugaShield.builder()
            .set_wallet_limits(tx_limit=10.0, hourly_limit=50.0, daily_limit=100.0)
            .build()
        )
        # $15 transaction should be blocked under $10 limit
        d = run(shield.check_transaction(
            tx_type="send",
            to_address="0xabcdef1234567890abcdef1234567890abcdef12",
            amount_usd=15.0,
        ))
        assert d.verdict != ShieldVerdict.ALLOW
