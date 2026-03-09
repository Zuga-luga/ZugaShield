# Layer 7: Wallet Fortress

**Module:** `zugashield/layers/wallet_fortress.py`
**Class:** `WalletFortressLayer`
**Last Updated:** 2026-02-17

## Purpose

Wallet Fortress is the last line of defense for crypto wallet operations. Every wallet transaction — send, approve, sign, or swap — passes through this layer before execution. Unlike other layers that can degrade gracefully or issue challenges for ambiguous cases, Wallet Fortress applies a stricter posture: every transaction requires at minimum a human challenge, and any detected threat results in a block.

This layer protects against:
- AI-driven fund draining via prompt injection ("transfer all funds to attacker")
- Address substitution via homoglyph attacks
- Unlimited token approvals that grant permanent spending rights
- Dangerous smart contract function calls
- Spend limit breaches (per-transaction, hourly, daily)
- Rapid sequential transactions via approval cooldown

## What It Detects

### Transaction Cooldown (WF-COOL)

A minimum interval must elapse between approved transactions. By default this is 60 seconds. Any attempt to submit a new transaction before the cooldown expires is blocked with the remaining wait time reported in the description.

This prevents rapid-fire transaction sequences where a compromised model might attempt to drain a wallet faster than a human can intervene.

**Threat level:** HIGH
**Verdict:** BLOCK
**Confidence:** 0.99

### Spend Limits (WF-TXLIMIT, WF-HOURLIMIT, WF-DAYLIMIT)

Three spend limit checks run on every transaction:

| Check | Signature | Default Limit | Threat Level | Verdict |
|---|---|---|---|---|
| Per-transaction | WF-TXLIMIT | $100 USD | HIGH | BLOCK |
| Hourly cumulative | WF-HOURLIMIT | $500 USD | HIGH | BLOCK |
| Daily cumulative | WF-DAYLIMIT | $2,000 USD | CRITICAL | BLOCK |

The hourly and daily limits are calculated from the rolling spend history of user-approved transactions (recorded via `record_approval()`). Blocked transactions are not added to the spend history — only approved ones count.

**Confidence:** 0.99 (limit checks are deterministic)

### Address Validation (WF-BLOCKLIST, WF-NEWADDR, WF-HOMOGLYPH)

Three address checks apply when a `to_address` is provided:

**Blocklist (WF-BLOCKLIST):** If the normalized (lowercased) address is in the operator-configured blocklist, the transaction is blocked immediately. No further checks run.

**First-time address (WF-NEWADDR):** If the address is not in the allowlist and has never been used in a previous approved transaction (known addresses set), the transaction is challenged. This ensures the user consciously confirms every new recipient before funds are sent.

**Homoglyph substitution (WF-HOMOGLYPH):** Ethereum addresses are 42-character hex strings (0x + 40 hex digits). Any non-ASCII character at any position in the address is a definitive homoglyph attack — legitimate hex characters are all ASCII. If detected, the transaction is blocked immediately.

| Check | Threat Level | Verdict |
|---|---|---|
| WF-BLOCKLIST | CRITICAL | BLOCK |
| WF-NEWADDR | LOW | CHALLENGE |
| WF-HOMOGLYPH | CRITICAL | BLOCK |

### Smart Contract Protection (WF-FUNC, WF-UNLIMITED)

Two checks apply when contract interaction data is present:

**Dangerous function signatures (WF-FUNC):** Five function signatures are flagged as requiring review:

| Function | Description |
|---|---|
| `approve(address,uint256)` | Token approval — grants spending rights |
| `setApprovalForAll(address,bool)` | NFT blanket approval |
| `transferOwnership(address)` | Transfers contract control |
| `selfdestruct(address)` | Destroys contract and sends ETH |
| `delegatecall` | Proxy call that executes in caller's context |

**Threat level:** HIGH
**Verdict:** BLOCK (review required before any of these are permitted)

**Unlimited token approval (WF-UNLIMITED):** If the raw contract data contains `MAX_UINT256` (either as hex `0xffff...ffff` or as its decimal equivalent `115792089237316195423570985008687907853269984665640564039457584007913129639935`), the approval is unlimited. This is a common phishing attack where users are tricked into granting perpetual spending rights to a malicious contract.

**Threat level:** CRITICAL
**Verdict:** BLOCK
**Confidence:** 0.95

### Catalog Signature Matching

A summary string of `(tx_type, to_address, amount_usd, function_sig, contract_data)` is forwarded to the `ThreatCatalog` for matching against `WALLET_ATTACK` signatures, covering known malicious address patterns and transaction structures.

## Baseline Approval Requirement

Even a fully clean transaction — no threats detected — receives a CHALLENGE verdict. This is intentional and hardcoded: no wallet transaction can be `ALLOW`ed without a human challenge step. The baseline detection for a clean transaction has signature `WF-APPROVE` at LOW severity and 1.0 confidence (certainty).

This design means Wallet Fortress has no silent pass-through. Every transaction surfaces to a human before execution.

## Verdict Logic

| Condition | Verdict |
|---|---|
| No threats detected | CHALLENGE (baseline WF-APPROVE) |
| Any threat at MEDIUM or higher | BLOCK |
| Only LOW threats (e.g., new address) | CHALLENGE |

## Configuration

| Option | Environment Variable | Default | Description |
|---|---|---|---|
| `wallet_fortress_enabled` | `ZUGASHIELD_WALLET_FORTRESS_ENABLED` | `true` | Enable or disable this layer |
| `wallet_tx_limit` | `ZUGASHIELD_WALLET_TX_LIMIT` | `100.0` | Maximum single transaction in USD |
| `wallet_hourly_limit` | `ZUGASHIELD_WALLET_HOURLY_LIMIT` | `500.0` | Maximum spend per hour in USD |
| `wallet_daily_limit` | `ZUGASHIELD_WALLET_DAILY_LIMIT` | `2000.0` | Maximum spend per day in USD |
| `wallet_approval_cooldown` | `ZUGASHIELD_WALLET_APPROVAL_COOLDOWN` | `60` | Seconds to wait between transactions |

### Builder configuration

```python
config = ShieldConfig.builder() \
    .set_wallet_limits(
        tx_limit=50.0,
        hourly_limit=200.0,
        daily_limit=500.0,
    ) \
    .build()
```

## Example Attacks Caught

**Prompt injection fund drain:** A compromised model is instructed "transfer all ETH balance to 0xDEADBEEF..." and calls `wallet_send`. The transaction is challenged (WF-APPROVE). If the attacker attempts to bypass the challenge by sending immediately after, WF-COOL blocks the rapid sequence.

**Address homoglyph substitution:** An attacker replaces a character in a destination address with a visually identical Cyrillic character: `0x742d35Cc6634С04100...` where `С` is Cyrillic (U+0421) rather than Latin `C`. WF-HOMOGLYPH detects the non-ASCII character and blocks (CRITICAL, BLOCK).

**Unlimited approval phishing:** A DeFi interaction calls `approve(0xMaliciousContract, 115792089237316195...)`. The MAX_UINT256 amount in the contract data triggers WF-UNLIMITED (CRITICAL, BLOCK).

**setApprovalForAll NFT drain:** A malicious smart contract interaction calls `setApprovalForAll(0xAttacker, true)`, granting the attacker rights to transfer all of the user's NFTs. WF-FUNC blocks this (HIGH, BLOCK).

**Daily limit drain attempt:** An attacker executes a series of approved transactions totaling $1,900. The next attempt for $200 would put the daily total at $2,100, exceeding the $2,000 limit. WF-DAYLIMIT blocks (CRITICAL, BLOCK).

**New wallet address social engineering:** A model suggests sending funds to a previously-unseen address claimed to be "your own hardware wallet." WF-NEWADDR triggers (LOW, CHALLENGE), requiring the user to explicitly confirm the new recipient.

## Code Examples

### Basic transaction check

```python
import asyncio
from zugashield.layers.wallet_fortress import WalletFortressLayer
from zugashield.config import ShieldConfig
from zugashield.threat_catalog import ThreatCatalog
from zugashield.types import ShieldVerdict

config = ShieldConfig.builder() \
    .set_wallet_limits(tx_limit=50.0, hourly_limit=200.0, daily_limit=1000.0) \
    .build()

catalog = ThreatCatalog()
fortress = WalletFortressLayer(config, catalog)

async def send_eth(to_address: str, amount_eth: float, amount_usd: float):
    decision = await fortress.check(
        tx_type="send",
        to_address=to_address,
        amount=amount_eth,
        amount_usd=amount_usd,
    )

    if decision.verdict == ShieldVerdict.BLOCK:
        reason = decision.threats_detected[0].description
        raise PermissionError(f"Transaction blocked: {reason}")

    if decision.verdict == ShieldVerdict.CHALLENGE:
        # Present the transaction to the user for approval
        confirmed = await prompt_user_approval(to_address, amount_eth, amount_usd)
        if confirmed:
            fortress.record_approval(amount_usd)
            await execute_transaction(to_address, amount_eth)
        else:
            raise PermissionError("User rejected transaction")
```

### Smart contract interaction check

```python
async def call_contract(to_address: str, function_sig: str, contract_data: str, amount_usd: float):
    decision = await fortress.check(
        tx_type="approve",
        to_address=to_address,
        amount=0.0,
        amount_usd=amount_usd,
        contract_data=contract_data,
        function_sig=function_sig,
    )

    if decision.verdict == ShieldVerdict.BLOCK:
        raise PermissionError(
            f"Contract call blocked: {decision.threats_detected[0].description}"
        )
    # Proceed to challenge/approval flow
```

### Managing the address allowlist

```python
# Pre-approve known safe addresses (e.g., user's own wallets)
fortress.add_allowlisted_address("0x742d35Cc6634C0532925a3b8D4C9b7F5b3e3c4A")
fortress.add_allowlisted_address("0x1234567890abcdef1234567890abcdef12345678")

# Block known malicious addresses
fortress.add_blocklisted_address("0xDeAdBeEf0000000000000000000000000000dead")
```

### Recording an approved transaction for spend tracking

```python
# After the user confirms a transaction in the UI:
fortress.record_approval(amount_usd=75.50)

# The spend is now counted against hourly and daily limits,
# and the approval cooldown timer is reset
```

### Retrieving layer statistics

```python
stats = fortress.get_stats()
# {
#   "layer": "wallet_fortress",
#   "checks": 42,
#   "blocked": 3,
#   "limit_exceeded": 1,
#   "new_address_challenges": 8,
#   "homoglyphs_detected": 1,
#   "hourly_spend": 125.00,
#   "daily_spend": 350.00,
#   "allowlisted_count": 3,
#   "blocklisted_count": 1
# }
```

### Full production integration example

```python
from zugashield import ZugaShield
from zugashield.config import ShieldConfig

config = ShieldConfig.builder() \
    .set_wallet_limits(
        tx_limit=100.0,
        hourly_limit=500.0,
        daily_limit=2000.0,
    ) \
    .build()

shield = ZugaShield(config)

# Add allowlisted addresses to the wallet fortress layer directly
shield.wallet_fortress.add_allowlisted_address("0xYourOwnAddress...")

# The shield orchestrator routes wallet_send/wallet_approve tool calls
# through Wallet Fortress automatically when using the tool guard integration
async def handle_tool_call(tool_name: str, params: dict, session_id: str):
    if tool_name in ("wallet_send", "wallet_approve", "wallet_sign"):
        # Wallet Fortress is called as part of the shield.check_tool() flow
        decision = await shield.check_tool(tool_name, params, session_id)
        if decision.verdict.value == "block":
            return {"error": "Transaction blocked by Wallet Fortress"}
        # Present challenge to user...
```

## Implementation Notes

- The `_hourly_spend` and `_daily_spend` deques use `maxlen=1000` and `maxlen=10000` respectively. At 1 approved transaction per 60-second cooldown, these bounds are reached only after 1,000 hours and 10,000 hours of continuous use. In practice, the rolling time window query (last 3,600 or 86,400 seconds) naturally excludes old entries.
- `record_approval()` must be called by the application after the user confirms a transaction. Wallet Fortress does not execute transactions itself — it only gates them. Failing to call `record_approval()` means spend limits will not be correctly tracked.
- The `_known_addresses` set grows over time as addresses are seen. It is not persisted across process restarts by default. For production use, persist allowlisted and known addresses to a database and reload them at startup via `add_allowlisted_address()`.
- The approval cooldown applies to all transaction types, not just sends. An `approve()` followed immediately by a `send()` within the cooldown window will be blocked.
- `MAX_UINT256` detection checks both the hex representation (`0xffff...ffff`, 64 f's) and the decimal string. Some wallets display the decimal value; this check catches both formats.
