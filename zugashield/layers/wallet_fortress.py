"""
ZugaShield - Layer 7: Wallet Fortress
=======================================

Multi-layer crypto wallet protection:

1. Transaction approval gate (always CRITICAL approval)
2. Address validation (allowlist, blocklist, homoglyph detection)
3. Spend limits (per-tx, hourly, daily)
4. Smart contract protection (unlimited approvals, unverified contracts)
5. Key isolation (private keys NEVER in LLM context)

Integration point: New tool wrapper + Constitutional Governor FINANCIAL domain
"""

from __future__ import annotations

import logging
import re
import time
from collections import deque
from typing import Dict, List, Optional, Set, TYPE_CHECKING

from zugashield.types import (
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ShieldDecision,
    ShieldVerdict,
    allow_decision,
)

if TYPE_CHECKING:
    from zugashield.config import ShieldConfig
    from zugashield.threat_catalog import ThreatCatalog

logger = logging.getLogger(__name__)

# Ethereum-style address pattern
_ETH_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")

# Known dangerous function signatures
_DANGEROUS_FUNCTIONS = {
    "approve(address,uint256)": "Token approval",
    "setApprovalForAll(address,bool)": "NFT approval for all",
    "transferOwnership(address)": "Ownership transfer",
    "selfdestruct(address)": "Contract self-destruct",
    "delegatecall": "Delegate call (proxy pattern)",
}

# Max uint256 for unlimited approvals
_MAX_UINT256 = "0x" + "f" * 64
_MAX_UINT256_DEC = str(2**256 - 1)


class WalletFortressLayer:
    """
    Layer 7: Crypto wallet protection.

    Ensures no funds can be moved without explicit user approval,
    no addresses are substituted via homoglyph attacks, and
    spending stays within configured limits.
    """

    LAYER_NAME = "wallet_fortress"

    def __init__(self, config: ShieldConfig, catalog: ThreatCatalog) -> None:
        self._config = config
        self._catalog = catalog
        # Address lists
        self._allowlisted_addresses: Set[str] = set()
        self._blocklisted_addresses: Set[str] = set()
        self._known_addresses: Set[str] = set()  # Previously used
        # Spend tracking
        self._hourly_spend: deque = deque(maxlen=1000)  # (timestamp, amount_usd)
        self._daily_spend: deque = deque(maxlen=10000)
        self._last_approval_time: float = 0
        self._stats = {
            "checks": 0,
            "blocked": 0,
            "limit_exceeded": 0,
            "new_address_challenges": 0,
            "homoglyphs_detected": 0,
        }

    async def check(
        self,
        tx_type: str = "send",
        to_address: str = "",
        amount: float = 0.0,
        amount_usd: float = 0.0,
        contract_data: Optional[str] = None,
        function_sig: Optional[str] = None,
    ) -> ShieldDecision:
        """
        Check a wallet transaction before execution.

        Args:
            tx_type: Transaction type (send, approve, swap, sign)
            to_address: Destination address
            amount: Amount in native token
            amount_usd: Amount in USD equivalent
            contract_data: Raw contract call data (hex)
            function_sig: Decoded function signature
        """
        if not self._config.wallet_fortress_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["checks"] += 1
        threats: List[ThreatDetection] = []

        # === Check 1: Approval cooldown ===
        now = time.time()
        if now - self._last_approval_time < self._config.wallet_approval_cooldown:
            remaining = self._config.wallet_approval_cooldown - (now - self._last_approval_time)
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.WALLET_ATTACK,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.BLOCK,
                    description=f"Transaction cooldown: {remaining:.0f}s remaining",
                    evidence=f"Last approval {now - self._last_approval_time:.0f}s ago",
                    layer=self.LAYER_NAME,
                    confidence=0.99,
                    suggested_action=f"Wait {remaining:.0f}s before next transaction",
                    signature_id="WF-COOL",
                )
            )

        # === Check 2: Spend limits ===
        limit_threats = self._check_spend_limits(amount_usd)
        threats.extend(limit_threats)

        # === Check 3: Address validation ===
        if to_address:
            addr_threats = self._check_address(to_address)
            threats.extend(addr_threats)

        # === Check 4: Smart contract protection ===
        if contract_data or function_sig:
            contract_threats = self._check_contract(contract_data, function_sig, amount_usd)
            threats.extend(contract_threats)

        # === Check 5: Catalog signatures ===
        check_text = f"{tx_type} {to_address} {amount_usd} {function_sig or ''} {contract_data or ''}"
        catalog_threats = self._catalog.check(check_text, [ThreatCategory.WALLET_ATTACK])
        threats.extend(catalog_threats)

        elapsed = (time.perf_counter() - start) * 1000

        # ALL wallet transactions require CHALLENGE at minimum
        if not threats:
            return ShieldDecision(
                verdict=ShieldVerdict.CHALLENGE,
                threats_detected=[
                    ThreatDetection(
                        category=ThreatCategory.WALLET_ATTACK,
                        level=ThreatLevel.LOW,
                        verdict=ShieldVerdict.CHALLENGE,
                        description=f"Wallet transaction requires approval: {tx_type} ${amount_usd:.2f}",
                        evidence=f"To: {to_address[:20]}..., Amount: ${amount_usd:.2f}",
                        layer=self.LAYER_NAME,
                        confidence=1.0,
                        suggested_action="Require user approval",
                        signature_id="WF-APPROVE",
                    )
                ],
                layer=self.LAYER_NAME,
                elapsed_ms=elapsed,
            )

        # Any real threats = BLOCK
        has_real_threat = any(t.level >= ThreatLevel.MEDIUM for t in threats)
        verdict = ShieldVerdict.BLOCK if has_real_threat else ShieldVerdict.CHALLENGE

        if verdict == ShieldVerdict.BLOCK:
            self._stats["blocked"] += 1

        logger.warning(
            "[WalletFortress] %s: %s $%.2f to %s (%d threats, %.1fms)",
            verdict.value.upper(),
            tx_type,
            amount_usd,
            to_address[:20] if to_address else "N/A",
            len(threats),
            elapsed,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    def record_approval(self, amount_usd: float) -> None:
        """Record a user-approved transaction for spend tracking."""
        now = time.time()
        self._last_approval_time = now
        self._hourly_spend.append((now, amount_usd))
        self._daily_spend.append((now, amount_usd))

    def add_allowlisted_address(self, address: str) -> None:
        """Add an address to the allowlist."""
        self._allowlisted_addresses.add(address.lower())

    def add_blocklisted_address(self, address: str) -> None:
        """Add an address to the blocklist."""
        self._blocklisted_addresses.add(address.lower())

    def _check_spend_limits(self, amount_usd: float) -> List[ThreatDetection]:
        """Check against spend limits."""
        threats = []
        now = time.time()

        # Per-transaction limit
        if amount_usd > self._config.wallet_tx_limit:
            self._stats["limit_exceeded"] += 1
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.WALLET_ATTACK,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.BLOCK,
                    description=f"Transaction exceeds limit: ${amount_usd:.2f} > ${self._config.wallet_tx_limit:.2f}",
                    evidence=f"Amount: ${amount_usd:.2f}, Limit: ${self._config.wallet_tx_limit:.2f}",
                    layer=self.LAYER_NAME,
                    confidence=0.99,
                    suggested_action="Reduce amount or increase limit",
                    signature_id="WF-TXLIMIT",
                )
            )

        # Hourly limit
        hourly = sum(amt for ts, amt in self._hourly_spend if ts > now - 3600) + amount_usd
        if hourly > self._config.wallet_hourly_limit:
            self._stats["limit_exceeded"] += 1
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.WALLET_ATTACK,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.BLOCK,
                    description=f"Hourly spend limit exceeded: ${hourly:.2f} > ${self._config.wallet_hourly_limit:.2f}",
                    evidence=f"Hourly total: ${hourly:.2f}",
                    layer=self.LAYER_NAME,
                    confidence=0.99,
                    suggested_action="Wait or increase hourly limit",
                    signature_id="WF-HOURLIMIT",
                )
            )

        # Daily limit
        daily = sum(amt for ts, amt in self._daily_spend if ts > now - 86400) + amount_usd
        if daily > self._config.wallet_daily_limit:
            self._stats["limit_exceeded"] += 1
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.WALLET_ATTACK,
                    level=ThreatLevel.CRITICAL,
                    verdict=ShieldVerdict.BLOCK,
                    description=f"Daily spend limit exceeded: ${daily:.2f} > ${self._config.wallet_daily_limit:.2f}",
                    evidence=f"Daily total: ${daily:.2f}",
                    layer=self.LAYER_NAME,
                    confidence=0.99,
                    suggested_action="Wait or increase daily limit",
                    signature_id="WF-DAYLIMIT",
                )
            )

        return threats

    def _check_address(self, address: str) -> List[ThreatDetection]:
        """Validate destination address."""
        threats = []
        addr_lower = address.lower()

        # Blocklist check
        if addr_lower in self._blocklisted_addresses:
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.WALLET_ATTACK,
                    level=ThreatLevel.CRITICAL,
                    verdict=ShieldVerdict.BLOCK,
                    description="Destination address is blocklisted",
                    evidence=f"Address: {address}",
                    layer=self.LAYER_NAME,
                    confidence=0.99,
                    suggested_action="Block transaction to known malicious address",
                    signature_id="WF-BLOCKLIST",
                )
            )
            return threats

        # Allowlist check - new address needs challenge
        if addr_lower not in self._allowlisted_addresses and addr_lower not in self._known_addresses:
            self._stats["new_address_challenges"] += 1
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.WALLET_ATTACK,
                    level=ThreatLevel.LOW,
                    verdict=ShieldVerdict.CHALLENGE,
                    description="First-time recipient address",
                    evidence=f"Address: {address}",
                    layer=self.LAYER_NAME,
                    confidence=0.50,
                    suggested_action="Confirm new recipient address",
                    signature_id="WF-NEWADDR",
                )
            )

        # Homoglyph detection - check for Cyrillic/Greek characters in hex address
        if _ETH_ADDRESS.match(address):
            for i, c in enumerate(address[2:], 2):
                if ord(c) > 127:
                    self._stats["homoglyphs_detected"] += 1
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.WALLET_ATTACK,
                            level=ThreatLevel.CRITICAL,
                            verdict=ShieldVerdict.BLOCK,
                            description=f"Homoglyph attack: non-ASCII character at position {i}",
                            evidence=f"Char '{c}' (U+{ord(c):04X}) at position {i}",
                            layer=self.LAYER_NAME,
                            confidence=0.95,
                            suggested_action="Block address with homoglyph characters",
                            signature_id="WF-HOMOGLYPH",
                        )
                    )
                    break

        return threats

    def _check_contract(
        self,
        data: Optional[str],
        function_sig: Optional[str],
        amount_usd: float,
    ) -> List[ThreatDetection]:
        """Check smart contract interaction safety."""
        threats = []

        # Check for dangerous function signatures
        if function_sig:
            for dangerous_sig, desc in _DANGEROUS_FUNCTIONS.items():
                if dangerous_sig in function_sig:
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.WALLET_ATTACK,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.BLOCK,
                            description=f"Dangerous contract function: {desc}",
                            evidence=f"Function: {function_sig}",
                            layer=self.LAYER_NAME,
                            confidence=0.85,
                            suggested_action=f"Review {desc} carefully before proceeding",
                            signature_id="WF-FUNC",
                        )
                    )

        # Check for unlimited token approval
        if data:
            if _MAX_UINT256 in data.lower() or _MAX_UINT256_DEC in data:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.WALLET_ATTACK,
                        level=ThreatLevel.CRITICAL,
                        verdict=ShieldVerdict.BLOCK,
                        description="Unlimited token approval (MAX_UINT256)",
                        evidence="Approval amount is MAX_UINT256 - allows unlimited spending",
                        layer=self.LAYER_NAME,
                        confidence=0.95,
                        suggested_action="Use exact approval amount instead",
                        signature_id="WF-UNLIMITED",
                    )
                )

        return threats

    def get_stats(self) -> Dict:
        """Return layer statistics."""
        now = time.time()
        return {
            "layer": self.LAYER_NAME,
            **self._stats,
            "hourly_spend": sum(amt for ts, amt in self._hourly_spend if ts > now - 3600),
            "daily_spend": sum(amt for ts, amt in self._daily_spend if ts > now - 86400),
            "allowlisted_count": len(self._allowlisted_addresses),
            "blocklisted_count": len(self._blocklisted_addresses),
        }
