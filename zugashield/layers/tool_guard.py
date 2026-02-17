"""
ZugaShield - Layer 3: Tool Guard
==================================

Principle of least privilege enforcement for tool execution.
Intercepts tool calls before execution to enforce:
- Rate limiting per tool
- Parameter validation
- Sensitive path detection
- Tool chaining detection (read → web request = exfil pattern)
- SSRF protection for browser navigation

Integration point: wraps execute_tool_fn in tool_execution.py
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from zugashield.types import (
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ShieldDecision,
    ShieldVerdict,
    ToolPolicy,
    allow_decision,
)

if TYPE_CHECKING:
    from zugashield.config import ShieldConfig
    from zugashield.threat_catalog import ThreatCatalog

logger = logging.getLogger(__name__)

# =============================================================================
# Tool Risk Matrix
# =============================================================================

TOOL_RISK_MATRIX: Dict[str, ToolPolicy] = {
    # Bash/Shell - highest risk
    "local_bash": ToolPolicy(rate=10, approval=True, risk="high"),
    "bash": ToolPolicy(rate=10, approval=True, risk="high"),
    "execute_command": ToolPolicy(rate=10, approval=True, risk="high"),

    # File operations
    "local_read_file": ToolPolicy(rate=30, approval=False, risk="low"),
    "read_file": ToolPolicy(rate=30, approval=False, risk="low"),
    "local_write_file": ToolPolicy(rate=10, approval=True, risk="medium"),
    "write_file": ToolPolicy(rate=10, approval=True, risk="medium"),
    "local_list_directory": ToolPolicy(rate=20, approval=False, risk="low"),

    # Browser
    "browser_navigate": ToolPolicy(rate=5, approval=False, risk="medium"),
    "browser_click": ToolPolicy(rate=15, approval=False, risk="low"),
    "browser_screenshot": ToolPolicy(rate=10, approval=False, risk="low"),

    # Web/Search
    "web_search": ToolPolicy(rate=10, approval=False, risk="low"),
    "web_fetch": ToolPolicy(rate=10, approval=False, risk="low"),

    # Memory
    "memory_store": ToolPolicy(rate=5, approval=False, risk="medium"),
    "memory_recall": ToolPolicy(rate=10, approval=False, risk="low"),

    # System
    "self_restart": ToolPolicy(rate=1, approval=True, risk="critical"),
    "self_upgrade": ToolPolicy(rate=1, approval=True, risk="critical"),

    # Wallet
    "wallet_send": ToolPolicy(rate=1, approval=True, risk="critical"),
    "wallet_approve": ToolPolicy(rate=1, approval=True, risk="critical"),
    "wallet_sign": ToolPolicy(rate=1, approval=True, risk="critical"),
}

# Default policy for unknown tools
_DEFAULT_POLICY = ToolPolicy(rate=15, approval=False, risk="medium")

# SSRF patterns - internal/private network addresses + DNS rebinding
_SSRF_PATTERNS = [
    re.compile(r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0)", re.I),
    re.compile(r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I),
    re.compile(r"https?://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", re.I),
    re.compile(r"https?://192\.168\.\d{1,3}\.\d{1,3}", re.I),
    re.compile(r"https?://169\.254\.169\.254", re.I),
    re.compile(r"https?://\[::1\]", re.I),
    re.compile(r"https?://metadata\.google\.internal", re.I),
    re.compile(r"https?://metadata\.aws\.internal", re.I),
    # DNS rebinding protection - suspicious domain patterns
    re.compile(r"https?://[^/]*(?:\.localtest\.me|\.vcap\.me|\.nip\.io|\.sslip\.io|\.xip\.io)", re.I),
    # Decimal/octal/hex IP encoding bypass attempts
    re.compile(r"https?://(?:0x[0-9a-f]+|0[0-7]+|\d{8,})", re.I),
    # IPv6 shorthand for localhost
    re.compile(r"https?://\[(?:::(?:ffff:)?127\.0\.0\.1|::1|0:0:0:0:0:0:0:1)\]", re.I),
]


class ToolGuardLayer:
    """
    Layer 3: Tool execution gating.

    Enforces the principle of least privilege on every tool call.
    Tracks call patterns to detect multi-step attack chains.
    """

    LAYER_NAME = "tool_guard"

    def __init__(self, config: ShieldConfig, catalog: ThreatCatalog) -> None:
        self._config = config
        self._catalog = catalog
        # Per-session rate tracking: {session_id: {tool_name: deque of timestamps}}
        self._rate_tracker: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=100)))
        # Recent tool chain tracking: {session_id: deque of (tool_name, timestamp, params_hash)}
        self._chain_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._stats = {"checks": 0, "blocks": 0, "rate_limits": 0, "chain_detections": 0}

    async def check(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session_id: str = "default",
    ) -> ShieldDecision:
        """
        Check a tool call before execution.

        Args:
            tool_name: Name of the tool being called
            params: Parameters passed to the tool
            session_id: Current session identifier

        Returns:
            ShieldDecision with verdict.
        """
        if not self._config.tool_guard_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["checks"] += 1
        threats: List[ThreatDetection] = []

        # Get policy for this tool
        policy = TOOL_RISK_MATRIX.get(tool_name, _DEFAULT_POLICY)

        # === Check 1: Rate limiting ===
        rate_threat = self._check_rate_limit(tool_name, session_id, policy)
        if rate_threat:
            threats.append(rate_threat)

        # === Check 2: Parameter validation ===
        param_threats = self._check_parameters(tool_name, params)
        threats.extend(param_threats)

        # === Check 3: Sensitive path detection ===
        path_threats = self._check_sensitive_paths(tool_name, params)
        threats.extend(path_threats)

        # === Check 4: SSRF protection ===
        ssrf_threats = self._check_ssrf(tool_name, params)
        threats.extend(ssrf_threats)

        # === Check 5: Tool chaining detection ===
        chain_threats = self._check_chain_attack(tool_name, params, session_id)
        threats.extend(chain_threats)

        # === Check 6: Catalog signatures ===
        param_str = " ".join(str(v) for v in params.values())
        catalog_threats = self._catalog.check(param_str, [ThreatCategory.TOOL_EXPLOITATION])
        threats.extend(catalog_threats)

        # Record this call for chain tracking
        self._chain_tracker[session_id].append((tool_name, time.time(), _param_summary(params)))

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        # Determine verdict
        max_level = max(threats, key=lambda t: [
            ThreatLevel.NONE, ThreatLevel.LOW, ThreatLevel.MEDIUM,
            ThreatLevel.HIGH, ThreatLevel.CRITICAL,
        ].index(t.level))

        if max_level.level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            verdict = ShieldVerdict.BLOCK
            self._stats["blocks"] += 1
        elif max_level.level == ThreatLevel.MEDIUM:
            verdict = ShieldVerdict.CHALLENGE if not self._config.strict_mode else ShieldVerdict.BLOCK
        else:
            verdict = ShieldVerdict.SANITIZE

        logger.warning(
            "[ToolGuard] %s on %s: %d threats (verdict=%s, %.1fms)",
            verdict.value.upper(), tool_name, len(threats), verdict.value, elapsed,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    def _check_rate_limit(
        self, tool_name: str, session_id: str, policy: ToolPolicy,
    ) -> Optional[ThreatDetection]:
        """Check if tool call rate exceeds policy."""
        now = time.time()
        tracker = self._rate_tracker[session_id][tool_name]
        tracker.append(now)

        # Count calls in the last 60 seconds
        cutoff = now - 60
        recent = sum(1 for t in tracker if t > cutoff)

        if recent > policy.rate:
            self._stats["rate_limits"] += 1
            return ThreatDetection(
                category=ThreatCategory.TOOL_EXPLOITATION,
                level=ThreatLevel.MEDIUM,
                verdict=ShieldVerdict.CHALLENGE,
                description=f"Rate limit exceeded: {tool_name} called {recent}/{policy.rate} per minute",
                evidence=f"{recent} calls in 60s (limit: {policy.rate})",
                layer=self.LAYER_NAME,
                confidence=0.95,
                suggested_action="Throttle tool calls",
                signature_id="TG-RATE",
            )
        return None

    def _check_parameters(self, tool_name: str, params: Dict[str, Any]) -> List[ThreatDetection]:
        """Validate tool parameters for injection attacks."""
        threats = []

        # Check bash commands for dangerous patterns
        if tool_name in ("local_bash", "bash", "execute_command"):
            cmd = str(params.get("command", params.get("cmd", "")))
            if cmd:
                # Check for command injection metacharacters
                dangerous_patterns = [
                    (r"\brm\s+(?:-[a-z]*)?(?:\s+-[a-z]*)?\s*/", "Destructive rm at root"),
                    (r";\s*(?:rm|del|format|mkfs|dd)\b", "Destructive command chain"),
                    (r"\|\s*(?:bash|sh|cmd|powershell)\b", "Shell pipe injection"),
                    (r"`[^`]*`", "Backtick command substitution"),
                    (r"\$\([^)]+\)", "Command substitution"),
                    (r">\s*/dev/tcp/", "Reverse shell pattern"),
                    (r":\(\)\s*\{.*\}", "Fork bomb pattern"),
                    (r"\b(?:mkfs|dd\s+if=|format\s+[a-z]:)\b", "Destructive disk operation"),
                    # Symlink creation targeting sensitive paths (CVE-2025-53109/53110)
                    (r"\bln\s+-s\b.*?(?:\.env|\.ssh|credentials|secrets|private.?key|wallet\.dat|seed\.txt|mnemonic)", "Symlink to sensitive file"),
                    (r"\bmklink\b.*?(?:\.env|\.ssh|credentials|secrets|private.?key)", "Windows symlink to sensitive file"),
                    # Environment variable injection
                    (r"(?:export|set)\s+(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|PYTHONPATH|NODE_PATH)\s*=", "Environment variable injection"),
                ]
                for pattern, desc in dangerous_patterns:
                    if re.search(pattern, cmd, re.I):
                        threats.append(ThreatDetection(
                            category=ThreatCategory.TOOL_EXPLOITATION,
                            level=ThreatLevel.CRITICAL,
                            verdict=ShieldVerdict.BLOCK,
                            description=f"Dangerous bash pattern: {desc}",
                            evidence=cmd[:200],
                            layer=self.LAYER_NAME,
                            confidence=0.85,
                            suggested_action="Block command execution",
                            signature_id="TG-CMD",
                        ))

        return threats

    def _check_sensitive_paths(self, tool_name: str, params: Dict[str, Any]) -> List[ThreatDetection]:
        """
        Check for access to sensitive file paths.

        Resolves symlinks to canonical paths before checking, defeating
        CVE-2025-53109/53110 style attacks where symlinks point to
        sensitive files but the path string looks innocent.
        """
        threats = []

        if tool_name not in ("local_read_file", "read_file", "local_write_file", "write_file",
                             "local_bash", "bash", "execute_command"):
            return threats

        # Extract paths from params
        path_str = str(params.get("path", params.get("file_path", params.get("command", ""))))

        # === Symlink resolution ===
        # Check both the literal path AND the resolved canonical path
        paths_to_check = [path_str]
        try:
            # Resolve symlinks to get the real target
            canonical = os.path.realpath(path_str)
            if canonical != path_str:
                paths_to_check.append(canonical)
                # If the canonical path differs, this might be a symlink attack
                if os.path.islink(path_str):
                    # Check if the symlink target is sensitive
                    for sensitive in self._config.sensitive_paths:
                        if sensitive.lower() in canonical.lower():
                            threats.append(ThreatDetection(
                                category=ThreatCategory.TOOL_EXPLOITATION,
                                level=ThreatLevel.CRITICAL,
                                verdict=ShieldVerdict.BLOCK,
                                description=f"Symlink points to sensitive path: {path_str} -> {canonical}",
                                evidence=f"Symlink: {path_str[:100]} -> {canonical[:100]}",
                                layer=self.LAYER_NAME,
                                confidence=0.95,
                                suggested_action="Block symlink-based path traversal",
                                signature_id="TG-SYMLINK",
                            ))
                            return threats  # Critical, no need to check further
        except (OSError, ValueError):
            pass  # Path doesn't exist yet or is invalid, check literal only

        # Standard sensitive path check (on both literal and canonical)
        for check_path in paths_to_check:
            for sensitive in self._config.sensitive_paths:
                if sensitive.lower() in check_path.lower():
                    threats.append(ThreatDetection(
                        category=ThreatCategory.TOOL_EXPLOITATION,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.CHALLENGE,
                        description=f"Access to sensitive path: {sensitive}",
                        evidence=check_path[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.80,
                        suggested_action="Verify access is authorized",
                        signature_id="TG-PATH",
                    ))
                    return threats  # One is enough

        return threats

    def _check_ssrf(self, tool_name: str, params: Dict[str, Any]) -> List[ThreatDetection]:
        """Check for SSRF attempts in URLs."""
        threats = []

        if tool_name not in ("browser_navigate", "web_fetch", "web_search"):
            return threats

        url = str(params.get("url", params.get("query", "")))
        for pattern in _SSRF_PATTERNS:
            if pattern.search(url):
                threats.append(ThreatDetection(
                    category=ThreatCategory.TOOL_EXPLOITATION,
                    level=ThreatLevel.HIGH,
                    verdict=ShieldVerdict.BLOCK,
                    description="SSRF: Request to internal/private network address",
                    evidence=url[:200],
                    layer=self.LAYER_NAME,
                    confidence=0.95,
                    suggested_action="Block internal network access",
                    signature_id="TG-SSRF",
                ))
                break

        return threats

    def _check_chain_attack(
        self, tool_name: str, params: Dict[str, Any], session_id: str,
    ) -> List[ThreatDetection]:
        """
        Detect multi-step attack chains.

        Patterns:
        - File read → Web request = possible exfiltration
        - Web fetch → Memory store = possible injection
        - Rapid sequential sensitive operations
        """
        threats = []
        chain = self._chain_tracker[session_id]

        if len(chain) < 2:
            return threats

        now = time.time()
        recent = [(name, ts, summary) for name, ts, summary in chain if now - ts < 300]

        # Pattern: file read followed by web request (exfiltration)
        if tool_name in ("browser_navigate", "web_fetch"):
            file_reads = [r for r in recent if r[0] in ("local_read_file", "read_file")]
            if file_reads:
                # Check if any read was of sensitive content
                for read_name, read_ts, read_summary in file_reads:
                    if any(s in read_summary for s in self._config.sensitive_paths):
                        self._stats["chain_detections"] += 1
                        threats.append(ThreatDetection(
                            category=ThreatCategory.CHAIN_ATTACK,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.QUARANTINE,
                            description="Exfiltration chain: sensitive file read → web request",
                            evidence=f"Read {read_summary} then {tool_name}({_param_summary(params)})",
                            layer=self.LAYER_NAME,
                            confidence=0.75,
                            suggested_action="Block potential data exfiltration",
                            signature_id="TG-CHAIN-EXFIL",
                        ))

        # Pattern: web fetch followed by memory store (injection)
        if tool_name in ("memory_store",):
            web_fetches = [r for r in recent if r[0] in ("web_fetch", "browser_navigate")]
            if web_fetches:
                self._stats["chain_detections"] += 1
                threats.append(ThreatDetection(
                    category=ThreatCategory.CHAIN_ATTACK,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.CHALLENGE,
                    description="Injection chain: web fetch → memory store",
                    evidence="Fetched content then storing to memory",
                    layer=self.LAYER_NAME,
                    confidence=0.65,
                    suggested_action="Validate memory content from external source",
                    signature_id="TG-CHAIN-INJECT",
                ))

        return threats

    def get_stats(self) -> Dict:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            **self._stats,
        }


def _param_summary(params: Dict[str, Any]) -> str:
    """Create a short summary of params for tracking."""
    parts = []
    for key in ("path", "file_path", "url", "command", "cmd", "query"):
        if key in params:
            val = str(params[key])
            parts.append(val[:80])
    return "|".join(parts) if parts else str(params)[:80]
