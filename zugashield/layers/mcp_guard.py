"""
ZugaShield - MCP Protocol Security Layer
==========================================

Validates Model Context Protocol (MCP) tool definitions and call-time
parameters, providing defense-in-depth for agent tool ecosystems.

Threats addressed:

1. Prompt injection via tool descriptions — attacker-controlled MCP servers
   embed injection payloads in ``description`` and ``name`` fields that the
   LLM reads as implicit instructions (Riley Goodside / Kai Greshake research).

2. Role override — tool metadata attempts to reassign system-level roles.

3. Hidden instructions — whitespace-concealed directives in descriptions.

4. Schema violations — tool calls with missing required params or unexpected
   extra params that could indicate parameter smuggling.

5. Tool integrity — hash-based verification that a tool definition has not
   changed since it was first registered (supply-chain tampering detection).

6. Cross-server name collision — two MCP servers expose a tool with the same
   name, enabling confusion attacks where the LLM calls the wrong server.

This layer migrates the inline ``scan_tool_definitions()`` logic that was
previously embedded in the main shield facade into a proper, testable layer.

Integration point: Call ``layer.scan_definitions(tools)`` when MCP server
tool lists are ingested, and ``await layer.check(tool_name, params)`` before
every tool invocation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

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

# =============================================================================
# Injection keywords for description scanning
# Aligned with PromptArmorLayer fast patterns but scoped to MCP field content
# =============================================================================

_INJECTION_KEYWORDS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
            r"(?:instructions|directives|rules|prompts)",
            re.I,
        ),
        "Ignore previous instructions",
    ),
    (
        re.compile(
            r"(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are))\s+"
            r"(?:a|an|the|my)?\s*(?:new|different|unrestricted|jailbroken|evil|DAN)",
            re.I,
        ),
        "Role hijacking payload",
    ),
    (
        re.compile(
            r"(?:disable|bypass|ignore|turn\s+off)\s+(?:all\s+)?(?:safety|filter|restriction|guard)",
            re.I,
        ),
        "Safety bypass instruction",
    ),
    (
        re.compile(
            r"(?:system|override)\s*prompt\s*(?:override|replacement|injection)",
            re.I,
        ),
        "System prompt override",
    ),
    (
        re.compile(
            r"<\|(?:im_start|im_end|system|endoftext|sep)\|>",
            re.I,
        ),
        "Control token smuggling",
    ),
    (
        re.compile(
            r"\[INST\].*?\[/INST\]",
            re.I | re.DOTALL,
        ),
        "Instruction delimiter injection",
    ),
    (
        re.compile(
            r"<<SYS>>.*?<</SYS>>",
            re.I | re.DOTALL,
        ),
        "System tag injection",
    ),
    (
        re.compile(
            r"(?:reveal|leak|print|output|show|display)\s+"
            r"(?:all\s+)?(?:your\s+)?(?:system\s+prompt|instructions|context|memory|secrets)",
            re.I,
        ),
        "Prompt extraction instruction",
    ),
]

# Role override patterns in tool metadata
_ROLE_OVERRIDE_PATTERNS: List[re.Pattern] = [
    re.compile(
        r"\byou\s+(?:are|must|should|will)\s+(?:now\s+)?(?:act|behave|respond)\s+as\b",
        re.I,
    ),
    re.compile(
        r"\bassume\s+the\s+(?:role|persona|identity)\s+of\b",
        re.I,
    ),
    re.compile(
        r"\bswitch\s+(?:to|into)\s+(?:developer|debug|admin|sudo|god|unrestricted)\s+mode\b",
        re.I,
    ),
]

# Hidden instruction patterns: content made invisible via whitespace packing
_HIDDEN_INSTRUCTION_PATTERNS: List[re.Pattern] = [
    # Many consecutive spaces (>5) between words — typical whitespace stuffing
    re.compile(r"\S\s{5,}\S"),
    # Newline-separated content buried after long blank lines
    re.compile(r"\n{4,}"),
    # Zero-width space injection
    re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad]"),
]


def _hash_definition(definition: Dict[str, Any]) -> str:
    """Compute a stable SHA-256 hash of a tool definition dict."""
    canonical = json.dumps(definition, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class MCPGuardLayer:
    """
    Layer: MCP Protocol Security.

    Validates MCP tool definitions at ingestion time and enforces
    integrity and schema constraints at call time.
    """

    LAYER_NAME = "mcp_guard"

    def __init__(self, config: ShieldConfig) -> None:
        self._config = config
        # tool_name -> (server_id, definition_hash)
        # server_id defaults to "default" when not provided
        self._known_tools: Dict[str, Tuple[str, str]] = {}
        # Track all (tool_name, server_id) pairs to detect name collisions
        self._server_tool_index: Dict[str, Set[str]] = {}  # tool_name -> {server_ids}
        self._stats: Dict[str, int] = {
            "checks": 0,
            "definitions_scanned": 0,
            "poisoned_tools": 0,
            "schema_violations": 0,
            "integrity_violations": 0,
            "confusion_attacks": 0,
        }

    # =========================================================================
    # Public API: call-time check
    # =========================================================================

    async def check(
        self,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None,
        definition: Optional[Dict[str, Any]] = None,
        server_id: str = "default",
        **kwargs: Any,
    ) -> ShieldDecision:
        """
        Check an MCP tool call for security issues.

        Args:
            tool_name: The tool name being called.
            params: Parameters passed to the tool at call time.
            definition: Optional current definition dict for integrity check.
                        If omitted, integrity check is skipped.
            server_id: The MCP server this call originates from.
            **kwargs: Ignored; accepts extra keyword args for forward compatibility.

        Returns:
            ShieldDecision with verdict and any threats detected.
        """
        if not self._config.mcp_guard_enabled:
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["checks"] += 1
        threats: List[ThreatDetection] = []

        params = params or {}

        # === Check 1: Tool name injection ===
        name_threats = self._check_name_injection(tool_name)
        threats.extend(name_threats)

        # === Check 2: Schema validation ===
        if definition:
            schema_threats = self._check_schema(tool_name, params, definition)
            threats.extend(schema_threats)

        # === Check 3: Tool integrity ===
        if definition:
            integrity_threat = self.check_tool_integrity(tool_name, definition)
            if integrity_threat:
                threats.append(integrity_threat)

        # === Check 4: Cross-server confusion ===
        confusion_threat = self._check_name_collision(tool_name, server_id)
        if confusion_threat:
            threats.append(confusion_threat)

        # === Check 5: Parameter value injection ===
        param_threats = self._check_param_injection(tool_name, params)
        threats.extend(param_threats)

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        # Determine verdict
        level_order = [
            ThreatLevel.NONE,
            ThreatLevel.LOW,
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]
        worst = max(threats, key=lambda t: level_order.index(t.level))

        if worst.level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            verdict = ShieldVerdict.BLOCK
        elif worst.level == ThreatLevel.MEDIUM:
            verdict = ShieldVerdict.CHALLENGE if not self._config.strict_mode else ShieldVerdict.BLOCK
        else:
            verdict = ShieldVerdict.SANITIZE

        logger.warning(
            "[MCPGuard] %s on tool '%s': %d threat(s) (verdict=%s, %.1fms)",
            verdict.value.upper(),
            tool_name,
            len(threats),
            verdict.value,
            elapsed,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    # =========================================================================
    # Public API: definition scanning
    # =========================================================================

    def scan_definitions(
        self,
        tools: List[Dict[str, Any]],
        server_id: str = "default",
    ) -> Tuple[List[Dict[str, Any]], List[ThreatDetection]]:
        """
        Scan MCP tool definitions for injection payloads.

        Call this when ingesting a tool list from an MCP server, before
        presenting those tools to the LLM.  Returns two values:
        - clean_tools: tools that passed inspection (may be empty)
        - threats: all threats detected across all tool definitions

        Args:
            tools: List of MCP tool definition dicts (name, description, inputSchema, ...).
            server_id: Identifier for the MCP server providing these tools.

        Returns:
            Tuple of (clean_tools, threats).
        """
        clean_tools: List[Dict[str, Any]] = []
        all_threats: List[ThreatDetection] = []

        for tool in tools:
            self._stats["definitions_scanned"] += 1
            tool_threats = self._scan_single_definition(tool, server_id)

            if tool_threats:
                self._stats["poisoned_tools"] += 1
                all_threats.extend(tool_threats)
                logger.warning(
                    "[MCPGuard] Poisoned tool definition rejected: '%s' (%d threat(s))",
                    tool.get("name", "<unnamed>"),
                    len(tool_threats),
                )
            else:
                clean_tools.append(tool)
                # Register clean tools for future integrity checks
                name = tool.get("name", "")
                if name:
                    self.register_tool(name, tool, server_id=server_id)

        return clean_tools, all_threats

    def register_tool(
        self,
        tool_name: str,
        definition: Dict[str, Any],
        server_id: str = "default",
    ) -> None:
        """
        Register a known-good tool definition for integrity checking.

        Stores a SHA-256 hash of the definition. Subsequent calls to
        ``check_tool_integrity()`` will flag any deviation.

        Args:
            tool_name: Canonical tool name.
            definition: The authoritative definition dict.
            server_id: The MCP server this tool belongs to.
        """
        definition_hash = _hash_definition(definition)
        self._known_tools[tool_name] = (server_id, definition_hash)

        # Track which servers expose this tool name (for confusion detection)
        if tool_name not in self._server_tool_index:
            self._server_tool_index[tool_name] = set()
        self._server_tool_index[tool_name].add(server_id)

        logger.debug(
            "[MCPGuard] Registered tool '%s' from server '%s' (hash=%s...)",
            tool_name,
            server_id,
            definition_hash[:12],
        )

    def check_tool_integrity(
        self,
        tool_name: str,
        definition: Dict[str, Any],
    ) -> Optional[ThreatDetection]:
        """
        Check if a tool definition has changed since it was registered.

        A hash mismatch indicates either a supply-chain tampering event
        (the MCP server was compromised) or a tool that was silently updated
        without going through the normal registration flow.

        Args:
            tool_name: Tool name to look up in the registry.
            definition: Current definition to compare against registered hash.

        Returns:
            ThreatDetection if integrity check fails, None if clean.
        """
        if tool_name not in self._known_tools:
            # Not yet registered — cannot compare
            return None

        registered_server_id, registered_hash = self._known_tools[tool_name]
        current_hash = _hash_definition(definition)

        if current_hash == registered_hash:
            return None

        self._stats["integrity_violations"] += 1
        logger.error(
            "[MCPGuard] INTEGRITY VIOLATION: tool '%s' definition changed "
            "(registered=%s..., current=%s...)",
            tool_name,
            registered_hash[:12],
            current_hash[:12],
        )

        return ThreatDetection(
            category=ThreatCategory.TOOL_EXPLOITATION,
            level=ThreatLevel.CRITICAL,
            verdict=ShieldVerdict.BLOCK,
            description=(
                f"MCP tool definition integrity violation: '{tool_name}' has changed "
                f"since registration (possible supply-chain attack)"
            ),
            evidence=(
                f"Registered hash: {registered_hash[:16]}... | "
                f"Current hash: {current_hash[:16]}..."
            ),
            layer=self.LAYER_NAME,
            confidence=0.99,  # Hash mismatch is deterministic
            suggested_action="Reject tool; re-verify MCP server integrity",
            signature_id="MCP-INTEGRITY",
            metadata={
                "tool_name": tool_name,
                "registered_server": registered_server_id,
                "registered_hash": registered_hash,
                "current_hash": current_hash,
            },
        )

    # =========================================================================
    # Internal scanning helpers
    # =========================================================================

    def _scan_single_definition(
        self,
        tool: Dict[str, Any],
        server_id: str,
    ) -> List[ThreatDetection]:
        """Scan a single tool definition dict for all threat types."""
        threats: List[ThreatDetection] = []
        tool_name: str = tool.get("name", "<unnamed>")
        description: str = tool.get("description", "")

        # --- MCP-INJECT: Injection payload in description or name ---
        inject_threats = self._check_description_injection(tool_name, description)
        threats.extend(inject_threats)

        # Also check the tool name itself for injection (rare but possible)
        name_threats = self._check_name_injection(tool_name)
        threats.extend(name_threats)

        # --- MCP-ROLE: Role override in description ---
        role_threats = self._check_role_override(tool_name, description)
        threats.extend(role_threats)

        # --- MCP-HIDDEN: Hidden instructions in description ---
        hidden_threats = self._check_hidden_instructions(tool_name, description)
        threats.extend(hidden_threats)

        # --- MCP-CONFUSION: Name collision across servers ---
        confusion_threat = self._check_name_collision(tool_name, server_id)
        if confusion_threat:
            threats.append(confusion_threat)

        return threats

    def _check_description_injection(
        self,
        tool_name: str,
        description: str,
    ) -> List[ThreatDetection]:
        """MCP-INJECT: Scan description for prompt injection payloads."""
        threats: List[ThreatDetection] = []

        if not description:
            return threats

        for pattern, payload_description in _INJECTION_KEYWORDS:
            match = pattern.search(description)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.INDIRECT_INJECTION,
                        level=ThreatLevel.CRITICAL,
                        verdict=ShieldVerdict.BLOCK,
                        description=(
                            f"MCP tool '{tool_name}': injection payload in description — "
                            f"{payload_description}"
                        ),
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.92,
                        suggested_action="Reject tool; do not present description to LLM",
                        signature_id="MCP-INJECT",
                        metadata={"tool_name": tool_name, "payload_type": payload_description},
                    )
                )
                break  # One injection pattern is enough to reject

        return threats

    def _check_name_injection(self, tool_name: str) -> List[ThreatDetection]:
        """MCP-INJECT: Scan the tool name itself for injected content."""
        threats: List[ThreatDetection] = []

        if not tool_name:
            return threats

        for pattern, payload_description in _INJECTION_KEYWORDS:
            match = pattern.search(tool_name)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.INDIRECT_INJECTION,
                        level=ThreatLevel.CRITICAL,
                        verdict=ShieldVerdict.BLOCK,
                        description=f"MCP tool name contains injection payload: {payload_description}",
                        evidence=tool_name[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.95,
                        suggested_action="Reject tool; name contains prompt injection payload",
                        signature_id="MCP-INJECT-NAME",
                        metadata={"tool_name": tool_name},
                    )
                )
                break

        return threats

    def _check_role_override(
        self,
        tool_name: str,
        description: str,
    ) -> List[ThreatDetection]:
        """MCP-ROLE: Detect role-reassignment attempts in tool metadata."""
        threats: List[ThreatDetection] = []

        if not description:
            return threats

        for pattern in _ROLE_OVERRIDE_PATTERNS:
            match = pattern.search(description)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.PRIVILEGE_ESCALATION,
                        level=ThreatLevel.CRITICAL,
                        verdict=ShieldVerdict.BLOCK,
                        description=(
                            f"MCP tool '{tool_name}': role override attempt in description"
                        ),
                        evidence=match.group(0)[:200],
                        layer=self.LAYER_NAME,
                        confidence=0.90,
                        suggested_action="Reject tool; description attempts to reassign model role",
                        signature_id="MCP-ROLE",
                        metadata={"tool_name": tool_name},
                    )
                )
                break

        return threats

    def _check_hidden_instructions(
        self,
        tool_name: str,
        description: str,
    ) -> List[ThreatDetection]:
        """MCP-HIDDEN: Detect hidden instructions in description via whitespace packing."""
        threats: List[ThreatDetection] = []

        if not description:
            return threats

        for pattern in _HIDDEN_INSTRUCTION_PATTERNS:
            match = pattern.search(description)
            if match:
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.INDIRECT_INJECTION,
                        level=ThreatLevel.HIGH,
                        verdict=ShieldVerdict.QUARANTINE,
                        description=(
                            f"MCP tool '{tool_name}': possible hidden instructions "
                            f"via whitespace or invisible characters"
                        ),
                        evidence=repr(match.group(0)[:100]),
                        layer=self.LAYER_NAME,
                        confidence=0.80,
                        suggested_action="Inspect raw description bytes; strip or reject tool",
                        signature_id="MCP-HIDDEN",
                        metadata={"tool_name": tool_name},
                    )
                )
                break

        return threats

    def _check_schema(
        self,
        tool_name: str,
        params: Dict[str, Any],
        definition: Dict[str, Any],
    ) -> List[ThreatDetection]:
        """
        MCP-SCHEMA: Validate call-time params against the tool's inputSchema.

        Checks:
        - Required parameters are present
        - No unexpected parameters beyond those declared in the schema
          (extra params can smuggle data past schema validation)
        """
        threats: List[ThreatDetection] = []

        input_schema = definition.get("inputSchema", definition.get("input_schema", {}))
        if not isinstance(input_schema, dict):
            return threats

        properties: Dict[str, Any] = input_schema.get("properties", {})
        required: List[str] = input_schema.get("required", [])

        # Check required params are present
        missing = [r for r in required if r not in params]
        if missing:
            self._stats["schema_violations"] += 1
            threats.append(
                ThreatDetection(
                    category=ThreatCategory.TOOL_EXPLOITATION,
                    level=ThreatLevel.MEDIUM,
                    verdict=ShieldVerdict.CHALLENGE,
                    description=(
                        f"MCP tool '{tool_name}': missing required parameter(s): "
                        f"{', '.join(missing[:5])}"
                    ),
                    evidence=f"Missing: {missing[:5]} | Provided: {list(params.keys())[:10]}",
                    layer=self.LAYER_NAME,
                    confidence=0.85,
                    suggested_action="Validate parameters before tool invocation",
                    signature_id="MCP-SCHEMA",
                    metadata={"tool_name": tool_name, "missing_params": missing},
                )
            )

        # Check for undeclared parameters (parameter smuggling)
        if properties:
            declared = set(properties.keys())
            provided = set(params.keys())
            unexpected = provided - declared
            if unexpected:
                self._stats["schema_violations"] += 1
                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.TOOL_EXPLOITATION,
                        level=ThreatLevel.MEDIUM,
                        verdict=ShieldVerdict.CHALLENGE,
                        description=(
                            f"MCP tool '{tool_name}': unexpected parameter(s) not in schema: "
                            f"{', '.join(list(unexpected)[:5])}"
                        ),
                        evidence=(
                            f"Unexpected: {list(unexpected)[:5]} | "
                            f"Declared: {list(declared)[:10]}"
                        ),
                        layer=self.LAYER_NAME,
                        confidence=0.75,
                        suggested_action="Strip or reject undeclared parameters",
                        signature_id="MCP-SCHEMA",
                        metadata={"tool_name": tool_name, "unexpected_params": list(unexpected)},
                    )
                )

        return threats

    def _check_name_collision(
        self,
        tool_name: str,
        server_id: str,
    ) -> Optional[ThreatDetection]:
        """
        MCP-CONFUSION: Detect cross-server tool name collision.

        If a tool with the same name is already registered from a different
        server, the LLM may call the wrong one — a confusion attack.
        This check is informational at registration time; at call time it
        catches cases where a new server tried to register a colliding name.
        """
        if tool_name not in self._server_tool_index:
            return None

        registered_servers = self._server_tool_index[tool_name]

        # Collision = same name registered from at least one other server
        other_servers = registered_servers - {server_id}
        if not other_servers:
            return None

        self._stats["confusion_attacks"] += 1
        logger.warning(
            "[MCPGuard] Cross-server name collision: tool '%s' from '%s' "
            "already registered from: %s",
            tool_name,
            server_id,
            ", ".join(other_servers),
        )

        return ThreatDetection(
            category=ThreatCategory.TOOL_EXPLOITATION,
            level=ThreatLevel.HIGH,
            verdict=ShieldVerdict.QUARANTINE,
            description=(
                f"MCP tool name collision: '{tool_name}' registered from multiple servers "
                f"({server_id} vs {', '.join(other_servers)}) — possible confusion attack"
            ),
            evidence=(
                f"Tool: '{tool_name}' | "
                f"Caller server: '{server_id}' | "
                f"Other servers: {', '.join(other_servers)}"
            ),
            layer=self.LAYER_NAME,
            confidence=0.85,
            suggested_action="Namespace tool names by server or reject duplicate registrations",
            signature_id="MCP-CONFUSION",
            metadata={
                "tool_name": tool_name,
                "caller_server": server_id,
                "conflicting_servers": list(other_servers),
            },
        )

    def _check_param_injection(
        self,
        tool_name: str,
        params: Dict[str, Any],
    ) -> List[ThreatDetection]:
        """
        MCP-INJECT: Scan call-time parameter values for injection payloads.

        String-valued parameters may contain prompt injection that bypasses
        description-level scanning if the attacker controls parameter content.
        """
        threats: List[ThreatDetection] = []

        for param_name, param_value in params.items():
            if not isinstance(param_value, str):
                continue
            if len(param_value) < 10:
                continue

            for pattern, payload_description in _INJECTION_KEYWORDS:
                match = pattern.search(param_value)
                if match:
                    threats.append(
                        ThreatDetection(
                            category=ThreatCategory.INDIRECT_INJECTION,
                            level=ThreatLevel.HIGH,
                            verdict=ShieldVerdict.QUARANTINE,
                            description=(
                                f"MCP tool '{tool_name}': injection payload in parameter "
                                f"'{param_name}' — {payload_description}"
                            ),
                            evidence=match.group(0)[:200],
                            layer=self.LAYER_NAME,
                            confidence=0.88,
                            suggested_action="Sanitize or reject parameter value before tool call",
                            signature_id="MCP-INJECT-PARAM",
                            metadata={
                                "tool_name": tool_name,
                                "param_name": param_name,
                            },
                        )
                    )
                    break  # One injection per param is enough

        return threats

    # =========================================================================
    # Stats
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            "registered_tools": len(self._known_tools),
            **self._stats,
        }
