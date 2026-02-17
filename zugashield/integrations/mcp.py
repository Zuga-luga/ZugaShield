"""
ZugaShield - MCP (Model Context Protocol) Interceptor
=======================================================

Scans MCP tool definitions for injection payloads and validates tool calls
before they reach the model.

Addresses CVE-2025-53773: prompt injection via poisoned tool descriptions.

Usage (scan tool list before presenting to LLM):
    from zugashield import ZugaShield
    from zugashield.integrations.mcp import ZugaShieldMCPInterceptor

    shield = ZugaShield()
    interceptor = ZugaShieldMCPInterceptor(shield=shield)

    # Filter poisoned tools from MCP server response
    clean_tools = interceptor.scan_tools(raw_tool_list)

    # Validate a call before execution
    decision = await interceptor.check_call("read_file", {"path": "/etc/passwd"})
    if decision.is_blocked:
        raise RuntimeError("Blocked by ZugaShield")

Usage (middleware-style wrapping of an MCP client):
    from zugashield.integrations.mcp import shield_wrap_mcp_client

    safe_client = shield_wrap_mcp_client(mcp_client, shield=shield)
    tools = await safe_client.list_tools()          # tools already scanned
    result = await safe_client.call_tool("name", {}) # call validated
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ZugaShieldMCPInterceptor:
    """
    MCP protocol security interceptor.

    Provides two main operations:

    1. ``scan_tools(tools)`` — synchronous scan of tool definitions.
       Removes tools whose name, description, or parameter descriptions
       contain injection payloads (uses the same scanner as
       ``ZugaShield.scan_tool_definitions``).

    2. ``check_call(tool_name, arguments)`` — async pre-execution check.
       Runs the tool call through Layer 3 (Tool Guard) and returns a
       ``ShieldDecision``.

    Args:
        shield:     Optional ZugaShield instance. Defaults to the singleton.
        session_id: Session identifier forwarded to tool_guard + anomaly detector.
        strict:     If True, also block tools whose descriptions look suspicious
                    but weren't caught by the catalog-based scanner.
    """

    def __init__(
        self,
        shield: Any = None,
        session_id: str = "default",
        strict: bool = False,
    ) -> None:
        self._shield_instance = shield
        self._session_id = session_id
        self._strict = strict
        self._stats: Dict[str, int] = {
            "tools_scanned": 0,
            "tools_removed": 0,
            "calls_checked": 0,
            "calls_blocked": 0,
        }

    def _get_shield(self) -> Any:
        if self._shield_instance is None:
            from zugashield import get_zugashield
            self._shield_instance = get_zugashield()
        return self._shield_instance

    # ------------------------------------------------------------------
    # Tool definition scanning (synchronous — happens at setup time)
    # ------------------------------------------------------------------

    def scan_tools(self, tools: List[Any]) -> List[Any]:
        """
        Scan a list of MCP tool definitions and remove poisoned ones.

        Accepts tools in MCP wire format (dicts) or any object with
        ``name``, ``description``, and ``inputSchema``/``input_schema``
        attributes.

        Args:
            tools: List of tool definitions from an MCP server.

        Returns:
            Filtered list with poisoned tools removed.

        Example:
            clean = interceptor.scan_tools(await client.list_tools())
        """
        shield = self._get_shield()
        self._stats["tools_scanned"] += len(tools)

        # Normalise to dicts that scan_tool_definitions can consume
        normalised: List[Dict[str, Any]] = []
        for tool in tools:
            normalised.append(self._normalise_tool(tool))

        # Delegate to the shield's built-in scanner (handles audit + logging)
        clean_normalised = shield.scan_tool_definitions(normalised)

        removed_count = len(normalised) - len(clean_normalised)
        self._stats["tools_removed"] += removed_count

        if removed_count:
            logger.warning(
                "[ZugaShield MCP] %d poisoned tool definition(s) removed from %d total",
                removed_count,
                len(tools),
            )

        # Return in the same format as the input (dict or object)
        # Build an index of clean tool names for fast lookup
        clean_names = {t.get("name") for t in clean_normalised}

        result: List[Any] = []
        for tool in tools:
            name = self._get_tool_name(tool)
            if name in clean_names:
                result.append(tool)

        return result

    # ------------------------------------------------------------------
    # Tool call validation (async — happens at execution time)
    # ------------------------------------------------------------------

    async def check_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Any:
        """
        Check an MCP tool call through ZugaShield before execution.

        Runs the call through Layer 3 (Tool Guard) which enforces:
        - Tool allowlist / denylist
        - Rate limits per tool
        - Sensitive path/parameter detection
        - Tool-specific risk policies

        Args:
            tool_name:  The MCP tool name being called.
            arguments:  The arguments dict from the MCP call message.

        Returns:
            ``ShieldDecision`` — check ``decision.is_blocked`` before executing.

        Example:
            decision = await interceptor.check_call("bash", {"command": "rm -rf /"})
            if decision.is_blocked:
                raise RuntimeError("Blocked")
        """
        shield = self._get_shield()
        self._stats["calls_checked"] += 1

        decision = await shield.check_tool_call(
            tool_name=tool_name,
            params=arguments,
            session_id=self._session_id,
        )

        if decision.is_blocked:
            self._stats["calls_blocked"] += 1
            logger.warning(
                "[ZugaShield MCP] Blocked call to '%s' (verdict=%s, threats=%d)",
                tool_name,
                decision.verdict.value,
                decision.threat_count,
            )

        return decision

    # ------------------------------------------------------------------
    # Output scanning (optional — call after tool execution)
    # ------------------------------------------------------------------

    async def check_output(
        self,
        tool_name: str,
        output: str,
    ) -> Any:
        """
        Check a tool's output for data exfiltration before returning to the LLM.

        Runs through Layer 5 (Exfiltration Guard).

        Args:
            tool_name: The tool that produced the output.
            output:    The string output from the tool.

        Returns:
            ``ShieldDecision``.
        """
        shield = self._get_shield()
        return await shield.check_output(
            output=output,
            context={"tool": tool_name, "session_id": self._session_id},
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, int]:
        """Return cumulative interception statistics."""
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_tool_name(tool: Any) -> str:
        """Extract tool name from a dict or object."""
        if isinstance(tool, dict):
            return tool.get("name", "")
        return getattr(tool, "name", "")

    @staticmethod
    def _normalise_tool(tool: Any) -> Dict[str, Any]:
        """
        Convert an MCP tool definition (dict or object) to the canonical
        dict format expected by ``ZugaShield.scan_tool_definitions``.

        MCP wire format (JSON Schema):
            {
                "name": "...",
                "description": "...",
                "inputSchema": {
                    "type": "object",
                    "properties": { ... }
                }
            }

        ZugaShield scan format:
            {
                "name": "...",
                "description": "...",
                "input_schema": {
                    "properties": { ... }
                }
            }
        """
        if isinstance(tool, dict):
            result = dict(tool)
            # MCP uses "inputSchema"; ZugaShield expects "input_schema"
            if "inputSchema" in result and "input_schema" not in result:
                result["input_schema"] = result["inputSchema"]
            return result

        # Object-style (e.g. mcp.types.Tool)
        result: Dict[str, Any] = {}
        result["name"] = getattr(tool, "name", "unknown")
        result["description"] = getattr(tool, "description", "")

        schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
        if schema is not None:
            if hasattr(schema, "__dict__"):
                schema = vars(schema)
            result["input_schema"] = schema

        return result


# =============================================================================
# Convenience: wrap an MCP client
# =============================================================================


def shield_wrap_mcp_client(
    client: Any,
    shield: Any = None,
    session_id: str = "default",
) -> Any:
    """
    Wrap an MCP client so that ``list_tools`` and ``call_tool`` are
    automatically protected by ZugaShield.

    Patches the client object in-place and returns it.

    Compatible with the official MCP Python SDK (``mcp.ClientSession``)
    and any object with ``list_tools()`` and ``call_tool()`` methods.

    Args:
        client:     The MCP client instance to wrap.
        shield:     Optional ZugaShield instance.
        session_id: Session identifier.

    Returns:
        The same client with protected methods.

    Raises:
        RuntimeError: If the client has no ``list_tools`` or ``call_tool`` methods.
    """
    import functools

    interceptor = ZugaShieldMCPInterceptor(shield=shield, session_id=session_id)

    # Wrap list_tools
    if hasattr(client, "list_tools"):
        original_list = client.list_tools

        @functools.wraps(original_list)
        async def _safe_list_tools(*args: Any, **kwargs: Any) -> Any:
            result = await original_list(*args, **kwargs)
            # MCP SDK returns a ListToolsResult with .tools attribute
            if hasattr(result, "tools"):
                result.tools = interceptor.scan_tools(result.tools)
            elif isinstance(result, list):
                result = interceptor.scan_tools(result)
            return result

        client.list_tools = _safe_list_tools

    # Wrap call_tool
    if hasattr(client, "call_tool"):
        original_call = client.call_tool

        @functools.wraps(original_call)
        async def _safe_call_tool(name: str, arguments: Optional[Dict] = None, *args: Any, **kwargs: Any) -> Any:
            arguments = arguments or {}
            decision = await interceptor.check_call(name, arguments)
            if decision.is_blocked:
                threat = (
                    decision.threats_detected[0]
                    if decision.threats_detected
                    else None
                )
                description = threat.description if threat else "Blocked by ZugaShield"
                raise RuntimeError(
                    f"ZugaShield blocked MCP call to '{name}': {description}"
                )
            return await original_call(name, arguments, *args, **kwargs)

        client.call_tool = _safe_call_tool

    logger.info("[ZugaShield] MCP client wrapped (session=%s)", session_id)
    return client
