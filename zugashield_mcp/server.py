"""
ZugaShield MCP Server
======================

Model Context Protocol server providing 9 security scanning tools
for AI agents. Runs as stdio transport.

Usage:
    python -m zugashield_mcp.server
    # or via entry point:
    zugashield-mcp

Tools provided:
    1. scan_input       - Scan user input for prompt injection
    2. scan_output      - Scan LLM output for data leakage
    3. scan_tool_call   - Validate a tool call before execution
    4. scan_tool_definitions - Scan MCP tool definitions for injection
    5. scan_memory      - Scan memory content before storage
    6. scan_document    - Pre-ingestion scanning for RAG documents
    7. get_threat_report - Get current threat statistics
    8. get_config       - Get current shield configuration
    9. update_config    - Update shield configuration
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Try to import MCP SDK
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
    _HAS_MCP = True
except ImportError:
    _HAS_MCP = False

from zugashield import ZugaShield  # noqa: E402


def _decision_to_dict(decision) -> Dict[str, Any]:
    """Convert ShieldDecision to JSON-serializable dict."""
    return {
        "verdict": decision.verdict.value,
        "is_blocked": decision.is_blocked,
        "threat_count": decision.threat_count,
        "max_threat_level": decision.max_threat_level.value,
        "elapsed_ms": round(decision.elapsed_ms, 2),
        "threats": [
            {
                "category": t.category.value,
                "level": t.level.value,
                "description": t.description,
                "evidence": t.evidence[:200],
                "confidence": t.confidence,
                "signature_id": t.signature_id,
            }
            for t in decision.threats_detected
        ],
    }


def create_server() -> "Server":
    """Create and configure the MCP server."""
    if not _HAS_MCP:
        raise ImportError(
            "MCP SDK is required. Install with: pip install zugashield[mcp]"
        )

    server = Server("zugashield")
    shield = ZugaShield()

    @server.list_tools()
    async def list_tools() -> List[Tool]:
        return [
            Tool(
                name="scan_input",
                description="Scan user input for prompt injection, encoding attacks, and other threats",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "User input text to scan"},
                        "session_id": {"type": "string", "description": "Optional session ID for multi-turn tracking"},
                    },
                    "required": ["text"],
                },
            ),
            Tool(
                name="scan_output",
                description="Scan LLM output for data leakage, secrets, PII, and exfiltration patterns",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "LLM output text to scan"},
                        "session_id": {"type": "string", "description": "Optional session ID"},
                    },
                    "required": ["text"],
                },
            ),
            Tool(
                name="scan_tool_call",
                description="Validate a tool call before execution (SSRF, command injection, path traversal)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string", "description": "Name of the tool being called"},
                        "params": {"type": "object", "description": "Tool call parameters"},
                        "session_id": {"type": "string", "description": "Optional session ID"},
                    },
                    "required": ["tool_name", "params"],
                },
            ),
            Tool(
                name="scan_tool_definitions",
                description="Scan MCP tool definitions for hidden injection payloads (CVE-2025-53773)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "tools": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "List of tool definition objects",
                        },
                    },
                    "required": ["tools"],
                },
            ),
            Tool(
                name="scan_memory",
                description="Scan memory content before storage for poisoning attacks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "Memory content to scan"},
                        "source": {"type": "string", "description": "Source of the memory (user, web, etc.)"},
                    },
                    "required": ["content"],
                },
            ),
            Tool(
                name="scan_document",
                description="Pre-ingestion scanning for RAG documents",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "Document text to scan"},
                        "source": {"type": "string", "description": "Document source"},
                        "document_type": {"type": "string", "description": "Document type (pdf, html, txt)"},
                    },
                    "required": ["content"],
                },
            ),
            Tool(
                name="get_threat_report",
                description="Get current threat statistics and audit log",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "description": "Max audit events to return", "default": 20},
                    },
                },
            ),
            Tool(
                name="get_config",
                description="Get current ZugaShield configuration",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            Tool(
                name="update_config",
                description="Update ZugaShield configuration",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "strict_mode": {"type": "boolean", "description": "Enable strict mode"},
                        "enabled": {"type": "boolean", "description": "Enable/disable shield"},
                    },
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
        try:
            if name == "scan_input":
                ctx = {}
                if "session_id" in arguments:
                    ctx["session_id"] = arguments["session_id"]
                decision = await shield.check_prompt(arguments["text"], context=ctx or None)
                result = _decision_to_dict(decision)

            elif name == "scan_output":
                ctx = {}
                if "session_id" in arguments:
                    ctx["session_id"] = arguments["session_id"]
                decision = await shield.check_output(arguments["text"], context=ctx or None)
                result = _decision_to_dict(decision)

            elif name == "scan_tool_call":
                decision = await shield.check_tool_call(
                    arguments["tool_name"],
                    arguments["params"],
                    arguments.get("session_id", "default"),
                )
                result = _decision_to_dict(decision)

            elif name == "scan_tool_definitions":
                clean_tools = shield.scan_tool_definitions(arguments["tools"])
                removed = len(arguments["tools"]) - len(clean_tools)
                result = {
                    "total_scanned": len(arguments["tools"]),
                    "clean_tools": len(clean_tools),
                    "removed": removed,
                    "clean_tool_names": [t.get("name", "?") for t in clean_tools],
                }

            elif name == "scan_memory":
                decision = await shield.check_memory_write(
                    content=arguments["content"],
                    source=arguments.get("source", "unknown"),
                )
                result = _decision_to_dict(decision)

            elif name == "scan_document":
                decision = await shield.check_document(
                    content=arguments["content"],
                    source=arguments.get("source", "external"),
                    document_type=arguments.get("document_type", ""),
                )
                result = _decision_to_dict(decision)

            elif name == "get_threat_report":
                limit = arguments.get("limit", 20)
                result = {
                    "dashboard": shield.get_dashboard_data(),
                    "recent_events": shield.get_audit_log(limit=limit),
                }

            elif name == "get_config":
                result = shield.get_version_state()

            elif name == "update_config":
                if "strict_mode" in arguments:
                    shield._config.strict_mode = arguments["strict_mode"]
                if "enabled" in arguments:
                    shield._config.enabled = arguments["enabled"]
                result = {"status": "updated", "config": shield.get_version_state()}

            else:
                result = {"error": f"Unknown tool: {name}"}

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            logger.error("[ZugaShield MCP] Error in %s: %s", name, e)
            return [TextContent(
                type="text",
                text=json.dumps({"error": str(e)}),
            )]

    return server


async def _run_server():
    """Run the MCP server with stdio transport."""
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    """Entry point for the MCP server."""
    if not _HAS_MCP:
        print("Error: MCP SDK is required. Install with: pip install zugashield[mcp]")
        sys.exit(1)
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_run_server())


if __name__ == "__main__":
    main()
