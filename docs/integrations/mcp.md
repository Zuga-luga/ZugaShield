# MCP Integration

ZugaShield ships both an MCP server (`zugashield-mcp`) that exposes 9 security tools over the Model Context Protocol, and a Python interceptor (`ZugaShieldMCPInterceptor`) that wraps any MCP client.

## Install

```bash
pip install "zugashield[mcp]"
```

## MCP Server (zugashield-mcp)

The server runs as a stdio transport process, making ZugaShield's scanning available to any MCP client including Claude Desktop.

```bash
# Start manually
python -m zugashield_mcp.server
# or via entry point
zugashield-mcp
```

### 9 Tools

| Tool | Description |
|------|-------------|
| `scan_input` | Scan user input for prompt injection, encoding attacks, and other threats |
| `scan_output` | Scan LLM output for data leakage, secrets, and PII |
| `scan_tool_call` | Validate a tool call before execution (SSRF, command injection, path traversal) |
| `scan_tool_definitions` | Scan MCP tool definitions for hidden injection payloads (CVE-2025-53773) |
| `scan_memory` | Scan memory content before storage for poisoning attacks |
| `scan_document` | Pre-ingestion scanning for RAG documents |
| `get_threat_report` | Get current threat statistics and audit log |
| `get_config` | Get current ZugaShield configuration and enabled layers |
| `update_config` | Update shield configuration (strict_mode, enabled) |

### Tool Response Format

All `scan_*` tools return a JSON object:

```json
{
  "verdict": "allow",
  "is_blocked": false,
  "threat_count": 0,
  "max_threat_level": "none",
  "elapsed_ms": 1.24,
  "threats": []
}
```

When blocked:

```json
{
  "verdict": "block",
  "is_blocked": true,
  "threat_count": 1,
  "max_threat_level": "critical",
  "elapsed_ms": 2.1,
  "threats": [
    {
      "category": "prompt_injection",
      "level": "critical",
      "description": "Classic ignore instruction override",
      "evidence": "ignore all previous instructions",
      "confidence": 0.95,
      "signature_id": "PI-001"
    }
  ]
}
```

### Claude Desktop Setup

Add to `claude_desktop_config.json` (usually at `~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "zugashield": {
      "command": "python",
      "args": ["-m", "zugashield_mcp.server"]
    }
  }
}
```

With a virtual environment:

```json
{
  "mcpServers": {
    "zugashield": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "zugashield_mcp.server"]
    }
  }
}
```

After saving, restart Claude Desktop.

## Python Interceptor (ZugaShieldMCPInterceptor)

For Python applications using an MCP client, use `ZugaShieldMCPInterceptor` to scan tool definitions and validate calls.

### Scan Tool Definitions

```python
from zugashield import ZugaShield
from zugashield.integrations.mcp import ZugaShieldMCPInterceptor

shield = ZugaShield()
interceptor = ZugaShieldMCPInterceptor(shield=shield)

# Remove poisoned tools before presenting to LLM
raw_tools = await client.list_tools()
clean_tools = interceptor.scan_tools(raw_tools)
```

Accepts tools in MCP wire format (dicts with `name`, `description`, `inputSchema`) or as objects. Returns the same type as input with poisoned tools removed.

### Validate Tool Calls

```python
decision = await interceptor.check_call("bash", {"command": "rm -rf /"})
if decision.is_blocked:
    raise RuntimeError("Blocked by ZugaShield")
```

Runs the call through Layer 3 (Tool Guard): allowlist/denylist, rate limits, sensitive path detection.

### Check Tool Output

```python
decision = await interceptor.check_output("read_file", file_contents)
if decision.is_blocked:
    # Strip sensitive data before returning to LLM
    ...
```

Runs through Layer 5 (Exfiltration Guard).

### Statistics

```python
stats = interceptor.get_stats()
# {"tools_scanned": 12, "tools_removed": 1, "calls_checked": 45, "calls_blocked": 2}
```

## Convenience Wrapper (shield_wrap_mcp_client)

Patches a `ClientSession`-style MCP client in place to protect `list_tools` and `call_tool` automatically.

```python
from zugashield.integrations.mcp import shield_wrap_mcp_client

safe_client = shield_wrap_mcp_client(mcp_client, shield=shield, session_id="user-abc")

tools = await safe_client.list_tools()       # Poisoned tools removed
result = await safe_client.call_tool(        # Call validated before execution
    "read_file", {"path": "/etc/passwd"}
)
```

Compatible with the official MCP Python SDK (`mcp.ClientSession`) and any object with `list_tools()` and `call_tool()` methods.

If a call is blocked, `RuntimeError` is raised:

```
RuntimeError: ZugaShield blocked MCP call to 'read_file': Sensitive path detected
```

Last Updated: 2026-02-17
