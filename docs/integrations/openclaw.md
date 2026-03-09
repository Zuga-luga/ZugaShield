# OpenClaw Plugin

`@zugashield/openclaw-plugin` integrates ZugaShield into [OpenClaw](https://github.com/openclaw/openclaw), protecting all channels (Signal, Telegram, Discord, WhatsApp, web) from a single plugin.

## Architecture

```
User (any channel) -> OpenClaw Gateway -> ZugaShield hooks -> zugashield-mcp (Python, stdio)
```

The plugin spawns `zugashield-mcp` as a managed child process. The process stays resident — there is no per-call spawn cost. Tool calls are always fail-closed regardless of configuration.

## Install

### 1. Install ZugaShield

```bash
pip install "zugashield[mcp]"
```

### 2. Install the plugin

```bash
npm install @zugashield/openclaw-plugin
```

Or clone into `extensions/`:

```bash
cd extensions
git clone https://github.com/AntonioCiolworking/zugashield-openclaw-plugin zugashield
cd zugashield && npm install && npm run build
```

### 3. Configure openclaw.json

```json
{
  "plugins": {
    "entries": {
      "zugashield": {
        "enabled": true,
        "config": {
          "fail_closed": true,
          "strict_mode": false
        }
      }
    }
  }
}
```

### 4. Restart OpenClaw

```bash
openclaw restart
```

### 5. Verify

Send `/shield status` from any channel. Expected output:

```
--- ZugaShield Status ---
Python: 3.12.0
Scanner: CONNECTED
Fail-closed: true
Strict mode: false
Scanning: inputs=true outputs=true tools=true memory=true
```

## 4 Gateway Hooks

The plugin registers up to 4 hooks at `priority: 100` (runs before other plugins). All hooks use `criticality: "required"`.

| Hook | ZugaShield Tool | Protects Against |
|------|----------------|-----------------|
| `preRequest` | `scan_input` | Prompt injection, unicode smuggling, instruction override |
| `preToolExecution` | `scan_tool_call` | SSRF, command injection, path traversal |
| `preResponse` | `scan_output` | Secret leakage, PII exposure, data exfiltration |
| `preRecall` | `scan_memory` | Memory poisoning, embedded instructions |

Each hook can be toggled independently via the `scan.*` config options.

## Configuration

All fields are optional — defaults are secure.

```json
{
  "fail_closed": true,
  "strict_mode": false,
  "scan": {
    "inputs": true,
    "outputs": true,
    "tool_calls": true,
    "memory": true
  },
  "excluded_channels": [],
  "mcp": {
    "python_executable": "python",
    "call_timeout_ms": 80,
    "startup_timeout_ms": 8000,
    "max_reconnect_attempts": 10
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `fail_closed` | `true` | Block requests when scanner is unavailable |
| `strict_mode` | `false` | Block medium+ threats (default: high/critical only) |
| `scan.inputs` | `true` | Scan user messages before processing |
| `scan.outputs` | `true` | Scan responses before delivery |
| `scan.tool_calls` | `true` | Validate tool calls (cannot be excluded by channel) |
| `scan.memory` | `true` | Scan memory before recall |
| `excluded_channels` | `[]` | Channel IDs to skip scanning (tool calls are never skipped) |
| `mcp.python_executable` | `"python"` | Path to Python 3.10+ interpreter |
| `mcp.call_timeout_ms` | `80` | Per-scan timeout in milliseconds |
| `mcp.startup_timeout_ms` | `8000` | MCP server startup timeout |
| `mcp.max_reconnect_attempts` | `10` | Auto-reconnect attempts before giving up |

## /shield Command

Available from any connected channel.

| Subcommand | Description |
|-----------|-------------|
| `/shield status` | Connection state, Python version, enabled layers |
| `/shield report` | Scan count, block count, recent threat events |
| `/shield` (no args) | Shows usage help |

## Startup Behavior

Registration is asynchronous. On startup:

1. Plugin resolves config and runs a preflight check (verifies Python version and `zugashield_mcp` is importable).
2. If preflight fails, only the `/shield` command is registered (no hooks). This ensures no false sense of security.
3. If preflight passes, a `ShieldClient` is created, the `zugashield-mcp` service is registered, and all configured hooks are registered.

## Reconnection

If the MCP server process crashes, the plugin retries with exponential backoff and jitter: `500ms * 2^attempt` (capped at 30 seconds), up to `max_reconnect_attempts`.

## Child Process Environment

The plugin passes a minimal, curated environment to the `zugashield-mcp` child process. It explicitly blocks most host environment variables to prevent leaking API keys or credentials to the subprocess. Only system essentials, Python runtime variables, and non-secret ZugaShield config variables are forwarded.

Last Updated: 2026-02-17
