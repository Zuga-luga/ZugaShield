---
name: zugashield
description: 7-layer AI security + ML detection for OpenClaw. Covers all 10 OWASP Agentic AI risks — prompt injection, tool misuse, memory poisoning, data exfiltration, and more — across ALL channels (Signal, Telegram, Discord, WhatsApp, web) simultaneously.
metadata:
  openclaw:
    requires:
      env: []
      bins:
        - python
      primaryModel: any
    permissions:
      - subprocess
  author: Zuga-luga
  license: MIT
  homepage: https://github.com/Zuga-luga/ZugaShield
  npm: zugashield-openclaw-plugin
---

# ZugaShield Security Scanner

7-layer AI security scanning plugin for OpenClaw. Protects all channels simultaneously by hooking into the Gateway — the single chokepoint for all traffic.

## What It Blocks

| Attack | Hook | Detection |
|--------|------|-----------|
| Prompt injection | preRequest | 150+ signatures, TF-IDF ML (88.7% recall), unicode smuggling, encoding evasion |
| SSRF / Command injection | preToolExecution | Cloud metadata URLs, shell metacharacters (always fail-closed) |
| Secret / PII leakage | preResponse | API keys, tokens, credentials, high-entropy strings |
| Memory poisoning | preRecall | Embedded instructions, sleeper payloads in recalled memories |
| DNS exfiltration | preResponse | High-entropy subdomains, data-in-DNS patterns |
| Path traversal | preToolExecution | Directory traversal sequences, symlink attacks |
| Supply chain attacks | startup | SHA-256 model verification, canary validation, version pinning |

## Install

```bash
pip install "zugashield[mcp]"
npm install zugashield-openclaw-plugin
openclaw plugins install ./node_modules/zugashield-openclaw-plugin
openclaw restart
```

## Verify

```
/shield status
```

Should show: `CONNECTED` with 7 active layers.

## Configuration

In `openclaw.json` under `plugins.entries.openclaw-plugin.config`:

- `fail_closed` (default: true) — Block requests when scanner is down
- `strict_mode` (default: false) — Block medium+ threats (not just high/critical)
- `scan.inputs` / `scan.outputs` / `scan.tool_calls` / `scan.memory` — Toggle individual hooks

## How It Works

ZugaShield spawns a Python MCP server as a managed child process. Each message, tool call, and response passes through the scanner in <15ms. The plugin uses OpenClaw's Gateway hooks, meaning one install protects Signal + Telegram + Discord + WhatsApp + web simultaneously.

Tool calls are **always fail-closed** regardless of configuration — SSRF and command injection are too dangerous to allow through even temporarily.

## Links

- [GitHub](https://github.com/Zuga-luga/ZugaShield)
- [npm](https://www.npmjs.com/package/zugashield-openclaw-plugin)
- [PyPI](https://pypi.org/project/zugashield/)
