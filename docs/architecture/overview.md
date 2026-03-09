# ZugaShield Architecture Overview

Last Updated: 2026-02-17

---

## Summary

ZugaShield is a 7-layer security pipeline for AI agents. Every piece of content that flows through an agent — user messages, LLM outputs, tool calls, memory reads and writes, documents for RAG ingestion, and financial transactions — passes through one or more layers before being acted upon. The pipeline is async throughout, stateless within each layer call, and designed to fail closed on configuration but fail open on individual errors within optional layers.

---

## System Architecture Diagram

```
  Caller / AI Framework
         │
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          ZugaShield                                 │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Perimeter                                          │   │
│  │  HTTP size limits · rate limiting · encoding validation      │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                         │ (pass / BLOCK)                            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Layer 2: Prompt Armor                                       │   │
│  │  10 detection strategies: compiled regex · catalog ·         │   │
│  │  unicode · ASCII art · encoding · crescendo · flooding ·     │   │
│  │  few-shot · GlitchMiner · document embedding                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                         │                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Layer 3: Tool Guard                                         │   │
│  │  SSRF · command injection · path traversal · chain attacks   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                         │                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Layer 4: Memory Sentinel                                    │   │
│  │  Write-path poisoning · recall validation · RAG pre-scan     │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                         │                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Layer 5: Exfiltration Guard                                 │   │
│  │  70+ secret patterns · PII · canary tokens · DNS exfil       │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                         │                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Layer 6: Anomaly Detector                                   │   │
│  │  Cross-layer event correlation · session scoring ·           │   │
│  │  chain attack detection · alternating pattern detection      │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                         │                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Layer 7: Wallet Fortress                                    │   │
│  │  Transaction approval · spend limits · address validation    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                         │                                           │
│  ┌──── Cross-layer subsystems ────────────────────────────────┐    │
│  │  MCP Guard (tool definition integrity)                      │    │
│  │  LLM Judge (optional — ambiguous case arbitration)          │    │
│  │  Code Scanner (optional — LLM-generated code analysis)      │    │
│  │  CoT Auditor (optional — reasoning trace inspection)        │    │
│  │  ML Detector (optional — TF-IDF + ONNX DeBERTa)            │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
         │
         ▼
  ShieldDecision { verdict, threats_detected, layer, elapsed_ms }
```

---

## Input Flow: First BLOCK Wins

All primary check paths follow a short-circuit pipeline. As soon as any layer returns a verdict of `BLOCK` or `QUARANTINE`, the pipeline stops and returns that decision to the caller. Layers do not run in parallel; they run sequentially in order.

```
Input
  │
  ├─► Layer 1 check ──► verdict == BLOCK? ──► return immediately
  │
  ├─► Layer 2 check ──► verdict == BLOCK? ──► return immediately
  │
  ├─► Layer 3 check ──► verdict == BLOCK? ──► return immediately
  │
  ├─► ...
  │
  └─► All layers pass ──► return ALLOW
```

`SANITIZE` and `CHALLENGE` verdicts do not stop the pipeline. A `SANITIZE` result means the layer cleaned the input and the cleaned version is passed to subsequent layers. A `CHALLENGE` result is recorded and propagated to the final decision but does not halt scanning.

The final decision aggregates all non-ALLOW verdicts by selecting the most severe one.

---

## The 5-Verdict System

ZugaShield uses five ordered verdicts rather than the binary allow/block common in other tools. Each verdict specifies both an outcome and a remediation path.

| Verdict | Numeric Severity | Meaning | Typical Response |
|---------|-----------------|---------|-----------------|
| `ALLOW` | 0 | Clean, no threats detected | Pass through |
| `SANITIZE` | 1 | Threats detected but neutralizable | Strip dangerous content, continue with cleaned version |
| `CHALLENGE` | 2 | Suspicious but uncertain | Ask user to confirm intent; log event |
| `QUARANTINE` | 3 | High-confidence threat | Block and log; alert; preserve for forensics |
| `BLOCK` | 4 | Critical threat, no bypass possible | Hard reject; no fallback |

### Verdict mapping by threat level

Each layer maps its detected `ThreatLevel` to a verdict. The standard mapping is:

```
ThreatLevel.CRITICAL  →  BLOCK
ThreatLevel.HIGH      →  QUARANTINE  (BLOCK in strict mode)
ThreatLevel.MEDIUM    →  CHALLENGE   (QUARANTINE in strict mode)
ThreatLevel.LOW       →  SANITIZE
ThreatLevel.NONE      →  ALLOW
```

The Wallet Fortress layer deviates from this: even a clean transaction produces `CHALLENGE` because every financial transaction requires explicit user approval.

### ShieldDecision structure

Every layer returns a `ShieldDecision` object:

```python
@dataclass
class ShieldDecision:
    verdict: ShieldVerdict           # The five-level verdict
    threats_detected: List[ThreatDetection]
    layer: str                       # Which layer produced this decision
    elapsed_ms: float                # Scan time in milliseconds
    sanitized_input: Optional[str]   # Present when verdict == SANITIZE
    metadata: Dict[str, Any]         # Layer-specific context

    @property
    def is_blocked(self) -> bool:
        return self.verdict in (ShieldVerdict.BLOCK, ShieldVerdict.QUARANTINE)

    @property
    def requires_approval(self) -> bool:
        return self.verdict == ShieldVerdict.CHALLENGE
```

---

## Async Architecture

ZugaShield is built on Python `asyncio` throughout. All layer `check()` methods are `async` and `await`-able, enabling non-blocking use in any async framework (FastAPI, aiohttp, LangChain, CrewAI, etc.).

```python
# Concurrent scan of two independent inputs
decision_a, decision_b = await asyncio.gather(
    shield.check_prompt(user_message),
    shield.check_output(llm_response),
)
```

### Thread safety

- Each `ZugaShield` instance maintains its own per-layer state. Do not share a single instance across multiple threads without external synchronization.
- Rate trackers and session state use `collections.deque` with `maxlen` bounds to prevent unbounded memory growth.
- The global rate tracker in the Perimeter layer (`_global_rate_tracker`) is a module-level dictionary. In multi-process deployments, each process maintains an independent tracker. Use an external cache (Redis) if cross-process rate enforcement is required.
- The canary token registry (`_CANARY_TOKENS`) in `prompt_armor.py` is a module-level dictionary shared across all `ZugaShield` instances in the same process. This is intentional: cross-session canary leak detection requires a shared registry.

---

## Performance Characteristics

### Fast path (no optional layers)

The core 7 layers plus catalog matching complete in under 15ms on commodity hardware. The breakdown on a typical 200-character input:

| Layer | Typical latency |
|-------|----------------|
| Perimeter | < 0.5ms |
| Prompt Armor (fast path) | 1–3ms |
| Prompt Armor (catalog matching) | 1–2ms |
| Tool Guard | 0.5–1ms |
| Memory Sentinel | 0.5–1ms |
| Exfiltration Guard | 1–2ms |
| Anomaly Detector | 0.2ms |
| Wallet Fortress | 0.3ms |
| **Total** | **< 15ms** |

### Optional layers (added latency)

| Optional Layer | Added Latency | Condition |
|---------------|--------------|-----------|
| ML Detector (TF-IDF) | ~0.5ms | `ml_enabled=True`, model file present |
| ML Detector (ONNX DeBERTa) | ~30ms | Ambiguous TF-IDF score (affects ~10% of inputs) |
| LLM Judge | 100–500ms | `llm_judge_enabled=True`, average confidence 0.4–0.7 |
| Code Scanner (regex) | 1–3ms | `code_scanner_enabled=True` |
| Code Scanner (semgrep) | 200–2000ms | `code_scanner_enabled=True`, semgrep installed |
| CoT Auditor | < 1ms | `cot_auditor_enabled=True` |
| MCP Guard | < 1ms | `mcp_guard_enabled=True` |

### Design principles

- **Compiled patterns**: All regex is pre-compiled at class construction time, never at check time.
- **Short-circuit evaluation**: Individual checks within a layer stop as soon as a CRITICAL-level threat is found.
- **Lazy model loading**: ML models are loaded on the first call, not at import time.
- **Deque-bounded state**: All per-session history uses `deque(maxlen=N)` to bound memory.
- **Fail-open optional layers**: If an optional layer raises an exception, it returns the original decision rather than propagating the error.

---

## Entry Points

ZugaShield exposes three primary check methods on the `ZugaShield` facade:

```python
shield = ZugaShield()

# Check user input (runs layers 1, 2, and 6)
decision = await shield.check_prompt("user message")

# Check LLM output (runs layer 5 and 6)
decision = await shield.check_output("llm response text")

# Check a tool call before execution (runs layers 3 and 6)
decision = await shield.check_tool_call("web_request", {"url": "..."})
```

Additional entry points for specific use cases:

```python
# Memory write validation (layer 4)
decision = await shield.check_memory_write(content, source="web_fetch")

# Memory recall validation (layer 4)
decision = await shield.check_memory_recall(memories_list)

# RAG document pre-ingestion scan (layer 4)
decision = await shield.check_document(document_text, source="external")

# MCP tool definition scanning (MCP Guard)
clean_tools, threats = shield.scan_tool_definitions(tools_list, server_id="mcp-server-1")

# Wallet transaction (layer 7)
decision = await shield.check_wallet_transaction(tx_type="send", to_address="0x...", amount_usd=100.0)

# Chain-of-thought reasoning audit (CoT Auditor)
decision = await shield.check_reasoning(trace, stated_goal="Book a flight")

# LLM-generated code (Code Scanner)
decision = await shield.check_code(code_string, language="python")
```

---

## Configuration

ZugaShield reads all configuration from environment variables. No config files are required. Each layer can be individually toggled:

```
ZUGASHIELD_ENABLED=true
ZUGASHIELD_STRICT_MODE=false
ZUGASHIELD_PROMPT_ARMOR_ENABLED=true
ZUGASHIELD_TOOL_GUARD_ENABLED=true
ZUGASHIELD_MEMORY_SENTINEL_ENABLED=true
ZUGASHIELD_EXFILTRATION_GUARD_ENABLED=true
ZUGASHIELD_WALLET_FORTRESS_ENABLED=true
ZUGASHIELD_LLM_JUDGE_ENABLED=false
ZUGASHIELD_ML_ENABLED=false
```

Programmatic configuration via `ShieldConfig`:

```python
from zugashield import ZugaShield
from zugashield.config import ShieldConfig

shield = ZugaShield(ShieldConfig(
    strict_mode=True,
    ml_enabled=True,
    anomaly_threshold=50.0,
    wallet_tx_limit=100.0,
))
```
