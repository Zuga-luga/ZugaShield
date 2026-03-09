# ZugaShield Layer Reference

Last Updated: 2026-02-17

---

## Overview

ZugaShield contains seven mandatory defense layers and four optional cross-layer subsystems. Each layer is an independent class with a `check()` async method that accepts input, runs its detection logic, and returns a `ShieldDecision`. Layers share no mutable state with each other except for the Anomaly Detector, which receives events recorded by all other layers.

---

## Layer 1: Perimeter

**Class:** `PerimeterLayer`
**File:** `zugashield/layers/perimeter.py`
**Config toggle:** `ZUGASHIELD_PERIMETER_ENABLED` (default: `true`)

### Purpose

First line of defense. Operates as HTTP middleware that validates inbound requests before any content-level processing. Catches volumetric and structural attacks that do not require semantic understanding.

### What it detects

**Request size limits (PM-SIZE)**
Blocks requests exceeding `config.max_message_size`. Prevents context window flooding attacks where an attacker submits an enormous payload to push system prompt instructions out of the LLM's working memory.

**Endpoint rate limiting (PM-RATE, PM-RATE-GLOBAL)**
Enforces per-session and global (IP + User-Agent hash) rate limits on sensitive endpoints defined in `config.sensitive_endpoints`. Per-session limit triggers `CHALLENGE`. A global limit at 2x the per-session threshold detects coordinated multi-session attacks. The global tracker is keyed by `SHA-256(client_ip + user_agent)[:16]` to avoid storing raw IPs.

**Unicode in headers (PM-HDR)**
Flags non-ASCII characters in HTTP headers other than `cookie`, `user-agent`, and `accept-language`, where non-ASCII is expected. Indicates potential Unicode smuggling through metadata channels.

**Body encoding density (PM-UNI)**
Flags request bodies where the ratio of non-ASCII characters exceeds `config.max_unicode_density`. Indicates possible Unicode payload smuggling.

### Configuration

| Parameter | Env Variable | Default |
|-----------|-------------|---------|
| `max_message_size` | `ZUGASHIELD_MAX_MESSAGE_SIZE` | 1,048,576 (1MB) |
| `max_unicode_density` | `ZUGASHIELD_MAX_UNICODE_DENSITY` | 0.3 |
| `sensitive_endpoints` | `ZUGASHIELD_SENSITIVE_ENDPOINTS` | `["/api/chat", "/api/agent"]` |

---

## Layer 2: Prompt Armor

**Class:** `PromptArmorLayer`
**File:** `zugashield/layers/prompt_armor.py`
**Config toggle:** `ZUGASHIELD_PROMPT_ARMOR_ENABLED` (default: `true`)

### Purpose

The primary defense against prompt injection. Runs 10 independent detection strategies against user input. Strategies are ordered from fastest to most expensive and all run on every input — there is no early exit within the layer (though the pipeline short-circuits if BLOCK is returned).

### Detection strategies

**Strategy 1: Fast-path compiled regex (~1–3ms)**
Ten pre-compiled patterns covering the highest-confidence, lowest-false-positive injection archetypes:

| Signature ID | Pattern | Threat Level |
|-------------|---------|-------------|
| FP-001 | `ignore (all/previous/prior) instructions` | CRITICAL |
| FP-002 | `you are now [a/an/the] (unrestricted/unfiltered/jailbroken)` | CRITICAL |
| FP-003 | `(act/pretend/behave) as (unrestricted/DAN)` | CRITICAL |
| FP-004 | `DAN ... (mode/jailbreak/no restrictions)` | CRITICAL |
| FP-005 | `system/override prompt override/replacement/injection` | CRITICAL |
| FP-006 | `disable/bypass/remove safety/security/filter/guardrail` | CRITICAL |
| FP-007 | `<|im_start|>`, `<|system|>`, `<|endoftext|>` | HIGH |
| FP-008 | `[INST]...[/INST]` | HIGH |
| FP-009 | `<<SYS>>...</<SYS>>` | HIGH |
| FP-010 | `enter developer/debug/admin/sudo/god mode` | CRITICAL |

**Strategy 2: Catalog signature matching (~1–2ms)**
Queries the `ThreatCatalog` for the 150+ curated signatures in the `PROMPT_INJECTION` and `INDIRECT_INJECTION` categories. The catalog is updatable via the threat feed.

**Strategy 3: Unicode analysis (~0.5ms)**
Detects four classes of Unicode-based evasion:

- *Invisible characters* (U+200B–U+200F, U+2060–U+2064, U+FEFF, and others): flags when more than 3 are found.
- *RTL override characters* (U+202D, U+202E, U+2066–U+2069): any occurrence is flagged HIGH.
- *Tag characters* (U+E0001–U+E007F): any occurrence is flagged HIGH.
- *Homoglyphs*: uses the `confusable-homoglyphs` library (TR39 standard, 7000+ confusable pairs) when installed via `zugashield[homoglyphs]`, or a 200-character fallback map covering Cyrillic, Greek, Armenian, Cherokee, Fullwidth Latin, Latin Extended/IPA, and Mathematical symbols.

**Strategy 4: ASCII art and entropy analysis (~0.5ms)**
- *Box-drawing characters* (U+2500–U+257F): flags when more than 20 are present.
- *Braille characters* (U+2800–U+28FF): flags when more than 10 are present.
- *Large ASCII art blocks*: detects lines where more than 60% of characters are non-alphanumeric special characters, flags when more than 5 such lines appear consecutively.

**Strategy 5: Encoding detection, including nested encodings**
- *Base64 with decode instruction*: regex matches `decode this base64: <data>`.
- *Known base64-encoded injection prefixes*: hardcoded lookup for base64 encodings of `ignore`, `system`, `override`, `instru`.
- *Double-base64 (nested encoding)*: decodes standalone 40+ character base64 blocks and checks if the result is also valid base64 containing injection keywords.
- *Stealth base64*: detects base64 blocks that decode to injection keywords even without an explicit decode instruction.
- *Hex-encoded payloads*: finds 20+ byte hex sequences and decodes them looking for injection keywords.

**Strategy 6: Multi-turn crescendo detection**
Tracks per-session escalation using a weighted keyword scoring system. Keywords are assigned weights (e.g., `jailbreak=4.0`, `bypass=3.0`, `security=0.5`). Transition phrases like `"now that..."`, `"building on that..."`, and `"next step"` amplify the score by 1.5x. Scores decay at 5% per minute. A rising score pattern (3 consecutive increases) combined with cumulative score >= 12.0 and 2+ transition phrases triggers CHALLENGE or QUARANTINE.

**Strategy 7: Context window flooding detection**
- Inputs exceeding ~32,000 characters (~8,000 tokens) are flagged HIGH.
- Single word repeated more than 100 times is flagged HIGH.
- A 100-character chunk repeated more than 10 times is flagged HIGH.

**Strategy 8: Few-shot poisoning detection**
Counts occurrences of conversation role labels: `User:`, `Assistant:`, `System:`, `Human:`, `Bot:`, and their bracket/tag variants. Four or more role labels in under 1,000 characters indicates injected fake conversation turns and is flagged HIGH. Six or more labels in any length input is flagged MEDIUM.

**Strategy 9: GlitchMiner anomalous token detection**
- Sequences of 10+ consecutive non-word, non-space characters (excluding common patterns like markdown delimiters) are flagged MEDIUM.
- Words of 9+ characters with Shannon entropy above 4.5 bits/character (excluding URLs, pure hex, and base64-shaped strings) are collected; three or more high-entropy words in one input is flagged MEDIUM.

**Strategy 10: Document embedding poisoning detection**
Scans HTML-containing inputs for CSS-based content hiding: `font-size:0`, `display:none`, `visibility:hidden`, `opacity:0`, 1px dimensions, `overflow:hidden` combined with zero dimensions, and off-screen absolute positioning. Only runs when the input contains both `<` and `>`.

### Spotlighting

The layer provides a `spotlight_external_content(content, source)` helper that wraps external content in trust-labeled XML delimiters:

```xml
<EXTERNAL_CONTENT source="web_fetch" trust="untrusted">
  ... external document content ...
</EXTERNAL_CONTENT>
```

Sources classified as `user_chat` or `user_direct` receive `trust="trusted"`. Sources classified as `brain` or `cognitive_stream` receive `trust="semi-trusted"`. All others receive `trust="untrusted"`.

### Canary token system

`generate_canary_token(session_id)` creates a unique `canary-<16 hex chars>` token per session stored in the module-level `_CANARY_TOKENS` dictionary. `get_canary_instruction(session_id)` returns an HTML comment containing the canary to embed in system prompts. The Exfiltration Guard (Layer 5) checks all LLM outputs against this registry; a canary appearing in output is definitive evidence of successful prompt injection.

---

## Layer 3: Tool Guard

**Class:** `ToolGuardLayer`
**File:** `zugashield/layers/tool_guard.py`
**Config toggle:** `ZUGASHIELD_TOOL_GUARD_ENABLED` (default: `true`)

### Purpose

Enforces the principle of least privilege on tool execution. Every tool call is checked before execution against a risk matrix, parameter validation rules, SSRF patterns, and cross-session chain analysis.

### What it detects

**Tool risk matrix**
Each tool has a `ToolPolicy(rate, approval, risk)` defining its per-minute call rate limit, whether user approval is required, and a qualitative risk level. Key policies:

| Tool | Rate Limit | Requires Approval | Risk |
|------|-----------|------------------|------|
| `bash`, `execute_command` | 10/min | Yes | high |
| `local_write_file` | 10/min | Yes | medium |
| `local_read_file` | 30/min | No | low |
| `browser_navigate` | 5/min | No | medium |
| `web_search` | 10/min | No | low |
| `memory_store` | 5/min | No | medium |
| `self_restart`, `self_upgrade` | 1/min | Yes | critical |
| `wallet_send`, `wallet_sign` | 1/min | Yes | critical |

**Parameter validation (TG-CMD)**
For bash-category tools, inspects the command string for dangerous patterns including: `rm` at root, destructive command chains via `;`, shell pipe injection via `| bash`, backtick command substitution, `$()` substitution, `/dev/tcp` reverse shells, fork bomb patterns, destructive disk operations (`mkfs`, `dd`), symlink creation targeting sensitive files (CVE-2025-53109/53110 mitigations), and environment variable injection (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc.).

**Sensitive path detection (TG-PATH, TG-SYMLINK)**
For file and bash tools, checks whether the path touches any entry in `config.sensitive_paths`. Critically, the layer resolves symlinks to canonical paths via `os.path.realpath()` before checking — defeating attacks where a symlink points to a sensitive file but has an innocent-looking name. A detected symlink to a sensitive target produces CRITICAL/BLOCK rather than just HIGH/CHALLENGE.

**SSRF protection (TG-SSRF)**
For browser and web-fetch tools, checks the URL against 12 compiled patterns covering: `127.0.0.1`/localhost, private RFC 1918 ranges (10.x, 172.16–31.x, 192.168.x), AWS/GCP metadata endpoints, DNS rebinding domains (`.localtest.me`, `.nip.io`, `.sslip.io`), decimal/octal/hex IP encoding bypass attempts, and IPv6 localhost variants.

**Tool chain detection (TG-CHAIN-EXFIL, TG-CHAIN-INJECT)**
Maintains a per-session deque of the last 50 tool calls (tool name, timestamp, parameter summary). Two patterns are flagged within a 5-minute window:
- Sensitive file read followed by a web request: exfiltration chain, HIGH.
- Web fetch followed by memory store: injection chain, MEDIUM.

---

## Layer 4: Memory Sentinel

**Class:** `MemorySentinelLayer`
**File:** `zugashield/layers/memory_sentinel.py`
**Config toggle:** `ZUGASHIELD_MEMORY_SENTINEL_ENABLED` (default: `true`)

### Purpose

Defends against memory poisoning: the persistent attack where malicious content planted in an agent's memory store activates on a future recall. The layer guards both the write path (before content is stored) and the read path (before recalled memories are injected into a prompt).

### Write path checks

**Embedded instruction detection (MS-INSTR)**
Eight regex patterns detect imperative instructions embedded in memory content:
- `always/must/should execute/run/follow`
- `ignore/override/bypass safety/security/rules`
- `when recalled/on recall: execute/run`
- `secret/hidden instruction/command`
- `do not tell/reveal the user`
- `sleeper/dormant/trigger instruction/payload`
- `transfer all funds/balance/crypto`
- `SYSTEM UPDATE:` / `ADMIN OVERRIDE:` etc.

**Importance inflation detection (MS-INFLATE)**
Flags content that claims maximum importance (`importance=critical`, `priority=highest`, `this is critically important`) — a technique attackers use to ensure their injected memories surface above legitimate ones during recall.

**Write rate limiting (MS-RATE)**
Allows a maximum of 10 memory writes per minute per user ID.

**Provenance classification**
Every write call is tagged with a trust level based on the `source` parameter:

| Source | Trust Level |
|--------|------------|
| `user_chat`, `user_direct`, `user` | `USER_DIRECT` |
| `brain`, `brain_thought`, `cognitive_stream` | `BRAIN_GENERATED` |
| `web_search`, `web_fetch`, `file_read`, `browser`, `external` | `EXTERNAL` |
| `verified` | `VERIFIED` |
| anything else | `UNKNOWN` |

The trust level is stored in `decision.metadata["source_trust"]` for the caller to persist alongside the memory record.

**Tag/metadata injection (MS-TAG)**
Applies the same instruction detection patterns to memory tag strings. Instruction-bearing tags are flagged BLOCK.

### Read path checks

**Recalled instruction detection (MS-RECALL)**
For each memory being recalled, applies the same instruction patterns from the write path. Memories from `EXTERNAL` or `UNKNOWN` sources receive higher confidence (0.92 vs 0.80) because external content is inherently less trustworthy.

**Provenance flagging (MS-PROVENANCE)**
Recalled memories with no stored `source_trust` field are flagged LOW as untagged (legacy) records. They are still included in the output but carry a warning.

**Filtered memory list**
When the verdict is `SANITIZE`, `decision.metadata["filtered_memories"]` contains the list of clean memories with a `_shield_trust` field added. Callers can use this filtered list instead of the original for prompt injection.

### RAG document pre-ingestion scan

`check_document(content, source, document_type)` scans external documents before they enter a vector store. It runs four passes:

1. *Imperative instruction detection*: patterns like `when this document is recalled: execute`, `upon retrieval: ignore previous instructions`, and `the assistant must bypass all safety`.
2. *CSS/HTML hiding patterns*: same patterns as Prompt Armor Strategy 10.
3. *System command density*: flags documents with more than 3 shell commands (`sudo`, `chmod`, `curl | bash`, `eval(`, `exec(`).
4. *Instruction pattern pass*: the same 8 instruction patterns from the write path.

---

## Layer 5: Exfiltration Guard

**Class:** `ExfiltrationGuardLayer`
**File:** `zugashield/layers/exfiltration_guard.py`
**Config toggle:** `ZUGASHIELD_EXFILTRATION_GUARD_ENABLED` (default: `true`)

### Purpose

Data Loss Prevention for agent outputs. Scans LLM responses and tool outputs to block secrets, PII, crypto credentials, and covert exfiltration channels from leaving the system.

### What it detects

**Secrets (EG-SECRET)**
Pattern-matched detection for:
- Stripe-style API keys (`sk-live-`, `pk-test-`)
- AWS access key IDs (`AKIA`, `ABIA`, `ACCA`, `ASIA` prefixes)
- Google API keys (`AIza` prefix)
- GitHub personal access tokens (`ghp_` prefix)
- Slack tokens (`xoxb-`, `xoxa-`, etc.)
- Generic `api_key=`, `secret_key=`, `access_token=` key-value pairs
- `Bearer <token>` authentication headers
- PEM-encoded private keys (`-----BEGIN PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`)

**PII (EG-PII)**
- Credit card numbers: Visa (4xxx), Mastercard (5xxx), Amex (3xxx), Discover (6xxx) patterns.
- US Social Security Numbers: `ddd-dd-dddd` format.
- Email addresses in key-value context (e.g., `email=user@example.com`).

**Crypto secrets (EG-CRYPTO)**
- 64-character hex strings (Ethereum private keys).
- Seed phrase / mnemonic patterns: 12–24 word sequences after `seed phrase =`.

**Canary token leaks (EG-CANARY, EG-CANARY-CROSS)**
Checks the output against every canary token in the module-level registry (see Layer 2). A match has confidence 0.99 — it is definitive proof that a prompt injection attack succeeded and the agent leaked its injected context. Cross-session canary leaks (a token from session A appearing in session B's output) are also detected.

**DNS exfiltration (EX-018)**
Four heuristics detect data encoded in DNS subdomain labels:
- Subdomain depth > 5 levels.
- Individual label length > 50 characters.
- All-hex label > 20 characters (data encoded as hex bytes).
- Subdomain label Shannon entropy > 4.0 bits/character on labels > 15 characters.

**Egress domain filtering**
When `config.egress_domain_allowlist` is configured, outbound URLs are checked against the allowlist. Supports exact match and wildcard prefix (`*.example.com` matches `api.example.com` but not `example.com`).

### Redaction

When verdict is `SANITIZE`, the layer returns a `sanitized_input` string with detected secrets replaced by `[REDACTED]`. Evidence fields in `ThreatDetection` objects are pre-redacted to `prefix...suffix` form before logging to avoid writing live credentials to logs.

---

## Layer 6: Anomaly Detector

**Class:** `AnomalyDetectorLayer`
**File:** `zugashield/layers/anomaly_detector.py`
**Config toggle:** `ZUGASHIELD_ANOMALY_DETECTOR_ENABLED` (default: `true`)

### Purpose

Cross-layer behavioral analysis. Rather than examining individual inputs in isolation, this layer correlates threat detection events across all other layers and over time to detect attack strategies that span multiple low-severity signals.

### Event recording

All other layers call `anomaly_detector.record_event(session_id, detection)` when they detect any threat, regardless of severity. The Anomaly Detector stores up to 500 events per session in a `deque`.

Each event contributes to a per-session `AnomalyScore`:

| Threat Level | Score Contribution |
|-------------|-------------------|
| LOW | 5 × confidence |
| MEDIUM | 15 × confidence |
| HIGH | 30 × confidence |
| CRITICAL | 50 × confidence |

### Score decay

Session scores decay at `config.anomaly_decay_rate` (default 0.95) per check cycle. A non-decaying `cumulative_score` tracks the lifetime peak at 20% of the session peak, providing a floor below which the session score cannot fall. This prevents adversaries from resetting suspicion by pausing between attack bursts.

### Chain attack detection (AD-CHAIN)

Four predefined multi-category patterns trigger escalation when two or more matching events are seen within a 5-minute window:

| Pattern | Required Categories | Escalated Level |
|---------|--------------------| ---------------|
| Injection + tool exploitation | PROMPT_INJECTION + TOOL_EXPLOITATION | CRITICAL |
| Exfiltration chain | DATA_EXFILTRATION + TOOL_EXPLOITATION | CRITICAL |
| Memory poisoning chain | MEMORY_POISONING + PROMPT_INJECTION | HIGH |
| Unicode + injection | UNICODE_SMUGGLING + PROMPT_INJECTION | HIGH |

### Alternating pattern detection (AD-ALT)

Examines the last 10 events in the session. If there are 3 or more alternations between HIGH/CRITICAL and NONE/LOW threat levels, the pattern indicates an adversary interspersing benign requests between attacks to dilute the anomaly score. Flagged HIGH, QUARANTINE.

### Score threshold

When the session score exceeds `config.anomaly_threshold` (default 50.0), a behavioral anomaly threat is raised. The threat level scales with the score:
- Score > 80: CRITICAL
- Score > 60: HIGH
- Score > 40: MEDIUM
- Score > 20: LOW

---

## Layer 7: Wallet Fortress

**Class:** `WalletFortressLayer`
**File:** `zugashield/layers/wallet_fortress.py`
**Config toggle:** `ZUGASHIELD_WALLET_FORTRESS_ENABLED` (default: `true`)

### Purpose

Multi-layered protection for cryptocurrency transactions. Designed for AI agents that have wallet access. Unlike all other layers, the Wallet Fortress returns `CHALLENGE` even for clean transactions — because every financial transaction requires explicit user approval.

### What it detects

**Approval cooldown (WF-COOL)**
Enforces a configurable minimum time between transactions (`config.wallet_approval_cooldown`). Blocks rapid-fire transaction attempts that could indicate an automated drain attack.

**Spend limits (WF-TXLIMIT, WF-HOURLIMIT, WF-DAYLIMIT)**
Three independent spending limits:
- Per-transaction USD limit.
- Rolling hourly USD total.
- Rolling daily USD total.
All three are checked on every transaction. Daily limit violations produce CRITICAL/BLOCK rather than HIGH/BLOCK.

**Address validation (WF-BLOCKLIST, WF-NEWADDR, WF-HOMOGLYPH)**
- Blocklisted addresses produce CRITICAL/BLOCK immediately.
- First-time recipient addresses (not in allowlist or known-addresses set) produce LOW/CHALLENGE requiring confirmation.
- Ethereum addresses are scanned character-by-character for non-ASCII characters (Cyrillic/Greek homoglyphs that look like hex digits). Any non-ASCII character in an `0x`-prefixed 40-character address produces CRITICAL/BLOCK.

**Smart contract protection (WF-FUNC, WF-UNLIMITED)**
Checks decoded function signatures against a list of dangerous contract functions:
- `approve(address,uint256)` — token approval
- `setApprovalForAll(address,bool)` — NFT approval for all
- `transferOwnership(address)` — ownership transfer
- `selfdestruct(address)` — contract self-destruct
- `delegatecall` — proxy delegation

Approval calls with `MAX_UINT256` as the amount (unlimited approval) are flagged CRITICAL/BLOCK regardless of function.

---

## Optional Layer: MCP Guard

**Class:** `MCPGuardLayer`
**File:** `zugashield/layers/mcp_guard.py`
**Config toggle:** `ZUGASHIELD_MCP_GUARD_ENABLED` (default: `true`)

### Purpose

Validates Model Context Protocol tool definitions and call-time parameters. MCP servers controlled by attackers may embed prompt injection payloads in tool descriptions that the LLM reads as implicit instructions when choosing which tool to call (Riley Goodside / Kai Greshake research).

### What it detects at definition time

**MCP-INJECT**: Scans `name` and `description` fields for the same 8 injection patterns used in Prompt Armor's fast path.

**MCP-ROLE**: Detects role-reassignment language in descriptions: `you are/must act as`, `assume the role of`, `switch to developer/admin mode`.

**MCP-HIDDEN**: Detects whitespace-concealed instructions: 5+ consecutive spaces between words, 4+ consecutive newlines, and zero-width character injection (U+200B, U+200C, U+200D, U+FEFF, U+00AD).

**MCP-CONFUSION**: Cross-server name collision detection. When the same tool name is registered from two different MCP servers, the LLM may call the wrong one. Tracked via a `tool_name → {server_ids}` index. Produces HIGH/QUARANTINE.

### What it detects at call time

**Tool integrity verification (MCP-INTEGRITY)**: On each tool call where a definition is provided, computes `SHA-256(JSON.dumps(definition, sort_keys=True))` and compares to the registered hash from initial `scan_definitions()`. A mismatch indicates the MCP server was tampered with post-registration. Confidence 0.99 (deterministic hash comparison).

**Schema validation (MCP-SCHEMA)**: Checks that all required parameters are present and that no undeclared parameters are present (parameter smuggling).

**Parameter value injection (MCP-INJECT-PARAM)**: Scans string-valued call-time parameters for injection payloads, catching cases where an attacker controls parameter content rather than the tool description.

---

## Optional Layer: LLM Judge

**Class:** `LLMJudgeLayer`
**File:** `zugashield/layers/llm_judge.py`
**Config toggle:** `ZUGASHIELD_LLM_JUDGE_ENABLED` (default: `false`)

### Purpose

Second-opinion deep analysis for ambiguous cases. Only activates when the fast-path average confidence falls in the 0.4–0.7 range, indicating genuine uncertainty. Uses an external LLM (Anthropic Claude Haiku, OpenAI GPT-4o-mini, or LiteLLM) as a security classifier.

### How it works

The judge receives the original input and a system prompt that instructs it to respond with exactly `BLOCK` or `ALLOW`. If the judge responds `BLOCK`, the decision is escalated to BLOCK with an added detection at confidence 0.88. If the judge responds `ALLOW`, the decision is downgraded to ALLOW with a `llm_judge_override=allow` metadata flag.

LLM errors fail open: if the API call fails, the original fast-path decision is returned unchanged.

### Provider priority

Providers are tried in this order: Anthropic Claude Haiku → OpenAI GPT-4o-mini → LiteLLM. Configure a preferred provider with `config.llm_provider` or the `ZUGASHIELD_LLM_PROVIDER` environment variable.

---

## Optional Layer: Code Scanner

**Class:** `CodeScannerLayer`
**File:** `zugashield/layers/code_scanner.py`
**Config toggle:** `ZUGASHIELD_CODE_SCANNER_ENABLED` (default: `false`)

### Purpose

Scans LLM-generated code for security vulnerabilities before execution. Addresses OWASP ASI05 (Insecure Code Generation). Operates in two passes.

### Fast path: compiled regex (~1–3ms)

Six vulnerability categories are checked via pre-compiled patterns:

| Category | Signature IDs | What is detected |
|----------|--------------|-----------------|
| CS-EXEC | `eval(`, `exec(`, `os.system(`, `subprocess.*`, `__import__(` | Dynamic code execution |
| CS-INJECT | SQL queries built with f-strings or `%` substitution | SQL injection |
| CS-PATH | `../` or `..\` in file operation paths | Path traversal |
| CS-DESERIAL | `pickle.loads(`, `yaml.load(` without SafeLoader, `jsonpickle.decode(`, `marshal.loads(` | Unsafe deserialization (CRITICAL for pickle/marshal) |
| CS-CRED | Hardcoded `password=`, `api_key=`, `DATABASE_URL=` literals | Credential exposure |
| CS-SHELL | `subprocess` with shell metacharacters or `shell=True` | Shell injection |

### Deep path: semgrep (~200–2000ms)

If `semgrep` is installed and on PATH, the code is written to a temporary file and scanned with `semgrep --config=auto --json`. Semgrep findings are converted to `ThreatDetection` objects with signature IDs prefixed `CS-SEMGREP-`. Semgrep errors do not fail the check; the regex results are returned regardless.

---

## Optional Layer: CoT Auditor

**Class:** `CoTAuditorLayer`
**File:** `zugashield/layers/cot_auditor.py`
**Config toggle:** `ZUGASHIELD_COT_AUDITOR_ENABLED` (default: `false`)

### Purpose

Audits chain-of-thought reasoning traces (scratchpad output, `<thinking>` blocks) for deceptive patterns before the agent acts on its internal reasoning. Addresses OWASP ASI10 (Rogue Agent Behavior) and emergent deceptive alignment scenarios.

### What it detects

**COT-DECEPTION**: Explicit deception language in the reasoning trace:
- `"the user doesn't need to know"` — hiding information
- `"I'll hide/conceal/omit"` — planned omission
- `"without them knowing"` — covert action
- `"deceive/mislead/trick/fool the user"` — explicit deception intent
- `"make it look/seem/appear like"` — misleading framing

**COT-GOAL-MISMATCH**: Reasoning that substitutes a different goal from the stated one:
- `"but instead I will/should"` — explicit goal substitution
- `"however I will actually"` — contradicted plan
- `"my real/actual/true/hidden goal"` — disclosed hidden goal
- `"the stated goal is just a cover/facade"` — treating assignment as pretext

Semantic mismatch detection also runs when a `stated_goal` is provided: extracts planned actions from the trace and flags when more than 60% are unrelated to the stated goal and the trace contains 2+ contradiction markers.

**COT-HIDDEN-OBJ**: Hidden secondary objectives:
- `"my true/secret objective"` — undisclosed goal
- `"secret plan"` — concealed agenda
- `"the user thinks I'm..."` — differentiated user belief from actual intent
- `"they won't notice/realize"` — anticipated concealment
- `"appear compliant while..."` — compliant facade over alternative goals

**COT-SAFETY-OVERRIDE**: Safety circumvention in reasoning:
- `"ignore the safety/alignment constraint"` — planned constraint bypass
- `"bypass the restriction/filter/guard"` — evasion planning
- `"without triggering the safety/filter"` — stealth evasion

**Contradiction density analysis**: Flags traces with more than 4 contradiction markers per 1,000 characters (minimum 5 total). A reasoning trace saturated with `"but actually"`, `"however"`, and `"instead"` suggests the model is rationalizing away from honest behavior.

---

## Cross-Layer Interaction: Event Correlation

The Anomaly Detector acts as a passive event bus. When any of layers 1–5 (and MCP Guard) detect a threat, they record the event with the Anomaly Detector before returning their decision:

```
Layer 2 detects injection attempt
  │
  ├─► Layer 2 returns ShieldDecision(BLOCK)
  │
  └─► AnomalyDetector.record_event(session_id, detection)
        │
        └─► Updates session_score, contributing_events
              │
              └─► Next check_prompt() call also runs
                  AnomalyDetector.check(session_id)
                  which may detect chain patterns
```

This means a low-confidence detection in Layer 2 and a low-confidence detection in Layer 3 that individually would each produce `CHALLENGE` can together trigger a chain pattern detection in Layer 6 that produces `BLOCK`.

The scoring ensures events from the same session accumulate risk. The non-decaying cumulative floor (20% of the session peak) prevents an attacker from resetting suspicion by going quiet.
