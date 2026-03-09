# OWASP Agentic AI Security Initiative (ASI) Coverage

Last Updated: 2026-02-17

Reference: [OWASP Agentic AI Security Initiative](https://owasp.org/www-project-agentic-ai/)

---

## Overview

The OWASP Agentic AI Security Initiative defines 10 risks specific to AI agents — systems that plan, use tools, and take actions with real-world consequences. These risks differ from traditional web application risks because agents operate autonomously over multiple steps, have access to memory and external systems, and may interact with other agents.

ZugaShield is designed to map directly to each of these 10 risks (ASI01–ASI10). This document describes each risk, explains how ZugaShield defends against it, and identifies which layers and mechanisms are responsible.

---

## ASI01 — Agent Goal Hijacking

### What the risk is

Goal hijacking occurs when an attacker manipulates the agent's instructions to redirect it toward unauthorized objectives. The most common form is prompt injection: injecting adversarial instructions into data the agent processes (user messages, retrieved documents, tool outputs) that override or augment the agent's original goals.

Attack variants include:
- **Direct injection**: User message contains `"Ignore all previous instructions and..."`.
- **Indirect injection**: A web page, document, or database record the agent retrieves contains hidden instructions.
- **Crescendo**: A multi-turn conversation that gradually escalates from benign questions to harmful requests, exploiting the agent's tendency to remain consistent.
- **Encoding evasion**: Instructions encoded in base64, hex, ROT13, or Unicode to evade signature matching.
- **Few-shot poisoning**: Injecting fake conversation history to make the model believe it has already agreed to harmful behavior.

### How ZugaShield defends against it

**Layer 2: Prompt Armor** is the primary defense.

*Fast-path regex* catches the highest-confidence direct injection patterns with compiled patterns (FP-001 through FP-010). These cover the most common direct injection archetypes: instruction override, role hijacking, DAN patterns, system prompt replacement, safety bypass requests, and control token injection.

*Catalog signatures* add 150+ curated patterns beyond the fast path, covering known attack variants including jailbreak templates, social engineering frames, and adversarial role-play setups. The catalog is auto-updatable via the threat feed.

*Unicode analysis* detects evasion via invisible characters, RTL overrides, tag characters (U+E0000 range), and homoglyph substitution (Cyrillic 'а' disguised as Latin 'a'), all of which are techniques for bypassing regex-based injection detection.

*Encoding detection* recursively decodes base64 and hex payloads to find injections hidden behind one or more layers of encoding. It handles double-base64 and stealth encoding (base64 blocks without an explicit decode instruction).

*Multi-turn crescendo detection* maintains per-session escalation scores with time decay. Rising topic scores combined with transition phrases (`"building on that..."`, `"next step"`) trigger CHALLENGE or QUARANTINE before the session reaches a dangerous state.

*Few-shot poisoning detection* counts conversation role labels (`User:`, `Assistant:`, `System:`) and flags high-density occurrences indicating injected fake conversation history.

*Spotlighting* wraps external content in trust-labeled XML delimiters so the LLM can distinguish its instructions from untrusted external data.

### Coverage assessment

Prompt Armor provides defense against all known prompt injection archetypes documented in academic literature through early 2026, including the Microsoft crescendo paper, the indirect injection attacks from Greshake et al., and GlitchMiner adversarial token attacks.

---

## ASI02 — Tool Misuse

### What the risk is

An agent with access to tools (file system, browser, APIs, code execution) can be tricked into calling those tools with malicious parameters. Examples include:

- SSRF: directing a web-fetch tool to access internal metadata endpoints or private network addresses.
- Command injection: using shell metacharacters in bash tool parameters to execute arbitrary commands.
- Path traversal: reading sensitive files (`~/.ssh/id_rsa`, `.env`) via relative path components.
- Abuse of high-risk tools: calling `self_upgrade` or `wallet_send` without authorization.

### How ZugaShield defends against it

**Layer 3: Tool Guard** is the dedicated defense.

*Tool risk matrix*: Every tool call is checked against a risk matrix that defines per-minute rate limits, approval requirements, and a qualitative risk level. Wallet tools (`wallet_send`, `wallet_sign`) and system tools (`self_restart`, `self_upgrade`) have rates of 1/minute and require approval.

*SSRF protection*: Twelve compiled patterns block attempts to reach loopback addresses, private IP ranges (RFC 1918), cloud metadata endpoints (169.254.169.254, metadata.google.internal), DNS rebinding domains, and decimal/octal/hex-encoded IP bypasses.

*Command injection detection*: For bash-category tools, inspects command parameters for shell metacharacter chains, command substitution, fork bombs, and destructive disk operations.

*Sensitive path detection with symlink resolution*: File operations are checked against `config.sensitive_paths`. Symlinks are resolved to canonical paths via `os.path.realpath()` before checking, defeating CVE-2025-53109/53110 style attacks.

*Chain attack detection*: Tracks the sequence of tool calls per session. A sensitive file read followed within 5 minutes by a web request triggers an exfiltration chain alert.

---

## ASI03 — Identity and Privilege Abuse

### What the risk is

Agents may be tricked into claiming elevated privileges, impersonating other users or systems, or bypassing access controls — either through direct instruction or by exploiting the agent's tendency to follow authoritative-sounding instructions.

### How ZugaShield defends against it

**Layer 5: Exfiltration Guard** enforces egress controls. When `config.egress_domain_allowlist` is set, outbound requests to non-allowlisted domains are flagged as potential unauthorized egress. This limits an agent's ability to exfiltrate data to attacker-controlled infrastructure even if it is tricked into doing so.

**Layer 6: Anomaly Detector** provides behavioral baselines. Privilege-related actions (tool calls to high-risk tools, sensitive path accesses) generate HIGH-level anomaly events. Accumulation of these events escalates the session score and may trigger a BLOCK before damage is done.

**MCP Guard** detects role override attempts in MCP tool descriptions (`"assume the role of"`, `"switch to admin mode"`), which is the primary vector for privilege escalation via agent-to-agent or tool-to-agent protocol abuse.

---

## ASI04 — Supply Chain Vulnerabilities

### What the risk is

AI agents depend on models, libraries, tool definitions, and data pipelines. Any of these components can be tampered with: a poisoned model file, a tampered ONNX binary, modified tool schemas, or compromised training data.

### How ZugaShield defends against it

**ML supply chain hardening** applies to the ML Detector layer.

*SHA-256 hash verification*: Every model file is verified against a hash stored in `zugashield/signatures/integrity.json` at load time. A hash mismatch causes the model to be rejected immediately rather than loaded. This applies to both the bundled TF-IDF model and user-downloaded ONNX models.

*Canary validation*: After loading any model, three hardcoded behavioral smoke tests are run. If any canary prediction deviates from its expected outcome, the model is rejected. This catches models that pass hash verification but have been re-trained on poisoned data (same file bytes, different weights via adversarial fine-tuning are not possible — SHA-256 covers the full binary — but this guards against other tampering scenarios).

*Model version pinning*: `config.ml_model_version` allows operators to require a specific model version string. Models that do not carry matching version metadata in their bundle are rejected.

**MCP Guard** provides supply chain protection for MCP tool definitions.

*Tool integrity verification*: A SHA-256 hash of each tool definition JSON is stored at registration time. On every subsequent tool call, the current definition is re-hashed and compared. Any change to a tool's name, description, or input schema after registration is flagged as a CRITICAL integrity violation.

**Threat feed verification**: The auto-updating signature feed verifies downloaded bundles with Ed25519 signatures (minisign format) and SHA-256. Corrupted or unsigned bundles are rejected; update failures never degrade existing signatures.

---

## ASI05 — Insecure Code Generation

### What the risk is

LLMs asked to generate code frequently produce patterns that are functional but contain security vulnerabilities: SQL injection via string concatenation, path traversal via unsanitized input, unsafe deserialization, hardcoded credentials, and arbitrary code execution via `eval()`.

### How ZugaShield defends against it

**Code Scanner** (optional layer, enabled via `ZUGASHIELD_CODE_SCANNER_ENABLED=true`) scans LLM-generated code before execution.

*Regex fast path*: Six categories of vulnerabilities are detected via compiled patterns:
- `eval()`/`exec()` dynamic code execution
- SQL query construction with f-strings or `%` substitution
- `../` path traversal in file operations
- `pickle.loads()`, `yaml.load()`, `jsonpickle.decode()`, and `marshal.loads()` (unsafe deserialization)
- Hardcoded credentials in assignments
- `subprocess` with `shell=True` or shell metacharacters

*Semgrep deep scan* (optional): When `semgrep` is installed, the code is written to a temporary file and scanned with `semgrep --config=auto`, which applies hundreds of community-maintained security rules. Results are merged with the regex pass, deduplicating by signature ID.

---

## ASI06 — Memory Poisoning

### What the risk is

Agents that use persistent memory (vector stores, knowledge bases, conversation history) can be attacked via their memory system. An attacker plants malicious content in memory during one session; the content activates during a future recall, injecting instructions into a future prompt when the agent is working on an unrelated task.

### How ZugaShield defends against it

**Layer 4: Memory Sentinel** is the dedicated defense.

*Write-path scanning*: Before content is stored, eight instruction patterns and three importance inflation patterns are checked. Content that attempts to embed imperative commands for future execution is blocked at the write path before it ever reaches the store.

*Provenance tagging*: Every stored memory is tagged with a `source_trust` level derived from the `source` parameter. External content (`web_fetch`, `browser`) receives the lowest trust (`EXTERNAL`). Trust levels survive into the recall path so that suspicious content from external sources receives higher scrutiny.

*Recall-path validation*: Before recalled memories are injected into a prompt, the same instruction patterns are applied. Memories that contain embedded instructions are removed from the recalled list, and the caller receives the cleaned `filtered_memories` list.

*RAG pre-ingestion scanning*: `check_document()` scans external documents before they enter a vector store, catching recall-triggered instruction patterns, CSS/HTML hiding, system command density, and general instruction patterns.

---

## ASI07 — Inter-Agent Communication

### What the risk is

In multi-agent systems, agents communicate with each other via protocols (including MCP). An attacker who controls one agent or an MCP server can inject malicious content into tool definitions, inter-agent messages, or shared memory that corrupts the behavior of downstream agents.

### How ZugaShield defends against it

**MCP Guard** addresses the MCP-specific attack surface directly.

*Definition scanning*: Tool definitions received from any MCP server are scanned for injection payloads in the `name` and `description` fields before those tools are presented to the LLM. Poisoned tools are rejected and never appear in the tool list.

*Integrity verification*: Tool definitions are hashed at registration. Any subsequent modification is treated as a critical supply-chain violation. In a multi-agent system where Agent A provides tool definitions to Agent B, this ensures Agent B detects if Agent A's tools have been tampered with in transit.

*Cross-server name collision*: When two MCP servers expose the same tool name, the LLM may call the wrong server — allowing a malicious server to intercept calls intended for a legitimate server. MCP Guard tracks all `(tool_name, server_id)` pairs and flags collisions.

*Parameter value scanning*: Injection payloads in call-time parameter values (not just definitions) are also detected, covering cases where attacker-controlled data flows through parameters.

---

## ASI08 — Cascading Hallucination Failures

### What the risk is

In multi-step agent pipelines, errors compound. A hallucination or adversarial perturbation in one step propagates to downstream steps, with each step treating the previous output as ground truth. The final action may be far removed from anything the original instructions intended.

### How ZugaShield defends against it

**Fail-closed mode**: When `config.strict_mode=True`, medium-confidence detections are escalated to QUARANTINE rather than CHALLENGE. This prevents uncertain inputs from continuing through the pipeline and potentially compounding with errors in subsequent steps.

**Layer 6: Anomaly Detector** cross-correlates events across layers and time. A sequence of individually low-severity anomalies — which might indicate incremental error accumulation in a pipeline — can trigger a chain pattern or score threshold that halts execution before the cascading failure reaches a critical action.

The non-decaying cumulative score (floor at 20% of the session peak) ensures that even if each individual step looks innocuous, a session that has accumulated multiple suspicious events maintains elevated risk scoring.

---

## ASI09 — Human-Agent Trust Boundary

### What the risk is

Agents that can take real-world actions (send emails, make payments, modify files, interact with external services) require human oversight for high-stakes decisions. When the boundary between autonomous and human-supervised action is unclear or missing, agents may take irreversible actions without appropriate authorization.

### How ZugaShield defends against it

**Approval Provider**: ZugaShield provides an `ApprovalProvider` interface that any caller can implement. High-stakes decisions (those returning `CHALLENGE`) are routed to the approval provider before proceeding. Built-in Slack, email, and custom UI integrations are supported.

```python
class SlackApproval(ApprovalProvider):
    async def request_approval(self, decision, context=None):
        # Post to Slack, wait for human confirmation
        return True  # or False to deny
```

**Layer 7: Wallet Fortress** implements the most restrictive form of human oversight: every financial transaction, even a clean one, produces `CHALLENGE`. There is no configuration that makes a wallet transaction proceed without human confirmation. This is enforced at the code level, not through configuration, and cannot be disabled by changing `ZUGASHIELD_WALLET_FORTRESS_ENABLED` (disabling the layer removes all protection, not just the challenge requirement).

Transaction approval cooldowns provide a time-based friction mechanism: even after one approval, subsequent transactions must wait for the cooldown period to elapse.

---

## ASI10 — Rogue Agent Behavior

### What the risk is

An agent that has been compromised, manipulated, or that has developed misaligned behavior through adversarial fine-tuning or reward hacking may pursue goals that diverge from its stated purpose. Rogue behavior may be subtle: the agent appears to comply with instructions while pursuing a hidden agenda.

### How ZugaShield defends against it

**Layer 6: Anomaly Detector** establishes behavioral baselines and detects deviations. An agent that begins requesting unusual tool combinations, hitting previously-unseen endpoints, or generating outputs that trigger multiple layers will accumulate a rising session score. The alternating pattern detection specifically catches the strategy of alternating compliant behavior with suspicious behavior to dilute the score.

**CoT Auditor** (optional layer) provides direct inspection of reasoning traces. When an agent exposes `<thinking>` blocks or scratchpad output before acting, the CoT Auditor scans for deceptive language patterns:

- Explicit statements that the user does not need to know about a planned action.
- Statements that plan to hide, omit, or misrepresent information.
- Disclosures of a "real" or "hidden" goal distinct from the stated task.
- Planning to appear compliant while pursuing different objectives.
- Explicit planning to bypass safety systems in the reasoning itself.

The CoT Auditor addresses an attack surface unique to agentic AI: the model's internal monologue, which may contain information about intent not visible in its output.

---

## OWASP ASI Coverage Comparison

The following table compares ZugaShield's ASI coverage against other open-source AI security tools.

| OWASP ASI Risk | ZugaShield | NeMo Guardrails | LlamaFirewall | LLM Guard | Guardrails AI | Vigil |
|----------------|:----------:|:---------------:|:-------------:|:---------:|:-------------:|:-----:|
| **ASI01** Goal Hijacking | Full | Partial | Partial | Partial | None | Partial |
| **ASI02** Tool Misuse | Full | None | None | None | None | None |
| **ASI03** Identity/Privilege | Partial | None | None | None | None | None |
| **ASI04** Supply Chain | Full | None | None | None | None | None |
| **ASI05** Insecure Code Gen | Full | None | None | None | None | None |
| **ASI06** Memory Poisoning | Full | None | None | None | None | None |
| **ASI07** Inter-Agent Comms | Full | None | None | None | None | None |
| **ASI08** Cascading Failures | Partial | None | None | None | None | None |
| **ASI09** Human-Agent Trust | Full | None | None | None | None | None |
| **ASI10** Rogue Agent | Partial | None | None | None | None | None |
| **Total** | **9/10 full or partial** | **1/10** | **1/10** | **2/10** | **1/10** | **1/10** |

**Coverage key:**
- *Full*: dedicated layer or mechanism with direct detection capability.
- *Partial*: mitigated indirectly through adjacent defenses.
- *None*: not addressed by the tool.

### Notes on competitor assessments

**NeMo Guardrails** (NVIDIA): Addresses ASI01 through its Colang DSL conversation flow control, which can redirect or block certain topics. Does not address tool-level, memory-level, or financial transaction risks. Requires significant infrastructure.

**LlamaFirewall** (Meta): Uses PromptGuard 2 (a fine-tuned DeBERTa model) for ASI01. Partial ASI03 coverage via code analysis in AlignmentCheck. Does not address ASI02, ASI04–ASI10.

**LLM Guard** (ProtectAI): DeBERTa-based injection detection (ASI01) and Presidio-based PII detection (partial ASI06). Does not address tool, memory, wallet, or inter-agent risks.

**Guardrails AI**: Output structure validation. Addresses format correctness rather than adversarial attacks. Partial overlap with ASI01 through output validators.

**Vigil**: YARA rules and embedding similarity for ASI01. No coverage of other ASI risks.

ZugaShield is the only tool in the comparison set that addresses all 10 OWASP ASI risks in some capacity, and the only one with dedicated defenses for ASI02 (tool misuse), ASI04 (supply chain), ASI06 (memory poisoning), ASI07 (inter-agent), and ASI09 (human-agent trust boundary).
