# Changelog

All notable changes to ZugaShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-17

### Added

**ML Detection Layer (TF-IDF v2.0)**
- TF-IDF + Logistic Regression classifier trained on 9 public datasets (~20,000+ samples)
- 6 heuristic features: override keyword density, few-shot pattern count, special token density, repeated token indicator, imperative sentence density, second-person pronoun ratio
- Datasets: deepset/prompt-injections, Lakera/gandalf, rubend18/ChatGPT-Jailbreak, JailbreakBench/JBB-Behaviors, jackhhao/jailbreak-classification, reshabhs/SPML, Lakera/mosscap (DEF CON 31), xTRam1/safe-guard, qualifire/prompt-injections-benchmark
- Optional ONNX DeBERTa tier for higher accuracy (`pip install zugashield[ml]`)
- CLI: `zugashield-ml download`, `zugashield-ml info`, `zugashield-ml download --model prompt-guard-22m`

**ML Supply Chain Hardening**
- SHA-256 hash verification of model files at load time (integrity.json + sidecar files)
- Canary validation: 3 hardcoded behavioral smoke tests run after every model load
- Model version pinning via `ZUGASHIELD_ML_MODEL_VERSION` config
- Dual format support: v1.0 Pipeline (legacy) and v2.0 dict bundle with metadata

**New Optional Layers**
- CoT Auditor: chain-of-thought trace auditing for deceptive reasoning patterns
- MCP Guard: MCP protocol security — tool definition integrity, schema validation
- Code Scanner: LLM-generated code safety scanning (regex fast path + optional Semgrep)

**Framework Integrations**
- Starlette: base ASGI middleware with path exclusion and fail-closed mode
- CrewAI: tool wrapper with shield check
- LlamaIndex: callback handler

**Testing**
- Performance benchmarks: latency SLAs (<15ms per check), throughput (100 prompts), catalog load time
- Framework adapter integration tests (FastAPI, Flask, Starlette, LangChain, MCP, Approval)
- ML detector tests: hash verification, canary validation, version pinning, heuristic features

### Changed

- TF-IDF model retrained with optimized hyperparameters (C=50, ngram_range=(2,6), max_features=100K)
- Detection improvement: deepset recall 25% -> 88.7%, gandalf 99% -> 100%, 0% false positives
- 3-round systematic benchmark across 30+ configurations to find optimal training parameters

### Fixed

- `SecurityError` in `threat_catalog.py` was raised but never defined — added exception class
- Integrity verification now skips metadata sections (prefixed with `_`) in integrity.json

## [0.1.0] - 2026-02-17

First public release — extracted from Zugabot's internal security system into a standalone, zero-dependency package.

### Added

**Core Architecture**
- 7-layer defense system: Perimeter, Prompt Armor, Tool Guard, Memory Sentinel, Exfiltration Guard, Anomaly Detector, Wallet Fortress
- 5-verdict decision system: ALLOW, SANITIZE, CHALLENGE, QUARANTINE, BLOCK
- Fail-closed mode (`fail_closed=True`) — layers return BLOCK on unhandled exceptions
- Frozen `ShieldConfig` dataclass — immutable after construction, prevents runtime tampering
- Builder pattern: `ZugaShield.builder().fail_closed().enable_layers(...).build()`
- Sync wrappers for every async method (`check_prompt_sync`, etc.)
- Event hooks: `@shield.on_threat()`, `@shield.on_block`
- Custom layer registration: `shield.register_layer(MyLayer())`

**Threat Catalog**
- 150+ curated threat signatures across 11 categories
- Pre-compiled regex patterns for <1ms matching
- SHA-256 integrity verification of signature files on load
- Versioned catalog with update tracking

**Layer 1: Perimeter**
- HTTP method and content-type validation
- Request size limits with configurable thresholds
- Rate limiting per session and per endpoint
- Configurable sensitive endpoints (no longer hardcoded)

**Layer 2: Prompt Armor** (crown jewel — 10 detection strategies)
- Compiled regex catalog matching (150+ patterns)
- Spotlighting for indirect injection detection
- Nested encoding decode (base64, hex, ROT13)
- Unicode homoglyph analysis with ~200 confusable pairs
- Invisible character and zero-width detection
- ASCII art bypass detection via entropy analysis
- Context window flooding detection
- Few-shot poisoning detection
- GlitchMiner token detection (Shannon entropy per word)
- Document embedding detection (CSS hiding patterns)
- Multi-turn crescendo tracking

**Layer 3: Tool Guard**
- SSRF detection (localhost, metadata endpoints, DNS rebinding, decimal IP)
- Command injection and path traversal prevention
- Environment variable injection blocking
- Configurable tool risk matrix (no longer hardcoded tool names)
- Per-tool rate limiting with approval requirements

**Layer 4: Memory Sentinel**
- Memory write poisoning detection (embedded instructions, sleeper commands)
- Memory recall validation with provenance tagging
- RAG pre-ingestion document scanning (imperative detection, CSS hiding)

**Layer 5: Exfiltration Guard**
- 70+ secret patterns (API keys, private keys, JWTs, AWS credentials)
- PII detection (emails, SSNs, credit cards)
- Canary token leak detection
- DNS exfiltration monitoring (subdomain depth, entropy analysis)
- Markdown image exfiltration blocking
- Fixed egress allowlist — exact domain matching, explicit wildcard opt-in

**Layer 6: Anomaly Detector**
- Session risk scoring with behavioral baselines
- Cross-layer event correlation
- Non-decaying lifetime score (floor at 20% of peak)
- Cross-session cumulative scoring

**Layer 7: Wallet Fortress**
- Transaction limit enforcement
- Mixer/tumbler address detection
- Dangerous function signature blocking (approve unlimited, drain, transferOwnership)

**Optional Layers**
- LLM Judge: Provider-agnostic deep analysis (Anthropic, OpenAI, LiteLLM)
- Code Scanner: LLM-generated code safety scanning (regex fast path + optional Semgrep)
- CoT Auditor: Chain-of-thought trace auditing for deceptive reasoning
- MCP Guard: MCP protocol security — tool definition integrity, schema validation

**Multimodal**
- Image metadata injection detection (EXIF, alt-text)
- OCR text injection scanning
- Configurable degradation mode when Pillow is not installed

**Integrations**
- FastAPI: middleware + dashboard router (status, audit, config, catalog endpoints)
- Flask: `ZugaShieldFlask` extension + blueprint
- Starlette: base ASGI middleware
- LangChain: `ZugaShieldCallbackHandler`
- LlamaIndex: callback handler
- CrewAI: tool wrapper with shield check
- MCP: server with 9 scanning tools
- Abstract `ApprovalProvider` for human-in-the-loop (Slack, email, custom UI)

**Developer Experience**
- Zero required dependencies — runs with stdlib only
- `pip install zugashield` — works out of the box
- Full type annotations with `py.typed` marker
- 329 tests (unit, red team, integration, benchmarks)
- CI: ruff lint, mypy strict, pytest on Python 3.10/3.11/3.12

### Security Fixes (from internal audit)

- **Fail-closed mode**: Unhandled layer exceptions now return BLOCK instead of silently passing
- **Immutable config**: `ShieldConfig` is frozen — no runtime mutation
- **Signature integrity**: SHA-256 verification prevents tampered signature files
- **Egress allowlist hardening**: Exact domain matching replaces `endswith()` to prevent subdomain bypass
- **Rate limit persistence**: Global rate tracking survives session resets
- **Lifetime anomaly score**: Non-decaying floor prevents patience attacks
- **Expanded homoglyphs**: ~200 confusable pairs (up from 27)

[1.1.0]: https://github.com/Zuga-luga/ZugaShield/releases/tag/v1.1.0
[0.1.0]: https://github.com/Zuga-luga/ZugaShield/releases/tag/v0.1.0
