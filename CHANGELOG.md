# Changelog

All notable changes to ZugaShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-16

### Added

**Core**
- 7-layer defense architecture: Perimeter, Prompt Armor, Tool Guard, Memory Sentinel, Exfiltration Guard, Anomaly Detector, Wallet Fortress
- 150+ threat signatures across 11 categories
- Zero required dependencies — works out of the box

**Prompt Armor (Layer 2)**
- 10 detection strategies: regex catalog, spotlighting, encoding decode, unicode analysis, ASCII art detection, multi-turn escalation, context flooding, few-shot poisoning, GlitchMiner tokens, document embedding
- Compiled regex fast path for < 15ms overhead
- Canary token generation for exfiltration proof

**Tool Guard (Layer 3)**
- SSRF detection (localhost, metadata endpoints, DNS rebinding, decimal IP)
- Command injection and path traversal prevention
- Environment variable injection blocking

**Memory Sentinel (Layer 4)**
- Memory write poisoning detection (embedded instructions, sleeper commands, importance inflation)
- Memory recall validation (provenance tagging, external source flagging)
- RAG pre-ingestion document scanning

**Exfiltration Guard (Layer 5)**
- 70+ secret patterns (API keys, private keys, JWTs, AWS credentials)
- PII detection (emails, SSNs, credit cards)
- Canary token leak detection
- DNS exfiltration monitoring (subdomain depth, entropy analysis)
- Markdown image exfiltration blocking

**Anomaly Detector (Layer 6)**
- Session risk scoring with behavioral baselines
- Cross-layer event correlation

**Wallet Fortress (Layer 7)**
- Transaction limit enforcement
- Mixer/tumbler address detection
- Dangerous function signature blocking (approve unlimited, drain, transferOwnership)

**Multimodal**
- Image metadata injection detection (EXIF, alt-text)
- OCR text injection scanning
- 1x1 pixel steganography detection

**Integrations**
- MCP server with 9 scanning tools
- FastAPI dashboard (status, audit, config, catalog endpoints)
- Abstract `ApprovalProvider` for human-in-the-loop systems
- Optional LLM-as-Judge deep analysis via Anthropic API

[1.0.0]: https://github.com/Zuga-luga/ZugaShield/releases/tag/v1.0.0
