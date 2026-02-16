# Changelog

## [1.0.0] - 2026-02-16

### Added
- Initial release extracted from Zugabot production system
- 7-layer defense architecture (Perimeter, Prompt Armor, Tool Guard, Memory Sentinel, Exfiltration Guard, Anomaly Detector, Wallet Fortress)
- 150+ threat signatures across 11 categories
- 10 detection strategies in Prompt Armor layer
- Multimodal image injection detection
- LLM-as-Judge optional deep analysis
- Canary token system for exfiltration proof
- DNS exfiltration monitoring
- RAG pre-ingestion document scanning
- Context window flooding detection
- Few-shot poisoning detection
- GlitchMiner anomalous token detection
- Document embedding poisoning detection
- MCP server with 9 scanning tools
- FastAPI dashboard integration
- Abstract approval provider for HIL systems
- Zero required dependencies
- Optional extras: fastapi, multimodal, llm-judge, mcp
- 98+ test cases
