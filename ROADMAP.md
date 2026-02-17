# ZugaShield Roadmap

This is a living document. Priorities shift as new attack vectors emerge.

## v1.1 - Hardening (Q1 2026)

- [ ] **Community signature contributions** - Accept PRs for new detection patterns
- [ ] **OWASP LLM Top 10 mapping** - Map every detection to OWASP categories
- [ ] **Benchmarking suite** - Standardized evasion tests with pass/fail metrics
- [ ] **False positive rate tracking** - Automated FP measurement per layer

## v1.2 - Next-Gen Attacks (Q2 2026)

- [ ] **Multi-turn state machine** - Track conversation-level attack progression
- [ ] **Agent-to-agent injection** - Detect cross-agent prompt relay attacks
- [ ] **Fine-tune poisoning detection** - Identify outputs from poisoned models
- [ ] **Semantic similarity bypass detection** - Catch paraphrased injection attempts
- [ ] **Token-level analysis** - BPE tokenizer awareness for split-token attacks

## v1.3 - Enterprise Features (Q3 2026)

- [ ] **Policy-as-code** - Define custom detection rules in YAML/JSON
- [ ] **Streaming support** - Scan token-by-token as LLM generates output
- [ ] **Metrics export** - Prometheus/OpenTelemetry integration
- [ ] **Multi-tenant isolation** - Per-org config and signature sets
- [ ] **Audit log shipping** - Export to SIEM (Splunk, Datadog, etc.)

## v2.0 - Adaptive Defense (Q4 2026)

- [ ] **ML-based detection** - Trained classifier for ambiguous inputs
- [ ] **Adversarial training pipeline** - Automated red team -> signature generation
- [ ] **Federated threat intelligence** - Opt-in anonymous threat sharing across deployments
- [ ] **MITRE ATT&CK for AI mapping** - Full framework alignment
- [ ] **Real-time signature updates** - Pull new signatures without package upgrade

## Research Priorities

These are areas where the threat landscape is evolving fastest:

| Area | Why It Matters |
|------|---------------|
| MCP tool poisoning | New protocol, attack surface still being mapped |
| Multi-agent chain attacks | Agents calling agents creates transitive trust issues |
| Memory persistence attacks | Poisoned memories that activate weeks later |
| AI recommendation poisoning | Microsoft disclosed this Feb 2026 |
| Supply chain via model weights | Trojans embedded in fine-tuned models |
| Audio/video injection | Multimodal models expand the attack surface |

## How to Contribute to the Roadmap

1. Open a [Discussion](https://github.com/Zuga-luga/ZugaShield/discussions) to propose ideas
2. Vote on existing roadmap items by reacting with a thumbs-up
3. Submit bypass reports to help prioritize defenses
4. Contribute signatures for emerging attack patterns
