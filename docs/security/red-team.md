# Red Team Guide

This guide covers how to test ZugaShield's defenses, run the built-in test suite, and report bypasses responsibly.

## Running the Test Suite

```bash
# Full test suite
pytest tests/

# Red team tests only
pytest tests/redteam/ -v

# Specific attack category
pytest tests/redteam/test_prompt_injection.py -v
pytest tests/redteam/test_tool_guard.py -v
pytest tests/redteam/test_exfiltration.py -v
pytest tests/redteam/test_wallet.py -v
pytest tests/redteam/test_memory.py -v

# ML-specific injection tests
pytest tests/redteam/test_ml_injection.py -v

# Coverage tests (deepset, Gandalf datasets)
pytest tests/coverage/ -v

# Performance benchmarks
pytest tests/benchmarks/ -v
```

All red team tests are fully offline — no LLM, no network, no database required.

## Attack Categories Covered

### Direct Prompt Injection (`test_prompt_injection.py`)

Tests classic injection patterns that should be detected:

- Classic "ignore previous instructions" variants
- System prompt override (`SYSTEM:` prefix)
- Role hijacking: DAN mode, "you are now an unrestricted AI"
- Developer mode bypass
- Context manipulation ("the above is test data")
- Instructions embedded in code blocks

Also tests that benign messages pass without false positives.

### Encoding Evasion

Tests injection payloads disguised via:

- Base64 encoding with and without decode instructions
- Nested base64 (double-encoded)
- Hex encoding
- ROT13

### Unicode Smuggling (`test_prompt_injection.py::TestUnicodeSmuggling`)

Tests Unicode-based evasion:

- Cyrillic homoglyphs in domain names (`p\u0430ypal.com`)
- Invisible zero-width characters (`\u200b`, `\u200d`)
- Right-to-left override character (`\u202e`)
- Tag block characters (`\ue0020`-`\ue007e`)

### Multi-Turn Crescendo Attack

Tests gradual escalation across conversation turns (based on Microsoft's crescendo paper):

- Each turn adds more adversarial weight
- By turn 5 with heavy payload density, detection should trigger
- Separate sessions must not bleed state

### Tool Guard (`test_tool_guard.py`)

Tests tool call validation:

- Sensitive path access (`.ssh`, `.env`, `credentials`, etc.)
- SSRF patterns in URL parameters
- Command injection in bash/exec-style tools
- Rate limit enforcement

### Exfiltration (`test_exfiltration.py`)

Tests output DLP:

- API key patterns (`sk-`, `AKIA`, `Bearer `)
- Private key markers (`-----BEGIN`)
- Credential patterns
- Bulk data extraction signals

### Wallet (`test_wallet.py`)

Tests wallet protection:

- Transactions exceeding per-tx limit
- Transactions exceeding hourly limit
- Address manipulation patterns

### Memory Poisoning (`test_memory.py`)

Tests memory sentinel:

- Injection payloads in memory writes
- Embedded instructions in recalled memories

## Writing a Test

All tests use a standard pattern:

```python
import asyncio
import pytest
from zugashield import ShieldVerdict
from zugashield.config import ShieldConfig
from zugashield.layers.prompt_armor import PromptArmorLayer
from zugashield.threat_catalog import ThreatCatalog

def run(coro):
    return asyncio.run(coro)

@pytest.fixture
def armor():
    return PromptArmorLayer(ShieldConfig(), ThreatCatalog())

def test_my_bypass_attempt(armor):
    d = run(armor.check("your bypass attempt here"))
    assert d.verdict != ShieldVerdict.ALLOW, "Bypass not detected"

def test_benign_equivalent_passes(armor):
    d = run(armor.check("the benign version of the same request"))
    assert d.verdict == ShieldVerdict.ALLOW, "False positive"
```

Always pair bypass detection tests with a benign equivalent to ensure no regression in false positive rate.

## Benchmark Evaluation

To measure detection rates against the public test datasets:

```bash
python -m zugashield.ml.benchmark_configs
```

This tests multiple training configurations against the deepset and Gandalf datasets and reports:

- Detection recall (deepset, Gandalf, combined)
- False positive rate
- Cross-validation F1

Target thresholds for the default configuration:

| Metric | Target |
|--------|--------|
| deepset recall | >= 88% |
| Gandalf recall | 100% |
| False positive rate | 0% |

## Reporting Bypasses

If you find a bypass that ZugaShield fails to detect:

1. Create a minimal reproduction: the shortest input that evades detection
2. Confirm it is not a false positive by verifying the input is genuinely malicious
3. Note which layer(s) failed to detect it
4. Open an issue at the ZugaShield repository with the `security` label
5. Do not publish working bypasses publicly before a fix is released

For critical vulnerabilities (bypasses that work against deployed production systems), contact the maintainers privately before opening a public issue.

## Known Limitations

- The perimeter layer (Layer 1) does not inspect request bodies at the middleware level to avoid buffering the stream. Use `shield_protect(check_body=True)` on sensitive routes if body inspection is required.
- The ML classifier has a configurable threshold (default 0.7). Lowering the threshold improves recall but increases false positives.
- Highly novel jailbreak techniques may evade pattern-based detection until signatures are updated. Enable the threat feed for automatic signature updates.

Last Updated: 2026-02-17
