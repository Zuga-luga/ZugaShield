# Contributing to ZugaShield

Thanks for your interest in making AI agents more secure. Here's how to get started.

## Development Setup

```bash
git clone https://github.com/Zuga-luga/ZugaShield.git
cd ZugaShield
pip install -e ".[dev,all]"
```

## Running Tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR. The test suite covers prompt injection, encoding evasion, unicode smuggling, tool guard, memory poisoning, exfiltration, and more.

## Code Style

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
ruff check zugashield/ zugashield_mcp/ tests/
ruff format zugashield/ zugashield_mcp/ tests/
```

Key conventions:
- Line length: 120 characters
- Target: Python 3.9+
- Type hints encouraged but not required for internal code

## Adding Threat Signatures

Signatures live in `zugashield/signatures/*.json`. Each signature needs:

```json
{
  "id": "XX-NNN",
  "description": "What this detects",
  "patterns": ["regex_pattern_here"],
  "severity": "critical|high|medium|low",
  "category": "PROMPT_INJECTION|TOOL_EXPLOITATION|..."
}
```

After adding signatures, verify they compile:

```bash
python -m pytest tests/test_catalog.py -v
```

## Adding Detection Strategies

New detection methods go in the appropriate layer file under `zugashield/layers/`. Each layer follows the same pattern:

1. Add your detection method (e.g., `_check_new_attack()`)
2. Call it from the layer's `check()` method
3. Return `ThreatDetection` objects for matches
4. Add tests in `tests/test_redteam.py`

## Pull Requests

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Ensure all tests pass and linting is clean
4. Submit a PR with a clear description of what and why

## Reporting Bugs

Open an issue with:
- Python version
- ZugaShield version (`pip show zugashield`)
- Minimal reproduction steps
- Expected vs actual behavior
