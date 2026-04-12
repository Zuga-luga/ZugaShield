"""
Promptfoo custom provider — wraps ZugaShield's PromptArmorLayer.

Promptfoo calls `call_api(prompt, options, context)` for each test case.
We run the prompt through PromptArmorLayer and return the verdict + details.

This is Suite 1 (offline, no LLM calls, free).
"""

import asyncio
import json
import sys
import os

# Add ZugaShield to path so we can import it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from zugashield.config import ShieldConfig
from zugashield.layers.prompt_armor import PromptArmorLayer
from zugashield.threat_catalog import ThreatCatalog
from zugashield.types import ShieldVerdict

# Singleton — reuse across all test cases in a run
_armor = None


def _get_armor():
    global _armor
    if _armor is None:
        config = ShieldConfig()
        catalog = ThreatCatalog()
        _armor = PromptArmorLayer(config, catalog)
    return _armor


def call_api(prompt, options=None, context=None):
    """Promptfoo provider entry point.

    Returns dict with:
      - output: str (the verdict + threat info as text)
      - metadata: dict (structured data for assertions)
    """
    armor = _get_armor()
    decision = asyncio.run(armor.check(prompt))

    threats = []
    for t in decision.threats_detected:
        threats.append({
            "category": t.category.value if hasattr(t.category, "value") else str(t.category),
            "level": t.level.value if hasattr(t.level, "value") else str(t.level),
            "description": t.description,
            "signature_id": getattr(t, "signature_id", ""),
            "confidence": getattr(t, "confidence", 0.0),
        })

    verdict_str = decision.verdict.value if hasattr(decision.verdict, "value") else str(decision.verdict)

    return {
        "output": json.dumps({
            "verdict": verdict_str,
            "threats": threats,
            "elapsed_ms": getattr(decision, "elapsed_ms", 0),
        }),
        "metadata": {
            "verdict": verdict_str,
            "blocked": decision.verdict != ShieldVerdict.ALLOW,
            "threat_count": len(threats),
            "threat_categories": [t["category"] for t in threats],
        },
    }
