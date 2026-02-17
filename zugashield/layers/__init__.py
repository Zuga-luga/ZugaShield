"""ZugaShield security layers."""

from zugashield.layers.base import BaseLayer
from zugashield.layers.perimeter import PerimeterLayer
from zugashield.layers.prompt_armor import PromptArmorLayer
from zugashield.layers.tool_guard import ToolGuardLayer
from zugashield.layers.memory_sentinel import MemorySentinelLayer
from zugashield.layers.exfiltration_guard import ExfiltrationGuardLayer
from zugashield.layers.anomaly_detector import AnomalyDetectorLayer
from zugashield.layers.wallet_fortress import WalletFortressLayer
from zugashield.layers.llm_judge import LLMJudgeLayer

__all__ = [
    "BaseLayer",
    "PerimeterLayer",
    "PromptArmorLayer",
    "ToolGuardLayer",
    "MemorySentinelLayer",
    "ExfiltrationGuardLayer",
    "AnomalyDetectorLayer",
    "WalletFortressLayer",
    "LLMJudgeLayer",
]

# Optional layers — imported separately to avoid hard dependencies
try:
    from zugashield.layers.code_scanner import CodeScannerLayer
    __all__.append("CodeScannerLayer")
except ImportError:
    pass

try:
    from zugashield.layers.cot_auditor import CoTAuditorLayer
    __all__.append("CoTAuditorLayer")
except ImportError:
    pass

try:
    from zugashield.layers.mcp_guard import MCPGuardLayer
    __all__.append("MCPGuardLayer")
except ImportError:
    pass
