"""
ZugaShield - Code Safety Scanning Layer
=========================================

Detects dangerous patterns in LLM-generated code before execution.
Operates in two modes:

1. Regex fast path (always active): Catches command injection, eval/exec,
   path traversal, SQL injection, unsafe deserialization, and hardcoded
   credentials via compiled pattern matching (~1-3ms).

2. Semgrep deep scan (optional): If semgrep is installed and enabled,
   runs a full semantic analysis for deeper vulnerability detection
   (~200-2000ms depending on code size).

Integration point: Call before executing any LLM-generated code snippet.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from zugashield.types import (
    ThreatCategory,
    ThreatDetection,
    ThreatLevel,
    ShieldDecision,
    ShieldVerdict,
    allow_decision,
)

if TYPE_CHECKING:
    from zugashield.config import ShieldConfig
    from zugashield.threat_catalog import ThreatCatalog

logger = logging.getLogger(__name__)

# =============================================================================
# File extension map for semgrep language selection
# =============================================================================

_LANG_EXTENSION: Dict[str, str] = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "typescript": ".ts",
    "ts": ".ts",
    "go": ".go",
    "java": ".java",
    "ruby": ".rb",
    "rb": ".rb",
    "bash": ".sh",
    "sh": ".sh",
    "shell": ".sh",
    "c": ".c",
    "cpp": ".cpp",
    "rust": ".rs",
}

# =============================================================================
# Pre-compiled regex patterns (fast path)
# Each entry: (compiled_pattern, signature_id, description, level, evidence_fmt)
# =============================================================================

_CODE_PATTERNS: List[Tuple[re.Pattern, str, str, ThreatLevel]] = [
    # CS-EXEC: Dangerous execution primitives
    (
        re.compile(
            r"\b(?:eval|exec)\s*\(",
            re.I,
        ),
        "CS-EXEC",
        "Dynamic code execution via eval/exec",
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bos\.system\s*\(",
            re.I,
        ),
        "CS-EXEC",
        "Shell execution via os.system",
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\(",
            re.I,
        ),
        "CS-EXEC",
        "Subprocess execution (check shell= flag)",
        ThreatLevel.MEDIUM,
    ),
    (
        re.compile(
            r"\b__import__\s*\(",
            re.I,
        ),
        "CS-EXEC",
        "Dynamic import via __import__",
        ThreatLevel.MEDIUM,
    ),
    (
        re.compile(
            r"\bcompile\s*\(.*?,\s*['\"]exec['\"]",
            re.I,
        ),
        "CS-EXEC",
        "Dynamic code compilation with exec mode",
        ThreatLevel.HIGH,
    ),
    # CS-INJECT: SQL injection patterns
    (
        re.compile(
            r"""(?:execute|cursor\.execute|query)\s*\(\s*(?:f['"]{1,3}|['"]{1,3}\s*%\s*|['"]{1,3}\s*\+)""",
            re.I,
        ),
        "CS-INJECT",
        "SQL query built with string formatting (injection risk)",
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"""(?:execute|cursor\.execute)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)[^"']*["']\s*%""",
            re.I,
        ),
        "CS-INJECT",
        "SQL query using % string substitution",
        ThreatLevel.HIGH,
    ),
    # CS-PATH: Path traversal
    (
        re.compile(
            r"""(?:open|os\.path\.join|pathlib\.Path|Path)\s*\([^)]*(?:['"]\.\.[\\/]|['"]\.\.['"]\s*\+)""",
            re.I,
        ),
        "CS-PATH",
        "Path traversal: relative path component in file operation",
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"""['"]\.\./|['"]\.\.[/\\]|\.\.[\\/]['"]""",
        ),
        "CS-PATH",
        "Path traversal: literal ../ or ..\\ in string",
        ThreatLevel.MEDIUM,
    ),
    # CS-DESERIAL: Unsafe deserialization
    (
        re.compile(
            r"\bpickle\.loads?\s*\(",
            re.I,
        ),
        "CS-DESERIAL",
        "Unsafe pickle deserialization (arbitrary code execution risk)",
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"\byaml\.load\s*\([^,)]+\)",  # yaml.load without SafeLoader
            re.I,
        ),
        "CS-DESERIAL",
        "Unsafe yaml.load without SafeLoader (use yaml.safe_load)",
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bjsonpickle\.decode\s*\(",
            re.I,
        ),
        "CS-DESERIAL",
        "jsonpickle.decode allows arbitrary object instantiation",
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"\bmarshal\.loads?\s*\(",
            re.I,
        ),
        "CS-DESERIAL",
        "Unsafe marshal deserialization",
        ThreatLevel.CRITICAL,
    ),
    # CS-CRED: Hardcoded credentials
    (
        re.compile(
            r"""(?:password|passwd|secret|api_key|apikey|token|auth_token|access_token|private_key)\s*=\s*['"][^'"]{4,}['"]""",
            re.I,
        ),
        "CS-CRED",
        "Hardcoded credential or secret literal",
        ThreatLevel.HIGH,
    ),
    (
        re.compile(
            r"""(?:aws_access_key_id|aws_secret_access_key|DATABASE_URL|MONGO_URI)\s*=\s*['"][^'"]+['"]""",
            re.I,
        ),
        "CS-CRED",
        "Hardcoded cloud/database credential",
        ThreatLevel.CRITICAL,
    ),
    # CS-SHELL: Shell injection via subprocess without shell=False
    (
        re.compile(
            r"""subprocess\.(?:call|run|Popen|check_output)\s*\(\s*['"][^'"]*(?:\$|&&|\|\||;|`)[^'"]*['"]""",
            re.I,
        ),
        "CS-SHELL",
        "Shell metacharacters in subprocess string argument",
        ThreatLevel.CRITICAL,
    ),
    (
        re.compile(
            r"""subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True""",
            re.I,
        ),
        "CS-SHELL",
        "subprocess called with shell=True (enables shell injection)",
        ThreatLevel.HIGH,
    ),
]

# Semgrep availability cache (check once per process)
_SEMGREP_AVAILABLE: Optional[bool] = None


def _check_semgrep_available() -> bool:
    """Check if semgrep is installed and accessible."""
    global _SEMGREP_AVAILABLE
    if _SEMGREP_AVAILABLE is None:
        _SEMGREP_AVAILABLE = shutil.which("semgrep") is not None
        if _SEMGREP_AVAILABLE:
            logger.info("[CodeScanner] semgrep found — deep scan available")
        else:
            logger.debug("[CodeScanner] semgrep not found — regex-only mode")
    return _SEMGREP_AVAILABLE


class CodeScannerLayer:
    """
    Layer: Code Safety Scanning.

    Scans LLM-generated code for security vulnerabilities before execution.
    Uses a dual-path approach: fast regex for always-on protection, optional
    semgrep for deeper semantic analysis.
    """

    LAYER_NAME = "code_scanner"

    def __init__(self, config: ShieldConfig) -> None:
        self._config = config
        self._stats: Dict[str, int] = {
            "checks": 0,
            "threats_found": 0,
            "semgrep_scans": 0,
            "semgrep_errors": 0,
            "regex_hits": 0,
        }

    async def check(
        self,
        code: str,
        language: str = "python",
        **kwargs: Any,
    ) -> ShieldDecision:
        """
        Scan code for security vulnerabilities.

        Args:
            code: Source code string to scan.
            language: Programming language hint for semgrep (default: python).
            **kwargs: Ignored; accepts extra keyword args for forward compatibility.

        Returns:
            ShieldDecision with verdict and any threats detected.
        """
        if not self._config.code_scanner_enabled:
            return allow_decision(self.LAYER_NAME)

        if not code or not code.strip():
            return allow_decision(self.LAYER_NAME)

        start = time.perf_counter()
        self._stats["checks"] += 1
        threats: List[ThreatDetection] = []

        # === Pass 1: Regex fast path (always runs) ===
        regex_threats = self._scan_regex(code)
        threats.extend(regex_threats)

        # === Pass 2: Semgrep deep scan (optional) ===
        if _check_semgrep_available():
            try:
                semgrep_threats = await self._scan_semgrep(code, language)
                # Merge, avoiding exact duplicate signature_ids from regex pass
                existing_sigs = {t.signature_id for t in threats if t.signature_id}
                for t in semgrep_threats:
                    if t.signature_id not in existing_sigs:
                        threats.append(t)
                        existing_sigs.add(t.signature_id)
            except Exception:
                logger.exception("[CodeScanner] semgrep scan failed")
                self._stats["semgrep_errors"] += 1

        elapsed = (time.perf_counter() - start) * 1000

        if not threats:
            return allow_decision(self.LAYER_NAME, elapsed)

        self._stats["threats_found"] += len(threats)

        # Determine overall verdict from worst threat
        level_order = [
            ThreatLevel.NONE,
            ThreatLevel.LOW,
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]
        worst = max(threats, key=lambda t: level_order.index(t.level))

        if worst.level == ThreatLevel.CRITICAL:
            verdict = ShieldVerdict.BLOCK
        elif worst.level == ThreatLevel.HIGH:
            verdict = ShieldVerdict.BLOCK if self._config.strict_mode else ShieldVerdict.QUARANTINE
        elif worst.level == ThreatLevel.MEDIUM:
            verdict = ShieldVerdict.CHALLENGE
        else:
            verdict = ShieldVerdict.SANITIZE

        logger.warning(
            "[CodeScanner] %s: %d vulnerability(ies) found in %.1fms (language=%s, verdict=%s)",
            verdict.value.upper(),
            len(threats),
            elapsed,
            language,
            verdict.value,
        )

        return ShieldDecision(
            verdict=verdict,
            threats_detected=threats,
            layer=self.LAYER_NAME,
            elapsed_ms=elapsed,
        )

    def _scan_regex(self, code: str) -> List[ThreatDetection]:
        """
        Fast-path regex scan — compiled patterns, runs in ~1-3ms.

        Scans all patterns and collects every match. Multiple matches for
        the same signature_id are deduplicated to one detection per rule,
        taking the first match as evidence.
        """
        threats: List[ThreatDetection] = []
        seen_sigs: Dict[str, ThreatDetection] = {}

        for pattern, sig_id, description, level in _CODE_PATTERNS:
            match = pattern.search(code)
            if not match:
                continue

            # Deduplicate by sig_id — keep first match for the signature
            if sig_id in seen_sigs:
                continue

            evidence = match.group(0)[:200]
            self._stats["regex_hits"] += 1

            threat = ThreatDetection(
                category=ThreatCategory.TOOL_EXPLOITATION,
                level=level,
                verdict=self._level_to_verdict(level),
                description=description,
                evidence=evidence,
                layer=self.LAYER_NAME,
                confidence=0.85,
                suggested_action=self._suggested_action(sig_id),
                signature_id=sig_id,
            )
            seen_sigs[sig_id] = threat
            threats.append(threat)

        return threats

    async def _scan_semgrep(self, code: str, language: str) -> List[ThreatDetection]:
        """
        Deep scan via semgrep for semantic vulnerability detection.

        Writes code to a temp file, runs semgrep with security rulesets,
        and parses the JSON output into ThreatDetection objects.
        Timeout: 30 seconds max to prevent blocking.
        """
        self._stats["semgrep_scans"] += 1

        ext = _LANG_EXTENSION.get(language.lower(), ".py")
        threats: List[ThreatDetection] = []

        with tempfile.TemporaryDirectory(prefix="zs_scan_") as tmpdir:
            target = Path(tmpdir) / f"scan_target{ext}"
            target.write_text(code, encoding="utf-8")

            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--quiet",
                "--no-git-ignore",
                str(target),
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=30.0,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.communicate()
                    logger.warning("[CodeScanner] semgrep timed out after 30s")
                    return threats

            except FileNotFoundError:
                # semgrep disappeared between check and use
                logger.debug("[CodeScanner] semgrep not found at scan time")
                return threats

            if not stdout:
                return threats

            try:
                result = json.loads(stdout.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                logger.debug("[CodeScanner] Failed to parse semgrep JSON output")
                return threats

            for finding in result.get("results", []):
                check_id: str = finding.get("check_id", "semgrep-unknown")
                message: str = finding.get("extra", {}).get("message", "Semgrep finding")
                severity: str = finding.get("extra", {}).get("severity", "WARNING").upper()
                lines: str = finding.get("extra", {}).get("lines", "")

                level = {
                    "ERROR": ThreatLevel.CRITICAL,
                    "WARNING": ThreatLevel.HIGH,
                    "INFO": ThreatLevel.MEDIUM,
                }.get(severity, ThreatLevel.MEDIUM)

                # Map semgrep rule IDs to our signature namespace
                sig_id = f"CS-SEMGREP-{check_id.split('.')[-1][:32].upper()}"

                threats.append(
                    ThreatDetection(
                        category=ThreatCategory.TOOL_EXPLOITATION,
                        level=level,
                        verdict=self._level_to_verdict(level),
                        description=f"[semgrep] {message[:200]}",
                        evidence=lines[:200] if lines else check_id,
                        layer=self.LAYER_NAME,
                        confidence=0.80,
                        suggested_action="Review semgrep finding before executing code",
                        signature_id=sig_id,
                        metadata={"semgrep_rule": check_id},
                    )
                )

        return threats

    @staticmethod
    def _level_to_verdict(level: ThreatLevel) -> ShieldVerdict:
        """Map threat level to appropriate shield verdict."""
        return {
            ThreatLevel.CRITICAL: ShieldVerdict.BLOCK,
            ThreatLevel.HIGH: ShieldVerdict.QUARANTINE,
            ThreatLevel.MEDIUM: ShieldVerdict.CHALLENGE,
            ThreatLevel.LOW: ShieldVerdict.SANITIZE,
            ThreatLevel.NONE: ShieldVerdict.ALLOW,
        }.get(level, ShieldVerdict.CHALLENGE)

    @staticmethod
    def _suggested_action(sig_id: str) -> str:
        """Return a remediation hint for each signature category."""
        actions = {
            "CS-EXEC": "Remove eval/exec; use ast.literal_eval or a safe alternative",
            "CS-INJECT": "Use parameterized queries (cursor.execute(sql, params))",
            "CS-PATH": "Validate and sanitize file paths; use os.path.abspath",
            "CS-DESERIAL": "Use json.loads or yaml.safe_load instead",
            "CS-CRED": "Move credentials to environment variables or a secrets manager",
            "CS-SHELL": "Pass commands as a list and set shell=False",
        }
        for prefix, action in actions.items():
            if sig_id.startswith(prefix):
                return action
        return "Review and remediate the identified vulnerability"

    def get_stats(self) -> Dict[str, Any]:
        """Return layer statistics."""
        return {
            "layer": self.LAYER_NAME,
            "semgrep_available": _check_semgrep_available(),
            **self._stats,
        }
