"""
ZugaShield - LangChain Integration
=====================================

Callback handler that intercepts LLM prompts, tool calls, and LLM outputs
at the LangChain framework level.

Hooks:
    on_llm_start  — checks prompts before sending to the LLM (Layer 2)
    on_tool_start — checks tool calls before execution (Layer 3)
    on_llm_end    — checks LLM output for data exfiltration (Layer 5)

Usage:
    from langchain_openai import ChatOpenAI
    from zugashield import ZugaShield
    from zugashield.integrations.langchain import ZugaShieldCallbackHandler

    shield = ZugaShield()
    handler = ZugaShieldCallbackHandler(shield=shield)
    llm = ChatOpenAI(callbacks=[handler])

Usage with LCEL chains:
    chain = prompt | llm.with_config(callbacks=[handler]) | parser

Usage with agents:
    agent_executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when ZugaShield blocks an LLM or tool operation."""


# ---------------------------------------------------------------------------
# Try to inherit from the official LangChain async callback base class.
# If langchain_core is not installed, define a standalone no-op base so the
# handler still works via duck-typing (LangChain also accepts plain objects).
# ---------------------------------------------------------------------------
try:
    from langchain_core.callbacks import AsyncCallbackHandler as _LCBase

    _HAS_LANGCHAIN = True
    logger.debug("[ZugaShield] langchain_core detected — using AsyncCallbackHandler base")
except ImportError:
    _HAS_LANGCHAIN = False

    class _LCBase:  # type: ignore[no-redef]
        """Minimal stub so ZugaShieldCallbackHandler is importable without LangChain."""

        async def on_llm_start(self, *args: Any, **kwargs: Any) -> None: ...
        async def on_tool_start(self, *args: Any, **kwargs: Any) -> None: ...
        async def on_llm_end(self, *args: Any, **kwargs: Any) -> None: ...
        async def on_tool_end(self, *args: Any, **kwargs: Any) -> None: ...
        async def on_chain_start(self, *args: Any, **kwargs: Any) -> None: ...
        async def on_chain_end(self, *args: Any, **kwargs: Any) -> None: ...
        async def on_llm_error(self, *args: Any, **kwargs: Any) -> None: ...
        async def on_tool_error(self, *args: Any, **kwargs: Any) -> None: ...
        async def on_chain_error(self, *args: Any, **kwargs: Any) -> None: ...


class ZugaShieldCallbackHandler(_LCBase):
    """
    LangChain async callback handler that runs ZugaShield checks at each
    stage of the LLM pipeline.

    Raises ``SecurityError`` to abort the LangChain invocation when a threat
    is detected. LangChain propagates this as a regular Python exception,
    which the caller can catch.

    Args:
        shield:   Optional ZugaShield instance. Defaults to the singleton.
        raise_on_block: If True (default), raise SecurityError on BLOCK/QUARANTINE.
                        If False, log and continue (soft mode — use with care).
        session_id: Session identifier forwarded to tool_guard and anomaly detector.
    """

    raise_exceptions = True  # LangChain introspects this attribute

    def __init__(
        self,
        shield: Any = None,
        raise_on_block: bool = True,
        session_id: str = "default",
    ) -> None:
        if _HAS_LANGCHAIN:
            super().__init__()
        self._shield_instance = shield
        self._raise_on_block = raise_on_block
        self._session_id = session_id

    def _get_shield(self) -> Any:
        if self._shield_instance is None:
            from zugashield import get_zugashield
            self._shield_instance = get_zugashield()
        return self._shield_instance

    def _maybe_raise(self, decision: Any, context: str) -> None:
        """Raise SecurityError if the decision is blocked and raise_on_block is set."""
        if decision.is_blocked:
            threat = (
                decision.threats_detected[0]
                if decision.threats_detected
                else None
            )
            description = threat.description if threat else "Unknown threat"
            msg = f"ZugaShield [{decision.layer}] blocked {context}: {description}"
            logger.warning("[ZugaShield] %s", msg)
            if self._raise_on_block:
                raise SecurityError(msg)

    # ------------------------------------------------------------------
    # Layer 2: Prompt Armor — check prompts before sending to LLM
    # ------------------------------------------------------------------

    async def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Check each prompt for injection attacks before the LLM sees them."""
        shield = self._get_shield()
        model_name = (serialized or {}).get("id", ["unknown"])[-1]
        for i, prompt in enumerate(prompts):
            try:
                decision = await shield.check_prompt(
                    user_message=prompt,
                    context={"model": model_name, "prompt_index": i, "session_id": self._session_id},
                )
                self._maybe_raise(decision, f"prompt[{i}]")
            except SecurityError:
                raise
            except Exception:
                logger.exception(
                    "[ZugaShield] on_llm_start error for prompt[%d] — fail-open", i
                )

    # ------------------------------------------------------------------
    # Layer 3: Tool Guard — check tool calls before execution
    # ------------------------------------------------------------------

    async def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Check a tool call before execution."""
        shield = self._get_shield()
        tool_name: str = (serialized or {}).get("name", "unknown")
        try:
            decision = await shield.check_tool_call(
                tool_name=tool_name,
                params={"input": input_str},
                session_id=self._session_id,
            )
            self._maybe_raise(decision, f"tool '{tool_name}'")
        except SecurityError:
            raise
        except Exception:
            logger.exception(
                "[ZugaShield] on_tool_start error for tool '%s' — fail-open", tool_name
            )

    # ------------------------------------------------------------------
    # Layer 5: Exfiltration Guard — check LLM output for data leakage
    # ------------------------------------------------------------------

    async def on_llm_end(
        self,
        response: Any,
        **kwargs: Any,
    ) -> None:
        """Check LLM output for sensitive data before it reaches the caller."""
        shield = self._get_shield()
        try:
            # LangChain LLMResult has .generations: List[List[Generation]]
            generations = getattr(response, "generations", None) or []
            for gen_list in generations:
                for gen in gen_list:
                    text = getattr(gen, "text", None) or str(gen)
                    if not text:
                        continue
                    decision = await shield.check_output(
                        output=text,
                        context={"source": "llm_output", "session_id": self._session_id},
                    )
                    self._maybe_raise(decision, "LLM output")
        except SecurityError:
            raise
        except Exception:
            logger.exception("[ZugaShield] on_llm_end error — fail-open")

    # ------------------------------------------------------------------
    # Pass-through stubs (keep LangChain's callback protocol satisfied)
    # ------------------------------------------------------------------

    async def on_tool_end(self, output: str, **kwargs: Any) -> None:
        pass

    async def on_chain_start(
        self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any
    ) -> None:
        pass

    async def on_chain_end(
        self, outputs: Dict[str, Any], **kwargs: Any
    ) -> None:
        pass

    async def on_llm_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        pass

    async def on_tool_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        pass

    async def on_chain_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        pass
