"""
ZugaShield - LlamaIndex Integration
======================================

Callback handler that plugs into LlamaIndex's ``CallbackManager`` and
intercepts LLM calls, query executions, and tool/function calls.

Usage:
    import llama_index.core
    from zugashield import ZugaShield
    from zugashield.integrations.llamaindex import ZugaShieldCallbackHandler

    shield = ZugaShield()
    handler = ZugaShieldCallbackHandler(shield=shield)
    llama_index.core.Settings.callback_manager.add_handler(handler)

Or during Settings initialisation:
    from llama_index.core import Settings
    from llama_index.core.callbacks import CallbackManager

    Settings.callback_manager = CallbackManager([handler])
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when ZugaShield blocks a LlamaIndex operation."""


# ---------------------------------------------------------------------------
# Try to import LlamaIndex base classes and event types.
# Fall back to duck-typed stubs so the handler works without llama_index.
# ---------------------------------------------------------------------------
try:
    from llama_index.core.callbacks import (
        CBEventType,
        EventPayload,
    )
    from llama_index.core.callbacks.base_handler import BaseCallbackHandler as _LIBase

    _HAS_LLAMAINDEX = True
    logger.debug("[ZugaShield] llama_index.core detected")
except ImportError:
    _HAS_LLAMAINDEX = False

    class CBEventType:  # type: ignore[no-redef]
        """Minimal stub for CBEventType enum."""
        LLM = "llm"
        FUNCTION_CALL = "function_call"
        QUERY = "query"
        RETRIEVE = "retrieve"
        SYNTHESIZE = "synthesize"

    class EventPayload:  # type: ignore[no-redef]
        PROMPT = "prompt"
        COMPLETION = "completion"
        FUNCTION_CALL = "function_call"
        FUNCTION_OUTPUT = "function_output"
        QUERY_STR = "query_str"

    class _LIBase:  # type: ignore[no-redef]
        """Minimal stub so the handler is importable without llama_index."""

        event_starts_to_ignore: List[str] = []
        event_ends_to_ignore: List[str] = []

        def on_event_start(self, *args: Any, **kwargs: Any) -> str:
            return ""

        def on_event_end(self, *args: Any, **kwargs: Any) -> None: ...
        def start_trace(self, *args: Any, **kwargs: Any) -> None: ...
        def end_trace(self, *args: Any, **kwargs: Any) -> None: ...


class ZugaShieldCallbackHandler(_LIBase):
    """
    LlamaIndex callback handler that runs ZugaShield checks at key pipeline stages.

    Intercepts:
        CBEventType.LLM         — prompt check (Layer 2) on start,
                                   output check (Layer 5) on end
        CBEventType.FUNCTION_CALL — tool/function check (Layer 3) on start
        CBEventType.QUERY        — prompt check (Layer 2) on query string

    Raises ``SecurityError`` on BLOCK or QUARANTINE verdicts (configurable).

    Args:
        shield:         Optional ZugaShield instance. Defaults to singleton.
        raise_on_block: If True (default), raise SecurityError on blocked events.
        session_id:     Forwarded to tool_guard and anomaly detector.
    """

    # LlamaIndex reads these to decide which events to suppress
    event_starts_to_ignore: List[Any] = []
    event_ends_to_ignore: List[Any] = []

    def __init__(
        self,
        shield: Any = None,
        raise_on_block: bool = True,
        session_id: str = "default",
    ) -> None:
        if _HAS_LLAMAINDEX:
            super().__init__(
                event_starts_to_ignore=[],
                event_ends_to_ignore=[],
            )
        self._shield_instance = shield
        self._raise_on_block = raise_on_block
        self._session_id = session_id
        # Track active event IDs so we can correlate start/end
        self._active_events: Dict[str, str] = {}  # event_id -> event_type

    def _get_shield(self) -> Any:
        if self._shield_instance is None:
            from zugashield import get_zugashield
            self._shield_instance = get_zugashield()
        return self._shield_instance

    def _maybe_raise(self, decision: Any, context: str) -> None:
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

    def _run_async(self, coro: Any) -> Any:
        """Drive an async coroutine from the synchronous LlamaIndex callback."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, coro)
                    return future.result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    # ------------------------------------------------------------------
    # on_event_start — runs before each pipeline stage
    # ------------------------------------------------------------------

    def on_event_start(
        self,
        event_type: Any,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        payload = payload or {}
        shield = self._get_shield()

        try:
            # Layer 2: check prompt before LLM call
            if event_type == CBEventType.LLM:
                prompt = payload.get(EventPayload.PROMPT, "")
                if prompt:
                    decision = self._run_async(
                        shield.check_prompt(
                            user_message=str(prompt),
                            context={"source": "llamaindex_llm", "session_id": self._session_id},
                        )
                    )
                    self._maybe_raise(decision, "LLM prompt")

            # Layer 2: check query string before retrieval/synthesis
            elif event_type == CBEventType.QUERY:
                query = payload.get(EventPayload.QUERY_STR, "")
                if query:
                    decision = self._run_async(
                        shield.check_prompt(
                            user_message=str(query),
                            context={"source": "llamaindex_query", "session_id": self._session_id},
                        )
                    )
                    self._maybe_raise(decision, "query string")

            # Layer 3: check function/tool call
            elif event_type == CBEventType.FUNCTION_CALL:
                call_payload = payload.get(EventPayload.FUNCTION_CALL, {})
                if isinstance(call_payload, dict):
                    tool_name = call_payload.get("name", "unknown")
                    tool_args = call_payload.get("arguments", {})
                else:
                    tool_name = str(call_payload)
                    tool_args = {}
                decision = self._run_async(
                    shield.check_tool_call(
                        tool_name=tool_name,
                        params=tool_args if isinstance(tool_args, dict) else {"args": tool_args},
                        session_id=self._session_id,
                    )
                )
                self._maybe_raise(decision, f"tool '{tool_name}'")

        except SecurityError:
            raise
        except Exception:
            logger.exception(
                "[ZugaShield] on_event_start error for %s — fail-open", event_type
            )

        if event_id:
            self._active_events[event_id] = str(event_type)
        return event_id

    # ------------------------------------------------------------------
    # on_event_end — runs after each pipeline stage
    # ------------------------------------------------------------------

    def on_event_end(
        self,
        event_type: Any,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        payload = payload or {}
        shield = self._get_shield()

        try:
            # Layer 5: check LLM completion output for data exfiltration
            if event_type == CBEventType.LLM:
                completion = payload.get(EventPayload.COMPLETION, "")
                if completion:
                    output_text = (
                        str(completion)
                        if not hasattr(completion, "text")
                        else completion.text
                    )
                    decision = self._run_async(
                        shield.check_output(
                            output=output_text,
                            context={"source": "llamaindex_llm_end", "session_id": self._session_id},
                        )
                    )
                    self._maybe_raise(decision, "LLM output")

        except SecurityError:
            raise
        except Exception:
            logger.exception(
                "[ZugaShield] on_event_end error for %s — fail-open", event_type
            )

        self._active_events.pop(event_id, None)

    # ------------------------------------------------------------------
    # Trace lifecycle stubs (required by LlamaIndex protocol)
    # ------------------------------------------------------------------

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        pass

    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        pass
