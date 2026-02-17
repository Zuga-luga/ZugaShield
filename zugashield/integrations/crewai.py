"""
ZugaShield - CrewAI Integration
=================================

Tool wrapper that adds ZugaShield checks before and after CrewAI tool execution.

Usage (wrap a single tool):
    from crewai_tools import FileReadTool
    from zugashield import ZugaShield
    from zugashield.integrations.crewai import shield_wrap_tool

    shield = ZugaShield()
    safe_file_tool = shield_wrap_tool(FileReadTool(), shield=shield)

Usage (wrap all tools on a crew):
    from zugashield.integrations.crewai import shield_wrap_crew

    safe_crew = shield_wrap_crew(crew, shield=shield)

Usage (class-based, for custom tools):
    from crewai.tools import BaseTool
    from zugashield.integrations.crewai import ZugaShieldToolMixin

    class MyTool(ZugaShieldToolMixin, BaseTool):
        name: str = "my_tool"
        description: str = "Does something"

        def _run(self, **kwargs):
            ...
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when ZugaShield blocks a CrewAI tool call."""


def _run_async(coro: Any) -> Any:
    """Drive an async coroutine from synchronous CrewAI tool execution."""
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


def _get_default_shield() -> Any:
    from zugashield import get_zugashield
    return get_zugashield()


# =============================================================================
# shield_wrap_tool — functional wrapping for any CrewAI-compatible tool object
# =============================================================================


def shield_wrap_tool(
    tool: Any,
    shield: Any = None,
    session_id: str = "default",
    check_output: bool = True,
) -> Any:
    """
    Wrap a CrewAI tool to run ZugaShield checks before (and optionally after)
    tool execution.

    Works with:
    - ``crewai.tools.BaseTool`` subclasses
    - ``langchain.tools.BaseTool`` objects used in CrewAI
    - Any object with a ``run`` or ``_run`` method

    The wrapper patches the tool's ``run``/``_run`` method in-place and
    returns the same object, so existing agent definitions need no changes.

    Args:
        tool:         The tool instance to protect.
        shield:       Optional ZugaShield instance. Defaults to singleton.
        session_id:   Session identifier for the tool_guard layer.
        check_output: If True, also run exfiltration guard on the tool output.

    Returns:
        The same tool object with security checks injected.

    Raises:
        SecurityError: At call time if ZugaShield blocks the invocation.
    """
    _shield = shield  # may be None — resolved lazily

    def _get_shield() -> Any:
        nonlocal _shield
        if _shield is None:
            _shield = _get_default_shield()
        return _shield

    # Determine which method to wrap — prefer ``run`` for public interface
    if hasattr(tool, "run"):
        original_run = tool.run
        _method_name = "run"
    elif hasattr(tool, "_run"):
        original_run = tool._run
        _method_name = "_run"
    else:
        logger.warning(
            "[ZugaShield] shield_wrap_tool: tool '%s' has no run/_run method — skipping",
            getattr(tool, "name", repr(tool)),
        )
        return tool

    tool_name: str = getattr(tool, "name", type(tool).__name__)

    @functools.wraps(original_run)
    def _wrapped_run(*args: Any, **kwargs: Any) -> Any:
        shield_instance = _get_shield()

        # ---- Pre-execution: Layer 3 (Tool Guard) --------------------------
        # Build a flat params dict from positional + keyword args
        params: dict = dict(kwargs)
        if args:
            params["_args"] = list(args)

        try:
            decision = _run_async(
                shield_instance.check_tool_call(
                    tool_name=tool_name,
                    params=params,
                    session_id=session_id,
                )
            )
            if decision.is_blocked:
                threat = (
                    decision.threats_detected[0]
                    if decision.threats_detected
                    else None
                )
                description = threat.description if threat else "Unknown threat"
                raise SecurityError(
                    f"ZugaShield blocked tool '{tool_name}': {description}"
                )
        except SecurityError:
            raise
        except Exception:
            logger.exception(
                "[ZugaShield] Pre-execution check error for tool '%s' — fail-open",
                tool_name,
            )

        # ---- Execute the original tool ------------------------------------
        result = original_run(*args, **kwargs)

        # ---- Post-execution: Layer 5 (Exfiltration Guard) -----------------
        if check_output and result is not None:
            output_text = str(result)
            try:
                out_decision = _run_async(
                    shield_instance.check_output(
                        output=output_text,
                        context={"tool": tool_name, "session_id": session_id},
                    )
                )
                if out_decision.is_blocked:
                    threat = (
                        out_decision.threats_detected[0]
                        if out_decision.threats_detected
                        else None
                    )
                    description = threat.description if threat else "Unknown threat"
                    raise SecurityError(
                        f"ZugaShield blocked output from tool '{tool_name}': {description}"
                    )
            except SecurityError:
                raise
            except Exception:
                logger.exception(
                    "[ZugaShield] Post-execution check error for tool '%s' — fail-open",
                    tool_name,
                )

        return result

    # Patch the method on the tool instance
    setattr(tool, _method_name, _wrapped_run)

    # Async variant — some CrewAI tools expose _arun
    if hasattr(tool, "_arun"):
        original_arun = tool._arun

        @functools.wraps(original_arun)
        async def _wrapped_arun(*args: Any, **kwargs: Any) -> Any:
            shield_instance = _get_shield()
            params = dict(kwargs)
            if args:
                params["_args"] = list(args)

            try:
                decision = await shield_instance.check_tool_call(
                    tool_name=tool_name,
                    params=params,
                    session_id=session_id,
                )
                if decision.is_blocked:
                    threat = (
                        decision.threats_detected[0]
                        if decision.threats_detected
                        else None
                    )
                    description = threat.description if threat else "Unknown threat"
                    raise SecurityError(
                        f"ZugaShield blocked tool '{tool_name}': {description}"
                    )
            except SecurityError:
                raise
            except Exception:
                logger.exception(
                    "[ZugaShield] Async pre-execution check error for tool '%s' — fail-open",
                    tool_name,
                )

            result = await original_arun(*args, **kwargs)

            if check_output and result is not None:
                try:
                    out_decision = await shield_instance.check_output(
                        output=str(result),
                        context={"tool": tool_name, "session_id": session_id},
                    )
                    if out_decision.is_blocked:
                        threat = (
                            out_decision.threats_detected[0]
                            if out_decision.threats_detected
                            else None
                        )
                        description = threat.description if threat else "Unknown threat"
                        raise SecurityError(
                            f"ZugaShield blocked output from tool '{tool_name}': {description}"
                        )
                except SecurityError:
                    raise
                except Exception:
                    logger.exception(
                        "[ZugaShield] Async post-execution check error for '%s' — fail-open",
                        tool_name,
                    )

            return result

        tool._arun = _wrapped_arun

    logger.debug("[ZugaShield] Wrapped CrewAI tool: %s", tool_name)
    return tool


# =============================================================================
# shield_wrap_crew — convenience wrapper for entire crew
# =============================================================================


def shield_wrap_crew(crew: Any, shield: Any = None, session_id: str = "default") -> Any:
    """
    Wrap all tools on every agent in a CrewAI ``Crew`` instance.

    Modifies the crew in-place and returns it.

    Args:
        crew:       The CrewAI Crew instance.
        shield:     Optional ZugaShield instance.
        session_id: Session identifier forwarded to each wrapped tool.

    Returns:
        The same crew with all agent tools protected by ZugaShield.
    """
    agents = getattr(crew, "agents", []) or []
    total_wrapped = 0
    for agent in agents:
        agent_tools = getattr(agent, "tools", []) or []
        for i, tool in enumerate(agent_tools):
            agent_tools[i] = shield_wrap_tool(
                tool, shield=shield, session_id=session_id
            )
            total_wrapped += 1

    logger.info(
        "[ZugaShield] shield_wrap_crew: %d tool(s) protected across %d agent(s)",
        total_wrapped,
        len(agents),
    )
    return crew


# =============================================================================
# ZugaShieldToolMixin — mixin for class-based custom tools
# =============================================================================


class ZugaShieldToolMixin:
    """
    Mixin for CrewAI ``BaseTool`` subclasses that adds automatic ZugaShield
    checks on every ``run`` call.

    Usage:
        from crewai.tools import BaseTool
        from zugashield.integrations.crewai import ZugaShieldToolMixin

        class MyTool(ZugaShieldToolMixin, BaseTool):
            name: str = "my_tool"
            description: str = "Does something"

            def _run(self, query: str) -> str:
                return "result"

    The mixin overrides ``run`` to inject pre/post checks. Place it first in
    the MRO so its ``run`` is picked up before BaseTool's.
    """

    _zugashield_instance: Optional[Any] = None
    _zugashield_session_id: str = "default"
    _zugashield_check_output: bool = True

    def _get_shield(self) -> Any:
        if self._zugashield_instance is None:
            from zugashield import get_zugashield
            self._zugashield_instance = get_zugashield()
        return self._zugashield_instance

    def run(self, *args: Any, **kwargs: Any) -> Any:
        tool_name: str = getattr(self, "name", type(self).__name__)
        shield = self._get_shield()
        params = dict(kwargs)
        if args:
            params["_args"] = list(args)

        try:
            decision = _run_async(
                shield.check_tool_call(
                    tool_name=tool_name,
                    params=params,
                    session_id=self._zugashield_session_id,
                )
            )
            if decision.is_blocked:
                threat = (
                    decision.threats_detected[0]
                    if decision.threats_detected
                    else None
                )
                description = threat.description if threat else "Unknown threat"
                raise SecurityError(
                    f"ZugaShield blocked tool '{tool_name}': {description}"
                )
        except SecurityError:
            raise
        except Exception:
            logger.exception(
                "[ZugaShield] Mixin pre-run error for '%s' — fail-open", tool_name
            )

        result = super().run(*args, **kwargs)

        if self._zugashield_check_output and result is not None:
            try:
                out_decision = _run_async(
                    shield.check_output(
                        output=str(result),
                        context={"tool": tool_name, "session_id": self._zugashield_session_id},
                    )
                )
                if out_decision.is_blocked:
                    threat = (
                        out_decision.threats_detected[0]
                        if out_decision.threats_detected
                        else None
                    )
                    description = threat.description if threat else "Unknown threat"
                    raise SecurityError(
                        f"ZugaShield blocked output from '{tool_name}': {description}"
                    )
            except SecurityError:
                raise
            except Exception:
                logger.exception(
                    "[ZugaShield] Mixin post-run error for '%s' — fail-open", tool_name
                )

        return result
