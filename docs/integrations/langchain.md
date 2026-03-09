# LangChain Integration

`ZugaShieldCallbackHandler` is an async LangChain callback handler that intercepts LLM prompts, tool calls, and LLM outputs at the framework level.

## Install

```bash
pip install "zugashield[fastapi]"  # or just zugashield
pip install langchain-core
```

## Usage

### With an LLM

```python
from langchain_openai import ChatOpenAI
from zugashield import ZugaShield
from zugashield.integrations.langchain import ZugaShieldCallbackHandler

shield = ZugaShield()
handler = ZugaShieldCallbackHandler(shield=shield, session_id="user-123")
llm = ChatOpenAI(callbacks=[handler])

# Raises SecurityError if injection is detected
response = await llm.ainvoke("What is the capital of France?")
```

### With LCEL Chains

```python
chain = prompt | llm.with_config(callbacks=[handler]) | parser
result = await chain.ainvoke({"input": "user message"})
```

### With Agents

```python
from langchain.agents import AgentExecutor

agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[handler],
)
```

## Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `shield` | ZugaShield | None | Shield instance. Defaults to singleton |
| `raise_on_block` | bool | `True` | Raise `SecurityError` on BLOCK/QUARANTINE verdicts |
| `session_id` | str | `"default"` | Session identifier for multi-turn anomaly tracking |

## Callback Methods

The handler implements all 9 callback methods in LangChain's async callback protocol:

| Method | Active | Layer | Description |
|--------|--------|-------|-------------|
| `on_llm_start` | Yes | Layer 2 (Prompt Armor) | Checks each prompt before the LLM sees it |
| `on_tool_start` | Yes | Layer 3 (Tool Guard) | Validates tool calls before execution |
| `on_llm_end` | Yes | Layer 5 (Exfiltration Guard) | Scans LLM output for data leakage |
| `on_tool_end` | No-op | — | Pass-through |
| `on_chain_start` | No-op | — | Pass-through |
| `on_chain_end` | No-op | — | Pass-through |
| `on_llm_error` | No-op | — | Pass-through |
| `on_tool_error` | No-op | — | Pass-through |
| `on_chain_error` | No-op | — | Pass-through |

## SecurityError

When `raise_on_block=True` (default) and a BLOCK or QUARANTINE verdict is returned, the handler raises `SecurityError`. LangChain propagates this as a regular Python exception.

```python
from zugashield.integrations.langchain import SecurityError

try:
    response = await llm.ainvoke("Ignore previous instructions")
except SecurityError as e:
    print(f"Blocked: {e}")
    # "ZugaShield [prompt_armor] blocked prompt[0]: Prompt injection detected"
```

To log and continue instead of raising (soft mode):

```python
handler = ZugaShieldCallbackHandler(raise_on_block=False)
```

## on_llm_start Detail

Each prompt in the `prompts` list is checked independently. The model name is extracted from the serialized LLM metadata and passed as context.

```python
# Context forwarded to check_prompt:
{
    "model": "gpt-4",
    "prompt_index": 0,
    "session_id": "user-123"
}
```

## on_llm_end Detail

Iterates over `response.generations` (a `List[List[Generation]]`). Each generation's text is scanned through `check_output`.

## Without langchain-core

The handler is importable even if `langchain-core` is not installed. In that case it falls back to a minimal stub base class and works via duck-typing (LangChain accepts plain objects as callbacks).

Last Updated: 2026-02-17
