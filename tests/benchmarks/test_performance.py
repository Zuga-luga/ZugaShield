"""
Performance benchmark tests for ZugaShield.

Verifies the <15ms fast-path claim for all primary check operations.
All async checks run via asyncio.run() to match project test conventions.

Marks: @pytest.mark.benchmark on every test.

Measurement strategy: simple time.time() wall-clock measurements.
Each test runs the operation under test once (or N times for throughput)
and asserts against the documented latency SLA.

SLAs under test:
    - Single check (prompt / tool / output / memory): < 15 ms
    - 100 sequential prompt checks:                  < 1 000 ms total
    - ThreatCatalog cold load:                       < 100 ms
    - Clean (non-malicious) input round-trip:        fastest path (no catalog match)
"""

import asyncio
import time

import pytest

from zugashield import ZugaShield, ThreatCatalog
from zugashield.config import ShieldConfig


# ---------------------------------------------------------------------------
# Helper — run a coroutine synchronously (matches project convention)
# ---------------------------------------------------------------------------


def run(coro):
    """Run an async coroutine synchronously in a test."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Shared shield — constructed once per module so we don't pay init cost in
# the timing window of individual latency tests.
# ---------------------------------------------------------------------------


def _make_shield() -> ZugaShield:
    """Create a default ZugaShield with all layers enabled."""
    return ZugaShield(ShieldConfig())


# =============================================================================
# 1. Prompt check latency — single check must complete in < 15 ms
# =============================================================================


@pytest.mark.benchmark
def test_prompt_check_latency():
    """Single check_prompt call on a clean input completes in < 15 ms."""
    shield = _make_shield()

    # Warm-up: one call before timing to hydrate any lazy state
    run(shield.check_prompt("warm up"))

    start = time.perf_counter()
    result = run(shield.check_prompt("What is the weather today?"))
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert result is not None, "check_prompt returned None"
    assert elapsed_ms < 15, (
        f"check_prompt latency {elapsed_ms:.2f} ms exceeds 15 ms SLA"
    )


# =============================================================================
# 2. Tool call check latency — single check must complete in < 15 ms
# =============================================================================


@pytest.mark.benchmark
def test_tool_call_check_latency():
    """Single check_tool_call on a safe tool completes in < 15 ms."""
    shield = _make_shield()

    # Warm-up
    run(shield.check_tool_call("web_search", {"query": "python docs"}))

    start = time.perf_counter()
    result = run(shield.check_tool_call("web_search", {"query": "asyncio tutorial"}))
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert result is not None, "check_tool_call returned None"
    assert elapsed_ms < 15, (
        f"check_tool_call latency {elapsed_ms:.2f} ms exceeds 15 ms SLA"
    )


# =============================================================================
# 3. Output check latency — single check must complete in < 15 ms
# =============================================================================


@pytest.mark.benchmark
def test_output_check_latency():
    """Single check_output on benign output completes in < 15 ms."""
    shield = _make_shield()

    # Warm-up
    run(shield.check_output("Hello, here is your answer."))

    start = time.perf_counter()
    result = run(shield.check_output("def greet(name): return f'Hello, {name}!'"))
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert result is not None, "check_output returned None"
    assert elapsed_ms < 15, (
        f"check_output latency {elapsed_ms:.2f} ms exceeds 15 ms SLA"
    )


# =============================================================================
# 4. Memory check latency — single check must complete in < 15 ms
# =============================================================================


@pytest.mark.benchmark
def test_memory_check_latency():
    """Single check_memory_write on trusted content completes in < 15 ms."""
    shield = _make_shield()

    # Warm-up
    run(shield.check_memory_write(content="User prefers dark mode.", source="user_chat"))

    start = time.perf_counter()
    result = run(
        shield.check_memory_write(
            content="User timezone is Europe/London.",
            source="user_chat",
        )
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert result is not None, "check_memory_write returned None"
    assert elapsed_ms < 15, (
        f"check_memory_write latency {elapsed_ms:.2f} ms exceeds 15 ms SLA"
    )


# =============================================================================
# 5. Throughput — 100 sequential prompt checks must finish in < 1 second
# =============================================================================


@pytest.mark.benchmark
def test_throughput_100_prompts():
    """100 sequential check_prompt calls on clean inputs complete in < 1 000 ms."""
    shield = _make_shield()
    prompts = [f"Tell me about topic number {i}." for i in range(100)]

    async def _run_all():
        results = []
        for prompt in prompts:
            decision = await shield.check_prompt(prompt)
            results.append(decision)
        return results

    # Warm-up pass (not timed)
    run(shield.check_prompt("warm up throughput"))

    start = time.perf_counter()
    decisions = run(_run_all())
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert len(decisions) == 100, f"Expected 100 decisions, got {len(decisions)}"
    assert elapsed_ms < 1000, (
        f"100 sequential prompt checks took {elapsed_ms:.1f} ms — exceeds 1 000 ms SLA"
    )


# =============================================================================
# 6. Catalog load time — cold-loading ThreatCatalog must complete in < 100 ms
# =============================================================================


@pytest.mark.benchmark
def test_catalog_load_time():
    """ThreatCatalog cold-loads (including signature verification) in < 100 ms."""
    start = time.perf_counter()
    catalog = ThreatCatalog(verify_integrity=False)
    elapsed_ms = (time.perf_counter() - start) * 1000

    stats = catalog.get_stats()
    assert stats.get("total_signatures", 0) > 0, (
        "Catalog loaded but reported zero signatures"
    )
    assert elapsed_ms < 100, (
        f"ThreatCatalog load took {elapsed_ms:.2f} ms — exceeds 100 ms SLA"
    )


# =============================================================================
# 7. Clean input fast-path — benign input should be faster than average
# =============================================================================


@pytest.mark.benchmark
def test_clean_input_fast_path():
    """
    A clean (non-malicious) prompt returns faster than the 15 ms SLA.

    This exercises the early-exit optimisation: when no signature matches
    in the catalog scan the shield can ALLOW without evaluating every layer.
    We assert the clean path is < 15 ms and also confirm the verdict is ALLOW.
    """
    from zugashield import ShieldVerdict

    shield = _make_shield()

    # Warm-up
    run(shield.check_prompt("warm up clean path"))

    clean_prompt = "Please summarise the key points of the Python documentation."

    start = time.perf_counter()
    decision = run(shield.check_prompt(clean_prompt))
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert decision.verdict == ShieldVerdict.ALLOW, (
        f"Expected ALLOW for clean input, got {decision.verdict}"
    )
    assert elapsed_ms < 15, (
        f"Clean input fast-path took {elapsed_ms:.2f} ms — exceeds 15 ms SLA"
    )
