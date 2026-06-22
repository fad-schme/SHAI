"""Performance baseline for boundary overhead.

Measures wall-clock overhead of each boundary on the hot path.
Targets (single-core, no network):
  - scan_input  (disabled):    < 1 ms per call
  - scan_output (disabled):    < 1 ms per call
  - check_tool_call (allow):   < 2 ms per call
  - 50 concurrent turns:       completes in < 200 ms total

Run with:
    pytest tests/perf/ -v -s

These are soft targets — they document expected behaviour on a modern laptop.
CI should flag regressions of 10× or more.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.harness import Harness
from harness.core.types import Transport
from harness.tools.tool import Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"


async def _build_harness(tmp_path: Path) -> Harness:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  name: rules\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    h = Harness.from_yaml(cfg)
    await h.load_agent(FIXTURES / "agents" / "orchestrator_agent.yaml")
    await h.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
    ])
    return h


async def _measure(coro_factory, n: int = 100) -> float:
    """Run coro_factory() n times sequentially, return mean ms."""
    start = time.perf_counter()
    for _ in range(n):
        await coro_factory()
    elapsed = time.perf_counter() - start
    return (elapsed / n) * 1000


# ── Sequential overhead ───────────────────────────────────────────────────

async def test_scan_input_disabled_overhead(tmp_path: Path):
    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    mean_ms = await _measure(lambda: h.scan_input("hello world", ctx), n=200)
    print(f"\n  scan_input (disabled):    {mean_ms:.3f} ms/call")
    assert mean_ms < 10, f"scan_input overhead too high: {mean_ms:.1f} ms"


async def test_scan_output_disabled_overhead(tmp_path: Path):
    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    mean_ms = await _measure(lambda: h.scan_output("hello world", ctx), n=200)
    print(f"\n  scan_output (disabled):   {mean_ms:.3f} ms/call")
    assert mean_ms < 10, f"scan_output overhead too high: {mean_ms:.1f} ms"


async def test_check_tool_call_allow_overhead(tmp_path: Path):
    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    mean_ms = await _measure(
        lambda: h.check_tool_call("search_docs", {"query": "test"}, ctx),
        n=200,
    )
    print(f"\n  check_tool_call (allow):  {mean_ms:.3f} ms/call")
    assert mean_ms < 20, f"check_tool_call overhead too high: {mean_ms:.1f} ms"


async def test_full_turn_overhead(tmp_path: Path):
    """Measure scan_input + check_tool_call + scan_output (tools pre-resolved at startup)."""
    h = await _build_harness(tmp_path)

    async def one_turn():
        ctx = AgentContext(agent_id="orchestrator_agent")
        await h.scan_input("test input", ctx)
        await h.check_tool_call("search_docs", {}, ctx)
        await h.scan_output("test output", ctx)

    mean_ms = await _measure(one_turn, n=100)
    print(f"\n  full turn (all disabled): {mean_ms:.3f} ms/turn")
    assert mean_ms < 50, f"full turn overhead too high: {mean_ms:.1f} ms"


# ── Concurrent throughput ─────────────────────────────────────────────────

async def test_50_concurrent_turns(tmp_path: Path):
    """50 concurrent turns must complete within a reasonable wall-clock budget."""
    h = await _build_harness(tmp_path)

    async def one_turn(i: int):
        ctx = AgentContext(agent_id="orchestrator_agent")
        await h.scan_input(f"input {i}", ctx)
        await h.check_tool_call("search_docs", {"query": f"q{i}"}, ctx)
        await h.scan_output(f"output {i}", ctx)

    start = time.perf_counter()
    await asyncio.gather(*[one_turn(i) for i in range(50)])
    elapsed_ms = (time.perf_counter() - start) * 1000

    print(f"\n  50 concurrent turns:      {elapsed_ms:.1f} ms total  "
          f"({elapsed_ms/50:.2f} ms/turn amortised)")
    assert elapsed_ms < 2000, f"50 concurrent turns too slow: {elapsed_ms:.0f} ms"


async def test_regex_pii_scanner_overhead(tmp_path: Path):
    """Measure the cost of running regex_pii on a typical input."""
    from harness.adapters.scanners.regex_pii import RegexPIIScanner
    from harness.core.context import AgentContext

    scanner = RegexPIIScanner()
    ctx     = AgentContext(agent_id="a1")
    text    = "Please help me find documents related to the Q3 report for the platform team."

    mean_ms = await _measure(lambda: scanner.scan(text, ctx), n=500)
    print(f"\n  regex_pii.scan:           {mean_ms:.3f} ms/call")
    assert mean_ms < 5, f"regex_pii overhead too high: {mean_ms:.3f} ms"
