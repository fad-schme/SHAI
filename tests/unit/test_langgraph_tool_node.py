"""HarnessToolNode: which exceptions stay per-call and which stop the run."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from harness.core.context import AgentContext
from harness.core.errors import AuditEmissionError
from harness.integrations.langgraph import HarnessToolNode
from tests.unit.test_integrations import _build_harness

_SINK_TEXT = "all audit sinks failed: disk full on /var/log/shai"


class _SearchDocs:
    name = "search_docs"

    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.calls = 0

    async def ainvoke(self, args: dict[str, Any]) -> str:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return "docs"


def _calls(*ids: str) -> dict[str, Any]:
    return {"messages": [AIMessage(content="", tool_calls=[
        {"name": "search_docs", "args": {"query": "q"}, "id": i, "type": "tool_call"}
        for i in ids])]}


async def test_a_total_audit_outage_propagates_and_no_message_carries_the_sink_text(tmp_path: Path):
    h = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")
    tool = _SearchDocs()

    async def all_sinks_down(event: Any) -> None:
        raise AuditEmissionError(_SINK_TEXT)

    h._emitter.emit = all_sinks_down
    node = HarnessToolNode(tools=[tool], harness=h, ctx=ctx)

    with pytest.raises(AuditEmissionError):
        await node(_calls("1", "2"))

    assert tool.calls == 0, "the second call must not be attempted after the outage"


async def test_an_ordinary_tool_error_stays_per_call_and_the_batch_continues(tmp_path: Path):
    h = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")
    tool = _SearchDocs(error=ValueError("boom"))
    node = HarnessToolNode(tools=[tool], harness=h, ctx=ctx)

    result = await node(_calls("1", "2"))

    messages = result["messages"]
    assert [m.tool_call_id for m in messages] == ["1", "2"]
    assert all(m.status == "error" and "boom" in m.content for m in messages)
    assert tool.calls == 2
