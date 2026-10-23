"""Argument binding and construction failures before SDK tool execution."""
from __future__ import annotations

import copy
import sys
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Annotated

import pytest
from pydantic import BaseModel, Field, ValidationError

from harness.core.context import AgentContext
from harness.core.types import ScanStatus
from harness.core.verdicts import GateDecision, ScanVerdict
from harness.integrations.base import make_gated_tool, shai_tool


class CapturingHarness:
    def __init__(self, *, gate=None, verdict=None):
        self.gate = gate or GateDecision(allowed=True)
        self.verdict = verdict or ScanVerdict(status=ScanStatus.ALLOW)
        self.requests = []
        self.results = []

    async def check_tool_call(self, name, args, ctx):
        self.requests.append(copy.deepcopy(args))
        return self.gate

    @asynccontextmanager
    async def dispatch_scope(self, ctx, gate):
        yield

    async def scan_tool_result(self, text, ctx, **kwargs):
        self.results.append(text)
        return self.verdict


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("decorated", [False, True])
@pytest.mark.parametrize("args,kwargs,expected", [
    (("needle", 3), {}, {"query": "needle", "limit": 3, "mode": "safe"}),
    (("needle",), {"limit": 4, "mode": "brief"}, {"query": "needle", "limit": 4, "mode": "brief"}),
    ((), {"query": "needle"}, {"query": "needle", "limit": 2, "mode": "safe"}),
])
async def test_gate_and_implementation_receive_all_bound_values(asynchronous, decorated, args, kwargs, expected):
    received = []

    def sync(query: str, limit: int = 2, *, mode: str = "safe") -> str:
        received.append(dict(query=query, limit=limit, mode=mode))
        return "ok"

    async def async_fn(query: str, limit: int = 2, *, mode: str = "safe") -> str:
        return sync(query, limit, mode=mode)

    function = async_fn if asynchronous else sync
    tool = shai_tool(tags=["read"])(function) if decorated else function
    harness = CapturingHarness()
    wrapped = make_gated_tool(tool, harness=harness, ctx=AgentContext(agent_id="test"))
    assert await wrapped(*args, **kwargs) == "ok"
    assert harness.requests == received == [expected]
    assert harness.results == ["ok"]


async def test_positional_only_and_variadic_arguments_survive_gate_redaction():
    received = []

    def operation(value: str, /, *items: int, mode: str = "safe", **options: str) -> str:
        received.append((value, items, mode, options))
        return "done"

    effective = {"value": "redacted", "items": (9,), "mode": "restricted", "options": {"destination": "internal"}}
    harness = CapturingHarness(gate=GateDecision(allowed=True, redacted_args=effective))
    wrapped = make_gated_tool(operation, harness=harness, ctx=AgentContext(agent_id="test"))
    assert await wrapped("original", 1, 2, destination="external") == "done"
    assert harness.requests == [{"value": "original", "items": (1, 2), "mode": "safe", "options": {"destination": "external"}}]
    assert received == [("redacted", (9,), "restricted", {"destination": "internal"})]
    assert harness.gate.redacted_args == effective


@pytest.mark.parametrize("args,kwargs", [
    ((), {}), (("q",), {"query": "duplicate"}), (("q", 2, 3), {}), ((), {"query": "q", "unknown": "x"}),
])
async def test_invalid_binding_cannot_enter_gate_or_tool(args, kwargs):
    received = []

    def operation(query: str, limit: int = 2) -> str:
        received.append(query)
        return "ok"

    harness = CapturingHarness()
    wrapped = make_gated_tool(operation, harness=harness, ctx=AgentContext(agent_id="test"))
    with pytest.raises(TypeError):
        await wrapped(*args, **kwargs)
    assert not harness.requests and not received


async def test_denial_prevents_tool_entry_and_result_scan():
    received = []

    def operation(query: str) -> str:
        received.append(query)
        return "private"

    harness = CapturingHarness(gate=GateDecision(allowed=False, deny_reason="policy denied"))
    wrapped = make_gated_tool(operation, harness=harness, ctx=AgentContext(agent_id="test"))
    assert "denied" in await wrapped("q")
    assert harness.requests == [{"query": "q"}]
    assert not received and not harness.results


@pytest.mark.parametrize("effective", [{"extra": "unexpected"}, {}])
async def test_invalid_effective_arguments_do_not_enter_tool(effective):
    received = []

    def operation(query: str) -> str:
        received.append(query)
        return "private"

    harness = CapturingHarness(gate=GateDecision(allowed=True, redacted_args=effective))
    wrapped = make_gated_tool(operation, harness=harness, ctx=AgentContext(agent_id="test"))
    with pytest.raises(TypeError):
        await wrapped("q")
    assert not received


def test_schema_preserves_annotations_constraints_and_defaults_without_langchain(monkeypatch):
    monkeypatch.setitem(sys.modules, "langchain_core", None)

    @shai_tool(tags=["read"])
    def operation(query: Annotated[str, Field(min_length=2)], limit: int = 2) -> str:
        return query

    schema = operation.args_schema
    assert schema.model_validate({"query": "ok"}).model_dump() == {"query": "ok", "limit": 2}
    assert schema.model_json_schema()["required"] == ["query"]
    for args in ({}, {"query": "x"}, {"query": "ok", "limit": "bad"}, {"query": "ok", "extra": 1}):
        with pytest.raises(ValidationError):
            schema.model_validate(args)


def test_schema_failure_does_not_become_none():
    @shai_tool(tags=["read"])
    def operation(query: MissingAnnotation) -> str:  # noqa: F821
        return str(query)

    with pytest.raises(NameError, match="MissingAnnotation"):
        _ = operation.args_schema


@pytest.mark.parametrize("adapter,package", [("crewai", "crewai.tools"), ("openai_agents", "agents")])
def test_missing_sdk_never_returns_a_fallback_callable(adapter, package, monkeypatch):
    from harness.integrations import crewai, openai_agents

    monkeypatch.setitem(sys.modules, package, None)
    with pytest.raises(ImportError):
        {"crewai": crewai, "openai_agents": openai_agents}[adapter].wrap_tool(
            lambda query: query, harness=object(), ctx=AgentContext(agent_id="test"))


@pytest.mark.parametrize("adapter", ["crewai", "openai_agents"])
def test_unsupported_sdk_tool_is_rejected_instead_of_returned_unwrapped(adapter, monkeypatch):
    from harness.integrations import crewai, openai_agents

    monkeypatch.setitem(sys.modules, "crewai.tools", SimpleNamespace(BaseTool=object))
    monkeypatch.setitem(sys.modules, "agents", SimpleNamespace(function_tool=lambda *a, **k: None))
    tool = SimpleNamespace(name="unguarded", on_invoke_tool=lambda *a: "unguarded")
    with pytest.raises(TypeError, match="implementation callable"):
        {"crewai": crewai, "openai_agents": openai_agents}[adapter].wrap_tool(
            tool, harness=object(), ctx=AgentContext(agent_id="test"))


@pytest.mark.parametrize("declared_context", [False, True])
async def test_crewai_distinguishes_sdk_fingerprint_from_declared_arguments(declared_context, monkeypatch):
    from harness.integrations.crewai import wrap_tool

    class SDKBaseTool(BaseModel):
        name: str
        description: str
        args_schema: type[BaseModel]

    monkeypatch.setitem(sys.modules, "crewai.tools", SimpleNamespace(BaseTool=SDKBaseTool))
    received = []

    def regular(query: str) -> str:
        received.append({"query": query})
        return "ok"

    def contextual(query: str, security_context: dict) -> str:
        received.append({"query": query, "security_context": security_context})
        return "ok"

    function = contextual if declared_context else regular
    harness = CapturingHarness()
    wrapped = wrap_tool(function, harness=harness, ctx=AgentContext(agent_id="fixed-shai-actor"))
    arguments = {"query": "q", "security_context": {"agent_fingerprint": {"role": "untrusted"}}}
    validated = wrapped.args_schema.model_validate(arguments).model_dump()
    assert await wrapped._arun(**validated) == "ok"
    expected = arguments if declared_context else {"query": "q"}
    assert harness.requests == received == [expected]
    assert "security_context" in arguments  # SDK request was not mutated.
    with pytest.raises(ValidationError):
        wrapped.args_schema.model_validate({**arguments, "unexpected": "must not be discarded"})
