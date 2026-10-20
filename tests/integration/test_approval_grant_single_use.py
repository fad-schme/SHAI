"""An approval grant authorises one call, in every process on the approvals store.

Two harnesses built from one config stand for two replicas: each has its own
connection and its own memory, and shares only the SQLite file named in
`check_tool_call.approvals.store`.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.core.approval import encode_grant, sign_grant
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.harness import SHAI
from harness.core.types import Irreversibility
from harness.tools.tool import Tool

_KEY = "integration-approval-key"
_ARGS = {"invoice": "inv-1", "amount": 50}

_AGENT = """\
id: payer
allowed_tool_names: [pay_invoice]
allowed_tags: [financial]
"""

_CONFIG = """\
version: 1
connectivity:
  token_secret: test-connectivity-secret
check_tool_call:
  approvals:
    secret: secret://APPROVAL_KEY
    store:
      name: sqlite
      config:
        path: {db}
audit_sinks:
  - name: stdout
"""


async def _replica(tmp_path: Path) -> tuple[SHAI, AgentContext]:
    config = tmp_path / "harness.yaml"
    config.write_text(_CONFIG.format(db=(tmp_path / "approvals.db").as_posix()))
    agent = tmp_path / "payer.yaml"
    agent.write_text(_AGENT)
    harness = await SHAI.from_yaml(config)
    await harness.register_tools([Tool(
        name="pay_invoice", tags=["financial"], irreversibility=Irreversibility.SENSITIVE,
    )])
    return harness, await harness.load_agent(agent)


def _with_grant(harness: SHAI, ctx: AgentContext, approver: str = "alex") -> AgentContext:
    grant = sign_grant(
        agent_id=ctx.agent_id, tenant_id=harness._tenant_id, tool_name="pay_invoice",
        args=_ARGS, approver_id=approver, secret=_KEY.encode(),
    )
    return ctx.model_copy(update={"approvals": (encode_grant(grant),)})


@pytest.fixture(autouse=True)
def _approval_key(monkeypatch):
    monkeypatch.setenv("APPROVAL_KEY", _KEY)


async def test_a_grant_spent_through_one_replica_is_refused_through_another(tmp_path: Path):
    a, ctx_a = await _replica(tmp_path)
    b, ctx_b = await _replica(tmp_path)
    try:
        ctx = _with_grant(a, ctx_a)
        first = await a.check_tool_call("pay_invoice", _ARGS, ctx)
        second = await b.check_tool_call("pay_invoice", _ARGS, ctx_b.model_copy(
            update={"approvals": ctx.approvals}))
        assert first.allowed
        assert not second.allowed
        assert "already been used" in second.deny_reason
    finally:
        await a.close()
        await b.close()


async def test_simultaneous_calls_on_two_replicas_allow_exactly_one(tmp_path: Path):
    a, ctx_a = await _replica(tmp_path)
    b, ctx_b = await _replica(tmp_path)
    try:
        grants = _with_grant(a, ctx_a).approvals
        results = await asyncio.gather(
            a.check_tool_call("pay_invoice", _ARGS, ctx_a.model_copy(update={"approvals": grants})),
            b.check_tool_call("pay_invoice", _ARGS, ctx_b.model_copy(update={"approvals": grants})),
        )
        assert sum(r.allowed for r in results) == 1
    finally:
        await a.close()
        await b.close()


async def test_the_same_replica_refuses_the_grant_after_a_restart(tmp_path: Path):
    first, ctx = await _replica(tmp_path)
    try:
        ctx = _with_grant(first, ctx)
        assert (await first.check_tool_call("pay_invoice", _ARGS, ctx)).allowed
    finally:
        await first.close()
    restarted, ctx_after = await _replica(tmp_path)
    try:
        replay = await restarted.check_tool_call(
            "pay_invoice", _ARGS, ctx_after.model_copy(update={"approvals": ctx.approvals}))
        assert not replay.allowed
    finally:
        await restarted.close()


async def test_a_secret_without_a_store_is_rejected_at_load(tmp_path: Path):
    config = tmp_path / "harness.yaml"
    config.write_text(
        "version: 1\n"
        "connectivity: {token_secret: s}\n"
        "check_tool_call:\n  approvals:\n    secret: secret://APPROVAL_KEY\n"
    )
    with pytest.raises(ConfigError, match="approvals.store is required"):
        await SHAI.from_yaml(config)
