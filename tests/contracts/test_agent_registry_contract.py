"""AgentRegistry contract suite.

Covers: load, reload, deregister, list, get, conflict detection,
cross-field validation enforcement, and concurrent load safety.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError

from harness.agents.registry import AgentRegistry
from harness.core.errors import AgentConflictError, AgentNotRegisteredError


def _agent_yaml(tmp_path: Path, content: str, name: str = "agent.yaml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def _minimal(tmp_path: Path, agent_id: str = "test_agent", name: str = "agent.yaml") -> Path:
    return _agent_yaml(tmp_path, (
        f"id: {agent_id}\n"
        "allowed_tool_names: [search_docs]\n"
        "allowed_tags: [read, internal]\n"
    ), name=name)


# ── load ──────────────────────────────────────────────────────────────────

async def test_load_returns_agent_config(tmp_path: Path):
    reg = AgentRegistry()
    cfg = await reg.load(_minimal(tmp_path))
    assert cfg.id == "test_agent"
    assert "search_docs" in cfg.allowed_tool_names


async def test_load_idempotent_same_content(tmp_path: Path):
    reg = AgentRegistry()
    p   = _minimal(tmp_path)
    cfg1 = await reg.load(p)
    cfg2 = await reg.load(p)
    assert cfg1 == cfg2


async def test_load_conflict_raises(tmp_path: Path):
    reg = AgentRegistry()
    await reg.load(_minimal(tmp_path, "test_agent", "a.yaml"))
    different = _agent_yaml(tmp_path, (
        "id: test_agent\n"
        "allowed_tool_names: [fetch_doc]\n"   # different tools
        "allowed_tags: [read]\n"
    ), "b.yaml")
    with pytest.raises(AgentConflictError):
        await reg.load(different)


async def test_load_invalid_yaml_raises(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text("not: valid: yaml: :\n")
    reg = AgentRegistry()
    with pytest.raises(Exception):
        await reg.load(p)


async def test_load_invalid_schema_raises(tmp_path: Path):
    p = _agent_yaml(tmp_path, (
        "id: test_agent\n"
        "allowed_tool_names: []\n"  # empty — must fail validation
        "allowed_tags: [read]\n"
    ))
    reg = AgentRegistry()
    with pytest.raises(Exception):
        await reg.load(p)


async def test_load_subagent_tags_subset_enforced(tmp_path: Path):
    """Sub-agent tags must be ⊆ parent tags."""
    p = _agent_yaml(tmp_path, (
        "id: test_agent\n"
        "allowed_tool_names: [search_docs]\n"
        "allowed_tags: [read]\n"
        "sub_agents:\n"
        "  - id: sub1\n"
        "    allowed_tool_names: [search_docs]\n"
        "    allowed_tags: [read, external_write]\n"   # external_write not in parent
    ))
    reg = AgentRegistry()
    with pytest.raises(Exception):
        await reg.load(p)


# ── get ───────────────────────────────────────────────────────────────────

async def test_get_registered_agent(tmp_path: Path):
    reg = AgentRegistry()
    await reg.load(_minimal(tmp_path))
    cfg = reg.get("test_agent")
    assert cfg.id == "test_agent"


async def test_get_unregistered_raises(tmp_path: Path):
    reg = AgentRegistry()
    with pytest.raises(AgentNotRegisteredError):
        reg.get("nobody")


def test_get_is_sync():
    """get() must be synchronous — called on the hot path."""
    import inspect
    reg = AgentRegistry()
    assert not inspect.iscoroutinefunction(reg.get)


# ── reload ────────────────────────────────────────────────────────────────

async def test_reload_updates_agent(tmp_path: Path):
    reg = AgentRegistry()
    p   = _minimal(tmp_path)
    await reg.load(p)

    # Write new content
    p.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [search_docs, fetch_doc]\n"
        "allowed_tags: [read, internal]\n"
    )
    cfg = await reg.reload(p)
    assert "fetch_doc" in cfg.allowed_tool_names


async def test_reload_nonexistent_raises(tmp_path: Path):
    """Reloading an agent that was never loaded raises AgentNotRegisteredError."""
    reg = AgentRegistry()
    p   = _minimal(tmp_path)
    with pytest.raises(AgentNotRegisteredError):
        await reg.reload(p)


# ── deregister ────────────────────────────────────────────────────────────

async def test_deregister_removes_agent(tmp_path: Path):
    reg = AgentRegistry()
    cfg = await reg.load(_minimal(tmp_path))
    removed = await reg.deregister(cfg)
    assert removed is True
    with pytest.raises(AgentNotRegisteredError):
        reg.get("test_agent")


async def test_deregister_not_registered_returns_false(tmp_path: Path):
    """deregister returns False when item not registered — does not raise."""
    reg = AgentRegistry()
    # Build a minimal AgentConfig to pass as the item
    cfg = await reg.load(_minimal(tmp_path))
    await reg.deregister(cfg)           # remove it
    removed = await reg.deregister(cfg) # try again — already gone
    assert removed is False


# ── list ──────────────────────────────────────────────────────────────────

async def test_list_returns_all_agents(tmp_path: Path):
    reg = AgentRegistry()
    await reg.load(_minimal(tmp_path, "agent_a", "a.yaml"))
    await reg.load(_minimal(tmp_path, "agent_b", "b.yaml"))
    agents = await reg.list()
    ids = {a.id for a in agents}
    assert {"agent_a", "agent_b"} == ids


async def test_list_empty_registry(tmp_path: Path):
    reg = AgentRegistry()
    assert await reg.list() == []


# ── concurrent safety ─────────────────────────────────────────────────────

async def test_concurrent_load_different_agents(tmp_path: Path):
    """Loading 10 distinct agents concurrently must not raise or corrupt."""
    reg   = AgentRegistry()
    paths = [_minimal(tmp_path, f"agent_{i}", f"agent_{i}.yaml") for i in range(10)]

    results = await asyncio.gather(
        *[reg.load(p) for p in paths],
        return_exceptions=True,
    )
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors

    agents = await reg.list()
    assert len(agents) == 10


async def test_concurrent_get_is_safe(tmp_path: Path):
    """Concurrent sync get() calls on a populated registry must never raise."""
    reg = AgentRegistry()
    await reg.load(_minimal(tmp_path))

    async def _get():
        return reg.get("test_agent")

    results = await asyncio.gather(*[_get() for _ in range(50)], return_exceptions=True)
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors
