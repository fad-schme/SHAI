"""Tests for agents/registry.py."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.agents.registry import AgentRegistry
from harness.core.errors import AgentConflictError, AgentNotRegisteredError, ConfigError


@pytest.fixture
def registry() -> AgentRegistry:
    return AgentRegistry()


async def test_load_and_get(registry, orchestrator_yaml):
    cfg = await registry.load(orchestrator_yaml)
    assert cfg.id == "orchestrator_agent"
    assert registry.get("orchestrator_agent").id == "orchestrator_agent"


async def test_load_idempotent_on_identical(registry, orchestrator_yaml):
    cfg1 = await registry.load(orchestrator_yaml)
    cfg2 = await registry.load(orchestrator_yaml)
    assert cfg1 == cfg2


async def test_load_conflict_raises(registry, orchestrator_yaml, tmp_path):
    await registry.load(orchestrator_yaml)
    alt = tmp_path / "alt.yaml"
    alt.write_text(
        "id: orchestrator_agent\n"
        "display_name: Different\n"
        "allowed_tool_names: [search_docs]\n"
        "allowed_tags: [read]\n"
    )
    with pytest.raises(AgentConflictError):
        await registry.load(alt)


async def test_reload_replaces(registry, orchestrator_yaml, tmp_path):
    await registry.load(orchestrator_yaml)
    updated = tmp_path / "upd.yaml"
    updated.write_text(
        "id: orchestrator_agent\n"
        "display_name: Updated\n"
        "allowed_tool_names: [search_docs]\n"
        "allowed_tags: [read]\n"
    )
    cfg = await registry.reload(updated)
    assert cfg.display_name == "Updated"
    assert registry.get("orchestrator_agent").display_name == "Updated"


async def test_reload_unknown_raises(registry, orchestrator_yaml):
    with pytest.raises(AgentNotRegisteredError):
        await registry.reload(orchestrator_yaml)


async def test_reload_invalid_keeps_old(registry, orchestrator_yaml, tmp_path):
    await registry.load(orchestrator_yaml)
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: orchestrator_agent\n")  # missing required fields
    with pytest.raises(ConfigError):
        await registry.reload(bad)
    # Old definition still intact
    assert registry.get("orchestrator_agent").display_name == "Orchestrator"


async def test_deregister(registry, orchestrator_yaml):
    cfg = await registry.load(orchestrator_yaml)
    removed = await registry.deregister(cfg)
    assert removed is True
    with pytest.raises(AgentNotRegisteredError):
        registry.get("orchestrator_agent")


async def test_deregister_unknown_returns_false(registry, orchestrator_yaml):
    """deregister returns False when item not registered — does not raise."""
    cfg    = await registry.load(orchestrator_yaml)
    await registry.deregister(cfg)          # remove it
    result = await registry.deregister(cfg) # try again — already gone
    assert result is False


async def test_list_all(registry, orchestrator_yaml, research_yaml):
    await registry.load(orchestrator_yaml)
    await registry.load(research_yaml)
    agents = await registry.list()
    ids = {a.id for a in agents}
    assert ids == {"orchestrator_agent", "research_agent"}


async def test_load_invalid_file_raises(registry, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: orchestrator_agent\n")  # missing required fields
    with pytest.raises(ConfigError):
        await registry.load(bad)


async def test_get_unknown_raises(registry):
    with pytest.raises(AgentNotRegisteredError):
        registry.get("nobody")


async def test_concurrent_get_safe(registry, orchestrator_yaml):
    await registry.load(orchestrator_yaml)

    async def _get():
        return registry.get("orchestrator_agent")

    results = await asyncio.gather(*[_get() for _ in range(50)])
    assert all(r.id == "orchestrator_agent" for r in results)
