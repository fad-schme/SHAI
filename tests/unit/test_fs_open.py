"""`SHAI.fs.open` — a governed tool opens a file the gate approved, with the path
re-verified at the moment of use.

Real SHAI facade and real temporary directories: what matters is what happens
between the gate's check and the open.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.errors import DispatchRefused
from harness.core.governed_fs import LinkRefused, open_resolved
from harness.core.harness import SHAI
from harness.core.types import BoundaryName, Decision
from harness.core.verdicts import GateDecision
from tests.conftest import RecordingSink

ALLOWED = GateDecision(allowed=True)


def _link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        if os.name == "nt":
            made = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True, check=False,
            )
            if made.returncode == 0:
                return
    pytest.skip("platform cannot create symlinks or junctions")


@pytest.fixture
async def world(tmp_path: Path):
    for d in ("data", "out", "elsewhere"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "f.txt").write_text("hello")
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\nscan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    agent = tmp_path / "agents" / "a.yaml"
    agent.parent.mkdir()
    agent.write_text(
        "id: file_agent\nallowed_tool_names: [read_file]\nallowed_tags: [fs]\n"
        f"allowed_paths:\n  read: ['{(tmp_path / 'data').as_posix()}']\n"
        f"  write: ['{(tmp_path / 'out').as_posix()}']\n"
    )
    h = await SHAI.from_yaml(cfg)
    sink = RecordingSink()
    h._emitter._sinks.append(sink)
    await h.load_agent(agent)
    return h, sink, tmp_path


def _ctx() -> AgentContext:
    return AgentContext(agent_id="file_agent")


async def test_open_inside_the_read_grant_returns_the_file(world):
    h, _, root = world
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with h.fs.open(str(root / "data" / "f.txt")) as f:
            assert f.read() == "hello"


async def test_write_mode_inside_the_write_grant_opens_and_writes(world):
    h, _, root = world
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with h.fs.open(str(root / "out" / "new.txt"), "w", encoding="utf-8") as f:
            f.write("written")
    assert (root / "out" / "new.txt").read_text() == "written"


@pytest.mark.parametrize("mode", ["w", "a", "x", "r+", "wb"])
async def test_write_modes_are_refused_inside_a_read_only_grant(world, mode):
    h, _, root = world
    target = root / "data" / ("new.txt" if "x" in mode else "f.txt")
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with pytest.raises(DispatchRefused):
            h.fs.open(str(target), mode)


async def test_read_mode_is_allowed_inside_a_write_grant(world):
    h, _, root = world
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with h.fs.open(str(root / "out" / "f.txt"), "rb") as f:
            assert f.read() == b"hello"


async def test_outside_every_grant_is_refused(world):
    h, _, root = world
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with pytest.raises(DispatchRefused):
            h.fs.open(str(root / "elsewhere" / "f.txt"))


async def test_dotdot_escape_is_refused(world):
    h, _, root = world
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with pytest.raises(DispatchRefused):
            h.fs.open(f"{root}/data/../elsewhere/f.txt")


async def test_protected_agent_file_is_refused(world):
    h, _, root = world
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with pytest.raises(DispatchRefused, match="protected"):
            h.fs.open(str(root / "agents" / "a.yaml"))


async def test_called_outside_dispatch_scope_is_refused(world):
    h, _, root = world
    with pytest.raises(DispatchRefused, match="dispatch"):
        h.fs.open(str(root / "data" / "f.txt"))


async def test_an_unregistered_agent_has_no_grant(world):
    h, _, root = world
    async with h.dispatch_scope(AgentContext(agent_id="nobody"), ALLOWED):
        with pytest.raises(DispatchRefused):
            h.fs.open(str(root / "data" / "f.txt"))


async def test_a_subagent_is_held_to_its_own_grant(world):
    h, _, root = world
    parent = root / "agents" / "p.yaml"
    parent.write_text(
        "id: parent_agent\nallowed_tool_names: [read_file]\nallowed_tags: [fs]\n"
        f"allowed_paths:\n  read: ['{(root / 'data').as_posix()}', '{(root / 'out').as_posix()}']\n"
        "sub_agents:\n  - id: narrow\n    allowed_tool_names: [read_file]\n    allowed_tags: [fs]\n"
        f"    allowed_paths:\n      read: ['{(root / 'data').as_posix()}']\n"
    )
    await h.load_agent(parent)
    ctx = AgentContext(agent_id="parent_agent", sub_agent_id="narrow", allowed_tags=["fs"])
    async with h.dispatch_scope(ctx, ALLOWED):
        with h.fs.open(str(root / "data" / "f.txt")) as f:
            assert f.read() == "hello"
        with pytest.raises(DispatchRefused):
            h.fs.open(str(root / "out" / "f.txt"))


async def test_a_link_swapped_after_the_gate_check_is_refused_at_open(world):
    h, _, root = world
    (root / "data" / "sub").mkdir()
    (root / "data" / "sub" / "f.txt").write_text("inside")
    link = root / "data" / "swap"
    _link(link, root / "data" / "sub")
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with h.fs.open(str(link / "f.txt")) as f:
            assert f.read() == "inside"
        os.rmdir(link) if os.name == "nt" else link.unlink()
        _link(link, root / "elsewhere")
        with pytest.raises(DispatchRefused):
            h.fs.open(str(link / "f.txt"))


def test_a_final_component_link_is_refused_not_followed(tmp_path: Path):
    (tmp_path / "real").mkdir()
    link = tmp_path / "link"
    _link(link, tmp_path / "real")
    with pytest.raises(LinkRefused):
        open_resolved(str(link), "r")


def test_an_ordinary_file_error_is_not_a_link_refusal(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        open_resolved(str(tmp_path / "missing.txt"), "r")


async def test_each_open_emits_exactly_one_check_event_without_path_text(world):
    h, sink, root = world
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with h.fs.open(str(root / "data" / "f.txt")):
            pass
        with pytest.raises(DispatchRefused):
            h.fs.open(str(root / "elsewhere" / "distinctive_name.txt"))
    checks = [e for e in sink.events if e.boundary == BoundaryName.TOOL_DISPATCH_CHECK]
    assert [e.decision for e in checks] == [Decision.ALLOW, Decision.DENY]
    dumped = " ".join(e.model_dump_json() for e in checks)
    assert "distinctive_name" not in dumped
    assert str(root) not in dumped
    assert all(e.extra["check"] == "fs_open" for e in checks)
    assert "fs_rule" not in checks[0].extra
    assert checks[1].extra["fs_rule"] == "outside_read"


async def test_a_missing_approved_file_still_emits_its_check_event(world):
    h, sink, root = world
    async with h.dispatch_scope(_ctx(), ALLOWED):
        with pytest.raises(FileNotFoundError):
            h.fs.open(str(root / "data" / "missing.txt"))
    checks = [e for e in sink.events if e.boundary == BoundaryName.TOOL_DISPATCH_CHECK]
    assert len(checks) == 1
    assert checks[0].decision == Decision.ALLOW
