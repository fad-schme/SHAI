"""Gate layer 2 resolves each declared path argument and checks it against the
calling agent's `allowed_paths`.

Real temporary directories throughout: the rule's value is what happens after
`..`, symlinks and case are resolved, which a string-only test cannot reach.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from harness.agents.agent_config import AgentConfig
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.core.context import AgentContext
from harness.core.path_scope import canonicalize_path
from harness.core.types import Decision
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool
from tests.conftest import RecordingSink

READ_FILE = Tool(name="read_file", tags=["fs"], path_args={"path": "read"})
SAVE_FILE = Tool(name="save_file", tags=["fs"], path_args={"path": "write"})
COPY_FILE = Tool(name="copy_file", tags=["fs"], path_args={"src": "read", "dst": "write"})
TOOLS = {t.name: t for t in (READ_FILE, SAVE_FILE, COPY_FILE)}


def _agent(allowed_paths: dict[str, list[str]] | None = None, sub: dict | None = None) -> AgentConfig:
    data: dict[str, Any] = {
        "id": "test_agent",
        "allowed_tool_names": ["read_file", "save_file", "copy_file"],
        "allowed_tags": ["fs"],
    }
    if allowed_paths is not None:
        data["allowed_paths"] = allowed_paths
    if sub is not None:
        data["sub_agents"] = [sub]
    return AgentConfig.model_validate(data)


async def _gate(tool: str, args: dict[str, Any], agent: AgentConfig, *, sub: bool = False):
    sink = RecordingSink()
    ctx = AgentContext(
        agent_id="test_agent",
        sub_agent_id="sub" if sub else None,
        allowed_tags=["fs"] if sub else None,
    )
    decision = await check_tool_call.run(
        tool, args, ctx,
        agent_config=agent, tools=TOOLS, policy=RuleBasedPolicy(),
        arg_scanners=[], emitter=AuditEmitter([sink]), tenant_id="test",
    )
    return decision, sink


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for d in ("data", "data-evil", "out", "elsewhere"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "f.txt").write_text("x")
    return tmp_path


def _link(link: Path, target: Path) -> None:
    """Directory link to `target`; a junction where Windows will not make a
    symlink without privilege. Skips where neither can be made."""
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


def _grant(tree: Path, *, read=(), write=()) -> AgentConfig:
    return _agent({"read": [str(tree / r) for r in read], "write": [str(tree / w) for w in write]})


# ── containment ────────────────────────────────────────────────────────────

async def test_read_inside_read_root_allowed(tree):
    d, _ = await _gate("read_file", {"path": str(tree / "data" / "f.txt")}, _grant(tree, read=["data"]))
    assert d.allowed


async def test_write_root_grants_read_and_write(tree):
    agent = _grant(tree, write=["out"])
    assert (await _gate("read_file", {"path": str(tree / "out" / "f.txt")}, agent))[0].allowed
    assert (await _gate("save_file", {"path": str(tree / "out" / "new.txt")}, agent))[0].allowed


async def test_read_root_does_not_grant_write(tree):
    d, _ = await _gate("save_file", {"path": str(tree / "data" / "f.txt")}, _grant(tree, read=["data"]))
    assert not d.allowed


async def test_outside_every_root_denied(tree):
    d, _ = await _gate("read_file", {"path": str(tree / "elsewhere" / "f.txt")}, _grant(tree, read=["data"]))
    assert not d.allowed
    assert "path" in d.deny_reason


async def test_sibling_prefix_denied(tree):
    d, _ = await _gate("read_file", {"path": str(tree / "data-evil" / "f.txt")}, _grant(tree, read=["data"]))
    assert not d.allowed


async def test_root_itself_is_inside_the_grant(tree):
    d, _ = await _gate("read_file", {"path": str(tree / "data")}, _grant(tree, read=["data"]))
    assert d.allowed


async def test_a_file_entry_grants_just_that_file(tree):
    agent = _agent({"read": [str(tree / "data" / "f.txt")]})
    assert (await _gate("read_file", {"path": str(tree / "data" / "f.txt")}, agent))[0].allowed
    assert not (await _gate("read_file", {"path": str(tree / "data" / "g.txt")}, agent))[0].allowed


# ── canonicalization ───────────────────────────────────────────────────────

@pytest.mark.parametrize("spelling", [
    "{root}/data/../elsewhere/f.txt",
    "{root}/data/../../{parent}/elsewhere/f.txt",
    "{root}//elsewhere//f.txt",
    "{root}/elsewhere/./f.txt",
    "{root}/elsewhere/f.txt/",
])
async def test_spellings_that_resolve_outside_are_denied(tree, spelling):
    value = spelling.format(root=tree, parent=tree.name)
    d, _ = await _gate("read_file", {"path": value}, _grant(tree, read=["data"]))
    assert not d.allowed


async def test_dotdot_that_reenters_the_root_is_allowed(tree):
    value = f"{tree}/elsewhere/../data/f.txt"
    d, _ = await _gate("read_file", {"path": value}, _grant(tree, read=["data"]))
    assert d.allowed


async def test_mixed_separators_resolve_to_the_same_place(tree):
    value = str(tree / "data").replace(os.sep, "/") + "\\f.txt" if os.sep == "\\" else str(tree / "data" / "f.txt")
    d, _ = await _gate("read_file", {"path": value}, _grant(tree, read=["data"]))
    assert d.allowed


@pytest.mark.parametrize("value", [
    "relative/path.txt", "../up.txt", "", "file:///etc/passwd", "https://x/y", 42, ["/a"], {"p": 1},
])
async def test_malformed_or_non_path_values_are_denied(tree, value):
    d, _ = await _gate("read_file", {"path": value}, _grant(tree, read=["data"]))
    assert not d.allowed


async def test_nul_byte_denied_without_raising(tree):
    nul = chr(0)
    d, _ = await _gate("read_file", {"path": f"{tree}/data/f.txt{nul}.png"}, _grant(tree, read=["data"]))
    assert not d.allowed


def test_canonicalize_never_raises_on_unresolvable_input():
    for value in (None, 3.5, b"/a", "x" * 70_000, chr(0)):
        assert canonicalize_path(value) is None


async def test_absent_optional_path_argument_is_not_checked(tree):
    d, _ = await _gate("read_file", {}, _grant(tree, read=["data"]))
    assert d.allowed


async def test_symlink_inside_grant_pointing_outside_is_denied(tree):
    link = tree / "data" / "escape"
    _link(link, tree / "elsewhere")
    d, _ = await _gate("read_file", {"path": str(link / "f.txt")}, _grant(tree, read=["data"]))
    assert not d.allowed


async def test_symlink_inside_grant_pointing_inside_is_allowed(tree):
    (tree / "data" / "sub").mkdir()
    (tree / "data" / "sub" / "f.txt").write_text("x")
    link = tree / "data" / "alias"
    _link(link, tree / "data" / "sub")
    d, _ = await _gate("read_file", {"path": str(link / "f.txt")}, _grant(tree, read=["data"]))
    assert d.allowed


async def test_symlinked_grant_root_matches_what_it_points_to(tree):
    link = tree / "root_link"
    _link(link, tree / "data")
    agent = _agent({"read": [str(link)]})
    assert (await _gate("read_file", {"path": str(tree / "data" / "f.txt")}, agent))[0].allowed


async def test_symlink_swapped_between_calls_changes_the_result(tree):
    (tree / "data" / "sub").mkdir()
    (tree / "data" / "sub" / "f.txt").write_text("x")
    link = tree / "data" / "swap"
    _link(link, tree / "data" / "sub")
    agent = _grant(tree, read=["data"])
    assert (await _gate("read_file", {"path": str(link / "f.txt")}, agent))[0].allowed
    os.rmdir(link) if os.name == "nt" else link.unlink()
    _link(link, tree / "elsewhere")
    assert not (await _gate("read_file", {"path": str(link / "f.txt")}, agent))[0].allowed


async def test_case_differences_cannot_reach_a_sibling(tree):
    agent = _grant(tree, read=["data"])
    upper = str(tree / "DATA2" / "f.txt")
    assert not (await _gate("read_file", {"path": upper}, agent))[0].allowed
    insensitive = (tree / "DATA").exists()
    d, _ = await _gate("read_file", {"path": str(tree / "DATA" / "f.txt")}, agent)
    assert d.allowed is insensitive


def _requires_case_insensitive(tree: Path) -> None:
    if not (tree / "DATA").exists():
        pytest.skip("filesystem is case-sensitive")


def _case_sensitive_dir(tmp_path: Path) -> Path:
    """An empty directory where `data` and `DATA` are different names. Windows
    makes one per directory; skips where the platform cannot."""
    root = tmp_path / "cs"
    root.mkdir()
    if os.name == "nt":
        made = subprocess.run(
            ["fsutil", "file", "setCaseSensitiveInfo", str(root), "enable"],
            capture_output=True, check=False,
        )
        if made.returncode != 0:
            pytest.skip("cannot mark a directory case-sensitive")
    (root / "data").mkdir()
    try:
        (root / "DATA").mkdir()
    except FileExistsError:
        pytest.skip("filesystem is case-insensitive")
    return root


async def test_case_alias_of_a_granted_directory_is_accepted(tree):
    _requires_case_insensitive(tree)
    agent = _grant(tree, read=["data"])
    assert (await _gate("read_file", {"path": str(tree / "DATA" / "f.txt")}, agent))[0].allowed
    assert (await _gate("read_file", {"path": str(tree / "Data" / "F.TXT")}, agent))[0].allowed


async def test_case_alias_of_a_granted_root_is_accepted_in_the_grant(tree):
    _requires_case_insensitive(tree)
    agent = _agent({"read": [str(tree / "DATA")]})
    assert (await _gate("read_file", {"path": str(tree / "data" / "f.txt")}, agent))[0].allowed


async def test_outside_sibling_stays_denied_under_a_case_alias(tree):
    _requires_case_insensitive(tree)
    (tree / "data2").mkdir()
    (tree / "data2" / "f.txt").write_text("x")
    agent = _grant(tree, read=["data"])
    assert not (await _gate("read_file", {"path": str(tree / "DATA2" / "f.txt")}, agent))[0].allowed


async def test_new_file_write_through_a_case_alias_obeys_the_grant(tree):
    _requires_case_insensitive(tree)
    agent = _grant(tree, write=["out"])
    assert (await _gate("save_file", {"path": str(tree / "OUT" / "New.txt")}, agent))[0].allowed
    assert not (await _gate("save_file", {"path": str(tree / "DATA" / "New.txt")}, agent))[0].allowed


async def test_distinct_case_directories_stay_distinct_on_a_case_sensitive_directory(tmp_path):
    root = _case_sensitive_dir(tmp_path)
    (root / "data" / "f.txt").write_text("x")
    (root / "DATA" / "f.txt").write_text("x")
    agent = _agent({"read": [str(root / "data")]})
    assert (await _gate("read_file", {"path": str(root / "data" / "f.txt")}, agent))[0].allowed
    assert not (await _gate("read_file", {"path": str(root / "DATA" / "f.txt")}, agent))[0].allowed
    assert not (await _gate("save_file", {"path": str(root / "DATA" / "new.txt")}, agent))[0].allowed


# ── default deny, subagents, multi-argument tools ─────────────────────────

async def test_agent_without_allowed_paths_is_denied_every_path(tree):
    d, _ = await _gate("read_file", {"path": str(tree / "data" / "f.txt")}, _agent())
    assert not d.allowed


async def test_subagent_is_checked_against_its_own_grant(tree):
    agent = _agent(
        {"read": [str(tree / "data"), str(tree / "out")]},
        sub={"id": "sub", "allowed_tool_names": ["read_file"], "allowed_tags": ["fs"],
             "allowed_paths": {"read": [str(tree / "data")]}},
    )
    assert (await _gate("read_file", {"path": str(tree / "data" / "f.txt")}, agent, sub=True))[0].allowed
    assert (await _gate("read_file", {"path": str(tree / "out" / "f.txt")}, agent))[0].allowed
    assert not (await _gate("read_file", {"path": str(tree / "out" / "f.txt")}, agent, sub=True))[0].allowed


async def test_two_argument_tool_denies_when_either_argument_fails(tree):
    agent = _grant(tree, read=["data"], write=["out"])
    ok = {"src": str(tree / "data" / "f.txt"), "dst": str(tree / "out" / "f.txt")}
    assert (await _gate("copy_file", ok, agent))[0].allowed
    bad_dst = {**ok, "dst": str(tree / "data" / "f.txt")}
    bad_src = {**ok, "src": str(tree / "elsewhere" / "f.txt")}
    assert not (await _gate("copy_file", bad_dst, agent))[0].allowed
    assert not (await _gate("copy_file", bad_src, agent))[0].allowed


# ── audit ──────────────────────────────────────────────────────────────────

async def test_one_event_per_call_and_no_path_text_in_any_field(tree):
    secret_leaf = "very_distinctive_leaf_name.txt"
    value = str(tree / "elsewhere" / secret_leaf)
    d, sink = await _gate("read_file", {"path": value}, _grant(tree, read=["data"]))
    assert not d.allowed
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.decision == Decision.DENY
    dumped = event.model_dump_json()
    assert secret_leaf not in dumped
    assert str(tree) not in dumped
    assert secret_leaf not in d.deny_reason
    assert "'path'" in d.deny_reason


async def test_an_allowed_call_still_emits_exactly_one_event(tree):
    d, sink = await _gate("read_file", {"path": str(tree / "data" / "f.txt")}, _grant(tree, read=["data"]))
    assert d.allowed
    assert len(sink.events) == 1
