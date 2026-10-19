"""`path_args` on tools, and the rule that an `fs`-tagged tool must declare them.

The gate can only check a path argument it knows about. A tool tagged `fs` that
left `path_args` out would skip the check silently, so every route a tool takes
into the registry — direct registration, the decorator, and a source that merges
its own tags onto a tool — refuses it.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from harness.core.errors import ConfigError
from harness.core.harness import SHAI
from harness.core.types import Transport
from harness.integrations.base import extract_shai_tools, shai_tool
from harness.tools.registry import ToolRegistry
from harness.tools.tool import Tool


def test_declared_path_args_round_trip():
    t = Tool(name="copy_file", tags=["fs"], path_args={"src": "read", "dst": "write"})
    assert t.path_args == {"src": "read", "dst": "write"}
    assert Tool.model_validate(t.model_dump()) == t


def test_path_args_defaults_to_empty():
    assert Tool(name="search_docs", tags=["read"]).path_args == {}


@pytest.mark.parametrize("access", ["delete", "rw", "", "READ"])
def test_invalid_access_value_rejected(access):
    with pytest.raises(ValidationError):
        Tool(name="t", tags=["fs"], path_args={"path": access})


def test_decorator_declares_path_args_on_the_descriptor():
    @shai_tool(tags=["fs"], path_args={"src": "read", "dst": "write"})
    def copy_file(src: str, dst: str) -> str:
        return ""

    (descriptor,) = extract_shai_tools([copy_file])
    assert descriptor.path_args == {"src": "read", "dst": "write"}


def test_decorator_rejects_invalid_access_value():
    @shai_tool(tags=["fs"], path_args={"path": "delete"})  # type: ignore[arg-type]
    def f(path: str) -> str:
        return ""

    with pytest.raises(ValidationError):
        extract_shai_tools([f])


def test_registry_refuses_fs_tool_without_path_args():
    with pytest.raises(ConfigError, match="path_args"):
        ToolRegistry().register(Tool(name="read_file", tags=["fs", "read"]))


def test_registry_accepts_fs_tool_with_path_args():
    reg = ToolRegistry()
    assert reg.register(Tool(name="read_file", tags=["fs"], path_args={"path": "read"}))


def test_registry_accepts_tool_without_fs_tag_and_without_path_args():
    assert ToolRegistry().register(Tool(name="search_docs", tags=["read"]))


def test_registry_refuses_fs_tool_declared_through_the_decorator():
    @shai_tool(tags=["fs"])
    def read_file(path: str) -> str:
        return ""

    with pytest.raises(ConfigError, match="read_file"):
        ToolRegistry().register_many(extract_shai_tools([read_file]))


def test_changing_path_args_is_a_different_definition():
    reg = ToolRegistry()
    reg.register(Tool(name="read_file", tags=["fs"], path_args={"path": "read"}))
    with pytest.raises(ConfigError, match="path_args"):
        reg.register(Tool(name="read_file", tags=["fs"], path_args={"path": "write"}))


def test_identical_reregistration_is_idempotent():
    reg = ToolRegistry()
    t = Tool(name="read_file", tags=["fs"], path_args={"path": "read"})
    assert reg.register(t) is True
    assert reg.register(t) is False


async def _harness(tmp_path: Path, *, source_tags: list[str]) -> tuple[SHAI, Path]:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
        "sources:\n  - name: files\n    transport: local\n"
        f"    tags: {source_tags}\n    tool_names: [read_file]\n"
    )
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        "id: file_agent\n"
        "allowed_tool_names:\n  - read_file\n"
        "allowed_tags:\n  - read\n  - fs\n"
        "sources:\n  - files\n"
    )
    return await SHAI.from_yaml(cfg), agent


async def test_source_that_merges_the_fs_tag_cannot_smuggle_an_undeclared_tool(tmp_path: Path):
    h, agent = await _harness(tmp_path, source_tags=["fs"])
    await h.register_tools([Tool(name="read_file", tags=["read"], transport=Transport.LOCAL)])
    with pytest.raises(ConfigError, match="path_args"):
        await h.load_agent(agent)


async def test_source_that_merges_the_fs_tag_loads_a_declared_tool(tmp_path: Path):
    h, agent = await _harness(tmp_path, source_tags=["fs"])
    await h.register_tools([
        Tool(name="read_file", tags=["read"], transport=Transport.LOCAL,
             path_args={"path": "read"}),
    ])
    await h.load_agent(agent)
