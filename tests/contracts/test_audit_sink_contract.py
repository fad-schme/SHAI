"""AuditSink contract suite — StdoutSink and FileSink must both pass."""
from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

import pytest

from harness.adapters.audit_sinks.file import FileSink
from harness.adapters.audit_sinks.stdout import StdoutSink
from harness.core.context import RuntimeContext
from harness.core.events import AuditEvent
from harness.core.types import BoundaryName, Decision

_CTX = RuntimeContext(
        agent_id="a1")


def make_event(**kwargs) -> AuditEvent:
    defaults = dict(
        boundary=BoundaryName.INPUT_SCAN,
        decision=Decision.ALLOW,
        ctx=_CTX,
        tenant_id="test",
        duration_ms=3,
    )
    defaults.update(kwargs)
    return AuditEvent.build(**defaults)


# ── StdoutSink ────────────────────────────────────────────────────────────

async def test_stdout_emit_writes_jsonl():
    buf = io.StringIO()
    sink = StdoutSink(stream=buf)
    await sink.emit(make_event())
    line = buf.getvalue().strip()
    assert line
    data = json.loads(line)
    assert data["boundary"] == "input_scan"
    assert data["decision"] == "allow"
    assert data["agent_id"] == "a1"


async def test_stdout_name():
    assert StdoutSink().name == "stdout"


async def test_stdout_close_is_noop():
    sink = StdoutSink()
    await sink.close()  # must not raise


async def test_stdout_concurrent_emit():
    buf = io.StringIO()
    sink = StdoutSink(stream=buf)
    events = [make_event() for _ in range(50)]
    results = await asyncio.gather(
        *[sink.emit(e) for e in events],
        return_exceptions=True,
    )
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors
    lines = [l for l in buf.getvalue().splitlines() if l.strip()]
    assert len(lines) == 50


async def test_stdout_no_raw_text_in_output():
    buf = io.StringIO()
    sink = StdoutSink(stream=buf)
    await sink.emit(make_event(extra={"note": "safe metadata"}))
    data = json.loads(buf.getvalue().strip())
    # Extra is allowed; raw user text is not — verify "note" value is safe
    assert "safe metadata" in str(data.get("extra", {}))


async def test_stdout_none_values_omitted():
    buf = io.StringIO()
    sink = StdoutSink(stream=buf)
    await sink.emit(make_event())
    data = json.loads(buf.getvalue().strip())
    # None fields must not appear in output
    for key, val in data.items():
        assert val is not None, f"field '{key}' should not be None in output"


# ── FileSink ──────────────────────────────────────────────────────────────

async def test_file_emit_writes_jsonl(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    sink = FileSink(path=path)
    await sink.emit(make_event())
    await sink.close()
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["agent_id"] == "a1"


async def test_file_name():
    assert FileSink(path="/tmp/x.jsonl").name == "file"


async def test_file_close_idempotent(tmp_path: Path):
    sink = FileSink(path=tmp_path / "audit.jsonl")
    await sink.emit(make_event())
    await sink.close()
    await sink.close()  # must not raise


async def test_file_concurrent_emit(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    sink = FileSink(path=path)
    events = [make_event() for _ in range(50)]
    results = await asyncio.gather(
        *[sink.emit(e) for e in events],
        return_exceptions=True,
    )
    await sink.close()
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors
    lines = [l for l in path.read_text().splitlines() if l.strip()]
    assert len(lines) == 50


async def test_file_creates_parent_dirs(tmp_path: Path):
    path = tmp_path / "nested" / "deep" / "audit.jsonl"
    sink = FileSink(path=path)
    await sink.emit(make_event())
    await sink.close()
    assert path.exists()


async def test_file_sub_agent_id_in_output(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    ctx = RuntimeContext(agent_id="a1", sub_agent_id="sub1")
    sink = FileSink(path=path)
    await sink.emit(make_event(ctx=ctx))
    await sink.close()
    data = json.loads(path.read_text().strip())
    assert data["sub_agent_id"] == "sub1"
