"""Only configured scanners run — plus the hardcoded heuristic backstop.

Config is the only source of what runs at a boundary. The rule lives in
run_scan, so it holds for every boundary rather than being re-checked per
entry point: an enabled boundary with nothing configured to inspect the
content blocks, because "we looked and found nothing" and "nothing looked"
must not return the same verdict.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.audit.emitter import AuditEmitter
from harness.core.context import AgentContext
from harness.core.harness import SHAI
from harness.core.types import BoundaryName, Decision
from tests.conftest import RecordingSink

CTX = AgentContext(agent_id="a1")

_PII_ONLY = (
    "version: 1\n"
    "scan_input:\n  enabled: true\n  scanners:\n    - name: regex_pii\n"
    "scan_output:\n  enabled: false\n"
    "policy:\n  rules: []\n"
    "audit_sinks:\n  - name: stdout\n"
)
_INJECTION_ONLY = (
    "version: 1\n"
    "scan_input:\n  enabled: true\n  scanners:\n    - name: injection_scan\n"
    "scan_output:\n  enabled: false\n"
    "policy:\n  rules: []\n"
    "audit_sinks:\n  - name: stdout\n"
)


async def _harness(tmp_path: Path, body: str) -> tuple[SHAI, RecordingSink]:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(body)
    h = await SHAI.from_yaml(cfg)
    sink = RecordingSink()
    h._emitter = AuditEmitter([sink])
    return h, sink


# ── Boundaries emit under their own name ────────────────────────────────

async def test_scan_input_still_emits_input_scan(tmp_path):
    h, sink = await _harness(tmp_path, _PII_ONLY)
    await h.scan_input("hello", CTX)
    assert sink.events[0].boundary == BoundaryName.INPUT_SCAN


# ── The rule lives in run_scan, so it covers every boundary ──────────────

async def test_enabled_boundary_with_no_scanners_blocks(tmp_path):
    """Not limited to the narrow helpers — any enabled boundary with an empty
    scanner list fails closed at the canonical pipeline."""
    from harness.boundaries._scan import ScanState, run_scan
    from tests.conftest import boundary_config

    sink = RecordingSink()
    verdict = await run_scan(
        "anything at all", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[],
        config=boundary_config(),
        emitter=AuditEmitter([sink]),
        tenant_id="t",
        state=ScanState(str(tmp_path / "p.db")),
    )

    assert verdict.blocked
    assert len(sink.events) == 1
    assert sink.events[0].decision == Decision.BLOCKED


async def test_gate_arg_scanners_use_the_scanners_key(tmp_path):
    """check_tool_call declares its scanners under `scanners:`, like every
    scan_* boundary. The old `arg_scanners:` spelling is gone and, because the
    config models forbid unknown keys, a stale config fails loudly."""
    from harness.core.errors import ConfigError

    body = (
        "version: 1\n"
        "scan_input:\n  enabled: true\n  scanners:\n    - name: regex_pii\n"
        "scan_output:\n  enabled: false\n"
        "check_tool_call:\n  scanners:\n    - name: regex_pii\n"
        "policy:\n  rules: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    h, _ = await _harness(tmp_path, body)
    # ConfiguredScanner pairs, not bare instances: layer 7 resolves each
    # scanner's declared action the same way every other boundary does.
    assert [getattr(c.scanner, "name", "") for c in h._arg_scanners] == [
        "regex_pii", "heuristic_scan",
    ]

    stale = body.replace("check_tool_call:\n  scanners:", "check_tool_call:\n  arg_scanners:")
    cfg = tmp_path / "stale.yaml"
    cfg.write_text(stale)
    with pytest.raises(ConfigError):
        await SHAI.from_yaml(cfg)


async def test_disabled_boundary_still_allows(tmp_path):
    """Turning a boundary off is an explicit choice and stays an ALLOW —
    distinct from an enabled boundary with nothing to run."""
    from harness.boundaries._scan import ScanState, run_scan
    from tests.conftest import boundary_config

    sink = RecordingSink()
    verdict = await run_scan(
        "anything at all", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[],
        config=boundary_config(enabled=False),
        emitter=AuditEmitter([sink]),
        tenant_id="t",
        state=ScanState(str(tmp_path / "p.db")),
    )

    assert not verdict.blocked
    assert sink.events[0].disabled is True
    assert sink.events[0].decision == Decision.ALLOW
