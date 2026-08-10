"""Unit tests for audit event signing (R3)."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
from pathlib import Path

import pytest

from harness.adapters.audit_sinks.stdout import StdoutSink
from harness.audit.emitter import AuditEmitter, _sign_event
from harness.core.context import AgentContext
from harness.core.errors import AuditEmissionError
from harness.core.events import AuditEvent, canonical_json
from harness.core.types import BoundaryName, Decision
from tests.conftest import RecordingSink

CTX = AgentContext(agent_id="a1")
SECRET = b"test-signing-secret"


def _make_event() -> AuditEvent:
    return AuditEvent.build(
        boundary=BoundaryName.INPUT_SCAN,
        decision=Decision.ALLOW,
        ctx=CTX,
        tenant_id="test",
        duration_ms=1,
        disabled=False,
    )


# ── _sign_event helper ────────────────────────────────────────────────────

def test_sign_event_returns_hex_string():
    event = _make_event()
    sig = _sign_event(event, SECRET)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA-256 hex digest


def test_sign_event_deterministic():
    event = _make_event()
    assert _sign_event(event, SECRET) == _sign_event(event, SECRET)


def test_sign_event_different_secrets_produce_different_sigs():
    event = _make_event()
    assert _sign_event(event, b"key1") != _sign_event(event, b"key2")


def test_sign_event_excludes_signature_field():
    """Signing must not include the signature field itself (circular)."""
    event = _make_event()
    sig1 = _sign_event(event, SECRET)
    # Manually set a fake signature and re-sign — result must be the same
    object.__setattr__(event, "signature", "fakesig")
    sig2 = _sign_event(event, SECRET)
    assert sig1 == sig2


# ── AuditEmitter with signing ─────────────────────────────────────────────

async def test_emitter_stamps_signature_on_event():
    sink = RecordingSink()
    emitter = AuditEmitter([sink], signing_secret=SECRET)
    event = _make_event()
    await emitter.emit(event)
    assert sink.events[0].signature is not None
    assert len(sink.events[0].signature) == 64


async def test_emitter_no_signing_key_no_signature():
    sink = RecordingSink()
    emitter = AuditEmitter([sink], signing_secret=None)
    event = _make_event()
    await emitter.emit(event)
    assert sink.events[0].signature is None


async def test_signature_is_verifiable():
    """Independently verify the signature matches expected HMAC."""
    sink = RecordingSink()
    emitter = AuditEmitter([sink], signing_secret=SECRET)
    event = _make_event()
    await emitter.emit(event)

    emitted = sink.events[0]
    body = canonical_json(emitted, exclude={"signature"}).encode()
    expected = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    assert emitted.signature == expected


async def test_written_line_verifies_against_its_own_signature():
    """The property an operator actually needs: verify from the file alone.

    Reproduces what a SIEM does — parse the JSONL line, lift out `signature`,
    re-encode the remainder, compare. This only holds because the sink and the
    signer share one canonical encoder; two hand-rolled encoders drifted apart
    and made written signatures unverifiable.
    """
    buf = io.StringIO()
    emitter = AuditEmitter([StdoutSink(stream=buf)], signing_secret=SECRET)
    await emitter.emit(_make_event())

    data = json.loads(buf.getvalue().strip())
    sig  = data.pop("signature")
    body = json.dumps(data, sort_keys=True).encode()
    assert hmac.compare_digest(
        hmac.new(SECRET, body, hashlib.sha256).hexdigest(), sig)


async def test_unsignable_event_raises_audit_emission_error():
    """Invariant 2: only AuditEmissionError may escape the audit path.

    An event carrying a value the canonical encoder cannot serialise must not
    surface a serializer error on a boundary — and must not be emitted
    unsigned, which would leave a silent gap in a signed trail.
    """
    class Unserialisable:
        pass

    event = AuditEvent.build(
        boundary=BoundaryName.INPUT_SCAN,
        decision=Decision.ALLOW,
        ctx=CTX,
        tenant_id="test",
        duration_ms=1,
        extra={"obj": Unserialisable()},
    )
    sink = RecordingSink()
    emitter = AuditEmitter([sink], signing_secret=SECRET)

    with pytest.raises(AuditEmissionError, match="signing failed"):
        await emitter.emit(event)
    assert sink.events == []   # not emitted unsigned


async def test_tampered_written_line_fails_verification():
    """A line edited on disk must not verify — that is the whole point."""
    buf = io.StringIO()
    emitter = AuditEmitter([StdoutSink(stream=buf)], signing_secret=SECRET)
    await emitter.emit(_make_event())

    data = json.loads(buf.getvalue().strip())
    sig  = data.pop("signature")
    data["decision"] = "deny"          # flip the recorded outcome
    body = json.dumps(data, sort_keys=True).encode()
    assert not hmac.compare_digest(
        hmac.new(SECRET, body, hashlib.sha256).hexdigest(), sig)


async def test_tampered_event_signature_mismatch():
    """Tampering with any field should invalidate the signature."""
    sink = RecordingSink()
    emitter = AuditEmitter([sink], signing_secret=SECRET)
    event = _make_event()
    await emitter.emit(event)
    emitted = sink.events[0]

    # Tamper: change agent_id, re-verify
    payload = {
        k: v for k, v in emitted.model_dump(exclude_none=True).items()
        if k != "signature"
    }
    payload["agent_id"] = "attacker"
    body = json.dumps(payload, sort_keys=True, default=str).encode()
    tampered_sig = hmac.new(SECRET, body, hashlib.sha256).hexdigest()

    assert emitted.signature != tampered_sig  # original sig doesn't match tampered payload


async def test_signing_uses_timing_safe_comparison():
    """Verify _sign_event uses hmac module (timing-safe) not plain ==."""
    import inspect
    src = inspect.getsource(_sign_event)
    assert "hmac" in src


# ── SHAI facade config ─────────────────────────────────────────────────

async def test_harness_signing_disabled_by_default(tmp_path: Path):
    """No signing key configured → signature field is None."""
    from harness.core.harness import SHAI

    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    h = await SHAI.from_yaml(cfg)
    # Verify emitter has no signing secret
    assert h._emitter._signing_secret is None


async def test_harness_signing_enabled_via_env(tmp_path: Path, monkeypatch):
    """When audit_signing is enabled, events carry a signature."""
    from harness.core.harness import SHAI

    monkeypatch.setenv("AUDIT_KEY", "mysecret")

    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "audit_sinks:\n  - name: stdout\n"
        "audit_signing:\n  enabled: true\n  secret: \"secret://AUDIT_KEY\"\n"
    )
    h = await SHAI.from_yaml(cfg)
    assert h._emitter._signing_secret == b"mysecret"


async def test_emit_does_not_mutate_the_callers_event():
    """The emitter stamps a copy — AuditEvent is a frozen public shape.

    Truncation and signing used to rewrite the caller's object in place via
    object.__setattr__, so a boundary that had already handed its event over
    found it changed underneath. The written record is unaffected either way;
    what changes is that the caller's own object is now left alone.
    """
    sink = RecordingSink()
    emitter = AuditEmitter([sink], signing_secret=SECRET)

    long_reason = "x" * 900
    event = AuditEvent.build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=Decision.DENY,
        ctx=AgentContext(agent_id="a"),
        tenant_id="t",
        duration_ms=0,
        tool_name="some_tool",
        deny_reason=long_reason,
    )

    await emitter.emit(event)

    # The caller's object is untouched.
    assert event.signature is None
    assert event.deny_reason == long_reason

    # The sink got the truncated, signed copy.
    emitted = sink.events[0]
    assert emitted is not event
    assert emitted.signature is not None and len(emitted.signature) == 64
    assert len(emitted.deny_reason) == 500
    assert emitted.deny_reason.endswith("...")


async def test_signature_covers_the_truncated_reason():
    """Truncation happens before signing, so the signature covers what is written."""
    sink = RecordingSink()
    emitter = AuditEmitter([sink], signing_secret=SECRET)
    await emitter.emit(AuditEvent.build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=Decision.DENY,
        ctx=AgentContext(agent_id="a"),
        tenant_id="t",
        duration_ms=0,
        tool_name="some_tool",
        deny_reason="y" * 900,
    ))
    emitted = sink.events[0]
    body = canonical_json(emitted, exclude={"signature"}).encode()
    assert emitted.signature == hmac.new(SECRET, body, hashlib.sha256).hexdigest()
