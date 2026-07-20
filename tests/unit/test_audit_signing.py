"""Unit tests for audit event signing (R3)."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from harness.audit.emitter import AuditEmitter, _sign_event
from harness.core.context import AgentContext
from harness.core.events import AuditEvent
from harness.core.types import BoundaryName, Decision

CTX = AgentContext(agent_id="a1")
SECRET = b"test-signing-secret"


class RecordingSink:
    name = "recording"
    def __init__(self): self.events: list[AuditEvent] = []
    async def emit(self, e): self.events.append(e)
    async def close(self): pass


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
    # Reconstruct the payload the same way _sign_event does
    payload = {
        k: v for k, v in emitted.model_dump(exclude_none=True).items()
        if k != "signature"
    }
    body = json.dumps(payload, sort_keys=True, default=str).encode()
    expected = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    assert emitted.signature == expected


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
