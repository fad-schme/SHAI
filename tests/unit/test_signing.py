"""Tests for core/signing.py — the shared signed-envelope decoder.

`decode` raises exactly the caller's error type for every malformed envelope,
so each consumer (dispatch tokens, approval grants) denies through its own
audited path.
"""
from __future__ import annotations

import base64
import json

import pytest

from harness.core import signing

SECRET = b"signing-test-secret"
FIELDS = ("agent_id", "issued_at", "expires_at")


class _Err(Exception):
    pass


def _envelope(**overrides) -> str:
    claims = {
        "agent_id": "a1",
        "issued_at": "2020-01-01T00:00:00+00:00",
        "expires_at": "2999-01-01T00:00:00+00:00",
    }
    sig = signing.sign(claims, SECRET)
    data = {**claims, "signature": sig, **overrides}
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def _decode(encoded: str) -> dict:
    return signing.decode(encoded, secret=SECRET, fields=FIELDS, error=_Err, noun="thing")


def test_valid_envelope_decodes():
    assert _decode(_envelope())["agent_id"] == "a1"


@pytest.mark.parametrize("signature", [
    5, 1.5, True, False, None, [], ["a"], {}, {"a": 1},
    "", "wrong-ascii", "sïgnature", "\u202e", "x" * 100_000,
])
def test_bad_signature_raises_only_the_callers_error(signature):
    with pytest.raises(_Err):
        _decode(_envelope(signature=signature))


@pytest.mark.parametrize("signature", [5, None, [], {}, True])
def test_non_string_signature_message_names_no_value(signature):
    with pytest.raises(_Err, match="signature is not a string") as exc:
        _decode(_envelope(signature=signature))
    assert str(signature) not in str(exc.value).replace("signature is not a string", "")
