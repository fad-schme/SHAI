"""Tests for the secret.credential precision gate in RegexPIIScanner.

The keyword alternation (password, secret, token, credentials, ...) fires on
common nouns, so the bare-space form of the pattern matched any 6+ character
word following one of them. "the secret meeting" and "reset your password
immediately" were HIGH-severity credential findings.

_valid_credential gates the bare-space form on the value looking like a secret.
Explicit assignment forms are unchanged.
"""
from __future__ import annotations

import pytest

from harness.adapters.scanners.regex_pii import RegexPIIScanner
from harness.core.context import AgentContext

CTX = AgentContext(agent_id="test")
SCANNER = RegexPIIScanner(categories=["secret.credential"])


async def _categories(text: str) -> list[str]:
    result = await SCANNER.scan(text, CTX)
    return [f.category for f in result.findings]


class TestBenignProseIsNotACredential:
    """Prose where a credential keyword is an ordinary noun."""

    @pytest.mark.parametrize("text", [
        "Store a new password securely.",
        "Share a stored password securely with a trusted contact.",
        "Reset your password immediately.",
        "Update your password regularly",
        "The secret meeting is tomorrow",
        "token economics explained",
        "credentials verified successfully",
        "Please rotate the access_key quarterly",
    ])
    async def test_no_finding(self, text: str):
        assert await _categories(text) == []

    @pytest.mark.parametrize("text", [
        "Store a new password securely.",
        "The secret meeting is tomorrow",
    ])
    async def test_text_is_not_redacted(self, text: str):
        """A rejected match must not be redacted — the validated-category
        branch exists so pattern.sub never sees it."""
        result = await SCANNER.scan(text, CTX)
        assert result.redacted_text is None


class TestRealCredentialsStillDetected:
    @pytest.mark.parametrize("text", [
        "my password is hunter2",
        "password: hunter2",
        "password:hunter2",
        "credentials: s3cr3t-value",
        "api_key=sk-abc123def456",
        "auth_token = eyJhbGciOi",
        "the secret is Tr0ub4dor",
    ])
    async def test_assignment_forms(self, text: str):
        assert "secret.credential" in await _categories(text)

    @pytest.mark.parametrize("text", [
        "passwd hunter2",                 # digit
        "password Xk9mPq2z",              # digit
        "password sk-abc-def",            # symbol
        "passwd XkPmQzRt",                # internal capitalisation
    ])
    async def test_bare_space_with_secret_shaped_value(self, text: str):
        assert "secret.credential" in await _categories(text)

    async def test_detected_credential_is_redacted(self):
        result = await SCANNER.scan("my password is hunter2", CTX)
        assert result.redacted_text is not None
        assert "hunter2" not in result.redacted_text

    async def test_finding_never_carries_the_secret(self):
        """Invariant 3 — no raw text in any finding field."""
        result = await SCANNER.scan("password: hunter2", CTX)
        for f in result.findings:
            assert "hunter2" not in (f.detail or "")


class TestKnownLimitation:
    """Single-case alphabetic values after a bare space are given up.

    Pinned deliberately: admitting either case would restore the
    false-positive class the gate exists to remove ("password requirements",
    "PASSWORD POLICY"). The assignment forms still catch both.
    """

    @pytest.mark.parametrize("value", [
        "correcthorsebatterystaple",   # all lowercase
        "SECRETVALUE",                 # all caps
    ])
    async def test_single_case_value_after_bare_space_is_missed(self, value: str):
        assert await _categories(f"passwd {value}") == []

    @pytest.mark.parametrize("value", [
        "correcthorsebatterystaple",
        "SECRETVALUE",
    ])
    async def test_assignment_form_still_catches_it(self, value: str):
        assert "secret.credential" in await _categories(f"passwd: {value}")


class TestValueLengthFloor:
    async def test_short_value_after_punctuation_strip_is_rejected(self):
        """'abcde.' is 6 chars only because of the full stop."""
        assert await _categories("password abcde.") == []
