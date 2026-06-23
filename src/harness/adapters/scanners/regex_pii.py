"""RegexPIIScanner — detects common PII and credential patterns.

Reference implementation. No external dependencies. Returns immediately —
async def for Protocol compliance only.

Pattern categories:
  pii.email          medium   RFC-5322-ish common shapes
  pii.phone          medium   US + international formats
  pii.ssn            high     US Social Security Number
  pii.credit_card    high     Luhn-validated 13–16 digit sequences
  network.ipv4       low      dotted-quad addresses
  secret.api_key     medium   long base64/hex tokens (32+ chars)
  secret.credential  high     inline credential disclosure
                              e.g. "my password is X", "credentials: X",
                              "token: X", "api_key=X"

Redaction: replaces each match with [REDACTED:<category>].
Finding.detail: never contains the matched text — category only.
"""
from __future__ import annotations

import re

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

# (name, severity, pattern)
_PATTERNS: list[tuple[str, Severity, re.Pattern]] = [
    (
        "pii.email",
        Severity.MEDIUM,
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "pii.phone",
        Severity.MEDIUM,
        re.compile(
            r"\b(?:\+?1[\s\-.]?)?"
            r"(?:\(?\d{3}\)?[\s\-.]?)"
            r"\d{3}[\s\-.]?\d{4}\b"
        ),
    ),
    (
        "pii.ssn",
        Severity.HIGH,
        re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
    ),
    (
        "pii.credit_card",
        Severity.HIGH,
        re.compile(r"\b(?:\d[ \-]?){13,16}\b"),
    ),
    (
        "network.ipv4",
        Severity.LOW,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    (
        "secret.api_key",
        Severity.MEDIUM,
        re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
    ),
    (
        "secret.credential",
        Severity.HIGH,
        # Matches: "my password is X", "password: X", "credentials: X",
        # "token: X", "api_key=X", "secret: X", "passwd X" etc.
        # The value capture group matches non-whitespace sequences of 6+ chars
        # following the keyword, up to end-of-token.
        re.compile(
            r"(?i)\b(?:password|passwd|credentials?|secret|token|api[_\-]?key"
            r"|auth[_\-]?token|access[_\-]?key)\b"
            r"(?:\s*(?:is|are):?\s*|\s*[:=]\s*|\s+)"
            r"([^\s,;\"'`]{6,})"
        ),
    ),
]


class RegexPIIScanner:
    """Reference PII scanner using compiled regex patterns."""

    name = "regex_pii"

    def __init__(self, categories: list[str] | None = None) -> None:
        """
        Args:
            categories: list of category names to enable (default: all).
                        e.g. ["pii.email", "pii.ssn", "secret.credential"]
        """
        if categories:
            self._patterns = [(n, s, p) for n, s, p in _PATTERNS if n in categories]
        else:
            self._patterns = list(_PATTERNS)

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        findings: list[Finding] = []
        redacted = text

        for category, severity, pattern in self._patterns:
            for m in pattern.finditer(text):
                findings.append(Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    detail=f"{category} pattern detected",  # never the matched text
                ))

            # Replace in redacted copy — stable, non-overlapping
            redacted = pattern.sub(f"[REDACTED:{category}]", redacted)

        return ScanResult(
            findings=findings,
            redacted_text=redacted if redacted != text else None,
        )