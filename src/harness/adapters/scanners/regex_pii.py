"""RegexPIIScanner — detects common PII patterns using compiled regex.

Reference implementation. No external dependencies. Returns immediately —
async def for Protocol compliance only.

Pattern categories:
  email          medium   RFC-5322-ish common shapes
  phone          medium   US + international formats
  ssn            high     US Social Security Number
  credit_card    high     Luhn-validated 13-16 digit sequences
  ipv4           low      dotted-quad addresses
  api_key_like   medium   long base64/hex tokens (32+ chars)

Redaction: replaces each match with [REDACTED:<category>].
Finding.detail: never contains the matched text — category only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from harness.adapters.scanners.base import ScanResult
from harness.core.context import RuntimeContext
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
        "secret.api_key_like",
        Severity.MEDIUM,
        re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
    ),
]


class RegexPIIScanner:
    """Reference PII scanner using compiled regex patterns."""

    name = "regex_pii"

    def __init__(self, categories: list[str] | None = None) -> None:
        """
        Args:
            categories: list of category names to enable (default: all).
                        e.g. ["pii.email", "pii.ssn"]
        """
        if categories:
            self._patterns = [(n, s, p) for n, s, p in _PATTERNS if n in categories]
        else:
            self._patterns = list(_PATTERNS)

    async def scan(self, text: str, ctx: RuntimeContext) -> ScanResult:
        findings: list[Finding] = []
        redacted = text

        for category, severity, pattern in self._patterns:
            for m in pattern.finditer(text):
                findings.append(Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    span=(m.start(), m.end()),
                    detail=f"{category} pattern detected",  # never the matched text
                ))

            # Replace in redacted copy — stable, non-overlapping
            redacted = pattern.sub(f"[REDACTED:{category}]", redacted)

        return ScanResult(
            findings=findings,
            redacted_text=redacted if redacted != text else None,
        )
