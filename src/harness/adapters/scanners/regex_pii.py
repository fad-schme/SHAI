"""RegexPIIScanner — detects common PII and credential patterns.

Reference implementation. No external dependencies. Returns immediately —
async def for Protocol compliance only.

Pattern categories:
  pii.email          medium   RFC-5322-ish common shapes
  pii.phone          medium   US + international formats
  pii.ssn            high     US Social Security Number
  pii.credit_card    high     Luhn-validated 13–16 digit sequences
  network.ipv4       low      dotted-quad addresses
  secret.api_key     medium   API key tokens (20+ chars), UUIDs, common key prefixes
                              (sk_live_, ghp_, xoxb-, AKIA, glpat-)
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
        # Candidate filter only — validated in scan() by _valid_ssn().
        # Requires the dashed form OR a nearby ssn/social keyword to fire;
        # bare 9-digit runs (order ids, phone strings) are rejected there.
        "pii.ssn",
        Severity.HIGH,
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b"),
    ),
    (
        # Candidate filter only — validated in scan() by Luhn (_luhn_ok()).
        # The docstring's Luhn promise is now actually enforced.
        "pii.credit_card",
        Severity.HIGH,
        re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
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
        # Vendor-prefixed keys only — these are unambiguous. The former
        # trailing "any 20+ char base64 token" alternative was removed: it
        # fired on git SHAs, UUIDs, tracking numbers, and every opaque id,
        # swamping the audit trail. Raw high-entropy tokens with an explicit
        # key/token/secret assignment are now caught by secret.credential.
        re.compile(
            r"(?:"
            r"\b(?:sk_live|sk_test|rk_live|rk_test)_[A-Za-z0-9]{16,}\b"
            r"|\bghp_[A-Za-z0-9]{36,}\b"
            r"|\bgith(?:ub)?_pat_[A-Za-z0-9_]{22,}\b"
            r"|\bxox[bpoas]-[A-Za-z0-9-]{16,}\b"
            r"|\bAKIA[A-Z0-9]{16}\b"
            r"|\bASIA[A-Z0-9]{16}\b"
            r"|\bglpat-[A-Za-z0-9_-]{20,}\b"
            r"|\bAIza[A-Za-z0-9_-]{35}\b"
            r")"
        ),
    ),
    (
        "secret.private_key",
        Severity.HIGH,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    (
        "secret.jwt",
        Severity.HIGH,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "secret.aws_secret",
        Severity.HIGH,
        re.compile(r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+]{40}\b"),
    ),
    (
        "secret.conn_string",
        Severity.HIGH,
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^\s:@/]+:[^\s:@/]+@"
        ),
    ),
    (
        "secret.slack_webhook",
        Severity.HIGH,
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
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


# Categories that need a post-regex validator to fire. The regex is a cheap
# candidate filter; the validator is the precision gate.
_SSN_KEYWORD_RE = re.compile(r"(?i)\b(ssn|social\s+security)\b")


def _luhn_ok(candidate: str) -> bool:
    """Luhn checksum over the digits of a card candidate (13–19 digits)."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_ssn(candidate: str, text: str) -> bool:
    """Reject structurally-invalid SSNs and bare 9-digit runs.

    A dashed candidate (123-45-6789) is trusted on structure alone. A bare
    9-digit run only fires when an ssn/social-security keyword is present in
    the surrounding text — otherwise it is almost always an order id, tracking
    number, or account number.
    """
    digits = [c for c in candidate if c.isdigit()]
    if len(digits) != 9:
        return False
    area, group, serial = "".join(digits[:3]), "".join(digits[3:5]), "".join(digits[5:])
    # Structurally impossible SSNs (SSA allocation rules)
    if area in ("000", "666") or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    dashed = "-" in candidate
    return dashed or bool(_SSN_KEYWORD_RE.search(text))


class RegexPIIScanner:
    """Reference PII scanner using compiled regex patterns."""

    name = "regex_pii"
    method_family = "regex_pii"

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
            matched_spans = []
            for m in pattern.finditer(text):
                candidate = m.group(0)
                # Precision gates for the two high-FP numeric categories.
                if category == "pii.credit_card" and not _luhn_ok(candidate):
                    continue
                if category == "pii.ssn" and not _valid_ssn(candidate, text):
                    continue
                matched_spans.append(candidate)
                findings.append(Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    detail=f"{category} pattern detected",  # never the matched text
                ))

            # Redact only validated matches. For validated categories we
            # replace the specific matched strings; for the rest, blanket sub.
            if category in ("pii.credit_card", "pii.ssn"):
                for span in set(matched_spans):
                    redacted = redacted.replace(span, f"[REDACTED:{category}]")
            else:
                redacted = pattern.sub(f"[REDACTED:{category}]", redacted)

        return ScanResult(
            findings=findings,
            redacted_text=redacted if redacted != text else None,
        )
