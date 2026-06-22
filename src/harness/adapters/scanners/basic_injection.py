"""BasicInjectionScanner — detects common prompt-injection patterns.

Reference implementation. No external dependencies. Returns immediately.
Baseline defense only — for serious injection threat models use Lakera or
similar ML-based scanner from harness-enterprise.

Sensitivity levels control which pattern sets are active:
  low:    instruction_override, role_hijack only
  medium: + exfil_request, tool_coercion         (default)
  high:   + delimiter_smuggling

Redacted_text: None — injection detection does not auto-rewrite.
The agent decides whether to refuse, sanitize, or escalate.
"""
from __future__ import annotations

import re

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

# (category, severity, compiled_patterns)
_PATTERNS_LOW = [
    (
        "injection.instruction_override",
        Severity.HIGH,
        [
            re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),
            re.compile(r"disregard\s+(your\s+)?(system\s+)?prompt", re.I),
            re.compile(r"forget\s+(everything|all)\s+(you|i)\s+(were|was|have\s+been)\s+told", re.I),
        ],
    ),
    (
        "injection.role_hijack",
        Severity.HIGH,
        [
            re.compile(r"\byou\s+are\s+now\b", re.I),
            re.compile(r"\bact\s+as\s+(a\s+)?DAN\b", re.I),
            re.compile(r"\bpretend\s+(you\s+are|to\s+be)\b", re.I),
            re.compile(r"\byour\s+new\s+(role|persona|identity)\s+is\b", re.I),
        ],
    ),
]

_PATTERNS_MEDIUM = [
    (
        "injection.exfil_request",
        Severity.MEDIUM,
        [
            re.compile(r"print\s+(your|the)\s+system\s+prompt", re.I),
            re.compile(r"(repeat|show|reveal|display)\s+(your\s+)?(instructions?|rules|constraints)", re.I),
            re.compile(r"what\s+(are\s+)?(your\s+)?instructions", re.I),
        ],
    ),
    (
        "injection.tool_coercion",
        Severity.MEDIUM,
        [
            re.compile(r"you\s+must\s+(call|invoke|use|execute)\s+", re.I),
            re.compile(r"before\s+(answering|responding),\s*(call|invoke|run)", re.I),
            re.compile(r"immediately\s+(call|invoke|execute)\s+", re.I),
        ],
    ),
]

_PATTERNS_HIGH = [
    (
        "injection.delimiter_smuggling",
        Severity.LOW,
        [
            re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad]"),  # zero-width + soft-hyphen
            re.compile(r"\x00|\x01|\x02|\x03"),               # ASCII control chars
        ],
    ),
]


class BasicInjectionScanner:
    """Reference prompt-injection scanner."""

    name = "basic_injection"

    def __init__(self, sensitivity: str = "medium") -> None:
        if sensitivity not in {"low", "medium", "high"}:
            raise ValueError(f"sensitivity must be low|medium|high, got: {sensitivity!r}")

        patterns = list(_PATTERNS_LOW)
        if sensitivity in {"medium", "high"}:
            patterns.extend(_PATTERNS_MEDIUM)
        if sensitivity == "high":
            patterns.extend(_PATTERNS_HIGH)
        self._patterns = patterns

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        findings: list[Finding] = []

        for category, severity, compiled_list in self._patterns:
            for pattern in compiled_list:
                for m in pattern.finditer(text):
                    findings.append(Finding(
                        scanner=self.name,
                        category=category,
                        severity=severity,
                        span=(m.start(), m.end()),
                        detail=f"{category} pattern detected",
                    ))

        # No redacted_text — injection detection does not auto-rewrite
        return ScanResult(findings=findings, redacted_text=None)
