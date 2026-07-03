"""jailbreak_scan.py — guardrail-integrity classifier.

Detects attempts to override the model's alignment through persona assignment,
instruction override, refusal suppression, hypothetical laundering,
system-prompt extraction, or developer-mode activation.

Responsibilities: load and scan against jailbreak_patterns.yaml; return
findings with jailbreak.* categories so policy rules and audit consumers
can target them independently from injection findings.

Not responsible for: encoding detection or de-obfuscation (Control 0 handles
that upstream), PII redaction (regex_pii), or tool-call gating (the gate).
"""

from __future__ import annotations

from pathlib import Path

from harness.adapters.scanners.injection_scan import InjectionScanner

_DEFAULT_PATTERNS = Path(__file__).parent / "l10n" / "jailbreak_patterns.yaml"


class JailbreakScanner(InjectionScanner):
    """Guardrail-integrity classifier.

    Structurally identical to InjectionScanner — same YAML-driven catalog
    compilation, same three-tier scoring model, same Scanner Protocol.
    Differs only in: default pattern file (jailbreak_patterns.yaml),
    default name ("jailbreak_scan"), and finding categories (jailbreak.*).

    Register as a scanner in harness.yaml under any scan boundary:

        scan_input:
          scanners:
            - name: injection_scan    # data/tool-boundary attacks
            - name: jailbreak_scan    # guardrail-integrity attacks
    """

    name = "jailbreak_scan"

    def __init__(
        self,
        patterns_file: str | Path | None = None,
        name: str = "jailbreak_scan",
    ) -> None:
        super().__init__(
            patterns_file=patterns_file or _DEFAULT_PATTERNS,
            name=name,
        )
