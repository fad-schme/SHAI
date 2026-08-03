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
    method_family = "regex_catalog"
    default_patterns = _DEFAULT_PATTERNS

    # Deliberate: this scanner does NOT load injection_common.yaml.
    #
    # Its whole contract is that findings carry `jailbreak.*` categories so
    # policy rules and audit consumers can target guardrail-integrity attacks
    # independently of injection ones. The common catalog emits
    # `prompt_injection`, `tool_injection` and `prompt_extraction`, which would
    # put non-jailbreak categories in this scanner's output and break that
    # separation. It would also duplicate every common rule whenever
    # injection_scan runs alongside — the usual case in both shipped configs.
    #
    # Consequence, accepted: a boundary configured with `jailbreak_scan` and
    # nothing else does not get the common compounds. That is the same bargain
    # every scanner makes — an operator gets the catalog they declared. Declare
    # `injection_scan` alongside it to cover the data-channel families.
    # IdentitySpoofScanner opts out for the same reason.
    common_patterns = ()
