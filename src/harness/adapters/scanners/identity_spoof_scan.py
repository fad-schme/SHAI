"""identity_spoof_scan.py — agentic identity spoofing detector.

Detects messages that claim a privileged or trusted agent identity in
their body text without a verified channel backing that claim:

  - Claimed orchestrator / parent agent authority
  - Claimed system / SHAI / harness authority
  - Claimed peer agent identity with privilege escalation intent
  - Tool-result content embedding an authority claim (indirect injection)

Findings carry category prefix "identity_spoof.*" so policy rules and
audit consumers can target them independently from injection and jailbreak
findings.

Registered as "identity_spoof_scan" in the harness.scanners entry-point
group. Add to any scan boundary in harness.yaml:

    scan_input:
      scanners:
        - name: injection_scan
        - name: jailbreak_scan
        - name: identity_spoof_scan

    scan_tool_result:
      enabled: true
      scanners:
        - name: identity_spoof_scan   # catches ClawJacked-style authority claims
"""
from __future__ import annotations

from pathlib import Path

from harness.adapters.scanners.injection_scan import InjectionScanner

_DEFAULT_PATTERNS = Path(__file__).parent / "l10n" / "identity_spoof_patterns.yaml"


class IdentitySpoofScanner(InjectionScanner):
    """Agentic identity spoofing detector.

    Structurally identical to InjectionScanner — same YAML-driven catalog,
    same scoring model, same Scanner Protocol. Differs in default pattern
    file and finding categories (identity_spoof.*).
    """

    name = "identity_spoof_scan"

    def __init__(
        self,
        patterns_file: str | Path | None = None,
        name: str = "identity_spoof_scan",
    ) -> None:
        super().__init__(
            patterns_file=patterns_file or _DEFAULT_PATTERNS,
            name=name,
        )
