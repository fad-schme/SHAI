"""ensemble.py — cross-method severity promotion.

Always on. Not configurable. Runs after all scanners complete.

When findings from 2+ distinct method families for the same category have a
combined severity weight that crosses the threshold, all findings in that
category are promoted to HIGH.

Corroboration counts method families, not scanner names — the same rule
TurnSignals.compute_risk applies. Two catalog scanners reading different
YAML files are one detection technique agreeing with itself, which is not
evidence enough to promote. Injection catalog + structural heuristic is.

Severity weights: LOW=1, MEDIUM=3, HIGH=6, CRITICAL=10.
Threshold: 4.0 (two MEDIUMs = 6 > 4.0 → promoted).
"""
from __future__ import annotations

from harness.core.types import Severity
from harness.core.verdicts import Finding

_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 1.0,
    Severity.MEDIUM: 3.0,
    Severity.HIGH: 6.0,
    Severity.CRITICAL: 10.0,
}

_THRESHOLD = 4.0


def promote_findings(findings: list[Finding]) -> list[Finding]:
    """Promote severity when cross-method weight crosses threshold.

    Only promotes upward. Only when 2+ distinct method families contributed.
    Returns the same list unchanged when nothing qualifies.
    """
    if not findings:
        return findings

    # Accumulate weight and contributing method families per category
    cat_weight: dict[str, float] = {}
    cat_families: dict[str, set[str]] = {}
    for f in findings:
        cat_weight[f.category] = cat_weight.get(f.category, 0.0) + _WEIGHTS.get(f.severity, 1.0)
        cat_families.setdefault(f.category, set()).add(f.method_family)

    # Categories that cross threshold with 2+ method families
    promote = {
        cat for cat, w in cat_weight.items()
        if w >= _THRESHOLD and len(cat_families.get(cat, set())) >= 2
    }

    if not promote:
        return findings

    return [
        f.model_copy(update={"severity": Severity.HIGH})
        if f.category in promote and f.severity < Severity.HIGH
        else f
        for f in findings
    ]
