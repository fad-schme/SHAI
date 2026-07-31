"""Scanner Protocol, ScanResult, and ConfiguredScanner.

ScanResult is internal — boundaries aggregate Scanner results into ScanVerdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from harness.core.types import Severity

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.types import ScanAction
    from harness.core.verdicts import Finding


@dataclass
class ScanResult:
    """Output of one scanner on one text. Internal — not part of public API."""
    findings:      list[Finding] = field(default_factory=list)
    redacted_text: str | None = None


@dataclass(frozen=True)
class SeverityScale:
    """Score thresholds for one scanner's scoring scale.

    Scales are not comparable across scanners — a catalog total of 6.0 and a
    heuristic total of 5.0 measure different evidence — so each scanner
    declares its own. What is shared is the *derivation*: the same ordering,
    the same escape hatch, and the same floor semantics, in one place instead
    of re-spelled as an if/elif chain per scanner.

    floor:
        Below it the evidence is too thin to report at all and `severity_for`
        returns None. `None` means no floor — any score yields a severity,
        which is correct for a scanner that only scores once it already has a
        concrete match (the catalog scanners return early on no match).
    """
    high:   float
    medium: float
    floor:  float | None = None

    def severity_for(
        self,
        score: float,
        *,
        force_high: bool = False,
        gate: bool = True,
    ) -> Severity | None:
        """Map a score to a severity, or None when it should not be reported.

        force_high — evidence that is categorical rather than cumulative. A
        catalog rule declaring `severity: high` fires whatever the total is.

        gate — a corroboration predicate the scanner computed. Passing it here
        rather than checking it separately is deliberate: a scanner that
        evaluates a bar and then forgets to apply it silently over-reports,
        which is exactly how a lone weak typoglycemia match came to contribute
        a full sub-score on its own. Making the gate an argument of the
        function that produces the severity keeps the two from drifting apart.
        """
        if not gate:
            return None
        if self.floor is not None and score < self.floor:
            return None
        if force_high or score >= self.high:
            return Severity.HIGH
        return Severity.MEDIUM if score >= self.medium else Severity.LOW


class Scanner(Protocol):
    """Inspect text and return findings. All async — production scanners are network-bound."""

    name: str
    method_family: str   # detection technique — used by TurnSignals for corroboration
                         # (regex_catalog | structural_heuristic | structural_file |
                         #  regex_pii | ml_classifier | unknown)
                         # A composite scanner that forwards another scanner's
                         # findings stamps each one with its producer's family and
                         # declares "unknown" here — run_scan fills in only the
                         # families a scanner left unset.

    async def scan(
        self,
        text: str,
        ctx: AgentContext,
    ) -> ScanResult:
        """Inspect text. Return findings and optional redacted form.

        Pure from the boundary's perspective — no side effects, no audit emission.
        Async because production scanners (Purview, Nightfall, Lakera) make
        HTTP calls. Reference scanners (regex) return immediately.

        Never include raw matched text in Finding.detail — category + severity
        is what audit consumers act on.
        """
        ...


@dataclass(frozen=True)
class ConfiguredScanner:
    """A scanner bound to the per-scanner overrides declared alongside it.

    Pairing happens where the AdapterRef is still in hand, so a scanner that
    fails to resolve or an appended backstop can never shift another scanner's
    action onto it. action=None means "use the boundary action".
    """
    scanner:     Scanner
    action:      ScanAction | None = None
    redact_with: str | None = None
