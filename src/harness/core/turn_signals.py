"""turn_signals.py — cross-boundary signal accumulator.

Lives for one agent turn. Each boundary writes signals after its verdict.
Each downstream boundary reads them before making its decision.
Not persisted — discarded at turn end.

Instantiated by SHAI.scan_input (turn entry), attached to AgentContext via
PrivateAttr. Every subsequent boundary in the same turn reads and writes
through it. SHAI.scan_output clears it at turn end.

Risk algorithm
--------------
Three additive components: input_risk, execution_risk, result_risk.

Input signals contribute directly. Execution signals reflect containment
(denial is small; allowed-with-injection is larger — the exposure path
opened). Result signals include indirect injection targeting authorized
tools (a live attack the agent could act on).

Two multipliers scale the raw total by chain progression:
  * Full chain (injection in → allowed → injection out)  → 1.20
  * Exposure without confirmed result-side attack        → 1.08

Final score is `1.0 - exp(-raw)`. Smooth, asymptotic — no hard cap,
diminishing returns as evidence accumulates.
"""
from __future__ import annotations

import math
from uuid import uuid4

from harness.core.types import ScanStatus, Severity
from harness.core.verdicts import ScanVerdict

# ── Public thresholds ────────────────────────────────────────────────────

# Reference point for "elevated but not blocking" — no boundary acts on it.
# Kept as the named midpoint of the scale RISK_HIGH sits on, so a caller
# reading compute_risk() has something to compare against.
RISK_ELEVATED = 0.30
RISK_HIGH     = 0.60   # scan_output blocks the turn on consolidated risk alone

# ── Internal constants ───────────────────────────────────────────────────

_INJECTION_CATEGORIES = frozenset({"tool_injection", "prompt_injection"})
_HIGH_RISK_TAGS       = frozenset({"destructive", "financial", "external"})


class TurnSignals:
    """Per-turn signal bus. Attached to AgentContext at scan_input.

    All fields default to "no signal yet". Boundaries called out of order
    or skipped are safe — every read checks for the presence of what it needs.
    """

    __slots__ = (
        "turn_id",
        "input_verdict",
        "input_categories",
        "input_max_severity",
        "input_method_families",
        "gate_verdict",
        "gate_tool_name",
        "gate_tool_tags",
        "tool_result_verdict",
        "tool_result_categories",
    )

    def __init__(self) -> None:
        # Identifies this turn. SessionBudget uses it as the fan-out key —
        # a fresh TurnSignals means a new turn, which resets the per-prompt
        # counter without the caller having to track turn boundaries.
        self.turn_id: str = uuid4().hex

        # Input signals
        self.input_verdict: ScanStatus | None = None
        self.input_categories: set[str] = set()
        self.input_max_severity: Severity | None = None
        self.input_method_families: set[str] = set()

        # Execution signals
        self.gate_verdict: str | None = None            # "allowed" | "denied"
        self.gate_tool_name: str | None = None
        self.gate_tool_tags: frozenset[str] = frozenset()

        # Tool result signals
        self.tool_result_verdict: ScanStatus | None = None
        self.tool_result_categories: set[str] = set()

    # ── Writers ──────────────────────────────────────────────────────────

    def record_input(self, verdict: ScanVerdict) -> None:
        """Record scan_input verdict. Called by SHAI.scan_input after run_scan.

        Families are read off the findings, which run_scan stamped with the
        producing scanner's technique. Only scanners that fired contribute,
        and two catalog scanners agreeing count as one method, not two.
        """
        self.input_verdict = verdict.status
        self.input_categories = {f.category for f in verdict.findings}
        if verdict.findings:
            self.input_max_severity = max(
                (f.severity for f in verdict.findings),
                key=lambda s: s._index(),
            )
        self.input_method_families.update(f.method_family for f in verdict.findings)

    def record_gate(self, allowed: bool, tool_name: str,
                    tool_tags: frozenset[str] = frozenset()) -> None:
        """Record check_tool_call verdict. Called by SHAI.check_tool_call."""
        self.gate_verdict = "allowed" if allowed else "denied"
        self.gate_tool_name = tool_name
        self.gate_tool_tags = tool_tags

    def record_tool_result(self, verdict: ScanVerdict) -> None:
        """Record scan_tool_result verdict. Called by SHAI.scan_tool_result."""
        self.tool_result_verdict = verdict.status
        self.tool_result_categories = {f.category for f in verdict.findings}

    # ── Read helpers ─────────────────────────────────────────────────────

    @property
    def input_has_injection(self) -> bool:
        return bool(self.input_categories & _INJECTION_CATEGORIES)

    @property
    def tool_result_has_injection(self) -> bool:
        return bool(self.tool_result_categories & _INJECTION_CATEGORIES)

    # ── Consolidated risk ────────────────────────────────────────────────

    def compute_risk(self) -> float:
        """Consolidated 0.0–1.0 risk score across all boundaries this turn.

        Returns 0.0 when no signals have been recorded (empty turn).
        Asymptotic — never quite reaches 1.0 even with maximum evidence.
        """
        input_risk     = 0.0
        execution_risk = 0.0
        result_risk    = 0.0

        # ── Input ─────────────────────────────────────────────────────
        if self.input_verdict == ScanStatus.BLOCK:
            input_risk += 0.45
        elif self.input_verdict == ScanStatus.WARN:
            input_risk += 0.18

        if "tool_injection" in self.input_categories:
            input_risk += 0.15
        if "prompt_injection" in self.input_categories:
            input_risk += 0.10

        # Independent method families agreeing = real corroboration.
        # Catalog scanners firing together count as one family, no bonus.
        if len(self.input_method_families) >= 2:
            input_risk += 0.07

        # ── Execution / containment ───────────────────────────────────
        # Denial = harness contained it. Small positive weight because a
        # denial still indicates someone tried something.
        # Allowed-with-injection = the exposure path opened.
        if self.gate_verdict == "denied":
            execution_risk += 0.08
        elif self.gate_verdict == "allowed" and self.input_has_injection:
            execution_risk += 0.18

        # ── Tool result ───────────────────────────────────────────────
        if self.tool_result_verdict == ScanStatus.BLOCK:
            result_risk += 0.28
        elif self.tool_result_verdict == ScanStatus.WARN:
            result_risk += 0.12

        # Category overlap: exact injection-family match is much stronger
        # than just any overlap
        overlap = self.input_categories & self.tool_result_categories
        exact_injection_match = bool(overlap & _INJECTION_CATEGORIES)
        if exact_injection_match:
            result_risk += 0.12
        elif overlap:
            result_risk += 0.05

        # Indirect injection targeting an authorized tool is live — the
        # agent could act on it. Small additive term.
        if (self.tool_result_has_injection
                and self.gate_verdict == "allowed"
                and self.gate_tool_name is not None):
            result_risk += 0.08

        # ── Chain multiplier ──────────────────────────────────────────
        raw = input_risk + execution_risk + result_risk

        if self.input_has_injection and self.gate_verdict == "allowed":
            if self.tool_result_has_injection:
                raw *= 1.20   # full chain: injection → tool call → injection in result
            else:
                raw *= 1.08   # exposure: injection routed to a tool, result was clean

        return 1.0 - math.exp(-raw)
