"""Shared enums. Bottom of the import graph — no harness.* imports."""
from enum import StrEnum


class BoundaryName(StrEnum):
    INPUT_SCAN     = "input_scan"
    TOOL_CALL_GATE = "tool_call_gate"
    OUTPUT_SCAN    = "output_scan"
    FILE_SCAN          = "file_scan"
    TOOL_RESULT_SCAN   = "tool_result_scan"
    # Source-connection time, not per-turn: MCP tool metadata is scanned once
    # per tool at tools/list, before the tool is registered. A tool refused
    # here never reaches the gate, so this is the only record of the refusal.
    MCP_METADATA_SCAN  = "mcp_metadata_scan"
    # Caller-driven subset of scan_input (SHAI.scan_pii / scan_injection).
    # Distinct from INPUT_SCAN so a consumer counting input scans per turn is
    # not thrown off by a helper call; `adapters` names the subset that ran.
    NARROW_SCAN        = "narrow_scan"
    SYSTEM             = "system"


class Decision(StrEnum):
    ALLOW    = "allow"
    DENY     = "deny"
    REDACT   = "redact"
    BLOCKED  = "blocked"
    WARN     = "warn"
    DEGRADED = "degraded"
    # Not a verdict: emitted once on boundary=SYSTEM when from_yaml() completes,
    # recording which components the process wired. See core/attestation.py.
    STARTUP  = "startup"


class OnError(StrEnum):
    """What happens when a scanner or adapter raises an exception.

    fail_closed — treat as BLOCK; content rejected (default, safe posture)
    fail_open   — treat as empty findings; content passes through
    degrade     — treat as WARN; content passes through, audit event flagged
    """
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN   = "fail_open"
    DEGRADE     = "degrade"


class Severity(StrEnum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    def _index(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self._index() >= other._index()

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self._index() > other._index()

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self._index() <= other._index()

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self._index() < other._index()


class Transport(StrEnum):
    LOCAL = "local"
    MCP   = "mcp"
    SKILL = "skill"

class ScanAction(StrEnum):
    """Action a boundary takes when a scanner finding crosses block_at severity.

    block  — hard stop; content is rejected, caller sees status=BLOCK
    alert  — pass through; content reaches destination, caller sees status=WARN
              Useful for observe-before-enforce rollout.
    redact — pass through with PII replaced by placeholder; status=ALLOW
             Scanner must return redacted_text; fallback to block if it does not.
    """
    BLOCK  = "block"
    ALERT  = "alert"
    REDACT = "redact"


class ScanStatus(StrEnum):
    """Outcome of a scan boundary call — replaces the old blocked: bool.

    ALLOW  — no findings above threshold, or action=redact applied
    WARN   — findings above threshold but action=alert; content passed through
    BLOCK  — findings above threshold and action=block; content rejected
    """
    ALLOW = "allow"
    WARN  = "warn"
    BLOCK = "block"



class Irreversibility(StrEnum):
    """Blast-radius classification for a tool.

    REVERSIBLE   — default; no extra gate.
    SENSITIVE    — denied without `approvals.sensitive_quorum` distinct approvers.
    IRREVERSIBLE — denied without `approvals.irreversible_quorum` distinct approvers.

    Approvers come from signed ApprovalGrants on ctx.approvals, verified at
    gate layer 3. The two tiers differ only in the quorum they require.
    """
    REVERSIBLE   = "reversible"
    SENSITIVE    = "sensitive"
    IRREVERSIBLE = "irreversible"
