"""Shared enums. Bottom of the import graph — no harness.* imports."""
from enum import StrEnum


class BoundaryName(StrEnum):
    INPUT_SCAN     = "input_scan"
    TOOL_CALL_GATE = "tool_call_gate"
    OUTPUT_SCAN    = "output_scan"
    FILE_SCAN          = "file_scan"
    TOOL_RESULT_SCAN   = "tool_result_scan"
    SYSTEM             = "system"


class Decision(StrEnum):
    ALLOW    = "allow"
    DENY     = "deny"
    REDACT   = "redact"
    BLOCKED  = "blocked"
    WARN     = "warn"
    DEGRADED = "degraded"


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
    SENSITIVE    — denied unless ctx.human_approved is True.
    IRREVERSIBLE — denied unless ctx.human_approved is True.
    """
    REVERSIBLE   = "reversible"
    SENSITIVE    = "sensitive"
    IRREVERSIBLE = "irreversible"
