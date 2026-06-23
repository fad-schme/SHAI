"""Shared enums. Bottom of the import graph — no harness.* imports."""
from enum import StrEnum


class BoundaryName(StrEnum):
    INPUT_SCAN     = "input_scan"
    TOOL_CALL_GATE = "tool_call_gate"
    OUTPUT_SCAN    = "output_scan"
    FILE_SCAN          = "file_scan"
    TOOL_RESULT_SCAN   = "tool_result_scan"


class Decision(StrEnum):
    ALLOW   = "allow"
    DENY    = "deny"
    REDACT  = "redact"
    BLOCKED = "blocked"
    WARN    = "warn"


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

