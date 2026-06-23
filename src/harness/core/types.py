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
