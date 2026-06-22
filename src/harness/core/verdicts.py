"""Wire types returned by the three boundaries. Part of the public API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, model_validator

from harness.core.types import Severity


class Finding(BaseModel, frozen=True):
    """One match returned by a Scanner."""
    scanner:  str
    category: str
    severity: Severity
    detail:   str | None = None              # short note — never the raw matched text


class ScanVerdict(BaseModel, frozen=True):
    """Aggregate result of scan_input or scan_output."""
    blocked:       bool
    findings:      list[Finding] = []
    redacted_text: str | None = None

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity._index()).severity


class GateDecision(BaseModel, frozen=True):
    """Result of check_tool_call."""
    allowed:       bool
    deny_reason:   str | None = None
    redacted_args: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _deny_requires_reason(self) -> "GateDecision":
        if not self.allowed and not self.deny_reason:
            raise ValueError("deny_reason is required when allowed=False")
        return self
