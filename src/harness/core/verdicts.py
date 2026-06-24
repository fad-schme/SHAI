"""Wire types returned by the three boundaries. Part of the public API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, model_validator

from harness.core.types import ScanStatus, Severity


class Finding(BaseModel, frozen=True):
    """One match returned by a Scanner."""
    scanner:  str
    category: str
    severity: Severity
    detail:   str | None = None   # short note — never the raw matched text


class ScanVerdict(BaseModel, frozen=True):
    """Aggregate result of a scan boundary call.

    status:
        ALLOW  — no findings above threshold, or action=redact applied cleanly
        WARN   — findings above threshold, action=alert; content passed through
        BLOCK  — findings above threshold, action=block; content rejected

    redacted_text:
        Set when action=redact and a scanner returned redacted_text.
        Callers should use  verdict.redacted_text or original_text.
    """
    status:        ScanStatus
    findings:      list[Finding] = []
    redacted_text: str | None = None

    # ── Convenience properties ─────────────────────────────────────────────

    @property
    def blocked(self) -> bool:
        """True when the boundary hard-blocked the content."""
        return self.status == ScanStatus.BLOCK

    @property
    def warned(self) -> bool:
        """True when findings were detected but action=alert let content through."""
        return self.status == ScanStatus.WARN

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity._index()).severity


class GateDecision(BaseModel, frozen=True):
    """Result of check_tool_call.

    dispatch_token:
        Set when allowed=True and connectivity.enabled=True in harness.yaml.
        Base64url-encoded signed DispatchToken. Pass to MCPSource.call() so
        ShaiTransport can attach it as X-Shai-Token on outbound requests.
        None when connectivity is disabled or the gate denied.
    """
    allowed:        bool
    deny_reason:    str | None = None
    redacted_args:  dict[str, Any] | None = None
    dispatch_token: str | None = None

    @model_validator(mode="after")
    def _deny_requires_reason(self) -> "GateDecision":
        if not self.allowed and not self.deny_reason:
            raise ValueError("deny_reason is required when allowed=False")
        return self
