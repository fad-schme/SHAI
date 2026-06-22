"""RuntimeContext — the identity envelope passed on every boundary call."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, field_validator


class RuntimeContext(BaseModel, frozen=True):
    # Agent identity — used internally for keying, policy, source activation
    tenant_id:    str
    agent_id:     str
    sub_agent_id: str | None = None
    allowed_tags: list[str] | None = None

    # Audit-only — never used for keying or policy decisions
    user_id:    str | None = None
    session_id: str | None = None

    @field_validator("tenant_id", "agent_id")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must be non-empty")
        return v

    def agent_key(self) -> tuple[str, str]:
        """Canonical key for ScopedRegistryView storage.

        Always (agent_id, sub_agent_id or ""). Never user_id or session_id —
        those are audit-only fields and must never influence internal keying.
        """
        return (self.agent_id, self.sub_agent_id or "")

    def to_log_fields(self) -> dict[str, Any]:
        """Canonical logging dict. Every logger calls this — never hand-build."""
        return {
            "tenant_id":    self.tenant_id,
            "agent_id":     self.agent_id,
            "sub_agent_id": self.sub_agent_id,
            "user_id":      self.user_id,
            "session_id":   self.session_id,
        }
