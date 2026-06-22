"""RuntimeContext — the identity envelope passed on every boundary call.

Contains exactly what is needed to identify an agent call:
  - agent_id:     which top-level agent is making this call
  - sub_agent_id: which subagent (if any); parent is always agent_id
  - allowed_tags: capability scope, set by scope_context_for_subagent

tenant_id is read from harness.yaml by the Harness instance and stamped
on AuditEvents directly — agents do not supply it.

user_id and session_id are not on RuntimeContext. If the operator needs
user-level audit correlation they put user_id in audit_tags on AgentConfig.
"""
from __future__ import annotations

from pydantic import BaseModel, field_validator


class RuntimeContext(BaseModel, frozen=True):
    agent_id:     str
    sub_agent_id: str | None = None
    allowed_tags: list[str] | None = None

    @field_validator("agent_id")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("agent_id must be non-empty")
        return v

    def agent_key(self) -> tuple[str, str]:
        """Canonical key for internal agent identity.

        Returns (agent_id, sub_agent_id or ""). Used in logging and
        for human-readable identification. Views are keyed on id(ctx),
        not agent_key(), to support concurrent same-agent turns.
        """
        return (self.agent_id, self.sub_agent_id or "")

    def to_log_fields(self) -> dict[str, str | None]:
        """Canonical logging dict. Every logger calls this."""
        return {
            "agent_id":     self.agent_id,
            "sub_agent_id": self.sub_agent_id,
        }
