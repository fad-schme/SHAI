"""AgentContext — the identity envelope passed on every boundary call.

Contains exactly what is needed to identify an agent call:
  - agent_id:     which top-level agent is making this call
  - sub_agent_id: which subagent (if any); parent is always agent_id
  - allowed_tags: capability scope, set by AgentContext.scope_subagent()

tenant_id is read from harness.yaml by the Harness instance and stamped
on AuditEvents directly — agents do not supply it.

Obtained by calling harness.load_agent() — never constructed directly
in agent code.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, PrivateAttr, field_validator

if TYPE_CHECKING:
    from harness.core.turn_signals import TurnSignals


class AgentContext(BaseModel, frozen=True):
    agent_id:        str
    sub_agent_id:    str | None = None
    allowed_tags:    list[str] | None = None
    # Session key for all session-scoped state — the threat accumulator and
    # SessionBudget both key on `conversation_id or agent_id`.
    conversation_id: str | None = None

    # Set to True by the agent after obtaining explicit human confirmation
    # for the current action. Required by SENSITIVE and IRREVERSIBLE tools.
    human_approved:  bool = False

    # Per-turn signal bus. Mutable — stored as PrivateAttr because Pydantic
    # frozen models block public-field writes. Attached by SHAI.scan_input
    # at turn start, cleared by SHAI.scan_output at turn end.
    _turn_signals: TurnSignals | None = PrivateAttr(default=None)

    @field_validator("agent_id")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("agent_id must be non-empty")
        return v

    def scope_subagent(self, sub_agent_id: str, *, allowed_tags: list[str]) -> AgentContext:
        """Return a new AgentContext scoped to a declared subagent.

        Called by Harness.scope_context_for_subagent() — not directly by
        agent code. The harness looks up the SubAgentConfig and passes the
        validated allowed_tags.

        Returns a frozen AgentContext with:
          - agent_id preserved (identifies the parent)
          - sub_agent_id set
          - allowed_tags narrowed to the subagent's declared tags
          - conversation_id preserved — delegation happens inside the parent's
            conversation, so session-keyed state (SessionBudget, the threat
            accumulator) must stay on one key. Dropping it hands a subagent a
            fresh step budget and splits accumulated threat evidence in two.

        Note: turn_signals is NOT propagated to subagents. Subagent invocations
        are separate turns from the parent's perspective.
        """
        return AgentContext(
            agent_id=self.agent_id,
            sub_agent_id=sub_agent_id,
            allowed_tags=allowed_tags,
            conversation_id=self.conversation_id,
        )

    def to_log_fields(self) -> dict[str, str | None]:
        """Canonical logging dict. Every logger calls this."""
        return {
            "agent_id":     self.agent_id,
            "sub_agent_id": self.sub_agent_id,
        }

    # ── TurnSignals accessors ──────────────────────────────────────────

    @property
    def turn_signals(self) -> TurnSignals | None:
        """Current turn's signal bus, or None if not in a turn."""
        return self._turn_signals

    def _attach_signals(self, signals: TurnSignals) -> None:
        """Attach a fresh TurnSignals. Called by SHAI.scan_input at turn start."""
        self._turn_signals = signals

    def _clear_signals(self) -> None:
        """Clear the signal bus. Called by SHAI.scan_output at turn end."""
        self._turn_signals = None
