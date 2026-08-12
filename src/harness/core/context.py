"""AgentContext — the identity envelope passed on every boundary call.

Contains exactly what is needed to identify an agent call:
  - agent_id:     which top-level agent is making this call
  - sub_agent_id: which subagent (if any); parent is always agent_id
  - allowed_tags: capability scope, set by AgentContext.scope_subagent()

tenant_id is read from harness.yaml by the Harness instance and stamped
on AuditEvents directly — agents do not supply it.

Obtained by calling harness.load_agent(), then narrowed with for_conversation()
and scope_subagent() — never constructed field-by-field in agent code.

**One context per concurrent turn.** A context carries the turn's signal bus
(see turn_signals.py): scan_input attaches it, scan_output clears it. Two turns
running concurrently through the *same* context object therefore write to one
bus — the second scan_input replaces the first turn's evidence, and the first
scan_output clears the second turn's. Derive one per conversation with
for_conversation(); the object returned by load_agent() is the template to
derive from, not a handle to share across live turns.

Sequential reuse is fine: a turn ends at scan_output, and the next may reuse
the same context. It is concurrency that needs distinct contexts, because
nothing in the context distinguishes two turns that present identically.
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

    # Encoded ApprovalGrants for the call about to be gated — see
    # harness.core.approval. Required by SENSITIVE and IRREVERSIBLE tools, which
    # the gate denies without a quorum of valid, bound grants. Carrying signed
    # grants rather than a boolean is deliberate: AgentContext is
    # caller-constructible, so a flag would be set by assignment and would bind
    # to no tool, no arguments, and no approver.
    approvals:       tuple[str, ...] = ()

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

    def for_conversation(self, conversation_id: str) -> AgentContext:
        """Return a context scoped to one conversation.

        This is how a caller gets a context per concurrent turn. `load_agent()`
        returns one context with no `conversation_id`, which collapses every
        session onto `agent_id`: one execution budget, one accumulated threat
        score, and — because a context carries the turn's signal bus — one bus
        shared by every turn running through it. Derive one of these per
        conversation and the three become independent.

        Everything else is preserved; only `conversation_id` changes. The new
        context starts with no signals attached, whatever the receiver's state.
        """
        if not conversation_id.strip():
            raise ValueError("conversation_id must be non-empty")
        return AgentContext(
            agent_id=self.agent_id,
            sub_agent_id=self.sub_agent_id,
            allowed_tags=self.allowed_tags,
            conversation_id=conversation_id,
            approvals=self.approvals,
        )

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
        are separate turns from the parent's perspective. Neither are approvals,
        so a delegated call is approved on its own terms by default. That is a
        default, not an enforced boundary: a grant binds a tool name and an
        args_digest, never a caller role, so a caller that passes the parent's
        grants down explicitly gets them honoured for that same tool and those
        same arguments. What a subagent may invoke at all is decided earlier, by
        allowed_tool_names (L1) and allowed_tags (L4).
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
