"""AgentConfig and SubAgentConfig — schema for agent-xx.yaml files.

Both are public API. Frozen. Cross-field validation enforces the
principle of least privilege at load_agent() time, not at gate time.
"""
from __future__ import annotations

import re
from datetime import date
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from harness.core.errors import SubAgentNotDeclaredError

if TYPE_CHECKING:
    pass

_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_VALID_ACTIONS  = {"allow", "deny", "redact", "suppress"}
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}


def _validate_id(v: str) -> str:
    if not _ID_RE.match(v):
        raise ValueError(
            f"id must be snake_case starting with a lowercase letter, got: {v!r}"
        )
    return v


class RuleMatchConfig(BaseModel, frozen=True, extra="forbid"):
    tool_tags:     list[str] = Field(default_factory=list)
    tool_names:    list[str] = Field(default_factory=list)
    transport:     list[str] = Field(default_factory=list)
    agent_ids:     list[str] = Field(default_factory=list)
    sub_agent_ids: list[str] = Field(default_factory=list)
    source_tags:   list[str] = Field(default_factory=list)
    any:           list[Any] = Field(default_factory=list)
    all:           list[Any] = Field(default_factory=list)
    not_:          Any | None = Field(default=None, alias="not")

    model_config = {"populate_by_name": True}


class RuleConfig(BaseModel, frozen=True, extra="forbid"):
    """One policy rule — same schema for an agent's `policy_rules:` and the
    global `policy.rules:` block in harness.yaml."""
    id:     str
    match:  RuleMatchConfig
    action: str
    reason: str | None = None
    redact: dict[str, Any] | None = None

    @field_validator("action")
    @classmethod
    def _valid_action(cls, v: str) -> str:
        if v not in _VALID_ACTIONS:
            raise ValueError(f"action must be one of {_VALID_ACTIONS}, got: {v!r}")
        return v

    @model_validator(mode="after")
    def _action_constraints(self) -> RuleConfig:
        if self.action == "deny" and not self.reason:
            raise ValueError(f"rule '{self.id}': reason required for deny action")
        if self.action == "redact" and self.redact is None:
            raise ValueError(f"rule '{self.id}': redact dict required for redact action")
        return self


def _names_source_tags(match: Any) -> bool:
    """True when a match, or any any/all/not expression inside it, names source_tags."""
    # Inline expressions are parsed the way the matcher parses them
    # (RuleMatchConfig accepts `not` and `not_`), so no spelling slips past.
    if isinstance(match, dict):
        try:
            match = RuleMatchConfig.model_validate(match)
        except ValidationError:
            return False        # not a match expression; the matcher rejects it
    if not isinstance(match, RuleMatchConfig):
        return False
    if match.source_tags:
        return True
    nested = [*match.any, *match.all]
    if match.not_ is not None:
        nested.append(match.not_)
    return any(_names_source_tags(n) for n in nested)


def _reject_source_scoped(rules: list[RuleConfig], owner: str) -> None:
    # _match_tool never reads source_tags, so a tool rule naming it has nothing
    # to compare against and matches every tool call: a narrowing rule that
    # widens. Source rules (policy.source_rules) are where the field belongs.
    for rule in rules:
        if _names_source_tags(rule.match):
            raise ValueError(
                f"{owner}policy_rules[{rule.id!r}]: match field source_tags is "
                f"source-scoped and cannot match a tool call. Use it in "
                f"policy.source_rules."
            )


class SubAgentConfig(BaseModel, frozen=True, extra="forbid"):
    """One subagent declared inside a parent's agent-xx.yaml."""
    id:                 str
    allowed_tool_names: list[str]
    allowed_tags:       list[str]
    sources:            list[str] = Field(default_factory=list)
    policy_rules:       list[RuleConfig] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        return _validate_id(v)

    @field_validator("allowed_tool_names", "allowed_tags")
    @classmethod
    def _non_empty(cls, v: list[str], info: Any) -> list[str]:
        if not v:
            raise ValueError(f"{info.field_name} must be non-empty")
        return v


class CredentialRef(BaseModel, frozen=True, extra="forbid"):
    """A credential an agent uses, referenced by name. Never holds a secret value."""
    name:       str = Field(min_length=1)
    expires_at: date | None = None
    rotated_at: date | None = None


class AgentConfig(BaseModel, frozen=True, extra="forbid"):
    """Complete agent profile loaded from agent-xx.yaml."""
    id:                 str
    display_name:       str | None = None
    version:            str | None = None

    # Non-human-identity profile. Declarative metadata for an operator's NHI
    # inventory or identity provider: stored and returned by
    # maintenance.registered_agents(), never read by a boundary, the gate or
    # the registry. Every field is optional; none changes a decision.
    description:     str | None = None
    owners:          list[str] = Field(default_factory=list)
    sponsors:        list[str] = Field(default_factory=list)
    environment:     str | None = None
    review_due:      date | None = None
    delegation_mode: Literal["autonomous", "on_behalf_of_user"] | None = None
    credential_refs: list[CredentialRef] = Field(default_factory=list)

    allowed_tool_names: list[str]
    allowed_tags:       list[str]
    sources:            list[str] = Field(default_factory=list)
    policy_rules:       list[RuleConfig] = Field(default_factory=list)
    sub_agents:         list[SubAgentConfig] = Field(default_factory=list)

    log_level:  str = "INFO"
    audit_tags: dict[str, str] = Field(default_factory=dict)
    limits:     dict[str, Any] = Field(default_factory=dict)
    # Per-agent execution budget overrides.  Merged onto the global budget by the
    # SHAI facade; validated here at parse time (see _valid_limits).

    @field_validator("limits")
    @classmethod
    def _valid_limits(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Reject unknown or ill-typed limit keys while parsing the file.

        Validating here rather than at load_agent() keeps agent loading atomic:
        a bad `limits:` block fails before anything is registered, so the harness
        can never hold an agent whose execution budget could not be built — such
        an agent would be gated with no budget at all.
        """
        if not v:
            return v
        # Local import: config.schema imports this module for RuleConfig.
        from harness.config.schema import ExecutionBudgetConfig

        try:
            ExecutionBudgetConfig.model_validate(v)
        except Exception as e:
            raise ValueError(f"invalid limits: block: {e}") from e
        return v

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        return _validate_id(v)

    @field_validator("allowed_tool_names", "allowed_tags")
    @classmethod
    def _non_empty(cls, v: list[str], info: Any) -> list[str]:
        if not v:
            raise ValueError(f"{info.field_name} must be non-empty")
        return v

    @field_validator("log_level")
    @classmethod
    def _valid_log_level(cls, v: str) -> str:
        if v not in _VALID_LOG_LEVELS:
            raise ValueError(f"log_level must be one of {_VALID_LOG_LEVELS}, got: {v!r}")
        return v

    @model_validator(mode="after")
    def _tool_rules_are_tool_scoped(self) -> AgentConfig:
        _reject_source_scoped(self.policy_rules, "")
        for sub in self.sub_agents:
            _reject_source_scoped(sub.policy_rules, f"sub_agent '{sub.id}': ")
        return self

    @model_validator(mode="after")
    def _validate_sub_agents(self) -> AgentConfig:
        parent_tools = set(self.allowed_tool_names)
        parent_tags  = set(self.allowed_tags)
        seen_ids: set[str] = set()

        for sub in self.sub_agents:
            if sub.id in seen_ids:
                raise ValueError(f"duplicate sub_agent id: {sub.id!r}")
            seen_ids.add(sub.id)

            extra_tools = set(sub.allowed_tool_names) - parent_tools
            if extra_tools:
                raise ValueError(
                    f"sub_agent '{sub.id}': allowed_tool_names contains tools not in "
                    f"parent allowed_tool_names: {sorted(extra_tools)}"
                )

            extra_tags = set(sub.allowed_tags) - parent_tags
            if extra_tags:
                raise ValueError(
                    f"sub_agent '{sub.id}': allowed_tags contains tags not in "
                    f"parent allowed_tags: {sorted(extra_tags)}"
                )

        return self

    def get_sub_agent(self, sub_agent_id: str) -> SubAgentConfig:
        """Return SubAgentConfig for sub_agent_id.

        Raises SubAgentNotDeclaredError if not declared under this agent.
        Called by Harness.scope_context_for_subagent().
        """
        for sub in self.sub_agents:
            if sub.id == sub_agent_id:
                return sub
        raise SubAgentNotDeclaredError(
            f"sub_agent '{sub_agent_id}' not declared under agent '{self.id}'",
            agent_id=self.id,
        )
