"""AgentConfig and SubAgentConfig — schema for agent-xx.yaml files.

Both are public API. Frozen. Cross-field validation enforces the
principle of least privilege at load_agent() time, not at gate time.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from harness.core.errors import SubAgentNotDeclaredError

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
    """One policy rule — same schema in agent-xx.yaml and global rules.yaml."""
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
    def _action_constraints(self) -> "RuleConfig":
        if self.action == "deny" and not self.reason:
            raise ValueError(f"rule '{self.id}': reason required for deny action")
        if self.action == "redact" and self.redact is None:
            raise ValueError(f"rule '{self.id}': redact dict required for redact action")
        return self


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


class AgentConfig(BaseModel, frozen=True, extra="forbid"):
    """Complete agent profile loaded from agent-xx.yaml."""
    id:                 str
    display_name:       str | None = None
    version:            str | None = None

    allowed_tool_names: list[str]
    allowed_tags:       list[str]
    sources:            list[str] = Field(default_factory=list)
    policy_rules:       list[RuleConfig] = Field(default_factory=list)
    sub_agents:         list[SubAgentConfig] = Field(default_factory=list)

    log_level:  str = "INFO"
    audit_tags: dict[str, str] = Field(default_factory=dict)

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
    def _validate_sub_agents(self) -> "AgentConfig":
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