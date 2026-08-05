"""Tool descriptor — metadata only, never executable.

The harness gates; the agent dispatches. Tool is part of the public API.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

from harness.core.types import Irreversibility, Transport


class ArgumentRule(BaseModel, frozen=True):
    """A single deterministic constraint on one argument of a tool call.

    The gate evaluates every rule on the tool and fails closed on the first
    violation. All constraint fields are optional — set only the ones relevant.

    Fields
    ------
    arg         Name of the argument this rule applies to.
    max_value   Numeric upper bound (inclusive).
    min_value   Numeric lower bound (inclusive).
    allowlist   Value must be one of these strings (exact match).
    pattern     Value must match this regex (re.search semantics).
    required    Argument must be present and non-None.
    user_origin Value must trace to the user, not to text a tool returned.

    Every field above except `user_origin` is evaluated by `evaluate()` against
    the arguments alone. `user_origin` is not: deciding it needs the turn's
    provenance record, so the gate enforces it at layer 6 and denies there (see
    check_tool_call._check_signal_correlation).

    Declare it only where it actually holds — a recipient, a path, an amount the
    user names. An argument the agent legitimately fills from something it read
    (a body, a summary, an address resolved out of a contact list) will trip it,
    so leaving it undeclared there is the correct configuration, not a gap.
    """
    arg:         str
    max_value:   float | None = None
    min_value:   float | None = None
    allowlist:   list[str] | None = None
    pattern:     str | None = None
    required:    bool = False
    user_origin: bool = False

    def evaluate(self, args: dict[str, Any]) -> str | None:
        """Return a violation message, or None if the rule passes.

        Never raises — a malformed rule is a violation, not an exception.
        """
        value = args.get(self.arg)

        if self.required and value is None:
            return f"required argument '{self.arg}' is missing"

        if value is None:
            return None  # absent optional arg — no further checks

        if self.max_value is not None:
            try:
                if float(value) > self.max_value:
                    return (
                        f"argument '{self.arg}' value {value} "
                        f"exceeds max {self.max_value}"
                    )
            except (TypeError, ValueError):
                return f"argument '{self.arg}' is not numeric (max_value check)"

        if self.min_value is not None:
            try:
                if float(value) < self.min_value:
                    return (
                        f"argument '{self.arg}' value {value} "
                        f"is below min {self.min_value}"
                    )
            except (TypeError, ValueError):
                return f"argument '{self.arg}' is not numeric (min_value check)"

        if self.allowlist is not None:
            if str(value) not in self.allowlist:
                return (
                    f"argument '{self.arg}' value '{value}' "
                    f"is not in the allowed set"
                )

        if self.pattern is not None:
            try:
                if not re.search(self.pattern, str(value)):
                    return (
                        f"argument '{self.arg}' value '{value}' "
                        f"does not match required pattern"
                    )
            except re.error as exc:
                return f"argument '{self.arg}' pattern is invalid: {exc}"

        return None


class Tool(BaseModel, frozen=True):
    """Describes one tool the agent may dispatch.

    transport is immutable after registration — raising ConfigError on any
    attempt to re-register the same name with a different transport.
    """
    name:         str
    tags:         list[str] = Field(default_factory=list)
    transport:    Transport = Transport.LOCAL
    description:  str | None = None

    # Deterministic argument-level constraints. Evaluated before the policy
    # engine. First violation denies the call regardless of injection context.
    argument_rules: list[ArgumentRule] = Field(default_factory=list)

    # Blast-radius classification. SENSITIVE and IRREVERSIBLE require a quorum
    # of signed ApprovalGrants on ctx.approvals before the gate will pass.
    irreversibility: Irreversibility = Irreversibility.REVERSIBLE

    @field_validator("name")
    @classmethod
    def _non_empty_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("tool name must be non-empty")
        return v

    @field_validator("tags")
    @classmethod
    def _canonical_tags(cls, v: list[str]) -> list[str]:
        """Sort and dedupe so tag order never affects equality.

        Every consumer reads tags as a set, so ordering carries no meaning —
        but equality is field-wise, and without this ["read","write"] and
        ["write","read"] would be two different tools to the registry.
        """
        return sorted(set(v))

    # Equality is Pydantic's field-wise comparison — every field is significant,
    # including argument_rules, irreversibility, and description. The registry
    # relies on it to tell an idempotent re-registration from one that would
    # swap security metadata (see ToolRegistry.register).
    #
    # __hash__ stays narrow and hand-written: argument_rules is a list, so a
    # generated hash over all fields would raise TypeError. A coarser hash is
    # contract-safe — stricter equality only ever yields fewer equal pairs, and
    # tools that are equal still agree on these three fields.
    def __hash__(self) -> int:
        return hash((self.name, self.transport, tuple(sorted(self.tags))))
