"""Tool descriptor — metadata only, never executable.

The harness gates; the agent dispatches. Tool is part of the public API.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

from harness.connectivity.scope import check_scope_policy
from harness.core.types import Irreversibility, Transport


class ScopeRulePolicy(BaseModel, frozen=True):
    """Host/IP-aware scope constraint for a URL-typed argument.

    Unlike `pattern` (a raw regex on the string value), this canonicalizes
    the value as a URL first — see connectivity.scope.canonicalize_host —
    so case, IDNA, and IP-literal encoding differences that resolve to the
    same destination don't slip past the check, and a value that fails to
    canonicalize (malformed URL, userinfo present) is denied outright.

    A pure data holder — the matching logic lives in
    connectivity.scope.check_scope_policy, since this module is metadata
    only (see module docstring).

    allowed_hosts    Canonical host must exactly match one of these.
    allowed_domains  Canonical host must equal one of these, or (with
                     allow_subdomains) be a proper subdomain of one.
    allow_subdomains Widen allowed_domains to match subdomains.
    allowed_cidrs    If the canonical host is an IP literal, it must fall
                     inside one of these ranges — see
                     connectivity.scope.is_ip_in_scope for the default-deny
                     posture on private/loopback/link-local/multicast/
                     reserved/unspecified addresses. An IP-literal value
                     can only be granted this way, never via allowed_hosts
                     or allowed_domains.
    """
    allowed_hosts:    list[str] | None = None
    allowed_domains:  list[str] | None = None
    allow_subdomains: bool = False
    allowed_cidrs:    list[str] | None = None

    def violation(self, value: str) -> str | None:
        """Return a violation reason, or None if value is in scope."""
        return check_scope_policy(
            value,
            allowed_hosts=self.allowed_hosts,
            allowed_domains=self.allowed_domains,
            allow_subdomains=self.allow_subdomains,
            allowed_cidrs=self.allowed_cidrs,
        )


class ArgumentRule(BaseModel, frozen=True):
    """A single deterministic constraint on one argument of a tool call.

    The gate evaluates every rule on the tool and fails closed on the first
    violation. All constraint fields are optional — set only the ones relevant.

    Fields
    ------
    arg          Name of the argument this rule applies to.
    max_value    Numeric upper bound (inclusive).
    min_value    Numeric lower bound (inclusive).
    allowlist    Value must be one of these strings (exact match).
    pattern      Value must match this regex (re.search semantics).
    scope_policy Value must be a URL whose canonical host/IP is in scope —
                 see ScopeRulePolicy. For destination-typed arguments
                 (webhook URLs, fetch targets); use instead of a
                 hand-written pattern, which can't safely canonicalize.
    required     Argument must be present and non-None.
    user_origin  Value must trace to the user, not to text a tool returned.

    Every field above except `user_origin` is evaluated by `evaluate()` against
    the arguments alone. `user_origin` is not: deciding it needs the turn's
    provenance record, so the gate enforces it at layer 6 and denies there (see
    check_tool_call._check_signal_correlation).

    Declare it only where it actually holds — a recipient, a path, an amount the
    user names. An argument the agent legitimately fills from something it read
    (a body, a summary, an address resolved out of a contact list) will trip it,
    so leaving it undeclared there is the correct configuration, not a gap.
    """
    arg:          str
    max_value:    float | None = None
    min_value:    float | None = None
    allowlist:    list[str] | None = None
    pattern:      str | None = None
    scope_policy: ScopeRulePolicy | None = None
    required:     bool = False
    user_origin:  bool = False

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

        if self.scope_policy is not None:
            reason = self.scope_policy.violation(str(value))
            if reason is not None:
                return f"argument '{self.arg}' {reason}"

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

    # Which ToolSource produced this tool, set by the source itself at load()
    # time. None for tools registered directly via register_tools() rather
    # than discovered from a source. Read by Harness._resolve_tools() instead
    # of guessing — see MCPSource._fetch_tools() for where MCP tools get theirs.
    source_name:  str | None = None

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
