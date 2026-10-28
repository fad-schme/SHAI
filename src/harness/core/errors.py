"""Harness exception hierarchy.

Every exception exposes structured context fields as attributes so log
formatters can pick them up without parsing the message string.
"""
from __future__ import annotations

from typing import Any


class HarnessError(Exception):
    def __init__(
        self,
        message: str,
        *,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        sub_agent_id: str | None = None,
        adapter: str | None = None,
        boundary: str | None = None,
        op: str | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(message)
        self.tenant_id    = tenant_id
        self.agent_id     = agent_id
        self.sub_agent_id = sub_agent_id
        self.adapter      = adapter
        self.boundary     = boundary
        self.op           = op
        self.extra        = extra

    def context(self) -> dict[str, Any]:
        """Structured fields for log formatters."""
        return {k: v for k, v in {
            "tenant_id":    self.tenant_id,
            "agent_id":     self.agent_id,
            "sub_agent_id": self.sub_agent_id,
            "adapter":      self.adapter,
            "boundary":     self.boundary,
            "op":           self.op,
            **self.extra,
        }.items() if v is not None}


class ConfigError(HarnessError):
    """Invalid harness.yaml or agent-xx.yaml content."""

class AgentNotRegisteredError(HarnessError):
    """agent_id not in AgentRegistry. check_tool_call maps this to a deny decision."""

class AgentConflictError(HarnessError):
    """Same agent_id already registered with different content. Use reload_agent."""

class SubAgentNotDeclaredError(HarnessError):
    """sub_agent_id not declared under the calling agent_id."""

class ToolNotRegisteredError(HarnessError):
    """Registry lookup miss. Maps to deny in check_tool_call."""

class ToolTagConflict(ConfigError):
    """Same tool name already registered and the ONLY difference is tags.

    The one registry rejection a source activation may absorb: a source that
    merges extra tags onto a known tool becomes a per-agent override
    (harness._wire_agent). Any other difference — transport, path_args,
    argument_rules, irreversibility, description — stays a plain ConfigError
    and fails agent wiring, so a colliding source tool can never silently
    shadow a registered definition."""

class PolicyEvaluationError(HarnessError):
    """Policy engine failed to evaluate. A normal deny is PolicyDecision, not this."""

class AuditEmissionError(HarnessError):
    """All configured sinks failed. Single sink failure is logged and swallowed."""

class NetworkPolicyError(HarnessError):
    """Raised by ShaiTransport when an outbound request violates connectivity policy.

    Covers: destination not in allowed_urls, method not in allowed_methods,
    invalid/tampered dispatch token, no token on strict policy.
    """

    def __init__(self, message: str, *, op: str = "network_egress") -> None:
        super().__init__(message, op=op)


class DispatchRefused(HarnessError):
    """Raised by SHAI.verify_tool_dispatch when it refuses the running local
    tool call. execute_gated_tool_call renders it as a denied GatedCall that
    carries the refusal reason to the model.
    """


class MCPInvocationError(HarnessError):
    """MCP server returned a JSON-RPC error during tool invocation.

    Attributes: source, tool, code, message mirror the JSON-RPC error fields.

    The formatted string deliberately omits `message`: it is text an untrusted
    server chose, and `str(e)` from this type reaches log fields and, through
    some frameworks' error handling, the model's context. The structured
    attribute keeps the full text for callers that handle it deliberately.
    """

    def __init__(self, source: str, tool: str, code: int, message: str) -> None:
        self.source  = source
        self.tool    = tool
        self.code    = code
        self.message = message
        super().__init__(
            f"MCP invocation error [{source}] tool={tool!r} code={code}",
            op="mcp_invoke",
        )


class ArgumentViolationError(HarnessError):
    """A tool argument failed a deterministic ArgumentRule check.

    check_tool_call converts this to GateDecision(allowed=False).
    """


class IrreversibleActionError(HarnessError):
    """A SENSITIVE or IRREVERSIBLE tool was called without a quorum of valid
    approval grants (see harness.core.approval).

    check_tool_call converts this to GateDecision(allowed=False).
    """
