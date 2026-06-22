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

class AdapterDiscoveryError(HarnessError):
    """Adapter name cannot be resolved to a registered entry point."""

class AdapterInitError(HarnessError):
    """Adapter constructor failed (bad credentials, unreachable backend)."""

class AgentNotRegisteredError(HarnessError):
    """agent_id not in AgentRegistry. check_tool_call maps this to a deny decision."""

class AgentConflictError(HarnessError):
    """Same agent_id already registered with different content. Use reload_agent."""

class SubAgentNotDeclaredError(HarnessError):
    """sub_agent_id not declared under the calling agent_id."""

class ToolNotRegisteredError(HarnessError):
    """Registry lookup miss. Maps to deny in check_tool_call."""

class PolicyEvaluationError(HarnessError):
    """Policy engine failed to evaluate. A normal deny is PolicyDecision, not this."""

class AuditEmissionError(HarnessError):
    """All configured sinks failed. Single sink failure is logged and swallowed."""
