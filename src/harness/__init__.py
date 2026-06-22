"""harness — control-plane SDK for production agents."""
from importlib.metadata import PackageNotFoundError, version

from harness.agents.agent_config import AgentConfig, RuleConfig, SubAgentConfig
from harness.core.context import RuntimeContext
from harness.core.errors import (
    AdapterDiscoveryError,
    AdapterInitError,
    AgentConflictError,
    AgentNotRegisteredError,
    AuditEmissionError,
    ConfigError,
    HarnessError,
    PolicyEvaluationError,
    SubAgentNotDeclaredError,
    ToolNotRegisteredError,
)
from harness.core.harness import Harness
from harness.core.types import BoundaryName, Decision, Severity, Transport
from harness.core.verdicts import Finding, GateDecision, ScanVerdict
from harness.tools.tool import Tool

try:
    __version__ = version("harness")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

__all__ = [
    "Harness",
    "Tool",
    "RuntimeContext",
    "AgentConfig",
    "SubAgentConfig",
    "RuleConfig",
    "ScanVerdict",
    "GateDecision",
    "Finding",
    "BoundaryName",
    "Decision",
    "Severity",
    "Transport",
    "HarnessError",
    "ConfigError",
    "AdapterDiscoveryError",
    "AdapterInitError",
    "AgentNotRegisteredError",
    "AgentConflictError",
    "SubAgentNotDeclaredError",
    "ToolNotRegisteredError",
    "PolicyEvaluationError",
    "AuditEmissionError",
    "__version__",
]
