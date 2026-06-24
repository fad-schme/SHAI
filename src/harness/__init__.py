"""shai — Secure Harness AI, control-plane SDK for production agents."""
from importlib.metadata import PackageNotFoundError, version

from harness.agents.agent_config import AgentConfig, RuleConfig, SubAgentConfig
from harness.core.context import AgentContext
from harness.core.errors import (
    AdapterDiscoveryError,
    AgentConflictError,
    AgentNotRegisteredError,
    AuditEmissionError,
    ConfigError,
    HarnessError,
    MCPInvocationError,
    PolicyEvaluationError,
    SubAgentNotDeclaredError,
    ToolNotRegisteredError,
)
from harness.core.harness import SHAI
from harness.core.types import (
    BoundaryName,
    Decision,
    ScanAction,
    ScanStatus,
    Severity,
    Transport,
)
from harness.core.verdicts import Finding, GateDecision, ScanVerdict
from harness.tools.registry import ToolRegistry
from harness.tools.source import (
    LocalSource,
    MCPSource,
    SkillSource,
    SourceRegistry,
    ToolSource,
)
from harness.connectivity.config import ConnectivityConfig
from harness.connectivity.token import DispatchToken, TokenError
from harness.tools.tool import Tool

try:
    __version__ = version("shai")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

__all__ = [
    # Facade
    "SHAI",
    "__version__",
    # Tools
    "Tool",
    "ToolRegistry",
    "ToolSource",
    "LocalSource",
    "SkillSource",
    "MCPSource",
    "SourceRegistry",
    # Agent
    "AgentContext",
    "AgentConfig",
    "SubAgentConfig",
    "RuleConfig",
    # Verdicts
    "ScanVerdict",
    "GateDecision",
    "Finding",
    # Types / enums
    "BoundaryName",
    "Decision",
    "ScanAction",
    "ScanStatus",
    "Severity",
    "Transport",
    # Errors
    "HarnessError",
    "ConfigError",
    "AdapterDiscoveryError",
    "AgentNotRegisteredError",
    "AgentConflictError",
    "SubAgentNotDeclaredError",
    "ToolNotRegisteredError",
    "PolicyEvaluationError",
    "AuditEmissionError",
    "MCPInvocationError",
    # Connectivity
    "ConnectivityConfig",
    "DispatchToken",
    "TokenError",
]
