"""shai — Secure Harness AI, control-plane SDK for production agents."""
from importlib.metadata import PackageNotFoundError, version

from harness.adapters.scanners.mcp_metadata_scanner import MCPMetadataScanner
from harness.agents.agent_config import AgentConfig, RuleConfig, SubAgentConfig
from harness.connectivity.config import ConnectivityConfig
from harness.connectivity.token import DispatchToken, TokenError
from harness.core.context import AgentContext
from harness.core.errors import (
    AdapterDiscoveryError,
    AgentConflictError,
    AgentNotRegisteredError,
    ArgumentViolationError,
    AuditEmissionError,
    ConfigError,
    HarnessError,
    IrreversibleActionError,
    MCPInvocationError,
    NetworkPolicyError,
    PolicyEvaluationError,
    SubAgentNotDeclaredError,
    ToolNotRegisteredError,
)
from harness.core.harness import SHAI
from harness.core.types import (
    BoundaryName,
    Decision,
    Irreversibility,
    ScanAction,
    ScanStatus,
    Severity,
    Transport,
)
from harness.core.verdicts import Finding, GateDecision, ScanVerdict
from harness.integrations.base import ShaiTool, shai_tool
from harness.tools.registry import ToolRegistry
from harness.tools.source import (
    LocalSource,
    MCPSource,
    SkillSource,
    SourceRegistry,
    ToolSource,
)
from harness.tools.tool import ArgumentRule, Tool

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
    "ArgumentRule",
    "Irreversibility",
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
    "ArgumentViolationError",
    "IrreversibleActionError",
    "AuditEmissionError",
    "MCPInvocationError",
    # Connectivity
    "ConnectivityConfig",
    # Tool decorator
    "shai_tool",
    "ShaiTool",
    "DispatchToken",
    "TokenError",
]
