"""shai — Secure Harness AI, control-plane SDK for production agents.

`SHAI` is the public API. Everything else exported here is a shape that appears
in one of its method signatures — what you pass in, what you get back, or what
can escape as an exception. Nothing is exported because it happens to be useful
internally.

Anything not listed in `__all__` is an implementation detail and may change
without a deprecation. Adapters are selected by name in harness.yaml, not
imported.
"""
from importlib.metadata import PackageNotFoundError, version

from harness.agents.agent_config import AgentConfig
from harness.core.context import AgentContext
from harness.core.errors import (
    AgentConflictError,
    AgentNotRegisteredError,
    AuditEmissionError,
    ConfigError,
    HarnessError,
    MCPInvocationError,
    NetworkPolicyError,
    SubAgentNotDeclaredError,
)
from harness.core.events import AuditEvent, NetworkAuditEvent
from harness.core.harness import SHAI
from harness.core.types import (
    BoundaryName,
    Decision,
    Irreversibility,
    ScanStatus,
    Severity,
    Transport,
)
from harness.core.verdicts import Finding, GateDecision, ScanVerdict
from harness.integrations.base import ShaiTool, shai_tool
from harness.maintenance import Maintenance
from harness.tools.source import ToolSource
from harness.tools.tool import ArgumentRule, Tool

try:
    # Must match `name` in pyproject.toml. The import package is `harness` and
    # the distribution is `shai-harness`; looking up the wrong one does not
    # fail loudly, it falls through to the sentinel below — which is how every
    # startup attestation came to record shai_version="0.0.0+dev" on a correct
    # install. test_version_matches_installed_distribution pins the two.
    __version__ = version("shai-harness")
except PackageNotFoundError:
    # Running from a source tree with nothing installed.
    __version__ = "0.0.0+dev"

__all__ = [
    # The API. Everything below is a shape one of its methods uses.
    "SHAI",
    "__version__",

    # Declaring tools — register_tools()
    "Tool",
    "ArgumentRule",
    "Irreversibility",
    "Transport",
    "shai_tool",
    "ShaiTool",

    # Agent scope — load_agent(), scope_context_for_subagent()
    "AgentContext",
    "AgentConfig",

    # What harness.maintenance returns — agent admin, kill switch, inspection
    "Maintenance",

    # What the boundaries return
    "ScanVerdict",
    "GateDecision",
    "Finding",
    "ScanStatus",
    "Severity",

    # What collect_events() yields
    "AuditEvent",
    "NetworkAuditEvent",
    "BoundaryName",
    "Decision",

    # What get_source() returns
    "ToolSource",

    # Exceptions that can escape a public method. The gate's own refusals are
    # GateDecision(allowed=False), never exceptions — these are startup and
    # dispatch failures.
    "HarnessError",
    "ConfigError",
    "AgentConflictError",
    "AgentNotRegisteredError",
    "SubAgentNotDeclaredError",
    "AuditEmissionError",
    "MCPInvocationError",
    "NetworkPolicyError",
]
