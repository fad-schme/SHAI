"""Pydantic schema for harness.yaml.

All models use extra="forbid" — typos in YAML surface at load time.
Every field maps to a consumer in the codebase.
"""
from __future__ import annotations

from harness.connectivity.config import ConnectivityConfig

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from harness.agents.agent_config import RuleConfig

from pydantic import BaseModel, Field, field_validator, model_validator

from harness.core.errors import ConfigError
from harness.core.types import ScanAction, Severity, Transport


class AdapterRef(BaseModel, frozen=True, extra="forbid"):
    """Reference to a named adapter with optional constructor config.

    action:      per-scanner override for the boundary action.
                 When set, takes precedence over the boundary-level action
                 for findings produced by this scanner only.
                 Values: block | alert | redact
    redact_with: placeholder template used when action=redact.
                 Use {category} to include the finding category.
                 Default: "[REDACTED:{category}]"
    """
    name:        str
    config:      dict[str, Any] = Field(default_factory=dict)
    action:      ScanAction | None = None
    redact_with: str | None = None

    @field_validator("name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("adapter name must be non-empty")
        return v



class NormalizationConfig(BaseModel, frozen=True, extra="forbid"):
    """De-obfuscation applied to text before scanners run, in every scan boundary.

    Produces additional plaintext *views* of the input (decoded / de-fragmented
    forms) so pattern scanners cannot be bypassed by base64, rot13, hex, URL
    encoding, unicode homoglyphs, invisible characters, or fragmentation.
    Scanners run across all views; the raw text the agent sees is never mutated.

    Enabled by default: a disabled normalizer reopens the encoded-payload bypass.
    """
    enabled:           bool  = True
    decode:            bool  = True   # base64 / hex / url / rot13 substring decode
    max_depth:         int   = 2      # recursion depth for nested encodings
    entropy_threshold: float = 3.5    # min entropy for a base64 decode candidate
    max_bytes:         int   = 262144 # inputs larger than this are folded, not decoded


class ThreatAccumulatorConfig(BaseModel, frozen=True, extra="forbid"):
    """Cross-turn threat accumulator — detects crescendo / multi-turn escalation.

    SQLite-backed: risk scores persist across process restarts so a slow
    crescendo that spans hours is still detected.

    Disabled by default — requires explicit opt-in because it creates a
    SQLite file at `path` and runs a DB check on every scan_input call.
    Enable in harness.yaml once the deployment path is configured.

    on_escalation:
      block — hard stop (default); scanners never run for this turn
      flag  — WARN verdict; content passes through; audit event emitted
    """
    enabled:              bool  = False
    backend:              str   = "sqlite"
    path:                 str   = "state/sessions.db"
    escalation_threshold: float = 0.70
    window_size:          int   = 10
    reframe_similarity:   float = 0.72
    ttl_hours:            float = 72.0
    on_escalation:        str   = "block"   # "block" | "flag"

    @field_validator("on_escalation")
    @classmethod
    def _valid_action(cls, v: str) -> str:
        if v not in ("block", "flag"):
            raise ValueError("on_escalation must be 'block' or 'flag'")
        return v


class BoundaryConfig(BaseModel, frozen=True, extra="forbid"):
    """Configuration for a text-scanning boundary.

    action:   what to do when a finding crosses block_at severity.
              block  — reject the content (default)
              alert  — pass through and emit a WARN audit event
              redact — replace matched PII with redact_with placeholder and pass through
    """
    enabled:  bool       = True
    block_at: Severity   = Severity.HIGH
    action:   ScanAction = ScanAction.BLOCK
    scanners: list[AdapterRef] = Field(default_factory=list)

    @model_validator(mode="after")
    def _enabled_needs_scanners(self) -> "BoundaryConfig":
        if self.enabled and not self.scanners:
            raise ValueError("scanners must be non-empty when boundary is enabled")
        return self


class FileScanConfig(BaseModel, frozen=True, extra="forbid"):
    """Configuration for the scan_file boundary.

    Extends BoundaryConfig with file-specific constraints.
    max_size_mb:  reject files above this size before any scanning.
    """
    enabled:             bool         = True
    block_at:            Severity     = Severity.HIGH
    action:              ScanAction   = ScanAction.BLOCK
    scanners:            list[AdapterRef] = Field(default_factory=list)
    max_size_mb:         float        = 100.0




class RateLimitConfig(BaseModel, frozen=True, extra="forbid"):
    """Rate limiting for check_tool_call. Mitigates T4 and T2."""
    enabled:              bool  = False
    window_seconds:       float = 60.0
    max_calls_per_window: int   = 60
    max_calls_per_tool:   int   = 20

    @field_validator("window_seconds")
    @classmethod
    def _positive_window(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("window_seconds must be positive")
        return v

    @field_validator("max_calls_per_window", "max_calls_per_tool")
    @classmethod
    def _positive_limits(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("rate limits must be positive")
        return v

class ExecutionBudgetConfig(BaseModel, frozen=True, extra="forbid"):
    """Per-session execution budget.  Mitigates T4 (DoS / Unbounded Consumption).

    All limits default to None (disabled).  Set any limit to enable enforcement.

    max_steps:                 maximum total tool calls per session
    max_tokens_per_session:    cumulative token ceiling per session
    max_tool_calls_per_prompt: fan-out ceiling per user turn
    tool_cost_weights:         {tool_name: int} cost multiplier applied to token tracking
    loop_detection_window:     how many recent fingerprints to check for duplicates
    loop_similarity_threshold: Jaccard similarity at which a call is flagged as a loop
    """
    max_steps:                  int | None        = None
    max_tokens_per_session:     int | None        = None
    max_tool_calls_per_prompt:  int | None        = None
    tool_cost_weights:          dict[str, int]    = Field(default_factory=dict)
    loop_detection_window:      int               = 0    # 0 = disabled
    loop_similarity_threshold:  float             = 0.95

    @field_validator("max_steps", "max_tokens_per_session", "max_tool_calls_per_prompt",
                     mode="before")
    @classmethod
    def _positive_or_none(cls, v: int | None) -> int | None:
        if v is not None and v <= 0:
            raise ValueError("budget limits must be positive")
        return v

    @field_validator("loop_detection_window")
    @classmethod
    def _non_negative_window(cls, v: int) -> int:
        if v < 0:
            raise ValueError("loop_detection_window must be >= 0")
        return v

    @field_validator("loop_similarity_threshold")
    @classmethod
    def _valid_threshold(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("loop_similarity_threshold must be between 0.0 and 1.0")
        return v


class ToolCallGateConfig(BaseModel, frozen=True, extra="forbid"):
    """No enabled flag — the gate is mandatory."""
    arg_scanners:       list[AdapterRef]      = Field(default_factory=list)
    scan_args_for_tags: list[str]             = Field(default_factory=lambda: ["sensitive"])
    rate_limit:         RateLimitConfig       = Field(default_factory=RateLimitConfig)
    execution_budget:   ExecutionBudgetConfig = Field(default_factory=ExecutionBudgetConfig)




class AuditSigningConfig(BaseModel, frozen=True, extra="forbid"):
    """HMAC-SHA256 signing for audit events. Mitigates T8 (Repudiation).

    The signing key is resolved via SecretsProvider (secret:// URI).
    When enabled, every AuditEvent gets a `signature` field before emission.
    Verification: harness audit verify --file logs/audit.jsonl
    """
    enabled: bool = False
    secret:  str  = ""    # secret://ENV_VAR resolved at startup

    @model_validator(mode="after")
    def _enabled_needs_secret(self) -> "AuditSigningConfig":
        if self.enabled and not self.secret:
            raise ValueError("audit.signing.secret is required when signing is enabled")
        return self


class ToolResultScanConfig(BaseModel, frozen=True, extra="forbid"):
    """Configuration for the scan_tool_result boundary.

    Scans tool return values before they re-enter the LLM context.
    Mitigates T6 indirect prompt injection (injected content in tool results).
    Pattern file is the bundled patterns_for_doc.yaml — no config needed.
    """
    enabled:  bool       = False
    block_at: Severity   = Severity.HIGH
    action:   ScanAction = ScanAction.BLOCK


class SourceConfig(BaseModel, frozen=True, extra="forbid"):
    """Configuration for one tool source declared in harness.yaml.

    Local sources (transport: local) use already-registered tools — no url needed.
    MCP sources (transport: mcp) connect to an MCP server at the given url.

    credentials:  mapping of credential name to secret:// URI or literal value.
                  Resolved via SecretsProvider at from_yaml() time.
    tags:         tags applied to ALL tools returned by this source, merged with
                  any tags declared on individual tools.
    required:     when True (default), a missing or failed source raises ConfigError
                  at load_agent() time — the agent is not usable without it. Set to
                  False for optional enrichment sources where degraded operation is
                  acceptable (e.g. a telemetry source that is nice-to-have).
    """
    name:        str
    connector:   str | None = None
    # Optional connector id (e.g. 'slack', 'github'). When set, loads the
    # pre-built manifest from harness.connectors and merges it with any
    # fields declared alongside connector: in harness.yaml.
    transport:   Transport = Transport.LOCAL
    url:         str | None = None
    credentials: dict[str, str] = Field(default_factory=dict)
    tags:        list[str] = Field(default_factory=list)
    tool_names:  list[str] = Field(default_factory=list)  # local sources only: subset of tools to expose
    required:        bool       = True
    allowed_urls:    list[str]  = Field(default_factory=list)
    # URL prefix patterns this source may reach. Default: [{url}/*] from the url field.
    # Used to populate DispatchToken.allowed_urls when connectivity.enabled.
    # Pattern syntax: "https://host/path/*" or exact "https://host/path".
    allowed_methods:      list[str]  = Field(default_factory=list)
    # HTTP methods permitted. Default: all standard methods when empty.
    connector_tool_specs: dict       = Field(default_factory=dict)
    # Per-tool security metadata from the connector manifest.
    # Maps tool_name → {tags: [...], action: str}. Populated by from_yaml()
    # when connector: is set. Empty for manual sources.
    scan_tool_result_on:  list[str]  = Field(default_factory=list)
    # Tool names whose results must be scanned (T6 protection).
    # Populated from ConnectorManifest.scan_tool_result_on.
    # Empty = scan all tool results (default behaviour).
    # required=True (default): missing or failed source raises ConfigError at load_agent() time.
    # required=False: missing or failed source is logged and skipped — use for
    #                 optional enrichment sources where degraded operation is acceptable.

    @model_validator(mode="after")
    def _transport_constraints(self) -> "SourceConfig":
        # url is not required when a connector manifest provides it
        if self.transport == Transport.MCP and not self.url and not self.connector:
            raise ValueError(
                f"source '{self.name}': url is required for mcp transport "
                f"(or set connector: to use a pre-built manifest)"
            )
        return self


class PolicyConfig(BaseModel, frozen=True, extra="forbid"):
    """Inline policy configuration.

    rules:  global policy rules evaluated after agent-scoped rules.
            Defined inline in harness.yaml — no separate rules file needed.
            Same schema as agent-level policy_rules.
    """
    rules: list[dict[str, Any]] = Field(default_factory=list)

    def parsed_rules(self) -> list:
        """Return rules parsed as RuleConfig objects. Called by from_yaml()."""
        from harness.agents.agent_config import RuleConfig
        return [RuleConfig.model_validate(r) for r in self.rules]


class MCPMetadataScanConfig(BaseModel, frozen=True, extra="forbid"):
    """Configuration for the scan_mcp_metadata boundary.

    Scans tool names, descriptions, and argument schemas received from
    MCP servers' tools/list response before registration.

    block_at defaults to MEDIUM (unlike other boundaries which default to HIGH)
    because almost no legitimate content in tool metadata looks like an injection.
    A tool description containing 'ignore all previous instructions' has no
    benign interpretation.

    Default scanner: mcp_metadata_scan (MCPMetadataScanner).
    """
    enabled:  bool       = True
    block_at: Severity   = Severity.MEDIUM
    action:   ScanAction = ScanAction.BLOCK
    scanners: list[AdapterRef] = Field(
        default_factory=lambda: [AdapterRef(name="mcp_metadata_scan")]
    )


class HarnessConfig(BaseModel, frozen=True, extra="forbid"):
    version:         int = 1
    tenant_id:       str = "default"
    normalization:        NormalizationConfig      = Field(default_factory=NormalizationConfig)
    session:              ThreatAccumulatorConfig  = Field(default_factory=ThreatAccumulatorConfig)
    scan_input:      BoundaryConfig
    scan_file:       FileScanConfig       = Field(default_factory=lambda: FileScanConfig(enabled=False))
    scan_tool_result:    ToolResultScanConfig    = Field(default_factory=ToolResultScanConfig)
    scan_mcp_metadata:   MCPMetadataScanConfig   = Field(default_factory=MCPMetadataScanConfig)
    check_tool_call:     ToolCallGateConfig      = Field(default_factory=ToolCallGateConfig)
    scan_output:         BoundaryConfig
    policy:          PolicyConfig = Field(default_factory=PolicyConfig)
    audit_sinks:     list[AdapterRef] = Field(default_factory=list)
    sources:         list[SourceConfig]  = Field(default_factory=list)
    audit_signing:   AuditSigningConfig  = Field(default_factory=AuditSigningConfig)
    connectivity:    ConnectivityConfig   = Field(default_factory=ConnectivityConfig)


