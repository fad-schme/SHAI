"""Pydantic schema for harness.yaml.

All models use extra="forbid" — typos in YAML surface at load time.
Every field maps to a consumer in the codebase.
"""
from __future__ import annotations

from typing import Any

from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from harness.connectivity.config import ConnectivityConfig
from harness.core.types import OnError, ScanAction, Severity, Transport


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
    density_threshold:    float = 0.05
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
    on_error: what happens when a scanner raises.
              fail_closed — treat as BLOCK (default, correct security posture)
              fail_open   — treat as empty findings (rollout / testing only)
              degrade     — treat as WARN; content passes, audit event flagged
    """
    enabled:  bool       = True
    block_at: Severity   = Severity.HIGH
    action:   ScanAction = ScanAction.BLOCK
    on_error: OnError    = OnError.FAIL_CLOSED
    scanners: list[AdapterRef] = Field(default_factory=list)

    @model_validator(mode="after")
    def _enabled_needs_scanners(self) -> BoundaryConfig:
        if self.enabled and not self.scanners:
            raise ValueError("scanners must be non-empty when boundary is enabled")
        return self


class FileScanConfig(BaseModel, frozen=True, extra="forbid"):
    """Configuration for the scan_file boundary.

    Same keys as BoundaryConfig, plus file-specific constraints. `scanners`
    means the same thing here as it does for scan_input: the content chain.
    Each scanner receives text extracted from the file and, for images, the
    EXIF/XMP metadata blob — never the path. The structural pass (MIME, size,
    extension, PDF JS, SVG, ZIP, Office macros) always runs ahead of it.

    max_size_mb: reject files above this size before any scanning.
    """
    # Off unless the operator asks for it: scan_file reads uploaded files from
    # disk, and a harness that never receives uploads should not be doing that.
    # One default, declared here — HarnessConfig used to override it to False
    # while this said True, so the schema disagreed with itself about what an
    # omitted scan_file block means.
    enabled:             bool         = False
    block_at:            Severity     = Severity.HIGH
    action:              ScanAction   = ScanAction.BLOCK
    on_error:            OnError      = OnError.FAIL_CLOSED
    scanners:            list[AdapterRef] = Field(default_factory=list)
    max_size_mb:         float        = 100.0

    @model_validator(mode="after")
    def _no_per_scanner_action(self) -> FileScanConfig:
        """Reject per-scanner action/redact_with under scan_file.

        The content chain runs inside FileScanner, so the boundary sees one
        scanner and per-scanner overrides have nothing to index against — they
        would be silently ignored. Use the boundary-level `action` instead.
        """
        bad = [
            s.name for s in self.scanners
            if s.action is not None or s.redact_with is not None
        ]
        if bad:
            raise ValueError(
                f"scan_file scanners do not support per-scanner 'action' or "
                f"'redact_with' (set on: {', '.join(bad)}). Use the "
                f"boundary-level 'action' for scan_file."
            )
        return self




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

    Every control counts something SHAI observes at its own boundary.

    max_steps:                 maximum total tool calls per session
    max_tool_calls_per_prompt: fan-out ceiling per user turn
    loop_detection_window:     how many recent fingerprints to check for duplicates
    loop_similarity_threshold: Jaccard similarity at which a call is flagged as a loop
    """
    max_steps:                  int | None        = None
    max_tool_calls_per_prompt:  int | None        = None
    loop_detection_window:      int               = 0    # 0 = disabled
    loop_similarity_threshold:  float             = 0.95

    @field_validator("max_steps", "max_tool_calls_per_prompt",
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


class RevocationConfig(BaseModel, frozen=True, extra="forbid"):
    """Agent kill switch — out-of-band revocation the gate enforces.

    path:
        JSON file holding the revoked agent ids. Written by
        `SHAI.maintenance.revoke_agent()` and by `shai agent revoke`, read by the gate.
        A file is the medium because the CLI runs in its own process and cannot
        reach the harness's memory. Empty (default) disables revocation.

    cache_ttl_seconds:
        How long a read is cached on the gate's hot path. **This is the kill
        latency** — a revocation written by another process takes effect within
        one TTL. Named here rather than left as an implementation accident.
        0 disables caching: every gate call reads the file, which is the fastest
        possible response at the cost of a read per call.

    Revocation denies at the tool-call gate, the same place
    `maintenance.deregister_agent()`
    does: it stops actions, not conversation. It is agent-scoped only —
    tool- and source-level denial belongs to policy rules.
    """
    path:              str   = ""
    cache_ttl_seconds: float = Field(default=5.0, ge=0, le=300)


class ApprovalsConfig(BaseModel, frozen=True, extra="forbid"):
    """Human-approval enforcement for SENSITIVE and IRREVERSIBLE tools.

    secret:
        HMAC-SHA256 key that signs ApprovalGrants. Resolved via secret:// at
        from_yaml() time. **Empty means approvals are unconfigured, and every
        SENSITIVE and IRREVERSIBLE tool is denied.** There is no weaker check to
        fall back to: a tool classified as needing verified approval in a
        deployment that cannot verify one is a tool that cannot run.

    sensitive_quorum / irreversible_quorum:
        Distinct approvers required. Quorum counts distinct `approver_id`s
        across the grants on AgentContext.approvals, so 2 means two people
        signed independently — two grants from one approver is still one.
    """
    secret:              str = ""
    sensitive_quorum:    int = Field(default=1, ge=1)
    irreversible_quorum: int = Field(default=2, ge=1)


class ToolCallGateConfig(BaseModel, frozen=True, extra="forbid"):
    """No enabled flag — the gate is mandatory."""
    # Named `scanners` like every scan_* boundary. These run over the tool's
    # arguments at gate layer 7, not over free text, but the key an operator
    # writes is the same one everywhere.
    scanners:           list[AdapterRef]      = Field(default_factory=list)
    scan_args_for_tags: list[str]             = Field(default_factory=lambda: ["sensitive"])
    rate_limit:         RateLimitConfig       = Field(default_factory=RateLimitConfig)
    execution_budget:   ExecutionBudgetConfig = Field(default_factory=ExecutionBudgetConfig)
    approvals:          ApprovalsConfig       = Field(default_factory=ApprovalsConfig)




class AuditSigningConfig(BaseModel, frozen=True, extra="forbid"):
    """HMAC-SHA256 signing for audit events. Mitigates T8 (Repudiation).

    The signing key is resolved via SecretsProvider (secret:// URI).
    When enabled, every AuditEvent gets a `signature` field before emission.
    Verification: shai audit verify --file logs/audit.jsonl --secret ENV_VAR
    """
    enabled: bool = False
    secret:  str  = ""    # secret://ENV_VAR resolved at startup

    @model_validator(mode="after")
    def _enabled_needs_secret(self) -> AuditSigningConfig:
        if self.enabled and not self.secret:
            raise ValueError("audit.signing.secret is required when signing is enabled")
        return self


class PatternsDBConfig(BaseModel, frozen=True, extra="forbid"):
    """Signed pattern database consumed at startup.

    The signing key is resolved via SecretsProvider (secret:// URI) — the same
    secret `shai patterns apply` signs with. When enabled, from_yaml() loads
    HMAC-SHA256 verified rules from `path` and merges them into the
    injection-family scanner catalogs. Rows failing verification are skipped,
    never fatal: a tampered row must not take the harness down, and the bundled
    YAML catalog stays active regardless.

    `path` also backs the heuristic-candidate cache — both tables live in the
    same DB file the CLI writes.
    """
    enabled: bool = False
    path:    str  = "state/patterns.db"
    secret:  str  = ""    # secret://ENV_VAR resolved at startup

    @model_validator(mode="after")
    def _enabled_needs_secret(self) -> PatternsDBConfig:
        if self.enabled and not self.secret:
            raise ValueError("patterns_db.secret is required when patterns_db is enabled")
        return self


class ToolResultScanConfig(BoundaryConfig):
    """Configuration for the scan_tool_result boundary.

    Scans tool return values before they re-enter the LLM context.
    Mitigates T6 indirect prompt injection (injected content in tool results).
    Configured injection_scan instances use the common and input catalogs.
    """
    enabled: bool = False


class SourceConfig(BaseModel, frozen=True, extra="forbid"):
    """Configuration for one tool source declared in harness.yaml.

    Local sources (transport: local | skill) use already-registered tools —
    no url needed. An MCP source is declared here by name only — no url,
    credentials, or allow-lists; those come entirely from the manifest file
    resolved by convention at `<mcp_manifests_dir>/<name>.yaml` — see
    `harness.mcp.manifest` and `harness.mcp.discovery`. A `transport: mcp`
    entry with no matching, approved manifest is not built into a live
    source at all (see harness.mcp.discovery) — this entry only declares
    that the name exists and governs its `required` handling.

    tags:         tags applied to ALL tools returned by this source, merged with
                  any tags declared on individual tools.
    required:     when True (default), a missing or failed source raises ConfigError
                  at load_agent() time — the agent is not usable without it. Set to
                  False for optional enrichment sources where degraded operation is
                  acceptable (e.g. a telemetry source that is nice-to-have). For an
                  MCP source, this also governs a manifest with no approved baseline:
                  required=True fails agent load; required=False is skipped.
    """
    name:        str
    transport:   Transport = Transport.LOCAL
    tags:        list[str] = Field(default_factory=list)
    tool_names:  list[str] = Field(default_factory=list)  # subset of tools to expose
    required:    bool      = True
    # required=True (default): missing or failed source raises ConfigError at load_agent() time.
    # required=False: missing or failed source is logged and skipped — use for
    #                 optional enrichment sources where degraded operation is acceptable.


class PolicyConfig(BaseModel, frozen=True, extra="forbid"):
    """Inline policy configuration.

    engine: which PolicyEngine gates tool calls and source activation.
            The built-in `rules` evaluator.

            An engine that cannot be built is fatal — a harness with no policy
            engine allows every tool call.

    source_rules:
            Which sources activate, evaluated by evaluate_source(). Every entry
            is `action: suppress`. Match on `source_tags`, `transport`,
            `agent_ids`, `sub_agent_ids` — a source rule scoped by a tool-level
            field is rejected here rather than silently ignored, because a
            narrowing rule that matches nothing narrows nothing.

            Per-tool-call policy is not here. An agent's tools are governed by
            its own config; an MCP source's tools by its manifest.

    forbidden_tag_combinations:
            Tag sets no single agent may declare together. Each entry is a list
            of two or more tags; an agent whose `allowed_tags` is a superset of
            any entry is rejected at load, before it can be registered.

            The list lives here rather than in the agent file on purpose: an
            agent declaring the combinations it may not hold would be declaring
            its own limits.

                policy:
                  forbidden_tag_combinations:
                    - [sensitive, external_write]
    """
    engine: AdapterRef = Field(default_factory=lambda: AdapterRef(name="rules"))
    source_rules: list[dict[str, Any]] = Field(default_factory=list)
    forbidden_tag_combinations: list[list[str]] = Field(default_factory=list)

    # Fields _match_source cannot honour. Accepting one would turn a rule the
    # operator wrote to narrow an activation into one that matches every source.
    _SOURCE_UNSUPPORTED = ("tool_names", "tool_tags", "any", "all", "not")

    @model_validator(mode="after")
    def _source_rules_are_source_scoped(self) -> PolicyConfig:
        for raw in self.source_rules:
            rule_id = raw.get("id", "<no id>")
            if raw.get("action") != "suppress":
                raise ValueError(
                    f"policy.source_rules[{rule_id!r}]: action must be 'suppress' — "
                    f"source rules decide which sources activate, not tool calls"
                )
            used = [f for f in self._SOURCE_UNSUPPORTED if (raw.get("match") or {}).get(f)]
            if used:
                raise ValueError(
                    f"policy.source_rules[{rule_id!r}]: match field(s) {used} are "
                    f"tool-scoped and cannot match a source. Use source_tags, "
                    f"transport, agent_ids or sub_agent_ids."
                )
            # Parse here so a malformed rule fails at config load, naming the
            # field. parsed_source_rules() is then total, and from_yaml() never
            # has to guess what went wrong.
            from harness.agents.agent_config import RuleConfig
            try:
                RuleConfig.model_validate(raw)
            except ValidationError as e:
                bad = ", ".join(
                    ".".join(str(x) for x in err["loc"]) for err in e.errors()
                )
                raise ValueError(
                    f"policy.source_rules[{rule_id!r}]: invalid field(s): {bad}"
                ) from e
        return self

    @field_validator("forbidden_tag_combinations")
    @classmethod
    def _valid_combinations(cls, v: list[list[str]]) -> list[list[str]]:
        for combo in v:
            if len(set(combo)) < 2:
                raise ValueError(
                    f"forbidden_tag_combinations entry must name at least two "
                    f"distinct tags, got: {combo!r}"
                )
        return v

    def parsed_source_rules(self) -> list:
        """Source-activation rules as RuleConfig objects. Called by from_yaml()."""
        from harness.agents.agent_config import RuleConfig
        return [RuleConfig.model_validate(r) for r in self.source_rules]

    def forbidden_tag_sets(self) -> list[frozenset[str]]:
        """Combinations as sets, for AgentRegistry. Called by from_yaml()."""
        return [frozenset(c) for c in self.forbidden_tag_combinations]


class MCPMetadataScanConfig(BaseModel, frozen=True, extra="forbid"):
    """Configuration for the scan_mcp_metadata boundary.

    Scans tool names, descriptions, and argument schemas received from
    MCP servers' tools/list response before registration.

    block_at defaults to MEDIUM (unlike other boundaries which default to HIGH)
    because almost no legitimate content in tool metadata looks like an injection.
    A tool description containing 'ignore all previous instructions' has no
    benign interpretation.

    action:
      block — refuse to register a tool whose metadata reaches block_at (default)
      alert — register it anyway and record the finding, for observe-before-enforce
              rollout. `redact` has no meaning here: the tool description is what
              is being judged, and a partially-redacted one still reaches the LLM.

    Default scanner: mcp_metadata_scan (MCPMetadataScanner).
    """
    enabled:  bool       = True
    block_at: Severity   = Severity.MEDIUM
    action:   ScanAction = ScanAction.BLOCK
    scanners: list[AdapterRef] = Field(
        default_factory=lambda: [AdapterRef(name="mcp_metadata_scan")]
    )

    @model_validator(mode="after")
    def _action_supported(self) -> MCPMetadataScanConfig:
        if self.action == ScanAction.REDACT:
            raise ValueError(
                "scan_mcp_metadata.action does not support 'redact' — a tool "
                "description is registered whole or not at all. Use 'block' or 'alert'."
            )
        return self


class MCPBaselineConfig(BaseModel, frozen=True, extra="forbid"):
    """Signed local store of approved MCP manifest hashes.

    A `transport: mcp` source (see SourceConfig) is only ever built —
    connected, tools registered — for a name whose manifest hash matches an
    approved record here at startup (see harness.mcp.discovery); an
    unapproved or hash-mismatched name is never built at all. Once built,
    though, the source stays connected even if its manifest changes
    mid-session — checked again on every check_tool_call for that source
    (the gate's R3 pre-gate check, harness.mcp.gate.McpBaselineGate), which
    is what catches a manifest edited after startup without needing a
    restart; approval stops *actions* from a built source, not its
    connection, the same posture agent revocation takes (see
    RevocationConfig). `shai mcp onboard` is the only writer — a clean
    onboarding pass auto-records `{id, file_hash, recorded_at}`.

    The signing key is resolved via SecretsProvider (secret:// URI), and is
    deliberately its own secret rather than reusing patterns_db.secret or
    audit_signing.secret — approving an MCP manifest is a distinct trust
    action from either.

    cache_ttl_seconds:
        How long a check is cached on the gate's hot path, per source. **This
        is the re-onboarding/kill latency** — editing a manifest (or running
        `shai mcp onboard`) takes effect on calls to that source within one
        TTL. 0 disables caching: every gate call re-hashes the manifest file
        and re-reads the baseline store.
    """
    path:              str   = "state/mcp_baseline.db"
    secret:            str   = ""    # secret://ENV_VAR resolved at startup
    cache_ttl_seconds: float = Field(default=5.0, ge=0, le=300)


class HarnessConfig(BaseModel, frozen=True, extra="forbid"):
    version:         int = 1
    tenant_id:       str = "default"
    normalization:        NormalizationConfig      = Field(default_factory=NormalizationConfig)
    session:              ThreatAccumulatorConfig  = Field(default_factory=ThreatAccumulatorConfig)
    scan_input:      BoundaryConfig
    scan_file:       FileScanConfig       = Field(default_factory=FileScanConfig)
    scan_tool_result:    ToolResultScanConfig    = Field(default_factory=ToolResultScanConfig)
    scan_mcp_metadata:   MCPMetadataScanConfig   = Field(default_factory=MCPMetadataScanConfig)
    check_tool_call:     ToolCallGateConfig      = Field(default_factory=ToolCallGateConfig)
    scan_output:         BoundaryConfig
    policy:          PolicyConfig = Field(default_factory=PolicyConfig)
    # Declared here so `extra="forbid"` accepts the block and `shai validate`
    # can see it. The provider itself is built from the *raw* block before
    # validation (config/loader.build_secrets_provider) — it is what resolves
    # the secret:// URIs the rest of this config holds.
    secrets:         AdapterRef = Field(default_factory=lambda: AdapterRef(name="env"))
    audit_sinks:     list[AdapterRef] = Field(default_factory=list)
    sources:         list[SourceConfig]  = Field(default_factory=list)
    audit_signing:   AuditSigningConfig  = Field(default_factory=AuditSigningConfig)
    patterns_db:     PatternsDBConfig    = Field(default_factory=PatternsDBConfig)
    connectivity:    ConnectivityConfig   = Field(default_factory=ConnectivityConfig)
    revocation:      RevocationConfig     = Field(default_factory=RevocationConfig)
    mcp_manifests_dir: str | None = None
    # Base directory a declared `transport: mcp` source name resolves against:
    # <mcp_manifests_dir>/<name>.yaml — see harness.mcp.discovery. Not scanned;
    # a name with no `sources:` entry is invisible to the harness. None
    # (default) means no MCP sources can be declared.
    mcp_baseline:      MCPBaselineConfig = Field(default_factory=MCPBaselineConfig)

    @model_validator(mode="after")
    def _mcp_sources_need_baseline_config(self) -> HarnessConfig:
        has_mcp_sources = any(s.transport == Transport.MCP for s in self.sources)
        if has_mcp_sources and not self.mcp_manifests_dir:
            raise ValueError(
                "mcp_manifests_dir is required when sources: declares a transport: mcp entry"
            )
        if has_mcp_sources and not self.mcp_baseline.secret:
            raise ValueError(
                "mcp_baseline.secret is required when sources: declares a transport: mcp entry"
            )
        return self
