"""Pydantic schema for harness.yaml.

All models use extra="forbid" — typos in YAML surface at load time.
Every field maps to a consumer in the codebase.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from harness.core.errors import ConfigError
from harness.core.types import Severity


class AdapterRef(BaseModel, frozen=True, extra="forbid"):
    name:   str
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("adapter name must be non-empty")
        return v



class BoundaryConfig(BaseModel, frozen=True, extra="forbid"):
    enabled:  bool = True
    block_at: Severity = Severity.HIGH
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
    scanners:            list[AdapterRef] = Field(default_factory=list)
    max_size_mb:         float        = 100.0

    @model_validator(mode="after")
    def _enabled_needs_scanners(self) -> "FileScanConfig":
        if self.enabled and not self.scanners:
            raise ValueError("scanners must be non-empty when scan_file is enabled")
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

class ToolCallGateConfig(BaseModel, frozen=True, extra="forbid"):
    """No enabled flag — the gate is mandatory."""
    arg_scanners:       list[AdapterRef] = Field(default_factory=list)
    scan_args_for_tags: list[str]        = Field(default_factory=lambda: ["sensitive"])
    rate_limit:         RateLimitConfig  = Field(default_factory=RateLimitConfig)




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
    enabled:  bool     = False
    block_at: Severity = Severity.HIGH


class HarnessConfig(BaseModel, frozen=True, extra="forbid"):
    version:         int = 1
    tenant_id:       str = "default"
    scan_input:      BoundaryConfig
    scan_file:       FileScanConfig       = Field(default_factory=lambda: FileScanConfig(enabled=False))
    scan_tool_result: ToolResultScanConfig = Field(default_factory=ToolResultScanConfig)
    check_tool_call: ToolCallGateConfig = Field(default_factory=ToolCallGateConfig)
    scan_output:     BoundaryConfig
    policy:          AdapterRef
    audit_sinks:     list[AdapterRef] = Field(default_factory=list)
    audit_signing:   AuditSigningConfig = Field(default_factory=AuditSigningConfig)


