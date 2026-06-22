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
    max_size_mb:          reject files above this size before any scanning.
    allowed_extensions:   whitelist of lowercase extensions (e.g. [".pdf", ".docx"]).
                          Empty list means all extensions are accepted.
    """
    enabled:             bool         = True
    block_at:            Severity     = Severity.HIGH
    scanners:            list[AdapterRef] = Field(default_factory=list)
    max_size_mb:         float        = 100.0
    allowed_extensions:  list[str]    = Field(default_factory=list)

    @model_validator(mode="after")
    def _enabled_needs_scanners(self) -> "FileScanConfig":
        if self.enabled and not self.scanners:
            raise ValueError("scanners must be non-empty when scan_file is enabled")
        return self


class ToolCallGateConfig(BaseModel, frozen=True, extra="forbid"):
    """No enabled flag — the gate is mandatory."""
    arg_scanners:       list[AdapterRef] = Field(default_factory=list)
    scan_args_for_tags: list[str]        = Field(default_factory=lambda: ["sensitive"])




class HarnessConfig(BaseModel, frozen=True, extra="forbid"):
    version:         int = 1
    tenant_id:       str = "default"
    scan_input:      BoundaryConfig
    scan_file:       FileScanConfig = Field(default_factory=lambda: FileScanConfig(enabled=False))
    check_tool_call: ToolCallGateConfig = Field(default_factory=ToolCallGateConfig)
    scan_output:     BoundaryConfig
    policy:          AdapterRef
    audit_sinks:     list[AdapterRef]
    tool_registry:   AdapterRef = Field(default_factory=lambda: AdapterRef(name="memory"))
    secrets:         AdapterRef = Field(default_factory=lambda: AdapterRef(name="env"))

    @field_validator("audit_sinks")
    @classmethod
    def _sinks_non_empty(cls, v: list[AdapterRef]) -> list[AdapterRef]:
        if not v:
            raise ValueError("audit_sinks must contain at least one sink")
        return v
