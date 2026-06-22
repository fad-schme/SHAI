"""Pydantic schema for harness.yaml.

All models use extra="forbid" — typos in YAML surface at load time.
Every field maps to a consumer in the codebase.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from harness.core.errors import ConfigError
from harness.core.types import Severity, Transport


class AdapterRef(BaseModel, frozen=True, extra="forbid"):
    name:   str
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("adapter name must be non-empty")
        return v


class ToolSourceConfig(BaseModel, frozen=True, extra="forbid"):
    name:        str
    transport:   Transport
    tags:        list[str] = Field(default_factory=list)
    tools:       list[str] = Field(default_factory=list)   # skill only
    url:         str | None = None                          # mcp only
    credentials: dict[str, str] = Field(default_factory=dict)  # secret:// refs
    config:      dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _transport_constraints(self) -> "ToolSourceConfig":
        if self.transport == Transport.SKILL and not self.tools:
            raise ValueError(f"source '{self.name}': tools required for skill transport")
        if self.transport == Transport.MCP and not self.url:
            raise ValueError(f"source '{self.name}': url required for mcp transport")
        return self


class BoundaryConfig(BaseModel, frozen=True, extra="forbid"):
    enabled:  bool = True
    block_at: Severity = Severity.HIGH
    scanners: list[AdapterRef] = Field(default_factory=list)

    @model_validator(mode="after")
    def _enabled_needs_scanners(self) -> "BoundaryConfig":
        if self.enabled and not self.scanners:
            raise ValueError("scanners must be non-empty when boundary is enabled")
        return self


class ToolCallGateConfig(BaseModel, frozen=True, extra="forbid"):
    """No enabled flag — the gate is mandatory."""
    arg_scanners:       list[AdapterRef] = Field(default_factory=list)
    scan_args_for_tags: list[str]        = Field(default_factory=lambda: ["sensitive"])


class AgentsConfig(BaseModel, frozen=True, extra="forbid"):
    directory: str | None = None  # informational only; harness does not watch


class LoggingConfig(BaseModel, frozen=True, extra="forbid"):
    level: str = "INFO"
    json_format: bool = True

    @field_validator("level")
    @classmethod
    def _valid_level(cls, v: str) -> str:
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ValueError(f"invalid log level: {v!r}")
        return v


class HarnessConfig(BaseModel, frozen=True, extra="forbid"):
    version:         int = 1
    scan_input:      BoundaryConfig
    check_tool_call: ToolCallGateConfig = Field(default_factory=ToolCallGateConfig)
    scan_output:     BoundaryConfig
    policy:          AdapterRef
    audit_sinks:     list[AdapterRef]
    tool_registry:   AdapterRef = Field(default_factory=lambda: AdapterRef(name="memory"))
    secrets:         AdapterRef = Field(default_factory=lambda: AdapterRef(name="env"))
    tool_sources:    list[ToolSourceConfig] = Field(default_factory=list)
    agents:          AgentsConfig = Field(default_factory=AgentsConfig)
    logging:         LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("audit_sinks")
    @classmethod
    def _sinks_non_empty(cls, v: list[AdapterRef]) -> list[AdapterRef]:
        if not v:
            raise ValueError("audit_sinks must contain at least one sink")
        return v
