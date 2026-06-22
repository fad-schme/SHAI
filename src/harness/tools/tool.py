"""Tool descriptor — metadata only, never executable.

The harness gates; the agent dispatches. Tool is part of the public API.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from harness.core.types import Transport


class Tool(BaseModel, frozen=True):
    """Describes one tool the agent may dispatch.

    input_schema is opaque to the harness — pydantic model class, JSON schema
    dict, or anything the registered toolkit uses. The harness stores and
    surfaces it to PolicyEngine; it does not interpret or validate it.

    transport is immutable after registration — raising ConfigError on any
    attempt to re-register the same name with a different transport.
    """
    name:         str
    input_schema: Any = Field(default=None)
    tags:         list[str] = Field(default_factory=list)
    transport:    Transport = Transport.LOCAL
    description:  str | None = None

    @field_validator("name")
    @classmethod
    def _non_empty_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("tool name must be non-empty")
        return v

    def __hash__(self) -> int:
        return hash((self.name, self.transport, tuple(sorted(self.tags))))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Tool):
            return NotImplemented
        return (
            self.name == other.name
            and self.transport == other.transport
            and sorted(self.tags) == sorted(other.tags)
        )
