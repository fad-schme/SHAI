"""AgentRegistry — runtime-managed in-memory registry of AgentConfig instances.

Operator-driven: no file watching, no automatic reload.
All public methods are async for consistency with the facade.
get() is intentionally sync — required so scope_context_for_subagent stays sync.

Concurrency: threading.Lock protects writes; GIL-safe dict reads on hot path.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from harness.agents.agent_config import AgentConfig
from harness.core.errors import (
    AgentConflictError,
    AgentNotRegisteredError,
    ConfigError,
)

log = logging.getLogger(__name__)


class AgentRegistry:

    def __init__(self) -> None:
        self._agents: dict[str, AgentConfig] = {}
        self._lock = threading.Lock()

    async def load(self, path: str | Path) -> AgentConfig:
        """Validate and register an agent-xx.yaml file.

        Idempotent on identical content.
        Raises AgentConflictError if same id registered with different content.
        Raises ConfigError on invalid file.
        """
        config = await asyncio.to_thread(self._parse, Path(path))
        with self._lock:
            existing = self._agents.get(config.id)
            if existing is not None:
                if existing == config:
                    return existing
                raise AgentConflictError(
                    f"agent '{config.id}' already registered with different content; "
                    "use reload_agent() to replace it",
                    agent_id=config.id,
                    op="load_agent",
                )
            self._agents[config.id] = config
        log.info("agent loaded", extra={"agent_id": config.id, "op": "load_agent"})
        return config

    async def reload(self, path: str | Path) -> AgentConfig:
        """Validate and atomically replace an existing agent definition.

        Invalid file: raises ConfigError, old definition kept intact.
        Unknown agent_id: raises AgentNotRegisteredError.
        """
        config = await asyncio.to_thread(self._parse, Path(path))
        with self._lock:
            if config.id not in self._agents:
                raise AgentNotRegisteredError(
                    f"agent '{config.id}' not registered; use load_agent() first",
                    agent_id=config.id,
                    op="reload_agent",
                )
            self._agents[config.id] = config
        log.info("agent reloaded", extra={"agent_id": config.id, "op": "reload_agent"})
        return config

    async def deregister(self, agent_id: str) -> None:
        """Remove an agent. Raises AgentNotRegisteredError if not found."""
        with self._lock:
            if agent_id not in self._agents:
                raise AgentNotRegisteredError(
                    f"agent '{agent_id}' not registered",
                    agent_id=agent_id,
                    op="deregister_agent",
                )
            del self._agents[agent_id]
        log.info("agent deregistered", extra={"agent_id": agent_id})

    def get(self, agent_id: str) -> AgentConfig:
        """HOT PATH — sync, lock-free dict read.

        Must stay sync so scope_context_for_subagent remains a pure sync function.
        Raises AgentNotRegisteredError on miss.
        """
        config = self._agents.get(agent_id)
        if config is None:
            raise AgentNotRegisteredError(
                f"agent '{agent_id}' not registered",
                agent_id=agent_id,
                op="check_tool_call",
            )
        return config

    async def list(self) -> list[AgentConfig]:
        """Return all registered agents in registration order."""
        return list(self._agents.values())

    @staticmethod
    def _parse(path: Path) -> AgentConfig:
        """Read, parse, validate. Runs in thread executor (called via asyncio.to_thread)."""
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            raise ConfigError(f"cannot read agent file {path}: {e}", op="load_agent") from e

        try:
            data: Any = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise ConfigError(f"invalid YAML in {path}: {e}", op="load_agent") from e

        if not isinstance(data, dict):
            raise ConfigError(
                f"{path} must be a YAML mapping, got {type(data).__name__}",
                op="load_agent",
            )

        try:
            return AgentConfig.model_validate(data)
        except ValidationError as e:
            first = e.errors()[0]
            loc = " → ".join(str(x) for x in first["loc"])
            msg = first["msg"]
            raise ConfigError(
                f"agent config validation failed [{path}]: {loc}: {msg}",
                op="load_agent",
            ) from e
