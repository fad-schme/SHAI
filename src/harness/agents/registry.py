"""AgentRegistry — in-memory registry for AgentConfig objects.

register / deregister / get / list, plus load(path) and reload(path) for
file-based agent registration.

get() is intentionally sync — required so scope_context_for_subagent
stays a pure sync function on the hot path.

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
    """In-memory registry for AgentConfig objects.

    Adds load(path) and reload(path) — file-based operations.
    get() is sync — hot path requirement for scope_context_for_subagent.
    """

    def __init__(
        self,
        *,
        forbidden_tag_combinations: list[frozenset[str]] | None = None,
    ) -> None:
        self._agents: dict[str, AgentConfig] = {}
        self._lock = threading.Lock()
        self._forbidden_tags = list(forbidden_tag_combinations or [])

    def register(self, item: AgentConfig) -> bool:
        """True = newly registered. False = identical already existed.
        Raises AgentConflictError if same id registered with different content.
        Raises ConfigError if allowed_tags contains a forbidden combination.
        """
        self._check_forbidden_tags(item)
        with self._lock:
            existing = self._agents.get(item.id)
            if existing is None:
                self._agents[item.id] = item
                log.info("agent registered", extra={"agent_id": item.id})
                return True
            if existing == item:
                return False  # idempotent
            raise AgentConflictError(
                f"agent '{item.id}' already registered with different content; "
                "use reload() to replace it",
                agent_id=item.id,
                op="register_agent",
            )

    def deregister(self, item: AgentConfig) -> bool:
        """True = removed. False = was not registered."""
        with self._lock:
            if item.id in self._agents:
                del self._agents[item.id]
                log.info("agent deregistered", extra={"agent_id": item.id})
                return True
            return False

    def get(self, agent_id: str) -> AgentConfig:
        """HOT PATH — sync, lock-free.

        Sync override of the async Protocol method — required so
        scope_context_for_subagent remains a pure sync function.
        Raises AgentNotRegisteredError on miss.
        """
        config = self._agents.get(agent_id)
        if config is None:
            raise AgentNotRegisteredError(
                f"agent '{agent_id}' not registered",
                agent_id=agent_id,
                op="get_agent",
            )
        return config

    def list(self) -> list[AgentConfig]:
        return list(self._agents.values())

    # ── File-based operations (agent-specific) ────────────────────────────

    async def load(self, path: str | Path) -> AgentConfig:
        """Parse, validate, and register an agent-xx.yaml file.

        Idempotent on identical content.
        Raises AgentConflictError if same id registered with different content.
        Raises ConfigError on invalid file or schema.
        """
        config = await asyncio.to_thread(self._parse, Path(path))
        self.register(config)
        log.info("agent loaded", extra={"agent_id": config.id, "path": str(path)})
        return config

    async def reload(self, path: str | Path) -> AgentConfig:
        """Parse, validate, and atomically replace an existing agent definition.

        Raises AgentNotRegisteredError if agent_id not already registered.
        Raises ConfigError on invalid file — old definition kept intact.
        """
        config = await asyncio.to_thread(self._parse, Path(path))
        # reload() replaces in place and does not go through register(), so the
        # forbidden-combination check has to be repeated here.
        self._check_forbidden_tags(config)
        with self._lock:
            if config.id not in self._agents:
                raise AgentNotRegisteredError(
                    f"agent '{config.id}' not registered; use load() first",
                    agent_id=config.id,
                    op="reload_agent",
                )
            self._agents[config.id] = config
        log.info("agent reloaded", extra={"agent_id": config.id, "path": str(path)})
        return config

    # ── Internal ──────────────────────────────────────────────────────────

    def _check_forbidden_tags(self, item: AgentConfig) -> None:
        """Reject an agent whose declared capability set is a toxic combination.

        Checked in register() rather than in AgentConfig — the combinations come
        from harness.yaml, which the model validator cannot see, and register()
        is the single choke point every load path goes through.

        Only the agent's own allowed_tags are checked: a subagent's tags are a
        subset of its parent's (Invariant 4), so a combination the parent does
        not hold is unreachable below it.
        """
        declared = set(item.allowed_tags)
        for combo in self._forbidden_tags:
            if combo <= declared:
                raise ConfigError(
                    f"agent '{item.id}': allowed_tags declares the forbidden "
                    f"combination {sorted(combo)}",
                    op="load_agent",
                )

    @staticmethod
    def _parse(path: Path) -> AgentConfig:
        """Read, parse, validate. Runs in thread executor."""
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            raise ConfigError(f"cannot read agent file {path}: {e}",
                              op="load_agent") from e
        try:
            data: Any = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise ConfigError(f"invalid YAML in {path}: {e}",
                              op="load_agent") from e
        if not isinstance(data, dict):
            raise ConfigError(
                f"{path} must be a YAML mapping, got {type(data).__name__}",
                op="load_agent",
            )
        try:
            return AgentConfig.model_validate(data)
        except ValidationError as e:
            first = e.errors()[0]
            loc   = " → ".join(str(x) for x in first["loc"])
            raise ConfigError(
                f"agent config validation failed [{path}]: {loc}: {first['msg']}",
                op="load_agent",
            ) from e
