"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.context import AgentContext

FIXTURES = Path(__file__).parent / "fixtures"
AGENTS   = FIXTURES / "agents"


@pytest.fixture
def ctx() -> AgentContext:
    return AgentContext(
        agent_id="orchestrator_agent",
    )


@pytest.fixture
def sub_ctx() -> AgentContext:
    return AgentContext(
        agent_id="orchestrator_agent",
        sub_agent_id="research_sub",
        allowed_tags=["read", "internal"],
    )


@pytest.fixture
def orchestrator_yaml() -> Path:
    return AGENTS / "orchestrator_agent.yaml"


@pytest.fixture
def research_yaml() -> Path:
    return AGENTS / "research_agent.yaml"


@pytest.fixture
def harness_yaml() -> Path:
    return FIXTURES / "harness.yaml"
