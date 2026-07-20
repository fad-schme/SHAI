"""Scanner Protocol and ScanResult.

ScanResult is internal — boundaries aggregate Scanner results into ScanVerdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.verdicts import Finding


@dataclass
class ScanResult:
    """Output of one scanner on one text. Internal — not part of public API."""
    findings:      list[Finding] = field(default_factory=list)
    redacted_text: str | None = None


class Scanner(Protocol):
    """Inspect text and return findings. All async — production scanners are network-bound."""

    name: str

    async def scan(
        self,
        text: str,
        ctx: AgentContext,
    ) -> ScanResult:
        """Inspect text. Return findings and optional redacted form.

        Pure from the boundary's perspective — no side effects, no audit emission.
        Async because production scanners (Purview, Nightfall, Lakera) make
        HTTP calls. Reference scanners (regex) return immediately.

        Never include raw matched text in Finding.detail — category + severity
        is what audit consumers act on.
        """
        ...
