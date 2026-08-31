"""mcp/reconciliation.py — manifest-vs-live tool comparison for onboarding.

The manifest is authoritative for what gets registered (harness.tools.source
uses it, not the live response, at runtime — see MCPSource._fetch_tools).
This module is the check that makes that trustworthy: it compares what the
manifest declares against what the live server's tools/list actually returns,
so a compromised server can't get a different description in front of the
LLM just by changing its own response — the comparison itself catches it.

Four cases (see spec):
  declared + present, compatible          → clean, no finding
  declared, absent from live server        → soft warning, never fails onboarding
  present, undeclared                      → dropped, informational only
  declared, live description diverges      → finding that DOES fail onboarding
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from harness.mcp.manifest import MCPManifest

# Below this similarity ratio, a live description is considered to have
# "diverged" from the manifest's declared text — not just reworded.
_DESCRIPTION_SIMILARITY_FLOOR = 0.6


class ReconciliationResult(BaseModel, frozen=True):
    absent:                list[str] = []   # declared, not live — soft warning
    undeclared:             list[str] = []   # live, not declared — informational
    description_mismatches: list[str] = []   # declared, live diverges — fails onboarding

    @property
    def fails_onboarding(self) -> bool:
        return bool(self.description_mismatches)


def _normalized_words(text: str) -> set[str]:
    return {w for w in text.lower().split() if w}


def _descriptions_diverge(declared: str, live: str) -> bool:
    """True when the live description no longer resembles the declared one.

    Jaccard similarity over whitespace-split words — cheap, deterministic,
    tolerant of light rewording (typo fixes, punctuation) while catching a
    wholesale description swap. Either side empty and the other not is
    always a divergence; both empty is not (nothing to compare).
    """
    declared_words = _normalized_words(declared)
    live_words = _normalized_words(live)
    if not declared_words and not live_words:
        return False
    if not declared_words or not live_words:
        return True
    intersection = declared_words & live_words
    union = declared_words | live_words
    similarity = len(intersection) / len(union)
    return similarity < _DESCRIPTION_SIMILARITY_FLOOR


def reconcile(manifest: MCPManifest, live_tools: list[dict[str, Any]]) -> ReconciliationResult:
    """Compare manifest.tools against a live tools/list response.

    live_tools: raw tool dicts as returned by tools/list (each with at least
    "name", optionally "description").
    """
    live_by_name = {
        str(t.get("name") or "").strip(): t
        for t in live_tools
        if str(t.get("name") or "").strip()
    }
    declared_names = {t.name for t in manifest.tools}

    absent: list[str] = []
    mismatches: list[str] = []
    for tool in manifest.tools:
        live = live_by_name.get(tool.name)
        if live is None:
            absent.append(tool.name)
            continue
        live_description = str(live.get("description") or "")
        if _descriptions_diverge(tool.description, live_description):
            mismatches.append(tool.name)

    undeclared = sorted(name for name in live_by_name if name not in declared_names)

    return ReconciliationResult(
        absent=sorted(absent),
        undeclared=undeclared,
        description_mismatches=sorted(mismatches),
    )
