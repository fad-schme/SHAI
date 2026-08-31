"""mcp/gate.py — the tool-call-gate enforcement point for MCP manifest
onboarding approval.

Approval is checked on every `check_tool_call` for an MCP-sourced tool (the
facade's R3 pre-gate check, `SHAI.check_tool_call`) — not once at
`from_yaml()` or `load_agent()`. A manifest edited mid-session (or freshly
approved by `shai mcp onboard`) takes effect on the next call within one
`cache_ttl_seconds`, the same latency model
`harness.agents.revocation.RevocationStore` uses for the agent kill switch.

A source is only ever built — connected and its tools registered — for a
name with an approved, matching baseline record at startup (see
`harness.mcp.discovery`); an unapproved or hash-mismatched name is never
built at all. Once built, though, a source stays connected even if its
manifest is edited mid-session — this gate stops *actions*, not connection,
the same posture agent revocation takes (see `revocation.py`'s module
docstring). A manifest edited after the harness started denies every tool
call against that source until `shai mcp onboard` (re-)approves it — no
restart needed.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from harness.mcp.baseline import lookup_baseline
from harness.mcp.manifest import manifest_file_hash

log = logging.getLogger(__name__)


class McpBaselineGate:
    """One instance per SHAI facade. Maps MCP source_name -> manifest path,
    and checks each against the signed baseline store behind a bounded
    per-source cache.

    Construct with an empty `manifest_paths` to disable entirely: `check()`
    then always returns (True, None) and no file or DB is ever touched —
    matches `RevocationStore`'s `path=None` disabled posture.
    """

    def __init__(
        self,
        manifest_paths: dict[str, Path],
        *,
        baseline_path: str | Path,
        secret: bytes,
        cache_ttl_seconds: float = 5.0,
    ) -> None:
        self._manifest_paths = dict(manifest_paths)
        self._baseline_path = baseline_path
        self._secret = secret
        self._ttl = cache_ttl_seconds
        self._cached: dict[str, tuple[bool, str | None]] = {}
        self._loaded_at: dict[str, float] = {}

    def check(self, source_name: str) -> tuple[bool, str | None]:
        """(approved, deny_reason). Hot path — cached per source_name.

        (True, None) for a source_name this gate doesn't know about — a
        local source, or an MCP source not currently discovered — there is
        nothing to gate here; an unknown MCP source_name is already denied
        earlier, at layer 1 (tool not registered) or layer 4 (not in the
        agent's tool map).
        """
        path = self._manifest_paths.get(source_name)
        if path is None:
            return True, None

        # Checked ahead of the cache, deliberately. A missing manifest is the
        # approved artifact being gone, not a transient read error, and it must
        # not wait out a TTL behind a cached approve — deleting the manifest is
        # the most direct way an operator revokes a source. Also drops any
        # cached verdict, so restoring the file re-verifies rather than
        # resurrecting the old one.
        if not path.is_file():
            self._cached.pop(source_name, None)
            self._loaded_at.pop(source_name, None)
            log.error("mcp manifest missing — denying",
                      extra={"source": source_name, "path": str(path)})
            return False, (
                f"MCP source '{source_name}' manifest is missing at {path} — "
                f"approval cannot be verified. Restore it, or remove the "
                f"source from sources: in harness.yaml"
            )

        now = time.monotonic()
        last = self._loaded_at.get(source_name, 0.0)
        if source_name not in self._cached or (now - last) >= self._ttl:
            self._cached[source_name] = self._evaluate(source_name, path)
            self._loaded_at[source_name] = now
        return self._cached[source_name]

    def _evaluate(self, source_name: str, path: Path) -> tuple[bool, str | None]:
        """Never raises.

        A missing manifest is caught by check() before the cache is consulted
        and never reaches here. Any other read failure keeps the last known verdict (the
        fail-safe-continuity posture RevocationStore takes on its file), or
        denies if there is no prior verdict — unlike revocation's
        default-allow, an MCP source defaults to unapproved.
        """
        try:
            current_hash = manifest_file_hash(path)
            baseline = lookup_baseline(self._baseline_path, source_name, self._secret)
        except Exception as e:
            if source_name in self._cached:
                log.error(
                    "mcp baseline check failed — keeping last known verdict",
                    extra={"source": source_name, "path": str(path),
                           "error": type(e).__name__},
                )
                return self._cached[source_name]
            log.error(
                "mcp baseline check failed on first check — denying",
                extra={"source": source_name, "path": str(path),
                       "error": type(e).__name__},
            )
            return False, f"MCP source '{source_name}' baseline check failed"

        if baseline is None:
            return False, (
                f"MCP source '{source_name}' needs onboarding — no approved "
                f"baseline for {path}. Run: "
                f"shai mcp onboard {path} --config <harness.yaml>"
            )
        if baseline["file_hash"] != current_hash:
            return False, (
                f"MCP source '{source_name}' manifest changed since it was "
                f"approved — re-onboarding required. Run: "
                f"shai mcp onboard {path} --config <harness.yaml>"
            )
        return True, None
