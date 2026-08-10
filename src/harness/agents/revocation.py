"""Agent revocation — the kill switch's enforcement half.

Per-agent containment already worked: `maintenance.deregister_agent()` drops an agent's
tools, limits, rate-limiter and budget, after which every `check_tool_call` for
it denies at the pre-gate, leaving other agents running. What was missing is a
way to trigger that from *outside* the process — it is a method on a live SHAI
handle, useless to an operator watching an agent misbehave.

This module is that trigger. Two operator surfaces write the same file:

    SHAI.maintenance.revoke_agent("billing_agent")   # in-process, applies immediately
    shai agent revoke billing_agent        # separate process

A CLI cannot reach another process's memory, so a file is the medium between
them. The gate reads it at the pre-gate behind a bounded cache, and
**`cache_ttl_seconds` is the kill latency** — an operator's revocation takes
effect within one TTL, so the number is named in config rather than left as an
accident of implementation.

Three properties are deliberate:

- **Persistent.** A restart must not un-kill a killed agent. That is the
  opposite of what an operator expects under incident pressure.
- **A read error never resurrects.** On a failed read the last known set is
  kept and the error logged. Failing open is a kill switch that silently
  stopped working; failing closed on an unreadable file would deny every agent
  in the process.
- **Agent-scoped only.** Tool- and source-level denial is what policy rules are
  for; a second way to express it would be a parallel path to gate layer 5.

Revocation stops *actions*, not conversation: it denies at the tool-call gate,
the same place `maintenance.deregister_agent()` does. Scan boundaries are unaffected.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)


class RevocationStore:
    """Reads and writes the revocation file. One instance per SHAI facade.

    Construct with path=None to disable revocation entirely: `is_revoked()`
    then always returns False and no file is ever touched.
    """

    def __init__(self, path: str | Path | None, *, cache_ttl_seconds: float = 5.0) -> None:
        self._path = Path(path) if path else None
        self._ttl = cache_ttl_seconds
        self._revoked: frozenset[str] = frozenset()
        self._loaded_at: float = 0.0
        if self._path is not None:
            # Prime the cache so the first gate call does not pay the read, and
            # so a broken file surfaces at startup rather than mid-incident.
            self._refresh(force=True)

    @property
    def enabled(self) -> bool:
        return self._path is not None

    def is_revoked(self, agent_id: str) -> bool:
        """True when this agent is revoked. Hot path — cached."""
        if self._path is None:
            return False
        self._refresh()
        return agent_id in self._revoked

    def revoked_agents(self) -> frozenset[str]:
        """The current revocation set, refreshed if the cache is stale."""
        if self._path is None:
            return frozenset()
        self._refresh()
        return self._revoked

    # ── Mutation ─────────────────────────────────────────────────────────

    def revoke(self, agent_id: str, *, reason: str | None = None) -> None:
        """Add an agent to the revocation file. Idempotent."""
        self._write({**self._read_entries(), agent_id: {
            "revoked_at": datetime.now(UTC).isoformat(),
            "reason": reason or "",
        }})
        log.warning("agent revoked", extra={"agent_id": agent_id, "op": "revoke_agent"})

    def restore(self, agent_id: str) -> bool:
        """Remove an agent from the revocation file. False if it was not there."""
        entries = self._read_entries()
        if agent_id not in entries:
            return False
        del entries[agent_id]
        self._write(entries)
        log.warning("agent restored", extra={"agent_id": agent_id, "op": "restore_agent"})
        return True

    # ── Internals ────────────────────────────────────────────────────────

    def _refresh(self, *, force: bool = False) -> None:
        if self._path is None:
            return
        now = time.monotonic()
        if not force and (now - self._loaded_at) < self._ttl:
            return
        try:
            self._revoked = frozenset(self._read_entries())
        except Exception as e:
            # Keep the previous set. Logged at error because a kill switch the
            # operator cannot read is an operational failure, even though the
            # last known revocations remain enforced.
            log.error("revocation file unreadable — keeping last known set",
                      extra={"op": "read_revocations", "path": str(self._path),
                             "revoked_count": len(self._revoked),
                             "error": type(e).__name__},
                      exc_info=True)
        self._loaded_at = now

    def _read_entries(self) -> dict[str, dict]:
        """Parse the file. A missing file is an empty set, not an error."""
        if self._path is None or not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        entries = data.get("revoked", {}) if isinstance(data, dict) else {}
        if not isinstance(entries, dict):
            raise ValueError("revocation file: 'revoked' must be an object")
        return entries

    def _write(self, entries: dict[str, dict]) -> None:
        if self._path is None:
            raise RuntimeError("revocation is not configured (no path)")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"revoked": entries}, indent=2, sort_keys=True)
        # Atomic replace: the gate in another process may read this file at any
        # moment, and a half-written one would parse as a failed read — which
        # keeps the *old* set, silently ignoring the revocation just written.
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, self._path)
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            raise
        # The writer sees its own write immediately; other processes wait a TTL.
        self._revoked = frozenset(entries)
        self._loaded_at = time.monotonic()
