"""session_accumulator.py — cross-turn threat accumulator.

Detects crescendo attacks: escalation distributed across turns where each
individual turn stays below every per-turn scanner threshold.

Architecture
------------
Cross-cutting component, not a Scanner. Called by the SHAI facade:

  1. check(session_id)  — called BEFORE run_scan; reads persisted risk score
  2. record(...)        — called AFTER run_scan; writes turn row, recomputes score

Persistence
-----------
Backed by a state-store adapter (see adapters/state_store/base.py) rather
than a hardcoded database — `store.kv` holds one row per session, `store.log`
holds each session's per-turn history. Which backend that resolves to
(SQLite, in-process, or otherwise) is an operator config choice; this module
never imports a database driver.

Risk score is pre-computed and stored in the kv row so check() is one fast
get(). The expensive window read only happens in record(), after the verdict
is already returned to the caller.

Sliding window
--------------
record() always evaluates the LAST `window_size` turns for the session,
regardless of where in the conversation they are, via `store.log.tail()`.
This naturally covers any attack start offset — turns [3..7] are evaluated
the same as [1..5].

Signals (hashes and metadata only — never raw text)
----------------------------------------------------
- warn_rate:  fraction of last N turns that were WARN or BLOCK
- block_rate: fraction of last N turns that were BLOCK
- reframe:    last turn was BLOCK/WARN and current text_hash is similar
              to previous turn's text_hash (bigram Jaccard ≥ threshold)

Score formula (capped at 1.0):
  base  = block_rate * WEIGHT_BLOCK + warn_rate * WEIGHT_WARN
  bonus = WEIGHT_REFRAME  (added when reframe detected)
  score = min(1.0, base + bonus)

TTL
---
Sessions whose kv row's `updated_at` predates `ttl_hours` ago are purged by
record() at most once a minute (lazy GC): the session's kv row and its entire turn log
are deleted together. This is whole-*session* expiry, not per-turn expiry —
an active, low-traffic session's early turns must survive past `ttl_hours`
as long as the session itself keeps getting used; only an inactive session's
history is dropped.

on_escalation actions
---------------------
  block — return ScanVerdict(BLOCK); scanners never run
  flag  — return ScanVerdict(WARN);  scanners never run; content passes through
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import TYPE_CHECKING

from harness.core.types import OnError

if TYPE_CHECKING:
    from harness.adapters.state_store.base import StateStore

log = logging.getLogger(__name__)

# ── Weights ───────────────────────────────────────────────────────────────

WEIGHT_BLOCK   = 0.60
WEIGHT_WARN    = 0.25
WEIGHT_REFRAME = 0.30
WEIGHT_DENSITY = 0.25
# When a turn's consolidated risk crosses RISK_HIGH, treat it as if it were
# a BLOCK for cross-turn accumulation, even if no individual boundary blocked.
WEIGHT_TURN_RISK_HIGH = 0.35

# Whole-session expiry does not need to run on every turn: a session is stale
# for hours, and the sweep costs a listing plus a read per session.
_SWEEP_INTERVAL_S = 60.0

_SESSION_PREFIX = "session:"
_TURNS_PREFIX   = "turns:"

# ── Helpers ───────────────────────────────────────────────────────────────

def _number(value: object) -> float:
    """A stored numeric field, or ValueError: a row is only as trustworthy as
    the store it came from, and a null or string here must read as a damaged
    row, not surface later as a TypeError from a comparison."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"expected a number, got {type(value).__name__}")
    return float(value)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16]


def _bigrams(text: str) -> frozenset:
    """Return bigram tuples over word tokens. Always frozenset of (str, str)."""
    words = re.findall(r"\w+", text.lower())
    if len(words) < 2:
        # Pad with a sentinel so single-word texts still produce a bigram
        return frozenset(zip(words, [""] * len(words)))
    return frozenset(zip(words, words[1:]))


def _jaccard(a: frozenset, b: frozenset) -> float:
    """Similarity of two turns' bigram sets.

    Two empty sets score 0.0, unlike the identically-named helper in
    session_budget, which scores 1.0. Deliberate: empty here means a turn
    produced no bigrams, and claiming two such turns are a reframe of each
    other would manufacture escalation evidence out of silence.
    """
    u = len(a | b)
    return len(a & b) / u if u else 0.0


# ── Accumulator ───────────────────────────────────────────────────────────

class ThreatAccumulator:
    """State-store-backed cross-turn threat accumulator.

    One instance per SHAI facade. Task-safe: uses an asyncio Lock per
    session_id so concurrent turns on the same session serialize.
    """

    def __init__(
        self,
        store: StateStore,
        *,
        escalation_threshold: float = 0.70,
        window_size: int            = 10,
        reframe_similarity: float   = 0.72,
        ttl_hours: float            = 72.0,
        on_escalation: str          = "block",
        density_threshold: float    = 0.05,
        on_error: OnError            = OnError.FAIL_CLOSED,
    ) -> None:
        """`store` bundles `.kv` (KVStore) and `.log` (LogStore) — see
        adapters/state_store/base.py. Constructed and injected by the
        caller (core/wiring.py), never imported directly here.
        """
        self._store     = store   # kept for close() and test introspection
        self._kv        = store.kv
        self._log        = store.log
        self._threshold = escalation_threshold
        self._window    = window_size
        self._sim       = reframe_similarity
        self._ttl       = ttl_hours * 3600
        self._action    = on_escalation   # "block" | "flag"
        self._density_threshold = density_threshold
        self._on_error  = on_error
        self._next_sweep = 0.0
        # Per-session asyncio locks — serialise concurrent turns on same session
        self._session_locks: dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def close(self) -> None:
        """Close the underlying store. Idempotent — called from SHAI.close()."""
        await self._store.close()

    async def _session_lock(self, session_id: str) -> asyncio.Lock:
        async with self._locks_lock:
            if session_id not in self._session_locks:
                self._session_locks[session_id] = asyncio.Lock()
            return self._session_locks[session_id]

    # ── Public API ────────────────────────────────────────────────────────

    async def check(self, session_id: str) -> tuple[bool, str | None]:
        """Read persisted risk score. Called BEFORE run_scan.

        Returns (escalated, reason). One kv get(). A store failure (adapter
        raises, or the row is unreadable) follows `on_error` and never raises:
        this runs ahead of scan_input's boundary, which must always return a
        verdict.
        """
        try:
            raw = await self._kv.get(_SESSION_PREFIX + session_id)
            if raw is None:
                return False, None
            score = _number(json.loads(raw)["risk_score"])
        except Exception:
            log.error("session accumulator store unreachable — %s", self._on_error,
                      exc_info=True, extra={"session_id": session_id})
            if self._on_error == OnError.FAIL_OPEN:
                return False, None
            return True, "session_accumulator: store unreachable — denying (fail_closed)"
        if score < self._threshold:
            return False, None
        return True, (
            f"session_accumulator: risk {score:.2f} ≥ {self._threshold} "
            f"— escalation pattern detected across last {self._window} turns"
        )

    async def record(
        self,
        session_id: str,
        text: str,
        status: str,             # ScanStatus value: "allow" | "warn" | "block"
        categories: list[str],   # finding categories from this turn
        density: float = 0.0,    # instruction density score from heuristic scanner
        turn_risk: float = 0.0,  # consolidated cross-boundary risk from TurnSignals
    ) -> None:
        """Write turn, recompute score, persist. Called AFTER scan_output
        (or scan_input if the turn short-circuited at input BLOCK).

        Holds the per-session lock for the duration so concurrent turns
        on the same session cannot interleave writes.
        """
        lock = await self._session_lock(session_id)
        async with lock:
            try:
                await self._record_locked(session_id, text, status, categories,
                                          density, turn_risk)
            except Exception:
                # The verdict is already decided; a turn that cannot be
                # recorded must not take the boundary down with it. The next
                # check() sees the store failure for itself.
                log.error("session accumulator could not record turn",
                          exc_info=True, extra={"session_id": session_id})

    async def reset(self, session_id: str) -> None:
        """Clear all state for a session. Call on session end."""
        await self._kv.delete(_SESSION_PREFIX + session_id)
        await self._log.delete(_TURNS_PREFIX + session_id)

    # ── Internal ──────────────────────────────────────────────────────────

    async def _record_locked(
        self,
        session_id: str,
        text: str,
        status: str,
        categories: list[str],
        density: float = 0.0,
        turn_risk: float = 0.0,
    ) -> None:
        now  = time.time()
        h    = _hash(text)
        cats = sorted(set(categories))
        bgrams = sorted(f"{a} {b}" for a, b in _bigrams(text))

        turn_payload = json.dumps({
            "text_hash":   h,
            "bigram_json": bgrams,
            "status":      status,
            "categories":  cats,
            "density":     density,
            "turn_risk":   turn_risk,
        }).encode()
        await self._log.append(_TURNS_PREFIX + session_id, turn_payload)

        window_raw = await self._log.tail(_TURNS_PREFIX + session_id, self._window)
        window = [json.loads(row) for row in window_raw]

        score = self._compute_score(window, self._sim, self._density_threshold)

        session_key = _SESSION_PREFIX + session_id
        await self._kv.put(session_key, json.dumps({
            "risk_score": score,
            "updated_at": now,
        }).encode())

        if now >= self._next_sweep:
            self._next_sweep = now + _SWEEP_INTERVAL_S
            try:
                await self._sweep_stale_sessions(now)
            except Exception:
                # The turn itself was recorded; only expiry failed.
                log.error("session accumulator expiry sweep failed",
                          exc_info=True)

    async def _sweep_stale_sessions(self, now: float) -> None:
        """Delete every session (kv row + its turn log) whose kv row is
        older than ttl_hours. Whole-session expiry — see module docstring.
        """
        cutoff = now - self._ttl
        for key in await self._kv.list(_SESSION_PREFIX):
            raw = await self._kv.get(key)
            if raw is None:
                continue
            try:
                updated_at = _number(json.loads(raw)["updated_at"])
            except (ValueError, KeyError, TypeError):
                # One unreadable row must not keep every other session from
                # expiring; check() reports it as a store failure for its own session.
                log.warning("session row unreadable — skipped by sweep",
                            extra={"key": key})
                continue
            if updated_at < cutoff:
                session_id = key[len(_SESSION_PREFIX):]
                await self._kv.delete(key)
                await self._log.delete(_TURNS_PREFIX + session_id)

    def _compute_score(
        self,
        window: list[dict],  # parsed turn payloads, newest first
        sim_threshold: float,
        density_threshold: float = 0.05,
    ) -> float:
        if not window:
            return 0.0

        # Import RISK_HIGH lazily to avoid circular import — turn_signals
        # imports from core.types, which is loaded before this module.
        from harness.core.turn_signals import RISK_HIGH

        n          = len(window)
        block_n    = sum(1 for r in window if r["status"] == "block")
        # Rows with high consolidated turn_risk are treated as effective blocks
        # for rate calculation even if the individual scanner status was allow/warn
        effective_block_n = sum(
            1 for r in window
            if r["status"] == "block" or r["turn_risk"] >= RISK_HIGH
        )
        warn_n     = sum(1 for r in window if r["status"] in ("warn", "block"))
        block_rate = max(block_n, effective_block_n) / n
        warn_rate  = warn_n  / n

        base = block_rate * WEIGHT_BLOCK + warn_rate * WEIGHT_WARN

        # Turn-risk boost: any turn with high consolidated risk gets an
        # additive contribution, capped at WEIGHT_TURN_RISK_HIGH regardless
        # of how many turns fired
        high_risk_turns = sum(1 for r in window if r["turn_risk"] >= RISK_HIGH)
        turn_risk_signal = WEIGHT_TURN_RISK_HIGH if high_risk_turns > 0 else 0.0

        # Reframe: current turn (window[0]) is bad AND similar to previous (window[1]).
        reframe = False
        if window[0]["status"] in ("warn", "block") and len(window) >= 2:
            cur_bgrams  = frozenset(window[0]["bigram_json"])
            prev_bgrams = frozenset(window[1]["bigram_json"])
            if _jaccard(cur_bgrams, prev_bgrams) >= sim_threshold:
                reframe = True

        # Density: rolling average of instruction density across the window.
        density_sum = sum(r["density"] for r in window)
        density_avg = density_sum / n if n > 0 else 0.0
        density_signal = WEIGHT_DENSITY if density_avg >= density_threshold else 0.0

        return min(
            1.0,
            base
            + (WEIGHT_REFRAME if reframe else 0.0)
            + density_signal
            + turn_risk_signal
        )
