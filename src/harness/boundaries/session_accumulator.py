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
SQLite via aiosqlite. Default path: state/sessions.db (configurable).
Schema: two tables —
  sessions(session_id, risk_score, updated_at)
  turns(id, session_id, ts, text_hash, status, categories, turn_index)

Risk score is pre-computed and stored in `sessions` so check() is one fast
SELECT. The expensive window scan only happens in record(), after the verdict
is already returned to the caller.

Sliding window
--------------
record() always evaluates the LAST `window_size` turns for the session,
regardless of where in the conversation they are. This naturally covers
any attack start offset — turns [3..7] are evaluated the same as [1..5].

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
Sessions older than ttl_hours are purged on each record() call (lazy GC).

on_escalation actions
---------------------
  block — return ScanVerdict(BLOCK); scanners never run
  flag  — return ScanVerdict(WARN);  scanners never run; content passes through
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── Weights ───────────────────────────────────────────────────────────────

WEIGHT_BLOCK   = 0.60
WEIGHT_WARN    = 0.25
WEIGHT_REFRAME = 0.30
WEIGHT_DENSITY = 0.25

# ── DDL ───────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    risk_score  REAL NOT NULL DEFAULT 0.0,
    updated_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS turns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL,
    ts          REAL    NOT NULL,
    text_hash   TEXT    NOT NULL,
    bigram_json TEXT    NOT NULL DEFAULT '[]',
    status      TEXT    NOT NULL,
    categories  TEXT    NOT NULL DEFAULT '[]',
    turn_index  INTEGER NOT NULL DEFAULT 0,
    density     REAL    NOT NULL DEFAULT 0.0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_turns_session ON turns(session_id, turn_index);
"""

# ── Helpers ───────────────────────────────────────────────────────────────

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
    u = len(a | b)
    return len(a & b) / u if u else 0.0


# ── Accumulator ───────────────────────────────────────────────────────────

class ThreatAccumulator:
    """Async, SQLite-backed cross-turn threat accumulator.

    One instance per SHAI facade. Thread/task-safe: uses an asyncio Lock
    per session_id so concurrent turns on the same session serialize.
    """

    def __init__(
        self,
        *,
        db_path: str = "state/sessions.db",
        escalation_threshold: float = 0.70,
        window_size: int            = 10,
        reframe_similarity: float   = 0.72,
        ttl_hours: float            = 72.0,
        on_escalation: str          = "block",
        density_threshold: float    = 0.05,
    ) -> None:
        self._db_path   = db_path
        self._threshold = escalation_threshold
        self._window    = window_size
        self._sim       = reframe_similarity
        self._ttl       = ttl_hours * 3600
        self._action    = on_escalation   # "block" | "flag"
        self._density_threshold = density_threshold
        self._db        = None            # aiosqlite connection, opened lazily
        self._init_lock = asyncio.Lock()
        # Per-session asyncio locks — serialise concurrent turns on same session
        self._session_locks: dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def _conn(self):
        """Return the shared connection, initialising DB on first call."""
        if self._db is not None:
            return self._db
        async with self._init_lock:
            if self._db is not None:
                return self._db
            import aiosqlite
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
            db = await aiosqlite.connect(self._db_path)
            db.row_factory = aiosqlite.Row
            await db.executescript(_DDL)
            await db.commit()
            self._db = db
        return self._db

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def _session_lock(self, session_id: str) -> asyncio.Lock:
        async with self._locks_lock:
            if session_id not in self._session_locks:
                self._session_locks[session_id] = asyncio.Lock()
            return self._session_locks[session_id]

    # ── Public API ────────────────────────────────────────────────────────

    async def check(self, session_id: str) -> tuple[bool, str | None]:
        """Read persisted risk score. Called BEFORE run_scan.

        Returns (escalated, reason). O(1) — single SELECT.
        """
        db = await self._conn()
        async with db.execute(
            "SELECT risk_score FROM sessions WHERE session_id = ?", (session_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None or row["risk_score"] < self._threshold:
            return False, None
        score = row["risk_score"]
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
    ) -> None:
        """Write turn, recompute score, persist. Called AFTER run_scan.

        Holds the per-session lock for the duration so concurrent turns
        on the same session cannot interleave writes.
        """
        lock = await self._session_lock(session_id)
        async with lock:
            await self._record_locked(session_id, text, status, categories, density)

    async def reset(self, session_id: str) -> None:
        """Clear all state for a session. Call on session end."""
        db = await self._conn()
        await db.execute("DELETE FROM turns WHERE session_id = ?", (session_id,))
        await db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        await db.commit()

    # ── Internal ──────────────────────────────────────────────────────────

    async def _record_locked(
        self,
        session_id: str,
        text: str,
        status: str,
        categories: list[str],
        density: float = 0.0,
    ) -> None:
        db   = await self._conn()
        now  = time.time()
        h    = _hash(text)
        cats = json.dumps(sorted(set(categories)))
        bgrams = json.dumps(sorted(f"{a} {b}" for a, b in _bigrams(text)))

        await db.execute(
            "INSERT OR IGNORE INTO sessions(session_id, risk_score, updated_at) "
            "VALUES(?, 0.0, ?)",
            (session_id, now),
        )

        async with db.execute(
            "SELECT COALESCE(MAX(turn_index), -1) + 1 FROM turns WHERE session_id = ?",
            (session_id,),
        ) as cur:
            row = await cur.fetchone()
        turn_idx = row[0]

        await db.execute(
            "INSERT INTO turns(session_id, ts, text_hash, bigram_json, status, categories, turn_index, density) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, now, h, bgrams, status, cats, turn_idx, density),
        )

        async with db.execute(
            "SELECT text_hash, bigram_json, status, density FROM turns "
            "WHERE session_id = ? ORDER BY turn_index DESC LIMIT ?",
            (session_id, self._window),
        ) as cur:
            window = await cur.fetchall()

        score = self._compute_score(window, self._sim, self._density_threshold)

        await db.execute(
            "UPDATE sessions SET risk_score = ?, updated_at = ? WHERE session_id = ?",
            (score, now, session_id),
        )

        cutoff = now - self._ttl
        await db.execute("DELETE FROM turns WHERE session_id IN "
                         "(SELECT session_id FROM sessions WHERE updated_at < ?)", (cutoff,))
        await db.execute("DELETE FROM sessions WHERE updated_at < ?", (cutoff,))
        await db.commit()

    def _compute_score(
        self,
        window: list,       # rows: (text_hash, bigram_json, status, density), newest first
        sim_threshold: float,
        density_threshold: float = 0.05,
    ) -> float:
        if not window:
            return 0.0

        n          = len(window)
        block_n    = sum(1 for r in window if r["status"] == "block")
        warn_n     = sum(1 for r in window if r["status"] in ("warn", "block"))
        block_rate = block_n / n
        warn_rate  = warn_n  / n

        base = block_rate * WEIGHT_BLOCK + warn_rate * WEIGHT_WARN

        # Reframe: current turn (window[0]) is bad AND similar to previous (window[1]).
        reframe = False
        if window[0]["status"] in ("warn", "block") and len(window) >= 2:
            cur_bgrams  = frozenset(json.loads(window[0]["bigram_json"]))
            prev_bgrams = frozenset(json.loads(window[1]["bigram_json"]))
            if _jaccard(cur_bgrams, prev_bgrams) >= sim_threshold:
                reframe = True

        # Density: rolling average of instruction density across the window.
        # A sustained 5%+ average signals a drip-feed injection.
        density_sum = sum(r["density"] for r in window)
        density_avg = density_sum / n if n > 0 else 0.0
        density_signal = WEIGHT_DENSITY if density_avg >= density_threshold else 0.0

        return min(1.0, base + (WEIGHT_REFRAME if reframe else 0.0) + density_signal)
