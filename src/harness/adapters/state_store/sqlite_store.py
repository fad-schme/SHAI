"""state_store/sqlite_store.py — SQLite-backed KVStore/LogStore adapter.

One file, two tables, one shared connection — SQLite becomes one adapter,
not the implementation each subsystem hardcodes. `.kv` and `.log` are
separate Protocol-conforming objects over the same connection (see
memory_store.py's docstring for why one class cannot implement both
Protocols directly).

kv_store holds opaque values only — no timestamp column. The one caller that
needs age-based cleanup on its kv-side data (the threat accumulator's
`sessions` rows) embeds its own `updated_at` in the serialised value and
does a bounded `list(prefix)` + filter + `delete` itself; see
session_accumulator.py. Keeping kv fully opaque avoids leaking any one
caller's schema into the store.

log_store has no timestamp column: nothing in the Protocol queries by time
(see base.py's LogStore docstring) — `id` alone gives insertion order for
`tail`, and expiry is a whole-key delete.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from harness.adapters.state_store.base import require_bytes

_DDL = """
CREATE TABLE IF NOT EXISTS kv_store (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS log_store (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    store_key TEXT    NOT NULL,
    value     BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_store_key ON log_store(store_key, id);
"""


class _SQLiteKV:
    """KVStore over the `kv_store` table of a shared aiosqlite connection."""

    name = "sqlite"

    def __init__(self, conn_getter) -> None:
        self._conn = conn_getter

    async def get(self, key: str) -> bytes | None:
        db = await self._conn(create=False)
        if db is None:
            return None
        async with db.execute(
            "SELECT value FROM kv_store WHERE key = ?", (key,)
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row is not None else None

    async def put(self, key: str, value: bytes) -> None:
        require_bytes(value)
        db = await self._conn()
        await db.execute(
            "INSERT INTO kv_store(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        await db.commit()

    async def batch_put(self, items: dict[str, bytes]) -> None:
        """All-or-nothing: one transaction for the whole batch.

        Exists so callers with an existing all-or-nothing guarantee (a
        signed pattern bundle apply) keep it once they no longer hold their
        own SQLite transaction directly.
        """
        for value in items.values():
            require_bytes(value)
        db = await self._conn()
        try:
            await db.executemany(
                "INSERT INTO kv_store(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                list(items.items()),
            )
        except BaseException:
            # The connection is shared: without this the rows written before
            # the failure stay pending and the next write commits them.
            await db.rollback()
            raise
        await db.commit()

    async def delete(self, key: str) -> None:
        db = await self._conn()
        await db.execute("DELETE FROM kv_store WHERE key = ?", (key,))
        await db.commit()

    async def list(self, prefix: str) -> list[str]:
        db = await self._conn(create=False)
        if db is None:
            return []
        # substr comparison rather than LIKE: LIKE is case-insensitive for
        # ASCII, which would let "Injection:x" answer a "injection:" listing
        # and make this adapter disagree with the in-process one.
        async with db.execute(
            "SELECT key FROM kv_store WHERE substr(key, 1, ?) = ?",
            (len(prefix), prefix),
        ) as cur:
            rows = await cur.fetchall()
        return [r[0] for r in rows]

    async def close(self) -> None:
        pass  # connection lifecycle owned by SQLiteStore


class _SQLiteLog:
    """LogStore over the `log_store` table of a shared aiosqlite connection."""

    name = "sqlite"

    def __init__(self, conn_getter) -> None:
        self._conn = conn_getter

    async def append(self, key: str, value: bytes) -> None:
        require_bytes(value)
        db = await self._conn()
        await db.execute(
            "INSERT INTO log_store(store_key, value) VALUES(?, ?)",
            (key, value),
        )
        await db.commit()

    async def tail(self, key: str, n: int) -> list[bytes]:
        if n <= 0:   # SQLite reads a negative LIMIT as "no limit"
            return []
        db = await self._conn(create=False)
        if db is None:
            return []
        async with db.execute(
            "SELECT value FROM log_store WHERE store_key = ? "
            "ORDER BY id DESC LIMIT ?",
            (key, n),
        ) as cur:
            rows = await cur.fetchall()
        return [r[0] for r in rows]

    async def delete(self, key: str) -> None:
        db = await self._conn()
        await db.execute("DELETE FROM log_store WHERE store_key = ?", (key,))
        await db.commit()

    async def close(self) -> None:
        pass  # connection lifecycle owned by SQLiteStore


class SQLiteStore:
    """Bundles a SQLite-backed `.kv` (KVStore) and `.log` (LogStore).

    Lazily opens one aiosqlite connection, shared by both, on first use —
    matching ThreatAccumulator's prior lazy-open behaviour so construction
    stays synchronous and cheap.
    """

    name = "sqlite"

    def __init__(self, *, path: str = "state/store.db") -> None:
        self._path = path
        self._db = None
        self._init_lock = asyncio.Lock()
        self.kv = _SQLiteKV(self._conn)
        self.log = _SQLiteLog(self._conn)

    async def _conn(self, *, create: bool = True):
        """The shared connection, opened on first use.

        `create=False` is for reads: an absent file means "no data", and
        opening it would create the file and its schema as a side effect of
        looking — on an operator's rules DB, from a read-only inspect.
        """
        if self._db is not None:
            return self._db
        if not create and not Path(self._path).exists():
            return None
        async with self._init_lock:
            if self._db is not None:
                return self._db
            import aiosqlite
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            db = await aiosqlite.connect(self._path)
            await db.executescript(_DDL)
            await db.commit()
            self._db = db
        return self._db

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None
