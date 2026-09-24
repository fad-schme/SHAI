"""state_store/base.py — KVStore and LogStore Protocols.

Two shapes, not one, because the callers need two different query patterns:

  KVStore  — point get/put/delete over an opaque value, plus a prefix
             listing and an atomic multi-key write. No per-key TTL: every
             current caller does bulk, caller-driven expiry already, so the
             Protocol does not invent per-key expiry nothing uses.

  LogStore — an append-only, per-key ordered log with a bounded tail read.
             The crescendo accumulator's per-turn history is a tail read
             over appended rows, not a point lookup; forcing it through
             KVStore would mean serialising and rewriting the whole turn
             history on every turn.

Both are async. The accumulator and pattern-DB runtime path already run
inside async boundaries (see python-conventions.md's boundary contract), and
a networked adapter needs real I/O. A conforming in-process adapter must not
introduce a scheduling hop of its own that a direct dict access would not
have paid — see state_store/memory_store.py.

Values are opaque bytes on both Protocols. Callers own serialisation; the
store never inspects or interprets a value.
"""
from __future__ import annotations

from typing import Protocol


def require_bytes(value: object) -> None:
    """The bytes-only value contract, enforced by every adapter alike: SQLite
    would otherwise bind a `str` into a BLOB column and hand it back as `str`,
    so a caller could pass against one adapter and fail against another."""
    if not isinstance(value, bytes | bytearray):
        raise TypeError(f"state store values must be bytes, got {type(value).__name__}")


class KVStore(Protocol):
    """Key-value storage. See module docstring."""

    name: str

    async def get(self, key: str) -> bytes | None:
        """Return the value for `key`, or None if absent."""
        ...

    async def put(self, key: str, value: bytes) -> None:
        """Write `value` at `key`, replacing any existing value."""
        ...

    async def batch_put(self, items: dict[str, bytes]) -> None:
        """Write every item, atomically: all keys land or none do.

        Exists for callers with an existing all-or-nothing contract to
        preserve (e.g. a signed bundle apply) — not a general transaction
        primitive.
        """
        ...

    async def delete(self, key: str) -> None:
        """Remove `key`. No error if it does not exist."""
        ...

    async def list(self, prefix: str) -> list[str]:
        """Return every key starting with `prefix`, in no particular order."""
        ...

    async def close(self) -> None:
        """Release any held resources (connections, file handles). Idempotent."""
        ...


class LogStore(Protocol):
    """Append-only ordered log, keyed and grouped like KVStore's keys.

    See module docstring.
    """

    name: str

    async def append(self, key: str, value: bytes) -> None:
        """Append `value` to the end of `key`'s log.

        No timestamp parameter: nothing in this Protocol queries by time —
        `tail` is insertion-order, and expiry is a whole-key `delete` driven
        by the caller's own kv-side staleness check (see the note on
        `delete` below). A caller that wants a per-entry time embeds it in
        `value` itself.
        """
        ...

    async def tail(self, key: str, n: int) -> list[bytes]:
        """Return up to the last `n` appended values for `key`, newest first."""
        ...

    async def delete(self, key: str) -> None:
        """Remove every entry for `key`. No error if none exist.

        There is deliberately no age-based bulk delete here: the one caller
        that expires log data (the crescendo accumulator) expires whole
        stale *sessions*, not individually-aged entries — an active
        session's early turns must survive past any per-entry cutoff as
        long as they're still inside its scoring window. That's a whole-key
        delete driven by the caller's own kv-side staleness check, not a
        store-level time filter.
        """
        ...

    async def close(self) -> None:
        """Release any held resources (connections, file handles). Idempotent."""
        ...


class StateStore(Protocol):
    """What one `store:` selection resolves to: a `KVStore` and a `LogStore`
    over the same backend, closed together. A subsystem uses whichever facet
    it needs (the session budget and the pattern store use only `kv`)."""

    name: str
    kv: KVStore
    log: LogStore

    async def close(self) -> None:
        """Release the backend. Idempotent."""
        ...
