"""_keyed_locks.py — per-key asyncio locks that exist only while in use.

Serialises concurrent calls on one key (a session) without blocking other keys.
An entry is created for the first holder or waiter and removed when the last one
leaves, so the table tracks work in flight and not every key ever seen.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


class KeyedLocks:
    def __init__(self) -> None:
        # key -> [lock, holders + waiters]
        self._entries: dict[str, list] = {}
        self._guard = asyncio.Lock()

    @asynccontextmanager
    async def hold(self, key: str) -> AsyncIterator[None]:
        """Hold the lock for `key`. A caller that arrives while another holds the
        lock waits, and the entry survives until the last of them has left."""
        async with self._guard:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = [asyncio.Lock(), 0]
            entry[1] += 1
        try:
            async with entry[0]:
                yield
        finally:
            # No await between the decrement and the removal, so no other task
            # can look the key up in between.
            entry[1] -= 1
            if entry[1] == 0:
                del self._entries[key]

    def __len__(self) -> int:
        return len(self._entries)
