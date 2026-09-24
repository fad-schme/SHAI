"""state_store/memory_store.py — in-process KVStore/LogStore adapter.

The default for `session_budget`: a single-process deployment should not pay
I/O latency on the tool-call gate's pre-checks just because the storage
interface is uniformly async. Every method here is a plain dict operation
with no `await` on anything that can suspend — on the single-threaded
asyncio event loop, that means a call from `get()` to its return never
yields control, so it costs the same as the direct dict access it replaces.

State does not survive a process restart and is not shared across replicas —
that is this adapter's contract. Durable, replica-shared storage is what the
SQLite adapter is for.

`KVStore` and `LogStore` both declare `delete`/`close`, so one class cannot
implement both Protocols directly — the second definition would shadow the
first. `InMemoryStore` composes two small Protocol-conforming objects
instead, sharing the underlying dicts, exposed as `.kv` and `.log`.
"""
from __future__ import annotations

from harness.adapters.state_store.base import require_bytes


class _MemoryKV:
    """KVStore over a plain dict."""

    name = "memory"

    def __init__(self, data: dict[str, bytes]) -> None:
        self._data = data

    async def get(self, key: str) -> bytes | None:
        return self._data.get(key)

    async def put(self, key: str, value: bytes) -> None:
        require_bytes(value)
        self._data[key] = value

    async def batch_put(self, items: dict[str, bytes]) -> None:
        # Validate everything first, then update: nothing awaits, so nothing
        # can interleave — atomic by construction on the single-threaded
        # event loop.
        for value in items.values():
            require_bytes(value)
        self._data.update(items)

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def list(self, prefix: str) -> list[str]:
        return [k for k in self._data if k.startswith(prefix)]

    async def close(self) -> None:
        pass


class _MemoryLog:
    """LogStore over a plain dict of lists."""

    name = "memory"

    def __init__(self, data: dict[str, list[bytes]]) -> None:
        self._data = data

    async def append(self, key: str, value: bytes) -> None:
        require_bytes(value)
        self._data.setdefault(key, []).append(value)

    async def tail(self, key: str, n: int) -> list[bytes]:
        if n <= 0:
            return []
        entries = self._data.get(key, [])
        return list(reversed(entries[-n:]))

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def close(self) -> None:
        pass


class InMemoryStore:
    """Bundles an in-process `.kv` (KVStore) and `.log` (LogStore).

    Config-facing name is "memory" — one `store:` selection wires one of
    these, and callers use whichever of `.kv`/`.log` they need.
    """

    name = "memory"

    def __init__(self, **_ignored) -> None:
        # _ignored: harness.yaml `config:` blocks may carry keys meant for
        # another backend (e.g. `path`, which sqlite uses) if an operator
        # copies a block between subsystems. This adapter takes no
        # configuration of its own, so anything present is simply unused
        # rather than a construction error.
        self.kv: _MemoryKV = _MemoryKV({})
        self.log: _MemoryLog = _MemoryLog({})

    async def close(self) -> None:
        await self.kv.close()
        await self.log.close()
