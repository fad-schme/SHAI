"""FileSink — JSONL rotating file sink.

asyncio.Lock serialises concurrent async emit() calls.
run_in_executor offloads the blocking write to a thread pool.
"""
from __future__ import annotations

import asyncio
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from harness.adapters.audit_sinks.stdout import _serialize
from harness.core.events import AuditEvent

log = logging.getLogger(__name__)


class FileSink:
    """Reference AuditSink — JSONL rotating file."""

    name = "file"

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = 100_000_000,   # 100 MB
        backup_count: int = 10,
        encoding: str = "utf-8",
    ) -> None:
        self._path = Path(path)
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._encoding = encoding
        self._lock = asyncio.Lock()
        self._handler: RotatingFileHandler | None = None

    def _ensure_handler(self) -> RotatingFileHandler:
        if self._handler is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._handler = RotatingFileHandler(
                filename=self._path,
                maxBytes=self._max_bytes,
                backupCount=self._backup_count,
                encoding=self._encoding,
            )
        return self._handler

    def _write(self, line: str) -> None:
        handler = self._ensure_handler()
        handler.stream.write(line)
        handler.stream.flush()
        # Check rotation by file size — avoids shouldRollover() which
        # requires a LogRecord argument and raises AttributeError on None.
        if handler.maxBytes > 0:
            handler.stream.seek(0, 2)           # seek to end
            if handler.stream.tell() >= handler.maxBytes:
                handler.doRollover()

    async def emit(self, event: AuditEvent) -> None:
        line = _serialize(event) + "\n"
        async with self._lock:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._write, line)

    async def close(self) -> None:
        async with self._lock:
            if self._handler is not None:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self._handler.close)
                self._handler = None
