"""StdoutSink — emits one JSON object per line to stdout."""
from __future__ import annotations

import sys
from typing import IO

from harness.core.events import AnyAuditEvent, canonical_json


class StdoutSink:
    """Reference AuditSink — JSONL to stdout."""

    name = "stdout"

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream or sys.stdout

    async def emit(self, event: AnyAuditEvent) -> None:
        line = canonical_json(event) + "\n"
        self._stream.write(line)
        self._stream.flush()

    async def close(self) -> None:
        pass
