"""Shared stdout and stderr access for CLI commands."""
from __future__ import annotations

import sys


class Console:
    def write(self, message: str = "", *, end: str = "\n") -> None:
        print(message, file=sys.stdout, end=end)

    def error(self, message: str) -> None:
        print(message, file=sys.stderr)

    def stdout_isatty(self) -> bool:
        return sys.stdout.isatty()


console = Console()
