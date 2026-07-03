"""harness audit tail — tail and filter an audit JSONL log."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


_DECISION_COLOURS = {
    "allow":   "\033[32m",   # green
    "warn":    "\033[33m",   # yellow
    "deny":    "\033[31m",   # red
    "blocked": "\033[31m",   # red
    "redact":  "\033[33m",   # yellow
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"


def _colour(decision: str) -> str:
    if not sys.stdout.isatty():
        return ""
    return _DECISION_COLOURS.get(decision, "")


def _format_event(raw: str, *, boundary_filter: str | None, decision_filter: str | None) -> str | None:
    try:
        ev = json.loads(raw)
    except json.JSONDecodeError:
        return None

    if boundary_filter and ev.get("boundary") != boundary_filter:
        return None
    if decision_filter and ev.get("decision") != decision_filter:
        return None

    ts       = ev.get("timestamp", "")[:23]   # trim to milliseconds
    boundary = ev.get("boundary", "?")
    decision = ev.get("decision", "?")
    agent    = ev.get("agent_id", "?")
    sub      = ev.get("sub_agent_id")
    tool     = ev.get("tool_name")
    reason   = ev.get("deny_reason")
    severity = ev.get("max_severity")
    count    = ev.get("finding_count", 0)
    extra    = ev.get("extra", {})

    col   = _colour(decision)
    reset = _RESET if col else ""

    agent_str = f"{agent}/{sub}" if sub else agent
    mid = f"{tool}" if tool else ""
    if severity and count:
        mid += f"  findings={count} max={severity}"
    if reason:
        mid += f"  reason={reason!r}"

    # Surface session accumulator escalation signal
    signals = extra.get("signals", [])
    if "session_escalation" in signals:
        mid += "  [session_escalation]"

    # Surface normalization transforms (de-obfuscation fired)
    transforms = extra.get("normalization", [])
    if transforms:
        mid += f"  [deobfuscated: {','.join(transforms)}]"

    dur = ev.get("duration_ms", "")
    dur_str = f" +{dur}ms" if dur else ""

    line = (
        f"{ts}  "
        f"{col}{decision:<7}{reset}  "
        f"{boundary:<16}  "
        f"{agent_str:<35}  "
        f"{mid}"
        f"{dur_str}"
    )
    return line.rstrip()


def _read_tail(file: Path | None, n: int) -> list[str]:
    """Read last n lines from a file."""
    if file is None:
        return []
    try:
        lines = file.read_text(encoding="utf-8").splitlines()
        return lines[-n:]
    except (OSError, UnicodeDecodeError):
        return []


def cmd_audit_tail(args: argparse.Namespace) -> int:
    follow         = args.follow
    last_n         = args.last
    boundary_filt  = args.boundary
    decision_filt  = args.decision
    file_arg       = args.file

    use_stdin = file_arg == "-"
    file_path = None if use_stdin else Path(file_arg)

    if not use_stdin and file_path and not file_path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 1

    def _emit(raw: str) -> None:
        line = _format_event(raw, boundary_filter=boundary_filt, decision_filter=decision_filt)
        if line:
            print(line)

    # Show last N lines first
    if not use_stdin and file_path:
        for raw in _read_tail(file_path, last_n):
            _emit(raw)

    if not follow:
        if use_stdin:
            for raw in sys.stdin:
                _emit(raw.rstrip())
        return 0

    # Follow mode — poll for new lines
    if use_stdin:
        try:
            for raw in sys.stdin:
                _emit(raw.rstrip())
        except KeyboardInterrupt:
            pass
        return 0

    # File follow mode
    try:
        with open(file_path, encoding="utf-8") as fh:
            fh.seek(0, 2)   # seek to end
            while True:
                raw = fh.readline()
                if raw:
                    _emit(raw.rstrip())
                else:
                    time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"\nError: {e}", file=sys.stderr)
        return 1

    return 0
