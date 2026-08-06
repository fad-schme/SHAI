"""shai audit — inspect and verify audit JSONL logs.

  shai audit tail   --file <path> [--follow] [--boundary NAME] [--decision D]
  shai audit verify --file <path> --secret <env_var>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import deque
from pathlib import Path

from harness_cli.console import console

_DECISION_COLOURS = {
    "allow":   "\033[32m",   # green
    "warn":    "\033[33m",   # yellow
    "deny":    "\033[31m",   # red
    "blocked": "\033[31m",   # red
    "redact":  "\033[33m",   # yellow
}
_RESET = "\033[0m"


def _colour(decision: str) -> str:
    if "NO_COLOR" in os.environ or not console.stdout_isatty():
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

    # Surface argument rule and irreversibility violations distinctly
    if reason and "argument rule violation" in reason:
        mid = mid.replace(f"  reason={reason!r}", f"  [argument_violation] reason={reason!r}")
    elif reason and "irreversible" in reason.lower() and "approv" in reason.lower():
        mid = mid.replace(f"  reason={reason!r}", f"  [irreversibility_blocked] reason={reason!r}")

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


def _read_tail(file: Path, n: int) -> list[str]:
    """Read last n lines from a file."""
    if n == 0:
        return []
    with file.open(encoding="utf-8") as fh:
        return [line.rstrip("\r\n") for line in deque(fh, maxlen=n)]


_MAX_REPORTED = 20


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify every signed line in an audit log against `audit_signing.secret`.

    Exit 0 only when every line verified. A tampered, unsigned, or unparsable
    line all fail the run: a signed trail with a hole in it does not answer the
    question signing was enabled to answer, and reporting a gap as success
    would be worse than not checking.
    """
    from harness.audit.emitter import verify_line

    secret = _signing_secret(args.secret)
    if secret is None:
        return 1

    use_stdin = args.file == "-"
    path = None if use_stdin else Path(args.file)
    if path is not None and not path.is_file():
        console.error(f"error: file not found: {path}")
        return 1

    try:
        if use_stdin:
            counts, failures = _verify_lines(sys.stdin, secret, verify_line)
        else:
            with path.open(encoding="utf-8") as fh:
                counts, failures = _verify_lines(fh, secret, verify_line)
    except (OSError, UnicodeDecodeError) as e:
        console.error(f"error: {e}")
        return 1

    ok, tampered, unsigned, malformed = counts
    bad = tampered + unsigned + malformed
    if failures:
        console.write("failures:")
        for line in failures:
            console.write(line)
        if bad > len(failures):
            console.write(f"  ... and {bad - len(failures)} more")

    total = ok + bad
    console.write(
        f"{total} records: {ok} verified, {tampered} mismatched, "
        f"{unsigned} unsigned, {malformed} malformed"
    )
    if total == 0:
        console.error("error: no records found")
        return 1
    return 0 if bad == 0 else 1


def _verify_lines(lines, secret: bytes, verify) -> tuple[tuple[int, int, int, int], list[str]]:
    """Classify every record as verified / mismatched / unsigned / malformed."""
    ok = tampered = unsigned = malformed = 0
    failures: list[str] = []

    def record(lineno: int, kind: str) -> None:
        if len(failures) < _MAX_REPORTED:
            failures.append(f"  line {lineno}: {kind}")

    for lineno, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            malformed += 1
            record(lineno, "not valid JSON")
            continue
        if not isinstance(event, dict):
            malformed += 1
            record(lineno, "not a JSON object")
        elif not event.get("signature"):
            unsigned += 1
            record(lineno, "no signature")
        elif verify(event, secret):
            ok += 1
        else:
            tampered += 1
            record(lineno, "SIGNATURE MISMATCH - record altered or wrong key")

    return (ok, tampered, unsigned, malformed), failures


def _signing_secret(env_var: str) -> bytes | None:
    """Resolve the signing key from an environment variable name.

    Same contract as `shai patterns` — the key is never a command-line
    argument, which would put it in the shell history and the process list.
    """
    value = os.environ.get(env_var)
    if not value:
        console.error(f"error: environment variable {env_var!r} not set")
        return None
    return value.encode()


def cmd_audit_tail(args: argparse.Namespace) -> int:
    follow         = args.follow
    last_n         = args.last
    boundary_filt  = args.boundary
    decision_filt  = args.decision
    file_arg       = args.file

    use_stdin = file_arg == "-"
    file_path = None if use_stdin else Path(file_arg)

    if file_path is not None and not file_path.is_file():
        console.error(f"Error: file not found: {file_path}")
        return 1

    def _emit(raw: str) -> None:
        line = _format_event(raw, boundary_filter=boundary_filt, decision_filter=decision_filt)
        if line:
            console.write(line)

    # Show last N lines first
    if file_path is not None:
        try:
            for raw in _read_tail(file_path, last_n):
                _emit(raw)
        except (OSError, UnicodeDecodeError) as e:
            console.error(f"Error: {e}")
            return 1

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
        console.error(f"\nError: {e}")
        return 1

    return 0
