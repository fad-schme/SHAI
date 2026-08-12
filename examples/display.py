"""display.py — shared display helpers for SHAI examples.

Import in any example:
    from display import c, print_header, print_section, print_startup,
                        print_conversation, print_audit_summary, print_gate_summary
"""
from __future__ import annotations

# Windows consoles default to a legacy codepage (cp1252), and every example
# below prints box-drawing characters. Without this the first print() raises
# UnicodeEncodeError before any SHAI output appears. Safe on POSIX, where the
# stream is already UTF-8.
import sys

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

import sys

# ── ANSI colours ──────────────────────────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def _colour_supported() -> bool:
    """True when the stream renders ANSI escapes.

    isatty() alone is not enough on Windows: a legacy console is a tty but
    prints escape codes literally. Windows 10+ can interpret them once
    ENABLE_VIRTUAL_TERMINAL_PROCESSING is set, so try to set it and fall back
    to no colour when that fails.
    """
    if not sys.stdout.isatty():
        return False
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # -11 = STD_OUTPUT_HANDLE, 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


USE_COLOUR = _colour_supported()


def c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}" if USE_COLOUR else text


# ── Layout ─────────────────────────────────────────────────────────────────

def print_header(title: str, subtitle: str = "") -> None:
    w = 62
    print()
    print(c(BOLD, "╔" + "═" * w + "╗"))
    print(c(BOLD, "║") + c(BOLD + CYAN, f"  {title:<{w-2}}") + c(BOLD, "  ║"))
    print(c(BOLD, "╚" + "═" * w + "╝"))
    if subtitle:
        print(c(DIM, f"  {subtitle}"))


def print_section(title: str) -> None:
    print()
    print(c(BOLD, f"  ┌─ {title}"))


def print_divider() -> None:
    print(f"  └{'─'*50}")


# ── Startup ────────────────────────────────────────────────────────────────

def print_startup(harness: object,
                  tool_notes: list[tuple[str, str]] | None = None) -> None:
    """Print harness config summary at startup.

    tool_notes: list of (tool_name, note) for tools worth calling out,
                e.g. [("write_file", "blocked by policy")]
    """
    tool_notes = tool_notes or []
    print_section("Starting up")
    cfg = harness._config
    print(f"  │  {c(GREEN, '✓')} SHAI loaded"
          f"  (tenant={c(CYAN, harness._tenant_id)})")
    print(f"  │  {c(GREEN, '✓')} scan_input={c(CYAN, str(cfg.scan_input.action))}"
          f"  scan_output={c(CYAN, str(cfg.scan_output.action))}")
    if tool_notes:
        parts = []
        for name, note in tool_notes:
            parts.append(f"{c(CYAN, name)}" + (f" {c(YELLOW, f'({note})')}" if note else ""))
        print(f"  │  {c(GREEN, '✓')} tools: {', '.join(parts)}")
    print_divider()


# ── Conversation ───────────────────────────────────────────────────────────

def print_user(question: str) -> None:
    print_section("Conversation")
    print(f"  │  {c(BOLD, 'User:')}  {question}")
    print("  │")


def print_thinking() -> None:
    print(f"  │  {c(DIM, 'Thinking...')}", end="\r", flush=True)


def print_agent(response: str, redacted: bool = False) -> None:
    print(f"  │  {' ' * 50}", end="\r")
    print(f"  │  {c(BOLD, 'Agent:')}  {response}")
    if redacted:
        print(f"  │  {c(YELLOW, '  ↳ output redacted by scan_output')}")
    print_divider()


def print_blocked(stage: str, detail: str = "") -> None:
    print(f"  │  {c(RED, f'✗ {stage} blocked')}"
          + (f"  {c(DIM, detail)}" if detail else ""))
    print_divider()


# ── Audit summary ──────────────────────────────────────────────────────────

_BOUNDARY_LABELS = {
    "input_scan":        "Input scan       ",
    "tool_call_gate":    "Tool gate        ",
    "tool_result_scan":  "Tool result scan ",
    "output_scan":       "Output scan      ",
    "file_scan":         "File scan        ",
    "mcp_metadata_scan": "MCP metadata scan",
    "system":            "System / degrade ",
}
_DECISION_COLS  = {"allow":    GREEN,  "deny":     RED,     "blocked": RED,
                   "warn":     YELLOW, "redact":   YELLOW,  "degraded": YELLOW}
_DECISION_ICONS = {"allow":    "✓",    "deny":     "✗",     "blocked": "✗",
                   "warn":     "⚠",    "redact":   "~",     "degraded": "◐"}


def print_audit_summary(events: list) -> None:
    """Display a formatted audit trail from harness.collect_events()."""
    print_section("SHAI Audit Trail")
    if not events:
        print(f"  │  {c(DIM, '(no events)')}")
        print_divider()
        return

    for i, ev in enumerate(events):
        tree   = "└" if i == len(events) - 1 else "├"
        bnd    = str(ev.boundary)
        dec    = str(ev.decision)
        label  = _BOUNDARY_LABELS.get(bnd, f"{bnd:<16}")
        col    = _DECISION_COLS.get(dec, DIM)
        icon   = _DECISION_ICONS.get(dec, "?")
        status = (c(DIM, f"{icon} {dec.upper()} (disabled)") if ev.disabled
                  else c(col, f"{icon} {dec.upper()}"))

        detail = ""
        if ev.tool_name:
            detail += f"  tool={c(CYAN, ev.tool_name)}"
        if ev.finding_count:
            detail += f"  findings={c(YELLOW, str(ev.finding_count))}"
        if ev.duration_ms:
            detail += f"  {c(DIM, str(ev.duration_ms) + 'ms')}"

        print(f"  │  {tree}─ {label}  {status}{detail}")

        if ev.deny_reason:
            pad = "      " if i == len(events) - 1 else "  │   "
            print(f"  │  {pad}   {c(RED, '↳')} {c(DIM, ev.deny_reason)}")

    print_divider()

    allows = sum(1 for e in events if str(e.decision) == "allow")
    denies = sum(1 for e in events if str(e.decision) in ("deny", "blocked"))
    warns  = sum(1 for e in events if str(e.decision) == "warn")
    parts  = [c(GREEN, f"{allows} allowed")]
    if warns:
        parts.append(c(YELLOW, f"{warns} warned"))
    if denies:
        parts.append(c(RED, f"{denies} denied/blocked"))
    print(f"     {len(events)} event(s):  {'  '.join(parts)}")


def print_gate_summary(events: list) -> None:
    """Print a focused summary of tool gate decisions."""
    gates = [e for e in events if str(e.boundary) == "tool_call_gate"]
    if not gates:
        return
    print_section("Tool gate decisions")
    for ev in gates:
        tool = str(ev.tool_name or "?")
        dec  = str(ev.decision)
        if dec == "allow":
            print(f"  │  {c(GREEN, '✓')} {c(CYAN, tool)} — allowed")
        else:
            print(f"  │  {c(RED, '✗')} {c(CYAN, tool)}"
                  f" — {c(RED, dec.upper())}"
                  f"  {c(DIM, ev.deny_reason or '')}")
    print_divider()
