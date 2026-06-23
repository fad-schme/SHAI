"""harness-cli — developer tools for SHAI.

Commands:
  harness validate           Validate harness.yaml and all agent files.
  harness agents list        List all registered agents.
  harness audit tail         Tail an audit JSONL log file.

Usage:
  harness validate [--config PATH]
  harness agents list [--config PATH]
  harness audit tail [--file PATH] [--follow]
"""
from __future__ import annotations

import argparse
import sys

from harness_cli.commands.validate import cmd_validate
from harness_cli.commands.agents import cmd_agents_list
from harness_cli.commands.audit import cmd_audit_tail


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="harness",
        description="SHAI developer tools",
    )
    p.add_argument(
        "--config", "-c",
        default="config/harness.yaml",
        metavar="PATH",
        help="Path to harness.yaml (default: config/harness.yaml)",
    )
    sub = p.add_subparsers(dest="command", metavar="command")

    # validate
    val = sub.add_parser("validate", help="Validate config and agent files")
    val.add_argument(
        "--agents-dir", "-a",
        default=None,
        metavar="DIR",
        help="Override agents directory",
    )

    # agents
    agents_p = sub.add_parser("agents", help="Agent management commands")
    agents_sub = agents_p.add_subparsers(dest="agents_command", metavar="subcommand")
    agents_sub.add_parser("list", help="List registered agents")

    # audit
    audit_p = sub.add_parser("audit", help="Audit log commands")
    audit_sub = audit_p.add_subparsers(dest="audit_command", metavar="subcommand")
    tail_p = audit_sub.add_parser("tail", help="Tail an audit JSONL file")
    tail_p.add_argument("--file", "-f", default="-", metavar="PATH",
                        help="Audit log path or '-' for stdin (default: stdin)")
    tail_p.add_argument("--follow", "-F", action="store_true",
                        help="Follow the file (like tail -f)")
    tail_p.add_argument("--last", "-n", type=int, default=20,
                        help="Number of lines to show (default: 20)")
    tail_p.add_argument("--boundary", "-b", default=None,
                        help="Filter by boundary name")
    tail_p.add_argument("--decision", "-d", default=None,
                        help="Filter by decision (allow|deny|blocked|redact)")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "validate":
        return cmd_validate(args)

    if args.command == "agents":
        if args.agents_command == "list":
            return cmd_agents_list(args)
        print("harness agents: specify a subcommand (list)", file=sys.stderr)
        return 1

    if args.command == "audit":
        if args.audit_command == "tail":
            return cmd_audit_tail(args)
        print("harness audit: specify a subcommand (tail)", file=sys.stderr)
        return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
