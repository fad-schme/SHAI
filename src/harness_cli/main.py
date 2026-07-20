"""shai — developer tools for SHAI.

Commands:
  shai validate           Validate harness.yaml and all agent files.
                          Shows: boundaries, execution budget, session config.
  shai agents list        List all registered agents and subagents.
  shai audit tail         Tail an audit JSONL log file with decision filtering.
                          Surfaces: argument violations, irreversibility blocks,
                          session escalations, and de-obfuscation signals.

Usage:
  shai validate [--config PATH] [--agents-dir DIR]
  shai agents list --agents-dir DIR [--config PATH]
  shai audit tail [--file PATH] [--follow] [--boundary NAME] [--decision DECISION]

Audit tail examples:
  shai audit tail --file logs/audit.jsonl --follow
  shai audit tail --file logs/audit.jsonl --boundary tool_call_gate --decision deny
  shai audit tail --file logs/audit.jsonl --decision deny --last 50
"""
from __future__ import annotations

import argparse
import sys

from harness_cli.commands.agents import cmd_agents_list
from harness_cli.commands.audit import cmd_audit_tail
from harness_cli.commands.patterns import (
    cmd_candidates_list,
    cmd_candidates_update,
    cmd_patterns_apply,
    cmd_patterns_list,
    cmd_patterns_verify,
)
from harness_cli.commands.validate import cmd_validate


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shai",
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

    # patterns
    pat_p = sub.add_parser("patterns", help="Manage the signed pattern database")
    pat_sub = pat_p.add_subparsers(dest="patterns_command", metavar="subcommand")

    apply_p = pat_sub.add_parser("apply", help="Apply a signed pattern bundle")
    apply_p.add_argument("--bundle", required=True, metavar="FILE",
                         help="Path to the signed bundle JSON file")
    apply_p.add_argument("--db", required=True, metavar="PATH",
                         help="Path to the patterns SQLite database")
    apply_p.add_argument("--secret", required=True, metavar="ENV_VAR",
                         help="Environment variable holding the signing secret")

    list_p = pat_sub.add_parser("list", help="List patterns in the database")
    list_p.add_argument("--db", required=True, metavar="PATH",
                        help="Path to the patterns SQLite database")

    verify_p = pat_sub.add_parser("verify", help="Verify all pattern signatures")
    verify_p.add_argument("--db", required=True, metavar="PATH",
                          help="Path to the patterns SQLite database")
    verify_p.add_argument("--secret", required=True, metavar="ENV_VAR",
                          help="Environment variable holding the signing secret")

    cand_p = pat_sub.add_parser("candidates", help="List heuristic candidates")
    cand_p.add_argument("--db", required=True, metavar="PATH")
    cand_p.add_argument("--status", default=None,
                        help="Filter by status: open | promoted | dismissed | retired")

    promote_p = pat_sub.add_parser("promote", help="Promote a candidate to read path")
    promote_p.add_argument("--db", required=True, metavar="PATH")
    promote_p.add_argument("--id", required=True, type=int)

    dismiss_p = pat_sub.add_parser("dismiss", help="Dismiss a candidate (false positive)")
    dismiss_p.add_argument("--db", required=True, metavar="PATH")
    dismiss_p.add_argument("--id", required=True, type=int)

    retire_p = pat_sub.add_parser("retire", help="Retire a promoted candidate")
    retire_p.add_argument("--db", required=True, metavar="PATH")
    retire_p.add_argument("--id", required=True, type=int)

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
        print("shai agents: specify a subcommand (list)", file=sys.stderr)
        return 1

    if args.command == "audit":
        if args.audit_command == "tail":
            return cmd_audit_tail(args)
        print("shai audit: specify a subcommand (tail)", file=sys.stderr)
        return 1

    if args.command == "patterns":
        if args.patterns_command == "apply":
            return cmd_patterns_apply(args)
        if args.patterns_command == "list":
            return cmd_patterns_list(args)
        if args.patterns_command == "verify":
            return cmd_patterns_verify(args)
        if args.patterns_command == "candidates":
            return cmd_candidates_list(args)
        if args.patterns_command == "promote":
            args.action = "promoted"
            return cmd_candidates_update(args)
        if args.patterns_command == "dismiss":
            args.action = "dismissed"
            return cmd_candidates_update(args)
        if args.patterns_command == "retire":
            args.action = "retired"
            return cmd_candidates_update(args)
        print("shai patterns: specify a subcommand (apply, list, verify, candidates, promote, dismiss, retire)",
              file=sys.stderr)
        return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
