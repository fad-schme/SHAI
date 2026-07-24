"""shai — developer tools for SHAI.

Commands:
  shai validate           Validate harness.yaml and optional agent files.
                          Shows: boundaries, execution budget, session config.
  shai agents list        List all registered agents and subagents.
  shai audit tail         Tail an audit JSONL log file with decision filtering.
                          Surfaces: argument violations, irreversibility blocks,
                          session escalations, and de-obfuscation signals.

Usage:
  shai --help
  shai COMMAND --help
  shai validate [--config PATH] [--agents-dir DIR]
  shai agents list --agents-dir DIR
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

_BOUNDARIES = (
    "input_scan",
    "tool_call_gate",
    "tool_result_scan",
    "output_scan",
    "file_scan",
    "mcp_metadata_scan",
    "system",
)
_DECISIONS = ("allow", "warn", "blocked", "deny", "redact", "degraded")


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shai",
        description="SHAI developer tools",
        epilog="Run 'shai COMMAND --help' for command-specific options.",
    )
    sub = p.add_subparsers(
        dest="command",
        metavar="COMMAND",
        title="commands",
    )

    # validate
    val = sub.add_parser(
        "validate",
        help="Validate config and agent files",
        description=(
            "Validate a harness config and, when requested, every agent YAML "
            "file in a directory."
        ),
    )
    val.add_argument(
        "--config", "-c",
        default="config/harness.yaml",
        metavar="PATH",
        help="Path to harness.yaml (default: config/harness.yaml)",
    )
    val.add_argument(
        "--agents-dir", "-a",
        default=None,
        metavar="DIR",
        help="Also validate agent YAML files in this directory",
    )
    val.set_defaults(handler=cmd_validate)

    # agents
    agents_p = sub.add_parser(
        "agents",
        help="Agent management commands",
        description="Inspect agent YAML files.",
    )
    agents_sub = agents_p.add_subparsers(
        dest="agents_command",
        metavar="COMMAND",
        title="commands",
        required=True,
    )
    agents_list = agents_sub.add_parser(
        "list",
        help="List registered agents",
        description="List valid agent YAML files and their declared capabilities.",
    )
    agents_list.add_argument(
        "--agents-dir", "-a",
        required=True,
        metavar="DIR",
        help="Directory containing agent YAML files",
    )
    agents_list.set_defaults(handler=cmd_agents_list)

    # audit
    audit_p = sub.add_parser(
        "audit",
        help="Audit log commands",
        description="Inspect SHAI audit JSONL logs.",
    )
    audit_sub = audit_p.add_subparsers(
        dest="audit_command",
        metavar="COMMAND",
        title="commands",
        required=True,
    )
    tail_p = audit_sub.add_parser(
        "tail",
        help="Tail an audit JSONL file",
        description="Read, filter, and optionally follow an audit JSONL stream.",
    )
    tail_p.add_argument("--file", "-f", default="-", metavar="PATH",
                        help="Audit log path or '-' for stdin (default: stdin)")
    tail_p.add_argument("--follow", "-F", action="store_true",
                        help="Follow the file (like tail -f)")
    tail_p.add_argument("--last", "-n", type=_non_negative_int, default=20, metavar="N",
                        help="Number of lines to show (default: 20)")
    tail_p.add_argument("--boundary", "-b", choices=_BOUNDARIES, default=None,
                        help="Filter by boundary name")
    tail_p.add_argument("--decision", "-d", choices=_DECISIONS, default=None,
                        help="Filter by decision")
    tail_p.set_defaults(handler=cmd_audit_tail)

    # patterns
    pat_p = sub.add_parser(
        "patterns",
        help="Manage the signed pattern database",
        description="Manage signed rules and heuristic candidates in the pattern database.",
    )
    pat_sub = pat_p.add_subparsers(
        dest="patterns_command",
        metavar="COMMAND",
        title="commands",
        required=True,
    )

    apply_p = pat_sub.add_parser(
        "apply",
        help="Apply a signed pattern bundle",
        description="Verify and atomically apply every rule in a signed JSON bundle.",
    )
    apply_p.add_argument("--bundle", required=True, metavar="FILE",
                         help="Path to the signed bundle JSON file")
    apply_p.add_argument("--db", required=True, metavar="PATH",
                         help="Path to the patterns SQLite database")
    apply_p.add_argument("--secret", required=True, metavar="ENV_VAR",
                         help="Environment variable holding the signing secret")
    apply_p.set_defaults(handler=cmd_patterns_apply)

    list_p = pat_sub.add_parser(
        "list",
        help="List patterns in the database",
        description="List installed pattern rules without verifying their signatures.",
    )
    list_p.add_argument("--db", required=True, metavar="PATH",
                        help="Path to the patterns SQLite database")
    list_p.set_defaults(handler=cmd_patterns_list)

    verify_p = pat_sub.add_parser(
        "verify",
        help="Verify all pattern signatures",
        description="Verify every installed pattern signature using an environment secret.",
    )
    verify_p.add_argument("--db", required=True, metavar="PATH",
                          help="Path to the patterns SQLite database")
    verify_p.add_argument("--secret", required=True, metavar="ENV_VAR",
                          help="Environment variable holding the signing secret")
    verify_p.set_defaults(handler=cmd_patterns_verify)

    cand_p = pat_sub.add_parser(
        "candidates",
        help="List heuristic candidates",
        description="List heuristic candidates, optionally filtered by lifecycle status.",
    )
    cand_p.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="Path to the patterns SQLite database",
    )
    cand_p.add_argument(
        "--status",
        choices=("open", "promoted", "dismissed", "retired"),
        default=None,
        help="Filter by lifecycle status",
    )
    cand_p.add_argument("--all", action="store_true", default=False,
                        help="Show all candidates including low hit-count noise")
    cand_p.set_defaults(handler=cmd_candidates_list)

    promote_p = pat_sub.add_parser(
        "promote",
        help="Promote a candidate to read path",
        description="Mark a heuristic candidate as promoted.",
    )
    promote_p.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="Path to the patterns SQLite database",
    )
    promote_p.add_argument("--id", required=True, type=int, help="Candidate ID")
    promote_p.set_defaults(handler=cmd_candidates_update, action="promoted")

    dismiss_p = pat_sub.add_parser(
        "dismiss",
        help="Dismiss a candidate (false positive)",
        description="Mark a heuristic candidate as dismissed.",
    )
    dismiss_p.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="Path to the patterns SQLite database",
    )
    dismiss_p.add_argument("--id", required=True, type=int, help="Candidate ID")
    dismiss_p.set_defaults(handler=cmd_candidates_update, action="dismissed")

    retire_p = pat_sub.add_parser(
        "retire",
        help="Retire a promoted candidate",
        description="Mark a promoted heuristic candidate as retired.",
    )
    retire_p.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="Path to the patterns SQLite database",
    )
    retire_p.add_argument("--id", required=True, type=int, help="Candidate ID")
    retire_p.set_defaults(handler=cmd_candidates_update, action="retired")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
