"""shai patterns — manage the signed pattern database.

  shai patterns apply --bundle <file> --db <path> --secret <env_var>
  shai patterns list  --db <path>
  shai patterns verify --db <path> --secret <env_var>
"""
from __future__ import annotations

import os
import sys


def cmd_patterns_apply(args) -> int:
    secret = os.environ.get(args.secret)
    if not secret:
        print(f"error: environment variable {args.secret!r} not set", file=sys.stderr)
        return 1

    from harness.patterns.store import apply_bundle
    try:
        count = apply_bundle(args.bundle, args.db, secret.encode())
        print(f"applied {count} patterns to {args.db}")
        return 0
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_patterns_list(args) -> int:
    from harness.patterns.store import list_rules
    rules = list_rules(args.db)
    if not rules:
        print("no patterns in database")
        return 0
    for r in rules:
        print(f"  {r['rule_id']:40s}  catalog={r['catalog']:15s}  v{r['version']}")
    print(f"\n{len(rules)} rules total")
    return 0


def cmd_patterns_verify(args) -> int:
    secret = os.environ.get(args.secret)
    if not secret:
        print(f"error: environment variable {args.secret!r} not set", file=sys.stderr)
        return 1

    from harness.patterns.store import verify_all
    valid, invalid = verify_all(args.db, secret.encode())
    print(f"valid: {valid}  invalid: {invalid}")
    return 0 if invalid == 0 else 1
