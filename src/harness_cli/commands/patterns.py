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


def cmd_candidates_list(args) -> int:
    from harness.patterns.store import list_candidates
    from harness.patterns.fingerprint import fingerprint_from_json
    import datetime

    min_hits = 1 if getattr(args, "all", False) else 0
    candidates = list_candidates(args.db, status=args.status, min_hits=min_hits)
    if not candidates:
        print("no candidates found")
        return 0

    for c in candidates:
        first = datetime.datetime.fromtimestamp(c["first_seen"]).strftime("%b-%d")
        last = datetime.datetime.fromtimestamp(c["last_seen"]).strftime("%b-%d")
        print(f"  id={c['id']}  hits={c['hit_count']}  severity={c['severity']}"
              f"  first={first}  last={last}  status={c['status']}")
        fp = fingerprint_from_json(c["fingerprint"])
        markers = ",".join(fp.get("markers", [])) or "none"
        print(f"    entropy={fp['entropy']}  density={fp['density']}"
              f"  markers=[{markers}]")
        print(f"    skeleton: {c['skeleton']}")
        print()
    print(f"{len(candidates)} candidates total")
    return 0


def cmd_candidates_update(args) -> int:
    from harness.patterns.store import set_candidate_status
    ok = set_candidate_status(args.db, args.id, args.action)
    if ok:
        print(f"candidate {args.id} → {args.action}")
        # The CLI runs in its own process — it cannot invalidate a running
        # SHAI instance's in-memory candidate cache. The DB update above is
        # authoritative; the harness will pick it up on its next cold read.
        # If a running harness needs the change reflected immediately, call
        # SHAI._scan_state.invalidate_promoted_cache() from the same process.
        return 0
    print(f"error: candidate {args.id} not found", file=sys.stderr)
    return 1
