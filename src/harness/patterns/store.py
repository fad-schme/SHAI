"""patterns/store.py — signed pattern storage and verification.

SQLite DB with HMAC-SHA256 per row. Loaded at startup by from_yaml(),
verified rules compiled and passed to InjectionScanner as extra_rules.

Schema:
    patterns(rule_id TEXT PK, catalog TEXT, payload TEXT, signature TEXT,
             version INT, created_at REAL)

payload is JSON: same structure as one entry in the YAML patterns file:
    {"name": "...", "meta": {...}, "strings": {...}, "functions": [...]}

Verification: HMAC-SHA256 over (rule_id + catalog + payload) using the
operator's signing secret (same secret:// resolution as audit signing).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
from pathlib import Path

log = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS patterns (
    rule_id    TEXT PRIMARY KEY,
    catalog    TEXT NOT NULL,
    payload    TEXT NOT NULL,
    signature  TEXT NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS heuristic_candidates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT NOT NULL,
    skeleton     TEXT NOT NULL,
    severity     TEXT NOT NULL,
    hit_count    INTEGER DEFAULT 1,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    status       TEXT DEFAULT 'open'
);
"""


def _sign_row(rule_id: str, catalog: str, payload: str, secret: bytes) -> str:
    body = (rule_id + catalog + payload).encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _verify_row(rule_id: str, catalog: str, payload: str, signature: str, secret: bytes) -> bool:
    expected = _sign_row(rule_id, catalog, payload, secret)
    return hmac.compare_digest(expected, signature)


def init_db(db_path: str | Path) -> None:
    """Create the patterns table if it doesn't exist."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(_DDL)


def load_verified_rules(
    db_path: str | Path,
    secret: bytes,
    catalog: str = "injection",
) -> list[dict]:
    """Load and verify pattern rows. Returns raw rule dicts for compilation.

    Skips rows with invalid signatures. Returns empty list if DB is missing.
    """
    path = Path(db_path)
    if not path.exists():
        return []

    rules: list[dict] = []
    with sqlite3.connect(str(path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT rule_id, catalog, payload, signature FROM patterns WHERE catalog = ?",
            (catalog,),
        ).fetchall()

    skipped = 0
    for row in rows:
        if not _verify_row(row["rule_id"], row["catalog"], row["payload"], row["signature"], secret):
            log.warning("pattern signature invalid — skipped",
                        extra={"rule_id": row["rule_id"], "catalog": row["catalog"]})
            skipped += 1
            continue
        try:
            rules.append(json.loads(row["payload"]))
        except json.JSONDecodeError:
            log.warning("pattern payload invalid JSON — skipped",
                        extra={"rule_id": row["rule_id"]})
            skipped += 1

    if rules:
        log.info("loaded %d verified patterns from DB (%d skipped)",
                 len(rules), skipped)
    return rules


def apply_bundle(
    bundle_path: str | Path,
    db_path: str | Path,
    secret: bytes,
) -> int:
    """Apply a signed pattern bundle to the DB. Atomic — all or nothing.

    Bundle format: JSON array of objects, each with:
        {"rule_id", "catalog", "payload", "signature", "version"}

    payload is a JSON string (the rule dict, JSON-encoded).
    Returns the number of rules applied.
    """
    import time

    with open(bundle_path, encoding="utf-8") as f:
        bundle = json.load(f)

    if not isinstance(bundle, list):
        raise ValueError("bundle must be a JSON array")

    # Verify all rows before writing any
    for entry in bundle:
        rule_id   = entry["rule_id"]
        catalog   = entry["catalog"]
        payload   = entry["payload"]
        signature = entry["signature"]
        if not _verify_row(rule_id, catalog, payload, signature, secret):
            raise ValueError(f"signature verification failed for rule_id={rule_id!r}")

    init_db(db_path)
    now = time.time()
    with sqlite3.connect(str(db_path)) as conn:
        for entry in bundle:
            conn.execute(
                "INSERT OR REPLACE INTO patterns (rule_id, catalog, payload, signature, version, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (entry["rule_id"], entry["catalog"], entry["payload"],
                 entry["signature"], entry.get("version", 1), now),
            )

    log.info("applied %d patterns from bundle", len(bundle))
    return len(bundle)


def list_rules(db_path: str | Path) -> list[dict]:
    """List all rules in the DB (for CLI display). No verification."""
    path = Path(db_path)
    if not path.exists():
        return []
    with sqlite3.connect(str(path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT rule_id, catalog, version, created_at FROM patterns ORDER BY catalog, rule_id"
        ).fetchall()
    return [dict(r) for r in rows]


def verify_all(db_path: str | Path, secret: bytes) -> tuple[int, int]:
    """Verify all rows. Returns (valid_count, invalid_count)."""
    path = Path(db_path)
    if not path.exists():
        return 0, 0
    with sqlite3.connect(str(path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT rule_id, catalog, payload, signature FROM patterns").fetchall()
    valid = invalid = 0
    for row in rows:
        if _verify_row(row["rule_id"], row["catalog"], row["payload"], row["signature"], secret):
            valid += 1
        else:
            invalid += 1
    return valid, invalid


# ── Heuristic candidates ─────────────────────────────────────────────────

_LSH_SIMILARITY_THRESHOLD = 0.7


def upsert_candidate(
    db_path: str | Path,
    fingerprint_json: str,
    skeleton: str,
    severity: str,
    lsh: str,
) -> None:
    """Insert or update a heuristic candidate. Deduplicates by LSH similarity."""
    import time
    from harness.patterns.fingerprint import fingerprint_from_json, lsh_jaccard

    path = Path(db_path)
    init_db(path)
    now = time.time()

    with sqlite3.connect(str(path)) as conn:
        conn.row_factory = sqlite3.Row
        # Check existing open/promoted candidates for similarity
        rows = conn.execute(
            "SELECT id, fingerprint FROM heuristic_candidates WHERE status IN ('open', 'promoted')"
        ).fetchall()

        for row in rows:
            existing_fp = fingerprint_from_json(row["fingerprint"])
            existing_lsh = existing_fp.get("lsh", "")
            if lsh_jaccard(lsh, existing_lsh) >= _LSH_SIMILARITY_THRESHOLD:
                conn.execute(
                    "UPDATE heuristic_candidates SET hit_count = hit_count + 1, last_seen = ? WHERE id = ?",
                    (now, row["id"]),
                )
                return

        conn.execute(
            "INSERT INTO heuristic_candidates (fingerprint, skeleton, severity, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (fingerprint_json, skeleton, severity, now, now),
        )

        # Cap: evict oldest low-hit open candidate when table exceeds 500
        count = conn.execute(
            "SELECT COUNT(*) FROM heuristic_candidates WHERE status = 'open'"
        ).fetchone()[0]
        if count > 500:
            conn.execute(
                "DELETE FROM heuristic_candidates WHERE id = ("
                "  SELECT id FROM heuristic_candidates"
                "  WHERE status = 'open' AND hit_count < 3"
                "  ORDER BY last_seen ASC LIMIT 1"
                ")"
            )


def load_promoted_candidates(db_path: str | Path) -> list[dict]:
    """Load all promoted candidates for scan-time lookup."""
    path = Path(db_path)
    if not path.exists():
        return []
    try:
        with sqlite3.connect(str(path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, fingerprint, skeleton, severity, hit_count "
                "FROM heuristic_candidates WHERE status = 'promoted'"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def list_candidates(db_path: str | Path, status: str | None = None, min_hits: int = 0) -> list[dict]:
    """List candidates for CLI display.

    When status is 'open' and min_hits is 0, defaults to min_hits=3
    to filter noise. Pass min_hits=1 (--all) to see everything.
    """
    path = Path(db_path)
    if not path.exists():
        return []
    effective_min = min_hits if min_hits > 0 else (3 if status == "open" else 1)
    with sqlite3.connect(str(path)) as conn:
        conn.row_factory = sqlite3.Row
        if status:
            rows = conn.execute(
                "SELECT * FROM heuristic_candidates WHERE status = ? AND hit_count >= ? ORDER BY hit_count DESC",
                (status, effective_min),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM heuristic_candidates WHERE hit_count >= ? ORDER BY hit_count DESC",
                (effective_min,),
            ).fetchall()
    return [dict(r) for r in rows]


def set_candidate_status(db_path: str | Path, candidate_id: int, status: str) -> bool:
    """Set candidate status. Returns True if a row was updated."""
    if status not in ("open", "dismissed", "promoted", "retired"):
        raise ValueError(f"invalid status: {status}")
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "UPDATE heuristic_candidates SET status = ? WHERE id = ?",
            (status, candidate_id),
        )
        return cursor.rowcount > 0
