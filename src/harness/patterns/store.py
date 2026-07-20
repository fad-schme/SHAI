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
