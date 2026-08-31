"""mcp/baseline.py — signed local store of approved MCP manifest hashes.

SQLite DB with one HMAC-SHA256-signed row per manifest id. `shai mcp onboard`
is the only writer: a clean onboarding pass is the operator's trust action,
recorded automatically (see harness.mcp.onboard). The gate's per-tool-call
approval check (harness.mcp.gate.McpBaselineGate) is the reader that matters
for enforcement — checked on every check_tool_call, not once at startup.

Schema:
    baseline(id TEXT PRIMARY KEY, file_hash TEXT, recorded_at REAL, signature TEXT)

Verification: HMAC-SHA256 over the canonical JSON encoding of
{id, file_hash} (sort_keys=True), using the operator's mcp_baseline secret —
its own secret, not patterns_db's or audit_signing's. A row that fails
verification is treated the same as a missing row: fail closed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS baseline (
    id          TEXT PRIMARY KEY,
    file_hash   TEXT NOT NULL,
    recorded_at REAL NOT NULL,
    signature   TEXT NOT NULL
);
"""


@contextmanager
def _connect(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _sign(manifest_id: str, file_hash: str, secret: bytes) -> str:
    body = json.dumps(
        {"id": manifest_id, "file_hash": file_hash}, sort_keys=True
    ).encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def init_db(db_path: str | Path) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.executescript(_DDL)


def record_baseline(
    db_path: str | Path, manifest_id: str, file_hash: str, secret: bytes
) -> None:
    """Record (or re-approve) a clean onboarding pass.

    Idempotent re-approval: re-running on an already-approved, unchanged
    manifest updates recorded_at without changing the stored hash — the row
    is INSERTed or REPLACEd wholesale, so this is a plain upsert either way.
    """
    init_db(db_path)
    signature = _sign(manifest_id, file_hash, secret)
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO baseline (id, file_hash, recorded_at, signature) "
            "VALUES (?, ?, ?, ?)",
            (manifest_id, file_hash, time.time(), signature),
        )
    log.info("mcp manifest baseline recorded",
              extra={"manifest_id": manifest_id, "file_hash": file_hash})


def lookup_baseline(
    db_path: str | Path, manifest_id: str, secret: bytes
) -> dict | None:
    """Return {"file_hash", "recorded_at"} for manifest_id, or None if there
    is no record, the DB doesn't exist yet, or the row fails signature
    verification (tampered rows are treated as absent — fail closed).
    """
    path = Path(db_path)
    if not path.exists():
        return None
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT id, file_hash, recorded_at, signature FROM baseline WHERE id = ?",
            (manifest_id,),
        ).fetchone()
    if row is None:
        return None
    expected = _sign(row["id"], row["file_hash"], secret)
    if not hmac.compare_digest(expected, row["signature"]):
        log.warning("mcp baseline signature invalid — treated as absent",
                    extra={"manifest_id": manifest_id})
        return None
    return {"file_hash": row["file_hash"], "recorded_at": row["recorded_at"]}
