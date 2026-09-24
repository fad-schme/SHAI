"""patterns/candidates_store.py — heuristic candidate cache, direct SQLite.

Deliberately not migrated onto the StateStore Protocol along with
patterns/store.py's rule table. Reads (`load_promoted_candidates`, via
ScanState.get_promoted) and writes (`upsert_candidate`, via
boundaries/_scan.py's `_record_candidate_if_needed`) both run inside
run_scan() — the synchronous-helper pipeline shared by every scan boundary,
not an isolated runtime call site. Moving this behind the (async) StateStore
Protocol would force that shared pipeline async; keeping it as its own,
narrowly-scoped exception was the smaller, safer change. See patterns/store.py's
module docstring.

SQLite DB with no signing — candidates are heuristic suggestions awaiting
human promotion (see set_candidate_status), not yet trusted rules.

Schema:
    heuristic_candidates(id, fingerprint, skeleton, severity, hit_count,
                          first_seen, last_seen, status)
"""
from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger(__name__)


@contextmanager
def _connect(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Open a connection that always closes, committing on clean exit.

    `with sqlite3.connect(...)` commits or rolls back but does **not** close —
    the transaction is the Connection's context manager, the handle is not. Every
    call site here used that form, so each leaked an open handle until GC. On
    POSIX that is an invisible leak; on Windows an open handle blocks `unlink`,
    which is how a temp-directory teardown around this DB came to fail.

    Rows come back as `sqlite3.Row` for every caller.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


_DDL = """
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


def init_db(db_path: str | Path) -> None:
    """Create the heuristic_candidates table if it doesn't exist."""
    with _connect(db_path) as conn:
        conn.executescript(_DDL)


def upsert_candidate(
    db_path: str | Path,
    fingerprint_json: str,
    skeleton: str,
    severity: str,
    lsh: str,
) -> None:
    """Insert or update a heuristic candidate. Deduplicates by LSH similarity."""
    import time

    from harness.patterns.fingerprint import (
        LSH_MATCH_THRESHOLD,
        fingerprint_from_json,
        lsh_jaccard,
    )

    path = Path(db_path)
    init_db(path)
    now = time.time()

    with _connect(path) as conn:
        # Check existing open/promoted candidates for similarity
        rows = conn.execute(
            "SELECT id, fingerprint FROM heuristic_candidates WHERE status IN ('open', 'promoted')"
        ).fetchall()

        for row in rows:
            existing_fp = fingerprint_from_json(row["fingerprint"])
            existing_lsh = existing_fp.get("lsh", "")
            if lsh_jaccard(lsh, existing_lsh) >= LSH_MATCH_THRESHOLD:
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
        with _connect(path) as conn:
            rows = conn.execute(
                "SELECT id, fingerprint, skeleton, severity, hit_count "
                "FROM heuristic_candidates WHERE status = 'promoted'"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        # Runs on the scan path: an unreadable candidate cache costs promoted-
        # candidate matching, never a verdict — so it recovers to "none", and
        # says so.
        log.debug("promoted candidates unreadable — none loaded", exc_info=True)
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
    with _connect(path) as conn:
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
    with _connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE heuristic_candidates SET status = ? WHERE id = ?",
            (status, candidate_id),
        )
        return cursor.rowcount > 0
