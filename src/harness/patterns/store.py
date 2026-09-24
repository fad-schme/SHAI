"""patterns/store.py — signed pattern (rule) storage and verification.

Backed by a state-store `.kv` (see adapters/state_store/base.py) rather than
a hardcoded database — SQLite is one adapter among others, resolved by the
caller and passed in. This module holds no database-driver import.

Heuristic-candidate storage lives in patterns/candidates_store.py, on direct
SQLite, deliberately not migrated here — see that module's docstring.

Keying: `"{catalog}:{rule_id}"`, so a catalog-scoped listing (as
load_verified_rules needs) is a `kv.list(prefix=catalog)` call.

Stored value is JSON: {rule_id, catalog, payload, signature, version,
created_at}. payload is itself a JSON string — same structure as one entry
in the YAML patterns file:
    {"name": "...", "meta": {...}, "match": "any", "strings": {...}, "functions": [...]}

Verification: HMAC-SHA256 over the canonical JSON encoding of
{rule_id, catalog, payload} (sort_keys=True), using the operator's signing
secret (same secret:// resolution as audit signing).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.adapters.state_store.base import StateStore

log = logging.getLogger(__name__)


def _sign_row(rule_id: str, catalog: str, payload: str, secret: bytes) -> str:
    """HMAC-SHA256 over the canonical JSON encoding of the three signed fields.

    Canonical JSON rather than concatenation: `rule_id + catalog + payload` has
    no field delimiter, so ("x", "injection") and ("xin", "jection") sign the
    same bytes. Since `catalog` routes a rule to a scanner, that ambiguity let a
    signed row be re-split to land on a different scanner without the key. Same
    canonicalization the audit emitter signs with.
    """
    body = json.dumps(
        {"rule_id": rule_id, "catalog": catalog, "payload": payload},
        sort_keys=True,
    ).encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _verify_row(rule_id: str, catalog: str, payload: str, signature: str, secret: bytes) -> bool:
    expected = _sign_row(rule_id, catalog, payload, secret)
    return hmac.compare_digest(expected, signature)


def _key(catalog: str, rule_id: str) -> str:
    return f"{catalog}:{rule_id}"


def _parse_row(key: str, raw: bytes, secret: bytes) -> dict | None:
    """The stored row, or None when it is malformed or not what its key claims.

    The signature covers rule_id, catalog and payload but not the key a row is
    filed under, and the key is what routes a rule to a scanner — so a row
    whose signed fields do not reproduce its own key is rejected, exactly as a
    bad signature is. A malformed row is skipped rather than fatal, like every
    other bad row: one damaged entry must not take the harness down.
    """
    try:
        row = json.loads(raw)
        rule_id, catalog = row["rule_id"], row["catalog"]
        payload, signature = row["payload"], row["signature"]
    except (ValueError, KeyError, TypeError):
        log.warning("pattern row malformed — skipped", extra={"key": key})
        return None
    if key != _key(catalog, rule_id) or not _verify_row(rule_id, catalog, payload, signature, secret):
        log.warning("pattern signature invalid — skipped",
                    extra={"rule_id": rule_id, "catalog": catalog})
        return None
    return row


async def load_verified_rules(
    store: StateStore,
    secret: bytes,
    catalog: str = "injection",
) -> list[dict]:
    """Load and verify pattern rows for one catalog. Returns raw rule dicts
    for compilation.

    Skips rows with invalid signatures. Returns empty list if none exist.
    """
    rules: list[dict] = []
    skipped = 0
    for key in await store.kv.list(_key(catalog, "")):
        raw = await store.kv.get(key)
        if raw is None:
            continue
        row = _parse_row(key, raw, secret)
        if row is None:
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


async def apply_bundle(bundle_path, store: StateStore, secret: bytes) -> int:
    """Apply a signed pattern bundle to the store. Atomic — all or nothing.

    Bundle format: JSON array of objects, each with:
        {"rule_id", "catalog", "payload", "signature", "version"}

    payload is a JSON string (the rule dict, JSON-encoded).
    Returns the number of rules applied.
    """
    with open(bundle_path, encoding="utf-8") as f:
        bundle = json.load(f)

    if not isinstance(bundle, list):
        raise ValueError("bundle must be a JSON array")

    # Verify all rows before writing any.
    now = time.time()
    items: dict[str, bytes] = {}
    for entry in bundle:
        rule_id   = entry["rule_id"]
        catalog   = entry["catalog"]
        payload   = entry["payload"]
        signature = entry["signature"]
        if ":" in catalog:
            raise ValueError(f"catalog may not contain ':': {catalog!r}")
        if not _verify_row(rule_id, catalog, payload, signature, secret):
            raise ValueError(f"signature verification failed for rule_id={rule_id!r}")
        items[_key(catalog, rule_id)] = json.dumps({
            "rule_id":    rule_id,
            "catalog":    catalog,
            "payload":    payload,
            "signature":  signature,
            "version":    entry.get("version", 1),
            "created_at": now,
        }).encode()

    # batch_put is atomic per adapter — all keys land or none do, preserving
    # the all-or-nothing guarantee the single SQL transaction gave for free.
    await store.kv.batch_put(items)

    log.info("applied %d patterns from bundle", len(bundle))
    return len(bundle)


async def list_rules(store: StateStore) -> list[dict]:
    """List all rules in the store (for CLI display). No verification."""
    out: list[dict] = []
    for key in await store.kv.list(""):
        raw = await store.kv.get(key)
        if raw is None:
            continue
        try:
            row = json.loads(raw)
            out.append({
                "rule_id":    row["rule_id"],
                "catalog":    row["catalog"],
                "version":    row["version"],
                "created_at": row["created_at"],
            })
        except (ValueError, KeyError, TypeError):
            log.warning("pattern row malformed — not listed", extra={"key": key})
    out.sort(key=lambda r: (r["catalog"], r["rule_id"]))
    return out


async def verify_all(store: StateStore, secret: bytes) -> tuple[int, int]:
    """Verify all rows. Returns (valid_count, invalid_count)."""
    valid = invalid = 0
    for key in await store.kv.list(""):
        raw = await store.kv.get(key)
        if raw is None:
            continue
        if _parse_row(key, raw, secret) is None:
            invalid += 1
        else:
            valid += 1
    return valid, invalid
