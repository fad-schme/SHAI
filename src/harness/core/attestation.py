"""Startup attestation — what this process is actually running.

`build_attestation` assembles the payload carried by the SYSTEM/STARTUP
AuditEvent emitted at the end of SHAI.from_yaml(). It answers one question:
which code, rules and destinations are wired into this harness right now.

Two deliberate limits:

  - It attests **wired** components, not installed ones. Adapter identity comes
    from the objects the config actually built.
  - Content only, no secrets. Source URLs are stripped of userinfo, query and
    fragment before they enter the payload (Invariant 3), and credentials are
    never read.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Sequence

    from harness.config.schema import HarnessConfig, SourceConfig

log = logging.getLogger(__name__)

# agent_id on the startup event. AuditEvent requires one and no agent is loaded
# yet — this value marks the event as describing the process itself.
STARTUP_AGENT_ID = "__harness__"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _component(obj: object, group: str) -> dict[str, Any]:
    """Identity of one wired adapter: name, import path, source-file digest.

    The digest covers the file the class was defined in — that is what makes
    the record an attestation rather than a listing. It is None when the source
    is unavailable (namespace-packaged, frozen, or defined interactively).
    """
    cls = type(obj)
    try:
        digest: str | None = _sha256_hex(Path(inspect.getfile(cls)).read_bytes())
    except (TypeError, OSError) as e:
        digest = None
        log.debug("attestation: no source file for %s.%s: %s",
                  cls.__module__, cls.__qualname__, e)
    return {
        "group":  group,
        "name":   getattr(obj, "name", cls.__qualname__),
        "module": f"{cls.__module__}.{cls.__qualname__}",
        "sha256": digest,
    }


def redact_url(url: str | None) -> str | None:
    """Scheme, host, port and path only — userinfo, query and fragment removed.

    Credentials and tokens ride in userinfo and query strings, and this payload
    goes to every audit sink.
    """
    if not url:
        return None
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return f"{parts.scheme}://{host}{parts.path}" if parts.scheme else host + parts.path


def _digest_of(payload: Any) -> str:
    """Order-independent digest of a JSON-serialisable structure."""
    return _sha256_hex(json.dumps(payload, sort_keys=True, default=str).encode())


def _patterns_db(config: HarnessConfig) -> dict[str, Any] | None:
    """Rule count and digest of the signed pattern DB, or None when disabled.

    Rows are individually HMAC-signed in the DB; this digest exists to tell two
    startups apart, not to re-establish authenticity.
    """
    if not config.patterns_db.enabled:
        return None
    from harness.patterns.store import list_rules

    rows = list_rules(config.patterns_db.path)
    return {
        "path":       str(config.patterns_db.path),
        "rule_count": len(rows),
        "digest":     _digest_of(sorted(
            f"{r['rule_id']}|{r['catalog']}|{r['version']}" for r in rows
        )),
    }


def _mcp_manifests(config: HarnessConfig) -> list[dict[str, Any]]:
    """Digest of every MCP source declared in `sources:` (transport: mcp),
    whether or not it currently has an approved baseline record — so an
    operator can see what's declared-but-unapproved offline.

    Offline-safe: resolves and hashes each declared name's manifest file but
    does not check the signed baseline store or connect to a server —
    approval/activation state is a runtime concern (see harness.mcp.discovery),
    not derivable from config alone. A name with no manifest file, or an
    invalid one, is skipped here rather than raising — from_yaml() is the
    fail-fast path; this is a best-effort inventory.
    """
    if not config.mcp_manifests_dir:
        return []
    from harness.core.types import Transport
    from harness.mcp.manifest import load_manifest_file, manifest_file_hash, manifest_path_for

    out: list[dict[str, Any]] = []
    for src_cfg in config.sources:
        if src_cfg.transport != Transport.MCP:
            continue
        path = manifest_path_for(src_cfg.name, config.mcp_manifests_dir)
        try:
            manifest = load_manifest_file(path)
        except Exception:
            continue
        out.append({
            "id":     manifest.id,
            "url":    redact_url(manifest.url),
            "digest": manifest_file_hash(path),
        })
    return sorted(out, key=lambda m: m["id"])


def build_config_attestation(
    *,
    config: HarnessConfig,
    sources: Sequence[SourceConfig],
) -> dict[str, Any]:
    """The part of the attestation derivable from config alone.

    Shared with the offline `shai harness` commands, which cannot instantiate
    adapters — so everything here must describe the config, never a live object.

    `sources` are the declared SourceConfigs, local and MCP alike (see
    config.schema.SourceConfig) — MCP manifest content is reported separately
    under `mcp_manifests`, one entry per `transport: mcp` name declared in
    `sources:`.
    """
    from harness import __version__

    source_rules = config.policy.parsed_source_rules()

    return {
        "shai_version":  __version__,
        "mcp_manifests": _mcp_manifests(config),
        "patterns_db":  _patterns_db(config),
        "policy": {
            # Source-activation rules — which sources this harness lets
            # activate. Per-tool-call policy is the agent's own config and,
            # for an MCP source, its manifest; neither is attested here.
            "source_rule_count": len(source_rules),
            "digest":            _digest_of(
                [r.model_dump(mode="json") for r in source_rules]
            ),
            # Enforced at agent load, not by a rule, so the digest above
            # would not move if an operator dropped it.
            "forbidden_tag_combinations": sorted(
                sorted(set(c)) for c in config.policy.forbidden_tag_combinations
            ),
        },
        "sources": [
            {
                "name":      src.name,
                "transport": str(src.transport),
                "tags":      sorted(src.tags),
            }
            for src in sources
        ],
    }


def build_attestation(
    *,
    config: HarnessConfig,
    scanners: Sequence[object],
    sinks: Sequence[object],
    policy: object,
    sources: Sequence[SourceConfig],
) -> dict[str, Any]:
    """Build the `extra` payload of the SYSTEM/STARTUP audit event.

    Adds the wired-adapter identities to the config-derived payload — the one
    part that requires live objects, and the reason the event says more about
    the process than `shai harness inspect` can offline.
    """
    components: dict[str, dict[str, Any]] = {}
    for obj, group in (
        *[(s, "scanner") for s in scanners],
        *[(s, "audit_sink") for s in sinks],
        (policy, "policy"),
    ):
        entry = _component(obj, group)
        components[f"{group}:{entry['module']}"] = entry

    return {
        "adapters": [components[k] for k in sorted(components)],
        **build_config_attestation(config=config, sources=sources),
    }
