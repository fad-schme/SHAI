# MCP Manifests Reference

An MCP source is **declared** under `sources:` in `harness.yaml`, by name,
the same way a local source is. Its manifest — endpoint, credentials, tags,
per-tool metadata — is entirely operator-authored and lives outside the
package, resolved by convention from the declared name:
`<mcp_manifests_dir>/<name>.yaml`. `mcp_manifests_dir` is not scanned; a
manifest file with no matching `sources:` entry is invisible to the harness,
and a `transport: mcp` entry with no manifest at that path is a load error
(honouring the entry's `required` flag). See `harness.mcp.manifest`,
`harness.mcp.discovery`, and `harness.mcp.onboard`.

---

## Declaring a manifest

```yaml
# harness.yaml
mcp_manifests_dir: ./mcp/
mcp_baseline:
  path: state/mcp_baseline.db
  secret: "secret://SHAI_MCP_BASELINE_KEY"   # own secret, required when
                                              # any source declares transport: mcp
  cache_ttl_seconds: 5   # re-onboarding/kill latency on the gate's hot path
sources:
  - name: slack
    transport: mcp
```

`SourceConfig` accepts only `name`/`transport` (plus fields every source
already has, like `tags`/`required`) for a `transport: mcp` entry — no url,
credentials, or allow-lists there; those stay manifest-only.

```yaml
# mcp/slack.yaml
id: slack
display_name: "Slack"
url: "https://mcp.slack.com/sse"
allowed_urls:
  - "https://mcp.slack.com/*"
  - "https://slack.com/api/*"
allowed_methods: [GET, POST]
tags: [external_mcp, messaging, external]
credentials:
  token: "secret://SLACK_BOT_TOKEN"
required: true       # governs whether a connection/load failure is fatal —
                      # same semantics as sources: required. Does NOT govern
                      # onboarding approval — see "The approval gate" below
tools:
  - name: send_message
    description: "Send a message to a channel or user"
    tags: [external_write, messaging]
    action: block
  - name: read_messages
    description: "Read messages from a channel"
    tags: [read, messaging]
    action: allow
```

`action` is `allow` or `block`, and it is enforced. Each `action: block`
compiles at startup to an ordinary deny rule evaluated by the existing
policy layer, placed ahead of every operator rule — agent-scoped and global
alike. Rules are first-match-wins, so a manifest denial cannot be overridden
by a rule in `harness.yaml` or an agent file; to grant the tool, change the
manifest and re-run `shai mcp onboard`. `action: allow` compiles to no rule
at all — it is the absence of a restriction, not a grant, so an operator
rule denying that tool still denies. The manifest adds denials, never
removes them.

---

## The approval gate

At every `SHAI.from_yaml()`, each `transport: mcp` `sources:` entry has its
manifest resolved, hashed, and checked against the signed baseline store —
a live `MCPSource` is built **only** for a name whose hash matches an
approved record:

```
no manifest file at all                   → load error (or skipped, per `required`) — never built
manifest exists, no baseline record       → not built at all — no stub, nothing registered
manifest exists, hash differs from record → not built at all — no stub, nothing registered
manifest exists, hash matches record      → built into a live MCPSource
```

An agent that declares a source name the harness didn't build gets the
ordinary "source not registered" handling (`SourceRegistry.activate()`),
honouring that source's `required` flag exactly like any other missing
source — this is where `required` matters for an MCP source's approval
state, distinct from its meaning for a missing manifest file.

For a source that *was* built, approval is re-checked separately, on
**every `check_tool_call`** for a tool from it (a gate pre-check,
`harness.mcp.gate.McpBaselineGate` — after revocation/rate-limit/
session-budget, before the seven-layer gate), not just once at startup:

```
hash still matches the baseline record → call proceeds to the seven-layer gate
hash no longer matches (manifest edited since startup) → every call denied, needs re-onboarding
```

Each check re-hashes the manifest and re-reads the baseline store, behind
`mcp_baseline.cache_ttl_seconds` of caching (default 5s — the same latency
model `RevocationConfig.cache_ttl_seconds` uses for the agent kill switch).
A denial here is a normal gate deny — `boundary=tool_call_gate`,
`decision=deny` — the same shape as any other. This is what catches a
manifest edited after the harness already started: the source was built
with a valid hash at startup, the file changes underneath it, and the next
call denies without needing a restart.

---

## Onboarding — the only path to approval

```bash
shai mcp onboard mcp/slack.yaml --config config/harness.yaml
```

One run:

1. Parse and validate the manifest (missing/invalid field → exit non-zero,
   names exactly what's wrong — no interactive prompting).
2. Connect live to the manifest's `url` and fetch `tools/list` — confirms
   reachability; the response is never used as registration content.
3. Scan the manifest's own declared tool name/description with
   `MCPMetadataScanner` (injection payloads) and `PromptDefenseScanner`
   (absence of defensive language).
4. Reconcile declared tools against the live response
   (`harness.mcp.reconciliation`):
   - declared + present, compatible → clean
   - declared, absent from live → soft warning, never fails onboarding
   - present, undeclared → dropped, informational only
   - declared, live description diverges → **fails onboarding** — the
     rug-pull signal: a compromised server can't swap in a different
     description without the comparison catching it
5. Emit exactly one `AuditEvent(boundary=mcp_source_onboarding)`, decision
   against `scan_mcp_metadata.block_at`. `extra["readiness"]` and
   `extra["protocol_posture"]` ride along as informational governance
   signal only — see `verdicts-events.md`.
6. On a clean pass, the manifest's hash is recorded into the baseline
   store — running the command *is* the approval, no separate flag.
   Nothing is recorded on failure.

Re-running onboarding on an already-approved, unchanged manifest is
idempotent re-approval: the hash doesn't change, only `recorded_at` does.
Edit the manifest and it fails closed again until re-onboarded.

---

## Per-tool tags are enforced at registration

The manifest is authoritative for what gets registered — name, description,
tags, all come from the manifest, never the live `tools/list` response
(`MCPSource._fetch_tools`). So a policy rule like:

```yaml
- id: block_writes
  match:
    tool_tags: [external_write]
  action: deny
```

...works correctly against manifest-declared tags without any extra
configuration, once the source is onboarded and active.

---

## Tool result scanning

Every tool result is scanned regardless of source. Manifests do not declare
a per-tool opt-out — a tool whose output looks like control-plane data is
exactly where an indirect-injection payload arrives unnoticed.

```python
tv = await harness.scan_tool_result(result, ctx)
```

---

## Dev/demo credentials

In development without real tokens, use a literal empty string rather than
an unset `secret://` reference:

```yaml
credentials:
  token: ""               # empty — no network calls will succeed
required: false
```

**Do not use `secret://MISSING_VAR`** for a manifest you don't intend to
onboard yet. Secret resolution happens both at harness startup (for an
already-approved manifest) and inside `shai mcp onboard` itself — either
will fail if the referenced env var is missing.
