# Connectors Reference

Pre-built security configurations for well-known MCP servers.
Use `connector:` in harness.yaml instead of hand-configuring every field.

---

## Why connectors

Without a connector, you configure every field manually:
```yaml
sources:
  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    tags: [external_mcp, messaging, external]
    allowed_urls:
      - "https://mcp.slack.com/*"
      - "https://slack.com/api/*"
      - "https://edgeapi.slack.com/*"
    allowed_methods: [GET, POST]
    # + you'd need to know which tools are risky and tag them correctly
```

With a connector, you write:
```yaml
sources:
  - name: slack
    connector: slack
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
```

The manifest supplies: `url`, `allowed_urls`, `allowed_methods`, `tags`,
per-tool security specs, and `scan_tool_result_on` declarations.

---

## Available Tier A connectors

| `connector:` | Service | Key security notes |
|---|---|---|
| `slack` | Slack | `send_message` blocked; read tools scanned |
| `github` | GitHub | `push_files`, `merge_pull_request` blocked+sensitive; code scanned |
| `notion` | Notion | All writes blocked; page content scanned |
| `jira` | Jira | `delete_issue` sensitive; JQL results scanned |
| `gmail` | Gmail | ALL tools sensitive; send blocked; all reads scanned |
| `postgresql` | PostgreSQL | `execute` blocked; ALL results sensitive+scanned |
| `stripe` | Stripe | ALL tools sensitive; payment/cancel blocked; customer data scanned |
| `google_drive` | Google Drive | `share_file` blocked (exfiltration); read content scanned |

---

## How it works

`from_yaml()` detects `connector:` on a source, loads the manifest, and merges:

```
manifest fields (url, allowed_urls, tags, tool_specs, scan_tool_result_on)
    + operator fields (name, credentials, any overrides)
    → SourceConfig
    → MCPSource with per-tool tags and scan_tool_result_on wired in
```

**Operator fields always override manifest defaults.**

---

## Per-tool tags (enforced)

Connector manifests declare per-tool security metadata. This is wired into
tool registration — tools from a connector arrive in the registry with the
correct tags, not just generic source-level tags.

```python
# After loading a Slack connector, the gate sees:
# send_message → tags: ["external_write", "messaging", "mcp"]
# read_messages → tags: ["read", "messaging", "mcp"]

gate = await harness.check_tool_call("send_message", args, ctx)
# A deny rule matching tool_tags: [external_write] fires correctly
```

This means a policy rule like:
```yaml
- id: block_writes
  match:
    tool_tags: [external_write]
  action: deny
```
...works correctly for connector tools without any extra configuration.

---

## scan_tool_result_on (enforced)

Manifests declare which tools have T6 risk (indirect injection in results).
When you call `scan_tool_result` with `tool_name=`, only declared tools are scanned.

```python
# Slack manifest declares: scan_tool_result_on: [read_messages, search_messages, get_channel_info]

# This tool IS in scan_tool_result_on — full scan runs
tv = await harness.scan_tool_result(result, ctx, tool_name="read_messages")

# This tool is NOT — emits disabled=True audit event, returns allow immediately
tv = await harness.scan_tool_result(result, ctx, tool_name="list_channels")
```

**Always pass `tool_name=` when using connectors.** It's optional for backward
compatibility but required for connector security to work as intended.

---

## Operator overrides

Any field from the manifest can be overridden:

```yaml
sources:
  - name: slack
    connector: slack
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
    required: false          # override manifest default (true)
    allowed_urls:            # restrict further than the manifest
      - "https://mcp.slack.com/*"
    tags:                    # add extra tags
      - external_mcp
      - messaging
      - trusted_source
```

---

## Inspecting manifests programmatically

```python
from harness.connectors import load_manifest, list_connectors

# List all installed connectors
print(list_connectors())
# ['github', 'gmail', 'google_drive', 'jira', 'notion', 'postgresql', 'slack', 'stripe']

# Inspect a manifest
m = load_manifest("slack")
print(m.url)                    # "https://mcp.slack.com/sse"
print(m.allowed_urls)           # ["https://mcp.slack.com/*", ...]
print(m.scan_tool_result_on)    # ["read_messages", "search_messages", "get_channel_info"]

for tool in m.tools:
    print(tool.name, tool.tags, tool.action)
    # "send_message", ["external_write", "messaging"], "block"
```

---

## Credentials format per connector

| Connector | Credential key | Value |
|---|---|---|
| `slack` | `token` | `xoxb-...` Slack bot token |
| `github` | `token` | GitHub personal access or App token |
| `notion` | `token` | Notion integration token |
| `jira` | `email` + `token` | Atlassian email + API token |
| `gmail` | `token` | OAuth2 access token |
| `postgresql` | `connection_string` | `postgresql://user:pass@host/db` |
| `stripe` | `token` | Stripe restricted API key |
| `google_drive` | `token` | OAuth2 access token |

---

## Dev/demo credentials

In development without real tokens, use empty strings:

```yaml
sources:
  - name: slack
    connector: slack
    credentials:
      token: ""               # empty — no network calls will be made
    required: false
```

**Do not use `secret://MISSING_VAR`** for optional sources in dev.
Secret resolution happens at `from_yaml()` time for all sources,
including `required: false`. The load will fail if the env var is missing.
