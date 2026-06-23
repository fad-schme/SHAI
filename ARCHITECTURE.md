# Harness — package architecture

A Python SDK that adds three security boundaries around an agent's LLM loop:
`scan_input`, `check_tool_call`, `scan_output`, with always-on structured audit
emission. The agent owns its loop; the harness governs the boundaries.

Three packages, mirroring UMA's open-core layout:

| Package | License | Contents |
|---|---|---|
| `harness` | Apache-2.0 (or BSL) | Core primitives, Protocol interfaces, reference adapters |
| `harness-enterprise` | Commercial | Production adapters: DLP, SIEM, enterprise policy, secrets |
| `harness-cli` | Apache-2.0 | Developer tools: policy validation, audit replay, scanner harness |

The core is genuinely useful standalone: a developer can build a real,
single-tenant harnessed agent with `pip install harness` alone, using reference
scanners (regex PII, basic injection patterns), the YAML rule-based policy
engine, and JSONL/file audit sinks. Enterprise drops in production-grade
adapters at the same Protocol slots — same `harness.yaml`, different adapter
names, no code change in the agent.

## Design principles

**One canonical path per boundary.** Each boundary has exactly one entry point
on the public facade. No parallel implementations, no "experimental" duplicate
paths. Same discipline AGENTS.md enforces for UMA.

**Backend agnostic by default.** Every external dependency — scanners, policy
engines, audit sinks, secrets stores, the tool registry — sits behind a
Protocol defined in `harness`. Implementations live wherever: reference ones
in `harness`, production ones in `harness-enterprise`, customer-written ones in
their own packages. Adapters are discovered via Python entry points and chosen
by name from `harness.yaml`.

**Configuration over code.** `harness.yaml` declares which scanners run, which
policy bundle is active, which audit sinks are wired, which tools are
registered. Switching from reference to enterprise adapters is a config edit
plus a `pip install harness-enterprise`.

**The agent owns the loop.** The harness never calls the LLM, never calls UMA,
never decides how many tool turns to allow. It exposes pure functions the
agent calls at the right boundaries. Framework integrations are thin adapters
that wire those calls into popular agent frameworks; if a customer's framework
isn't covered, the wiring is one line in their loop.

**Audit is not optional.** Every boundary call emits a structured event. The
sink is configurable; the emission is not. A CISO must be able to see every
input scan verdict, every tool gate decision, every output redaction in their
SIEM without code changes by the customer.

## Public API surface

The facade is small and stable. Everything else — including the package an
adapter lives in — is invisible to the agent.

```python
from harness import Harness, Tool, RuntimeContext

harness = Harness.from_yaml("harness.yaml")
harness.register_tools([
    Tool("search_docs", schema=SearchDocsSchema, tags=["read", "internal"]),
    Tool("send_email", schema=SendEmailSchema, tags=["external_write", "sensitive"]),
])

# Per-turn boundaries
verdict = harness.scan_input(text, ctx)          # ScanVerdict
gate = harness.check_tool_call(name, args, ctx)  # GateDecision
verdict = harness.scan_output(text, ctx)         # ScanVerdict
```

`ScanVerdict` carries `blocked: bool`, `findings: list[Finding]`, and an
optional `redacted_text: str | None`. `GateDecision` carries `allowed: bool`,
`deny_reason: str | None`, and an optional `redacted_args: dict | None`. Both
emit audit events as a side effect.

## Adapter Protocols (defined in `harness`, implemented anywhere)

| Protocol | Responsibility | Reference impl in `harness` | Production impl in `harness-enterprise` |
|---|---|---|---|
| `Scanner` | Inspect text, return findings | Regex PII catalog, basic injection patterns | Purview, Nightfall, Forcepoint, Lakera |
| `PolicyEngine` | Evaluate `(tool, args, ctx)` → decision | YAML rule evaluator | OPA bundle loader, Cedar |
| `AuditSink` | Accept structured `AuditEvent` | stdout JSONL, rotating file | Splunk, Sentinel, Elastic, OTel, S3+WORM |
| `ToolRegistry` | Store and look up registered tools | In-memory dict | Redis, central registry service |
| `SecretsProvider` | Resolve secret references | Env vars | Vault, AWS KMS, GCP Secret Manager |

Adapter discovery happens through Python entry points (`harness.scanners`,
`harness.policy`, etc.). Any package — `harness-enterprise`, a third-party
package, or the customer's own — can register an adapter under one of these
groups and have it available by name in `harness.yaml`. The agent code stays
the same.

## Folder structure

### Package 1 — `harness` (core, Apache-2.0)

```
harness/
├── pyproject.toml                       # entry-point groups declared here
├── README.md
├── AGENTS.md
├── LICENSE
├── harness.yaml.example
│
├── src/
│   └── harness/
│       ├── __init__.py                  # public exports: Harness, Tool, RuntimeContext, ...
│       │
│       ├── core/                        # framework-agnostic primitives
│       │   ├── __init__.py
│       │   ├── harness.py               # the Harness facade — only public entry point
│       │   ├── context.py               # RuntimeContext (tenant, agent, user, session)
│       │   ├── verdicts.py              # ScanVerdict, GateDecision, Finding
│       │   ├── events.py                # AuditEvent schema + emission helper
│       │   ├── errors.py                # HarnessError hierarchy
│       │   └── types.py                 # shared type aliases, enums (Severity, Action)
│       │
│       ├── boundaries/                  # the three boundary implementations
│       │   ├── __init__.py
│       │   ├── scan_input.py
│       │   ├── check_tool_call.py       # registry lookup + policy eval + arg scan
│       │   └── scan_output.py
│       │
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── tool.py                  # Tool dataclass (name, schema, tags)
│       │   └── registry.py              # in-process registration API + lookup
│       │
│       ├── policy/
│       │   ├── __init__.py
│       │   ├── engine.py                # PolicyEngine Protocol
│       │   ├── decision.py              # PolicyDecision
│       │   └── rules.py                 # reference rule-based YAML evaluator
│       │
│       ├── audit/
│       │   ├── __init__.py
│       │   ├── emitter.py               # AuditEmitter — fan-out to sinks
│       │   ├── sink.py                  # AuditSink Protocol
│       │   └── redaction.py             # field-level redaction helpers
│       │
│       ├── adapters/                    # PROTOCOLS + REFERENCE IMPLEMENTATIONS ONLY
│       │   ├── __init__.py
│       │   ├── discovery.py             # entry-point lookup, name → class resolver
│       │   │
│       │   ├── scanners/
│       │   │   ├── __init__.py
│       │   │   ├── base.py              # Scanner Protocol
│       │   │   ├── regex_pii.py         # reference: PII patterns
│       │   │   └── basic_injection.py   # reference: common prompt-injection patterns
│       │   │
│       │   ├── policy/
│       │   │   ├── __init__.py
│       │   │   └── base.py              # PolicyEngine Protocol (impl lives in policy/rules.py)
│       │   │
│       │   ├── audit_sinks/
│       │   │   ├── __init__.py
│       │   │   ├── base.py              # AuditSink Protocol
│       │   │   ├── stdout.py            # reference JSONL stdout
│       │   │   └── file.py              # reference rotating file
│       │   │
│       │   ├── tool_registry/
│       │   │   ├── __init__.py
│       │   │   ├── base.py              # ToolRegistry Protocol
│       │   │   └── memory.py            # reference in-process dict
│       │   │
│       │   └── secrets/
│       │       ├── __init__.py
│       │       ├── base.py              # SecretsProvider Protocol
│       │       └── env.py               # reference env-var lookup
│       │
│       ├── integrations/                # framework wiring helpers (optional)
│       │   ├── __init__.py
│       │   ├── langgraph.py             # HarnessGate node wrapper
│       │   ├── langchain.py             # wrap_tool, callback handler
│       │   ├── crewai.py
│       │   ├── pydantic_ai.py
│       │   ├── openai_agents.py
│       │   └── anthropic_sdk.py         # gated_dispatch for hand-rolled loops
│       │
│       └── config/
│           ├── __init__.py
│           ├── loader.py                # harness.yaml → HarnessConfig
│           ├── schema.py                # pydantic schema for harness.yaml
│           └── resolution.py            # env-var interpolation, secret refs
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contracts/                       # Protocol-conformance suite — see note below
│   └── fixtures/
│       └── harness.yaml
│
├── docs/
│   ├── architecture.md                  # this document
│   ├── boundaries.md                    # per-boundary semantics and contracts
│   ├── policy.md                        # rule grammar + plug-in policy engines
│   ├── adapters.md                      # writing a new adapter
│   ├── integrations.md                  # per-framework integration recipes
│   └── audit-schema.md                  # AuditEvent schema, field by field
│
└── examples/
    ├── hand_rolled_loop.py              # plain SDK loop with three boundaries wired
    ├── langgraph_agent.py
    ├── with_uma.py                      # harness + UMA composed by the agent
    └── policies/
        └── rules.yaml                   # example rule-based policy
```

**Note on `tests/contracts/`:** the Protocol-conformance suite lives in core
but is reusable. `harness-enterprise` imports it and runs each of its adapters
through it. Same for any third-party adapter package. That's how the open-core
boundary stays honest — every adapter, wherever it lives, passes the same
contract tests.

### Package 2 — `harness-enterprise` (commercial)

A separate distribution. Depends on `harness>=X.Y`. Registers production
adapters under the same entry-point groups core defines.

```
harness-enterprise/
├── pyproject.toml                       # depends on harness; registers entry points
├── README.md
├── LICENSE                              # commercial
│
├── src/
│   └── harness_enterprise/
│       ├── __init__.py
│       │
│       ├── scanners/
│       │   ├── __init__.py
│       │   ├── purview.py               # Microsoft Purview DLP
│       │   ├── nightfall.py
│       │   ├── forcepoint.py
│       │   └── lakera.py                # AI-specific (prompt injection, jailbreak)
│       │
│       ├── policy/
│       │   ├── __init__.py
│       │   ├── opa.py                   # OPA bundle loader + evaluator
│       │   └── cedar.py
│       │
│       ├── audit_sinks/
│       │   ├── __init__.py
│       │   ├── splunk.py
│       │   ├── sentinel.py
│       │   ├── elastic.py
│       │   ├── otel.py
│       │   └── s3_worm.py               # WORM-bucket archival
│       │
│       ├── tool_registry/
│       │   ├── __init__.py
│       │   ├── redis.py
│       │   └── service.py               # central multi-tenant registry client
│       │
│       └── secrets/
│           ├── __init__.py
│           ├── vault.py                 # HashiCorp Vault
│           ├── aws_kms.py
│           └── gcp_sm.py
│
├── tests/
│   ├── unit/
│   ├── integration/                     # mocked vendor SDKs
│   └── contracts/                       # imports tests.contracts from harness
│
└── docs/
    ├── installation.md
    ├── adapter-matrix.md                # which adapter for which use case
    └── runbooks/                        # per-adapter operational guides
        ├── purview.md
        ├── opa.md
        └── splunk.md
```

### Package 3 — `harness-cli` (Apache-2.0)

A separate distribution. Depends on `harness>=X.Y`. Installs the `harness`
command.

```
harness-cli/
├── pyproject.toml                       # entry: harness = harness_cli.main:cli
├── README.md
├── LICENSE
│
├── src/
│   └── harness_cli/
│       ├── __init__.py
│       ├── main.py                      # Click/Typer root: `harness`
│       │
│       ├── commands/
│       │   ├── __init__.py
│       │   ├── validate.py              # harness validate harness.yaml
│       │   ├── policy_test.py           # harness policy test --tool foo --args ...
│       │   ├── policy_diff.py           # harness policy diff old.yaml new.yaml
│       │   ├── scan.py                  # harness scan --text "..." (test scanners)
│       │   ├── audit_replay.py          # harness audit replay events.jsonl
│       │   ├── audit_tail.py            # harness audit tail
│       │   └── adapters_list.py         # harness adapters list (show installed)
│       │
│       └── lib/
│           ├── __init__.py
│           ├── fixtures.py              # synthetic events for replay/test
│           └── reporters.py             # console output formatting
│
├── tests/
│   └── unit/
│
└── docs/
    └── commands.md                      # one section per command
```

## Adapter discovery — how the packages compose

`harness` declares entry-point groups in its `pyproject.toml`:

```toml
[project.entry-points."harness.scanners"]
regex_pii        = "harness.adapters.scanners.regex_pii:RegexPIIScanner"
basic_injection  = "harness.adapters.scanners.basic_injection:BasicInjectionScanner"

[project.entry-points."harness.policy"]
rules            = "harness.policy.rules:RuleBasedPolicy"

[project.entry-points."harness.audit_sinks"]
stdout           = "harness.adapters.audit_sinks.stdout:StdoutSink"
file             = "harness.adapters.audit_sinks.file:FileSink"

[project.entry-points."harness.tool_registry"]
memory           = "harness.adapters.tool_registry.memory:InMemoryRegistry"

[project.entry-points."harness.secrets"]
env              = "harness.adapters.secrets.env:EnvSecrets"
```

`harness-enterprise` adds its own entries under the same groups:

```toml
[project.entry-points."harness.scanners"]
purview          = "harness_enterprise.scanners.purview:PurviewScanner"
nightfall        = "harness_enterprise.scanners.nightfall:NightfallScanner"
lakera           = "harness_enterprise.scanners.lakera:LakeraScanner"

[project.entry-points."harness.policy"]
opa              = "harness_enterprise.policy.opa:OPAPolicy"
cedar            = "harness_enterprise.policy.cedar:CedarPolicy"

[project.entry-points."harness.audit_sinks"]
splunk           = "harness_enterprise.audit_sinks.splunk:SplunkSink"
sentinel         = "harness_enterprise.audit_sinks.sentinel:SentinelSink"
# ... etc
```

`harness/adapters/discovery.py` enumerates entry points at startup. A
`harness.yaml` referencing `scanners: [regex_pii, purview]` resolves
`regex_pii` from `harness` and `purview` from `harness-enterprise`, transparently.
A customer-written package can register under the same groups and be picked up
the same way — no harness code changes.

## What each top-level area contains

**`core/`** — the smallest possible set of types and the public facade. Nothing
here depends on any adapter. `Harness` is a thin orchestrator: it holds
configured adapter instances and delegates to `boundaries/`. `RuntimeContext`
is the identity envelope (tenant, agent, user, session) the agent passes on
every call. `ScanVerdict`, `GateDecision`, and `AuditEvent` are the wire types
between the agent and the harness, and between the harness and its sinks.

**`boundaries/`** — one file per boundary, each owning the orchestration logic
for that boundary only. `scan_input.py` runs the configured input scanners and
aggregates findings. `check_tool_call.py` looks up the tool in the registry,
runs the policy engine, optionally scans args, and assembles a `GateDecision`.
`scan_output.py` mirrors `scan_input.py` with the output scanner set. Each
function emits its audit event before returning.

**`tools/`** — the tool registry abstraction and the `Tool` model. Registration
is a startup concern; lookup is the hot path. Tools carry their name, JSON
schema, and classification tags. Tags are what policy refers to
(`external_write`, `sensitive`, `read`), not implementation details.

**`policy/`** — the `PolicyEngine` Protocol and the reference rule-based
evaluator. A `PolicyDecision` is `allow | deny | redact`, optionally with
redacted args and a deny reason. The reference evaluator reads YAML rules over
tool tags; production users plug in OPA or Cedar from `harness-enterprise`.

**`audit/`** — the always-on audit pipeline. `AuditEmitter` is what every
boundary calls; it fans out to all configured sinks. Sinks implement the
`AuditSink` Protocol. `redaction.py` provides field-level redaction so
sensitive content in audit events doesn't leak into log aggregators.

**`adapters/`** — Protocol definitions and reference implementations only.
`discovery.py` resolves adapter names from config to classes by enumerating
entry points across all installed packages. Reference adapters are kept
deliberately simple — they exist so the SDK is usable without any extras, not
to compete with the enterprise versions.

**`integrations/`** — thin per-framework wrappers around the public facade.
Each file knows one framework's hook shape and exposes a one-liner that
customers drop into their agent code. Same pattern OpenTelemetry uses:
optional, framework-specific, never required.

**`config/`** — `harness.yaml` parsing, schema validation, env-var
interpolation, and secret resolution. The schema is the source of truth for
what a valid harness configuration looks like.

## Open-core boundary — what stays where

The dividing line is the `adapters/` namespace: `harness` ships Protocols and
reference implementations; `harness-enterprise` ships production
implementations under the same Protocols. Nothing in the public API differs
between editions — customers wire their choice in `harness.yaml`.

A few rules to keep the boundary clean:

- `harness-enterprise` may not add new public API surface visible to agent
  code. If a production adapter needs a capability the Protocol doesn't
  expose, that capability gets added to the Protocol in `harness` first.
- `harness` may not import from `harness-enterprise`. The dependency is
  one-way.
- Every adapter in `harness-enterprise` passes the same contract suite that
  the reference adapters pass in `harness`. The suite is published from
  `harness` as a reusable test fixture.
- A customer using only `harness` must be able to run a realistic agent in
  production — not a demo, a real single-tenant deployment. If reference
  adapters become non-functional placeholders, the open-core promise breaks.

## What's deliberately out of scope

A short list, because it's as important as what's in:

- **No LLM client.** The harness never imports an LLM SDK.
- **No agent loop.** The harness does not own the turn lifecycle. Turn budgets
  belong to the customer's agent code, not to the harness.
- **No memory primitives.** Memory is UMA's job; the harness doesn't store
  conversations, embed text, or do retrieval.
- **No response composition.** The agent assembles its own output from UMA's
  structured returns and the LLM's narrative. The fact/narrative split is
  preserved by UMA's outputs, not enforced by the harness.
- **No tool execution.** The harness gates, the agent dispatches.
- **No bulk data ingestion.** Data-lake connectors (Snowflake, Databricks,
  SharePoint) belong to a separate ingestion path into UMA, not to the
  per-turn boundaries this harness governs. If they ship under the same
  commercial umbrella, it's as a separate package (e.g. `harness-ingest`),
  not folded into the boundary SDK.

Each of these is a place where feature creep would erode the conceptual
integrity of the product. The discipline is the differentiator.
