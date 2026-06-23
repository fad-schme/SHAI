# Writing Adapters

SHAI discovers adapters via Python entry points. Any package can contribute adapters by registering them under the appropriate group. The harness resolves them by name at startup.

---

## Entry point groups

| Group | Interface | Reference implementations |
|---|---|---|
| `harness.scanners` | `Scanner` Protocol | `regex_pii`, `injection_scan` |
| `harness.policy` | `PolicyEngine` Protocol | `rules` |
| `harness.audit_sinks` | `AuditSink` Protocol | `stdout`, `file` |
| `harness.sources` | `ToolSource` Protocol | `local`, `skill`, `mcp` |
| `harness.secrets` | `SecretsProvider` ABC | `env` |

---

## Scanner

```python
from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.verdicts import Finding
from harness.core.types import Severity

class MyScanner:
    name = "my_scanner"   # must match entry point name

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        findings = []
        if "bad_pattern" in text:
            findings.append(Finding(
                scanner=self.name,
                category="my.category",
                severity=Severity.HIGH,
                detail="my.category pattern detected",  # category note only, never matched text
            ))
        return ScanResult(
            findings=findings,
            redacted_text=text.replace("bad_pattern", "[REDACTED]") if findings else None,
        )
```

**Rules:**
- `async def scan(...)` — always async even if sync internally
- `Finding.detail` — category + note only. Never include the matched substring.
- `redacted_text` — return `None` when nothing was redacted (not an empty string)
- Raise freely on hard errors; the boundary catches per-scanner exceptions and continues

---

## AuditSink

```python
from harness.core.events import AuditEvent

class MySink:
    name = "my_sink"

    async def emit(self, event: AuditEvent) -> None:
        # Ship the event. Raise on failure — AuditEmitter handles partial failures.
        ...

    async def close(self) -> None:
        # Flush and release resources. Must be idempotent.
        ...
```

**Rules:**
- `emit()` must be safe for concurrent async calls
- `close()` must be idempotent
- Raise on failure — never swallow exceptions (AuditEmitter handles them)
- Never log `event.extra` raw values

---

## PolicyEngine

```python
from harness.policy.engine import PolicyDecision, SourceDecision
from harness.core.context import AgentContext
from harness.tools.tool import Tool

class MyPolicy:
    name = "my_policy"

    async def evaluate(
        self,
        tool: Tool,
        args: dict,
        ctx: AgentContext,
        *,
        rules: list | None = None,
    ) -> PolicyDecision:
        # rules = agent-scoped rules, evaluated before your global rules
        # Return PolicyDecision(action="allow") as default
        ...

    async def evaluate_source(self, source, ctx: AgentContext) -> SourceDecision:
        return SourceDecision(active=True)   # default
```

**Rules:**
- Raise `PolicyEvaluationError` on engine failure (network, bad bundle)
- A normal deny is `PolicyDecision(action="deny", reason=...)` — not an exception
- `evaluate_source` defaults to active unless a rule suppresses

---

## ToolSource

```python
from harness.core.context import AgentContext
from harness.core.types import Transport
from harness.tools.tool import Tool

class MySource:
    name      = "my_source"
    transport = Transport.LOCAL
    tags: list[str] = []

    async def load(self, ctx: AgentContext) -> list[Tool]:
        # Return tools for this agent context.
        # Apply ctx.allowed_tags filter when set (subagent safety).
        ...

    async def close(self) -> None:
        # Release connections. Called from SHAI.close().
        ...
```

---

## SecretsProvider

```python
from harness.adapters.secrets.env import Secret, SecretNotFound

class MySecrets:
    name = "my_secrets"

    def resolve(self, reference: str) -> Secret:
        # reference is a bare name (secret:// prefix already stripped)
        # Return Secret(value=...). Raise SecretNotFound on miss.
        # Never log the resolved value.
        ...
```

**Rules:**
- `resolve()` is synchronous — called once at startup in `from_yaml()`
- Raise `SecretNotFound` on miss; `SecretsProviderError` on transport failure
- Never include the resolved value in repr, error messages, or logs

---

## Registering an adapter

```toml
# your_package/pyproject.toml
[project.entry-points."harness.scanners"]
my_scanner = "my_package.scanners:MyScanner"

[project.entry-points."harness.audit_sinks"]
my_sink = "my_package.sinks:MySink"
```

After `pip install`, the adapter is available by name in `harness.yaml`:

```yaml
scan_input:
  enabled: true
  scanners:
    - name: my_scanner
    - name: my_scanner
      config:
        threshold: 0.8    # passed as kwargs to __init__

audit_sinks:
  - name: my_sink
    config:
      endpoint: "https://..."
```

---

## Discovery and conflict detection

`adapters/discovery.py` loads all entry points for a group on first access and caches them. If two packages register the same name under the same group, `AdapterDiscoveryError` is raised at startup with both class paths listed. Name collisions are never silently resolved.

Canonical groups that SHAI monitors:

```python
GROUPS = frozenset({
    "harness.scanners",
    "harness.policy",
    "harness.audit_sinks",
    "harness.secrets",
})
```

Note: `harness.sources` adapters are constructed directly in `from_yaml()` from `config.sources`, not via discovery. Discovery covers adapters configured by name in `harness.yaml`.

---

## Contract tests

Every adapter must pass the relevant contract suite:

| Group | Contract file |
|---|---|
| scanners | `tests/contracts/test_scanner_contract.py` |
| audit_sinks | `tests/contracts/test_audit_sink_contract.py` |
| policy | `tests/contracts/test_policy_contract.py` |
| tool_sources | `tests/contracts/test_tool_sources_contract.py` |
| secrets | `tests/contracts/test_secrets_contract.py` |

Run against your implementation by parameterising the fixtures in the contract file.
