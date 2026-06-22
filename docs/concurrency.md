# Concurrency model

The authoritative reference for concurrent agent and subagent execution.
Read before implementing ToolRegistry, AuditSink, load_sources,
or any code touching shared state during a boundary call.

---

## 1. The core guarantee

One `Harness` instance safely serves any number of concurrent agents
and subagents. All facade methods are `async def` — the harness is
designed for asyncio-based concurrent execution.

Shared state (adapters, base ToolRegistry) is read-only after startup.
Per-turn state (ScopedRegistryView) is per-agent-identity, never shared.

---

## 2. Agent identity and isolation

The effective identity for all internal harness operations is:

```python
(agent_id, sub_agent_id or "")  # ctx.agent_key()
```

`user_id` and `session_id` on RuntimeContext are audit-only fields.
The harness never uses them for keying, policy evaluation, source
activation, or view management. Code that does is a bug.

Each concurrent agent/subagent pair has:
- Own RuntimeContext
- Own ScopedRegistryView (WeakValueDictionary keyed on agent_key())
- Own audit trail (agent_id + sub_agent_id in every AuditEvent)
- Own agent profile (AgentConfig or SubAgentConfig)
- Own source set (load_sources activates only declared sources)

---

## 3. ScopedRegistryView — the critical invariant

`load_sources` creates a per-call view and stores it in:

```python
self._views: WeakValueDictionary[tuple[str,str], ScopedRegistryView]
# key = (agent_id, sub_agent_id or "")
```

`check_tool_call` retrieves it by the same key. `unload_sources` drops it.
`WeakValueDictionary` provides a GC safety net if unload is not called.
Explicit `unload_sources` is still required.

The view writes only to an in-call overlay. The shared ToolRegistry base
(startup tools) is never written during a turn. Cross-agent tool leakage
is structurally impossible.

Parent and subagent have separate views:
```
("orchestrator", "")            → view with outlook_mcp + docs tools
("orchestrator", "research_sub") → view with docs tools only
```

---

## 4. Async model

All Protocol methods and facade methods are `async def`. This is a
one-pass architectural decision — no sync variants exist.

Runtime: `asyncio`. No `trio`, no `anyio`.

Reference adapters with no I/O (regex scanners, rules evaluator, env
secrets) implement `async def` methods that return immediately. The
async overhead is negligible; the consistency is mandatory.

Scanners run concurrently per boundary call via `asyncio.gather`.
AuditSink.emit() calls run concurrently via `asyncio.gather`.
ToolSource.load() calls run concurrently via `asyncio.gather`.

---

## 5. AuditSink async safety

All sink implementations must be safe for concurrent async calls.
This is stated in the Protocol and enforced by the concurrent-emit test
in `tests/contracts/sink_contract.py`.

- `StdoutSink` — stdout writes are fast; acceptable to call without
  locking. Interleaving possible at OS level. Dev/container use only.
- `FileSink` — uses `asyncio.Lock` around write + `run_in_executor`.
  Serialises writes; offloads blocking I/O to thread pool.
- Enterprise sinks — HTTP-based; inherently concurrent. Internal
  batching queues use `asyncio.Queue`.

---

## 6. AgentRegistry concurrency

`AgentRegistry.get()` is synchronous (required for `scope_context_for_subagent`
to remain sync). GIL-safe dict read in CPython.

Load/reload/deregister use `threading.Lock` for writes. Mixed
sync/async write operations use `asyncio.to_thread` when called from
async context.

---

## 7. What does NOT require coordination

- `scan_input` / `scan_output` — stateless, each call independent.
- `check_tool_call` — reads from view (per-agent) and base (read-only).
- `scope_context_for_subagent` — pure sync function, no shared writes.
- `PolicyEngine.evaluate` / `evaluate_source` — rules read-only.
- `SecretsProvider.resolve` — called only at startup, before async loop.

---

## 8. Test coverage

Unit tests: one file per module, test async boundaries with pytest-asyncio.

Integration tests:
- `test_end_to_end_turn.py` — full async turn, subagent turn, isolation.
- `test_concurrent_agents.py` — 10 concurrent agents, parent+subagent
  concurrent, overlapping load/unload.

Contract tests: all async. `sink_contract.py` includes concurrent-emit
test via `asyncio.gather`.
