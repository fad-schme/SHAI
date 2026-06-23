# Concurrency

One `SHAI` instance serves many concurrent agent turns safely.

---

## Threading model

| Component | Concurrency mechanism |
|---|---|
| `ToolRegistry` | `threading.Lock` for writes (startup only); lock-free dict reads on hot path |
| `AgentRegistry` | Same as `ToolRegistry` |
| `RateLimiter` | `threading.Lock` held only for deque operations (O(1) amortised) |
| `AuditEmitter` | `asyncio.gather` for concurrent sink fan-out |
| `SourceRegistry.activate()` | `asyncio.gather` for concurrent source loading |
| `FileSink` | `asyncio.Lock` serialises concurrent `emit()` calls; `run_in_executor` offloads blocking writes |
| `_agent_tools` | Dict populated at `load_agent()` time, read lock-free on every turn |

---

## Turn isolation

Each turn is identified by the `AgentContext` object passed to every boundary call. `AgentContext` is frozen (immutable) and carries `agent_id`, `sub_agent_id`, and `allowed_tags`.

Two concurrent turns for the same agent are distinguished by object identity — each holds a different `AgentContext` instance. There is no shared per-turn mutable state.

`_agent_tools[agent_id]` is a dict keyed by agent ID. It is populated once at `load_agent()` and read lock-free on every turn. Concurrent turns for the same agent read the same dict — which is safe because the dict is never mutated on the hot path.

---

## Concurrent parent + subagent turns

A common pattern — orchestrator turn and research subagent turn running simultaneously:

```python
ctx       = await harness.load_agent("agents/orchestrator.yaml")
child_ctx = harness.scope_context_for_subagent(ctx, "research_sub")

# Run concurrently — both use the same harness, different contexts
results = await asyncio.gather(
    orchestrator_turn(harness, ctx),
    research_turn(harness, child_ctx),
)
```

Both turns share `_agent_tools["orchestrator_agent"]`. The subagent's tool visibility is enforced by `check_tool_call` L2 (tag gate) at call time, not by a separate tool set. This is safe because `child_ctx.allowed_tags` is immutable.

---

## Rate limiter concurrency

`RateLimiter` holds a single `threading.Lock` for all bucket operations. The lock is acquired for the duration of the deque prune + append — typically microseconds. It is never held across I/O or async boundaries.

Under high concurrency the lock becomes a brief serialisation point on `check_tool_call`. This is intentional — the rate limiter's global budget counter must be exact.

---

## Hazards to avoid

**Do not share `AgentContext` between turns.** `AgentContext` is frozen but contextually meaningful — a context created for one turn should not be reused for a different turn of the same agent. Use `AgentContext(agent_id=...)` for each new turn.

**Do not call `register_tools()` on the hot path.** `register_tools()` acquires the `ToolRegistry` write lock and re-resolves all loaded agents. It is designed for startup. Calling it per-turn will serialize concurrent turns through the lock.

**Do not call `load_agent()` per turn.** `load_agent()` activates sources (potentially network calls for MCP), registers tools, and populates `_agent_tools`. It is a startup operation. Call it once; hold the returned `AgentContext` for the agent's lifetime.

**Do not mutate `gate.redacted_args`.** `GateDecision.redacted_args` is the policy engine's output. Callers should use it as-is or copy it before modification.
