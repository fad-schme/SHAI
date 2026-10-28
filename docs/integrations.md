# Integrations

If you already have an agent running on LangGraph, LangChain, the Anthropic SDK, CrewAI, PydanticAI, or the OpenAI Agents SDK, SHAI can wrap it in one line. You don't rewrite your agent — you replace the tool node (or add a middleware) and every boundary check happens automatically.

## The one decorator that ties them all together

```python
from harness.integrations.langchain import shai_tool   # any integration module works

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str:
    """Search internal documentation."""
    return _search(query)

@shai_tool(tags=["external_write", "sensitive"])
async def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    return await _send(to, subject, body)
```

`@shai_tool` produces a `ShaiTool` that satisfies both SHAI's `Tool` interface and the target framework's tool interface. Sync and async both work. Define the function once, use it across every integration below.

### Declaring argument rules and approval tiers

`@shai_tool` also takes the two security fields the gate enforces per tool:

```python
from harness import ArgumentRule, Irreversibility

@shai_tool(
    tags=["financial", "external"],
    argument_rules=[ArgumentRule(arg="recipient", user_origin=True)],
    irreversibility=Irreversibility.SENSITIVE,
)
async def transfer_funds(recipient: str, amount: int) -> str:
    """Transfer funds to a recipient account."""
    return await _transfer(recipient, amount)
```

- **`argument_rules`** — per-argument constraints enforced at gate layer 2 (`max_value`, `min_value`, `allowlist`, `pattern`, `scope_policy`, `required`). A numeric bound (`max_value` / `min_value`) admits only real numbers: NaN and booleans are violations, and an integer too large for a float is compared exactly rather than converted. `user_origin=True` is enforced at layer 6: the call is denied when that argument's value entered the turn through a tool result rather than the user's prompt. Declare it only where the user is the one who names the value — a recipient, a grantee. On an argument the agent legitimately resolves from something it read, it denies ordinary work.
- **`irreversibility`** — `SENSITIVE` or `IRREVERSIBLE` makes layer 3 deny until the configured quorum of signed approval grants is present. The default, `REVERSIBLE`, needs none.
- **`path_args`** — the arguments that name filesystem paths, each mapped to the access the tool needs (`"read"` or `"write"`), for example `path_args={"src": "read", "dst": "write"}`. A tool tagged `fs` must declare them; registration refuses it otherwise, whatever the tool's source.

Tools discovered from an MCP source can't declare `argument_rules` or `irreversibility` — the manifest has no field for them. They declare `path_args` in the manifest (see [connectors.md](connectors.md)).

## Which integration to use

| Your framework | Use |
|---|---|
| LangGraph | `HarnessToolNode` — drop-in replacement for `ToolNode` |
| LangChain Agent Loop (`create_agent`, v1.0+) | `ShaiMiddleware` — cleanest integration |
| LangChain classic (any version) | `wrap_tools()` |
| Anthropic SDK raw loop | `gated_dispatch` + `make_tool_result_from_denial` |
| CrewAI | `wrap_tools()` |
| PydanticAI | `create_tools()`, or `add_harness_middleware()` on an existing agent |
| OpenAI Agents SDK | `wrap_tools()` |
| Anything with manual tool dispatch | Call `check_tool_call`, `dispatch_scope` and `scan_tool_result` directly |

Every wrapper on this page runs the same contract: `check_tool_call` before
dispatch, `scan_tool_result` on what comes back. You never call either
yourself, and there is no longer an entry point that runs only half of it.

`scan_tool_result` always runs: an omitted block runs SHAI's recommended
scanners, and `scanners:` in `config/harness.yaml` chooses which ones.

**MCP tools need no local callable.** When a gated tool resolves to an MCP
source, the call is routed to that source with the gate's `dispatch_token`
attached — which is what `ShaiTransport` validates on the outbound request.
`HarnessToolNode` does this for any tool name not in its local list, and
`gated_dispatch` does it when you omit `dispatch`. Dispatching an MCP tool
yourself without threading `gate.dispatch_token` and the calling `ctx` into
`MCPSource.call(tool_name, args, ctx=ctx, dispatch_token=gate.dispatch_token)`
leaves the request untokened (and `ctx` is required: the transport refuses a
token presented by an agent other than the one it was issued to): refused under `token_policy: strict` (the
default), and forwarded but recorded with no `token_id` under `audit`.

## Local tools: checking the dispatch token

Every allowed call carries a dispatch token. For an MCP tool, `ShaiTransport`
checks it. A local tool checks its own by calling `verify_tool_dispatch` before
doing anything else — it needs a reference to the SHAI instance:

```python
@shai_tool(tags=["financial", "external"])
def transfer_funds(recipient: str, amount: int) -> str:
    harness.verify_tool_dispatch("transfer_funds", {"recipient": recipient, "amount": amount})
    return _transfer(recipient, amount)
```

The check is sync, so sync and async tools call it the same way. Pass the
arguments the tool is about to act on: the token commits to the arguments the
gate allowed to dispatch (redactions applied, the ones `execute_gated_tool_call`
hands to `invoke`), and a changed, added or removed argument is refused. The
digest covers exactly the dictionary the gate saw, and what the gate sees depends
on the wrapper: `make_gated_tool` (CrewAI, OpenAI Agents SDK, PydanticAI) applies
parameter defaults before the gate, so the digest includes them, while `wrap_tool`,
`HarnessToolNode`, the LangChain middleware and the Anthropic SDK helpers do not,
and LangChain coerces types through the args schema. A tool with defaulted
parameters therefore has no single correct form across wrappers; declare tools
without defaults, as above, or pass the arguments as the wrapper in use presents
them. It
passes only for an unexpired token the gate issued for this tool, this agent and
its local source, and each token passes once. Otherwise it raises
`DispatchRefused`, which every integration on this page turns into the same
denial a gate deny produces, so the model receives the refusal reason.
Each check emits one `tool_dispatch_check` audit event carrying the same
`token_id` as the call's gate and `scan_tool_result` events.

The integrations run each tool inside `harness.dispatch_scope(ctx, gate)`,
which is where the check finds the token. In a manual loop you open the scope
yourself — see [Manual dispatch](#manual-dispatch-any-framework).

### Opening files

A tool that reads or writes a file opens it with `harness.fs.open(path, mode)`
in place of the built-in `open()`. It works only inside `dispatch_scope`. It
resolves the path again at the moment of use against the calling agent's
`allowed_paths` and the protected set, opens the resolved location, and refuses
a final path component that became a link since the gate's check. A refusal
raises `DispatchRefused`, and each call emits one `tool_dispatch_check` event
that carries no path.

```python
@shai_tool(tags=["fs"], path_args={"path": "read"})
def read_file(path: str) -> str:
    with harness.fs.open(path) as f:
        return f.read()
```

## LangGraph

```python
from harness.integrations.langgraph import HarnessToolNode, shai_tool
from langgraph.graph import StateGraph, MessagesState, END

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

tools = [search_docs]

harness   = await SHAI.from_yaml("config/harness.yaml")
agent_ctx = await harness.load_agent("config/agents/my_agent.yaml")
llm       = your_chat_model.bind_tools(tools)  # any LangChain-compatible chat model
tool_node = await HarnessToolNode.create(tools, harness, agent_ctx)

# HarnessToolNode.create() calls register_tools() internally.
# Pass the same tools list to bind_tools() — no duplication.

graph = StateGraph(MessagesState)
graph.add_node("agent", lambda s: {"messages": [llm.invoke(s["messages"])]})
graph.add_node("tools", tool_node)
graph.set_entry_point("agent")
graph.add_conditional_edges("agent", lambda s: "tools" if s["messages"][-1].tool_calls else END)
graph.add_edge("tools", "agent")
app = graph.compile()
```

`HarnessToolNode` handles `check_tool_call` and `scan_tool_result` on every dispatch. Denied calls surface to the LLM as a tool error — the agent can try something else.

## LangChain Agent Loop (v1.0+)

```python
from harness.integrations.langchain import ShaiMiddleware, shai_tool
from langchain.agents import create_agent

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

tools      = [search_docs]
harness    = await SHAI.from_yaml("config/harness.yaml")
agent_ctx  = await harness.load_agent("config/agents/my_agent.yaml")
middleware = await ShaiMiddleware.create(tools, harness=harness, ctx=agent_ctx)

agent = create_agent(llm, tools=tools, middleware=[middleware])

with harness.collect_events() as events:
    result = await agent.ainvoke({"messages": [HumanMessage(question)]})
```

`ShaiMiddleware` wires all five boundaries via LangChain's hook system:

- `abefore_agent` → `scan_input`
- `awrap_tool_call` → `check_tool_call` + `scan_tool_result`
- `aafter_agent` → `scan_output`

Requires `pip install "langchain>=1.0" langgraph`.

## LangChain classic

Works with any LangChain version. Compatible with `create_react_agent` and custom loops.

```python
from harness.integrations.langchain import wrap_tools, shai_tool

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

harness     = await SHAI.from_yaml("config/harness.yaml")
agent_ctx   = await harness.load_agent("config/agents/my_agent.yaml")
gated_tools = await wrap_tools([search_docs], harness=harness, ctx=agent_ctx)

# wrap_tools() registers tools AND returns gated LangChain-compatible wrappers
llm = your_chat_model.bind_tools(gated_tools)  # any LangChain-compatible chat model
```

Denied calls raise `ToolException` — the agent sees the denial and continues.

## Anthropic SDK

```python
from harness.core.verdicts import GateDecision, ScanVerdict
from harness.integrations.anthropic_sdk import gated_dispatch, make_tool_result_from_denial

# In your tool dispatch loop. gated_dispatch runs check_tool_call, dispatches
# on allow, then scans the result for indirect injection (T6) — you do not
# call scan_tool_result yourself.
result = await gated_dispatch(
    tool_name, tool_args, ctx, harness=harness, dispatch=dispatch,
)

if isinstance(result, (GateDecision, ScanVerdict)):
    # GateDecision — the gate denied the call, it never ran.
    # ScanVerdict  — it ran, but the result was blocked as indirect injection.
    denial_block = make_tool_result_from_denial(result, tool_use_id)
    messages.append({"role": "user", "content": [denial_block]})
else:
    messages.append({"role": "user", "content": [{
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": result,
    }]})
```

`run_turn(user_text, ctx, harness=harness, llm_fn=llm_fn)` wraps a whole turn:
`scan_input`, your `llm_fn`, then `scan_output`. It returns a `ScanVerdict` when
either boundary blocked the turn: the input never reached the model, or the
response was rejected and is not returned. Abort the turn and decide what to
surface. It returns a `str` when the turn completed, which is the final response
and carries the redacted text when `scan_output` replaced content. When
`scan_input` redacts, the model receives the redacted text, and `llm_fn` is
called with it instead of the original. `ShaiMiddleware.abefore_agent` does the
same: it replaces the last human message in graph state with the redacted text.

## CrewAI

```python
from harness.integrations.crewai import wrap_tools, shai_tool

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

gated = await wrap_tools([search_docs], harness=harness, ctx=ctx)
# Pass `gated` as tools to your CrewAI Agent
```

Install `crewai` alongside SHAI. `wrap_tools()` returns native CrewAI `BaseTool`
objects with typed input schemas; sync and async execution both run SHAI's gate
and result scan. CrewAI's injected fingerprint metadata is kept separate from
the implementation's arguments unless the tool explicitly declares that field.

## PydanticAI

```python
from harness.integrations.pydantic_ai import create_tools, shai_tool
from pydantic_ai import Agent

@shai_tool(tags=["read", "internal"])
async def search_docs(query: str) -> str: ...

# create_tools() registers the tools and returns gated callables
gated = await create_tools([search_docs], harness=harness, ctx=ctx)
agent = Agent(model="openai:gpt-4o", tools=gated)
```

For an agent that already holds its tools, `add_harness_middleware(agent, harness=harness, ctx=ctx)` gates them in place: every function tool the agent exposes to the model runs through `check_tool_call` and `scan_tool_result`, rendered as `create_tools` renders them, and the tools must be registered with the harness. It is verified against `pydantic-ai-slim` 2.61 and later. It raises `ConfigError` before the agent runs, leaving the agent unchanged, for a toolset it cannot gate (an MCP server or dynamic toolset), a tool that takes a `RunContext`, or a tool that cannot be wrapped; use `create_tools()` for those tools. `harness_tool(harness=..., ctx=...)` gates a third-party function that `@shai_tool` can't wrap.

```python
```

## OpenAI Agents SDK

```python
from harness.integrations.openai_agents import wrap_tools, shai_tool
from agents import Agent

@shai_tool(tags=["read", "internal"])
async def search_docs(query: str) -> str: ...

gated = await wrap_tools([search_docs], harness=harness, ctx=ctx)
agent = Agent(name="assistant", tools=gated)
```

Install `openai-agents` alongside SHAI. Decorate the implementation with
`@shai_tool`; `wrap_tools()` registers its security metadata and creates the SDK
`FunctionTool`. Positional and keyword arguments, including defaults, are bound
to the original signature before SHAI authorizes the call. Missing SDKs and
unsupported tool objects raise during wrapping.

## Manual dispatch (any framework)

If your framework isn't listed, or you want full control:

```python
from langchain_core.messages import ToolMessage

from harness import DispatchRefused

async def run_loop(llm, messages, harness, ctx):
    for _ in range(10):
        response = await llm.ainvoke(messages)
        messages.append(response)

        if not response.tool_calls:
            return response.content

        for tc in response.tool_calls:
            gate = await harness.check_tool_call(tc["name"], tc["args"], ctx)
            if not gate.allowed:
                messages.append(ToolMessage(
                    content=f"Denied: {gate.deny_reason}", tool_call_id=tc["id"]))
                continue

            try:
                # The tool's verify_tool_dispatch reads the token from here.
                async with harness.dispatch_scope(ctx, gate):
                    raw = await dispatch(tc["name"], gate.redacted_args or tc["args"])
            except DispatchRefused as e:
                messages.append(ToolMessage(
                    content=f"Denied: {e}", tool_call_id=tc["id"]))
                continue

            tv      = await harness.scan_tool_result(str(raw), ctx, token_id=gate.token_id)
            content = tv.redacted_text or str(raw)
            if tv.blocked:
                content = "Tool result blocked by security policy"
            messages.append(ToolMessage(content=content, tool_call_id=tc["id"]))
```

This is what the higher-level integrations do internally — you're just doing it yourself.

## Composed system prompts

SHAI has no `scan_system_prompt` boundary, and deliberately so: a system prompt
you wrote is authored by the same party that configures SHAI, and scanning it
would mean scanning trusted text for attacks by its own author.

What matters is everything you *assemble into* it. RAG context, retrieved
memory, notes from an earlier turn, instructions pulled from a database, and
prompt templates served by an MCP server are not system prompts — they are
untrusted content that ends up in the most privileged position in the request.

**Scan content before assembly, at the boundary it actually crossed:**

| Where the text came from | Boundary it must cross first |
|---|---|
| A tool call's return value | `scan_tool_result` |
| An uploaded or retrieved file | `scan_file` |
| The end user | `scan_input` |
| An MCP server's prompt template | `scan_tool_result` — treat it as tool output, because that is what it is |

Assembling first and scanning the finished prompt does not work: by then the
untrusted fragment is indistinguishable from your own instructions.

One case the boundaries do not catch today, worth knowing about. Content that
crossed `scan_tool_result` and was *allowed* — no finding, or a finding below
`block_at` — can still be promoted into the system position, where it stops
being data and starts being instructions. Nothing in the gate knows that
happened. Keep retrieved content in user or tool-result positions rather than
the system block, and treat "this text may be promoted to instructions" as a
decision you own.

## What next

- [connectors.md](connectors.md) — MCP sources, manifest onboarding, dispatch tokens
- [testing.md](testing.md) — writing tests against SHAI, `collect_events()`
- [`.claude/skills/integrations.md`](../.claude/skills/integrations.md) — same content in compact form
