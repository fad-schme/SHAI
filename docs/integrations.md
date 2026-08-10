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

## Which integration to use

| Your framework | Use |
|---|---|
| LangGraph | `HarnessToolNode` — drop-in replacement for `ToolNode` |
| LangChain Agent Loop (`create_agent`, v0.3+) | `ShaiMiddleware` — cleanest integration |
| LangChain classic (any version) | `wrap_tools()` |
| Anthropic SDK raw loop | `gated_dispatch` + `make_tool_result_from_denial` |
| CrewAI | `wrap_tools()` |
| PydanticAI | `harness_tool` decorator + `add_harness_middleware()` |
| OpenAI Agents SDK | `wrap_tools()` |
| Anything with manual tool dispatch | Call `check_tool_call` + `scan_tool_result` directly |

Every wrapper on this page runs the same contract: `check_tool_call` before
dispatch, `scan_tool_result` on what comes back. You never call either
yourself, and there is no longer an entry point that runs only half of it.

Result scanning only does something when the boundary is on:
`scan_tool_result.enabled` defaults to `false`, and `config/harness.yaml`
ships it as `true`.

**MCP tools need no local callable.** When a gated tool resolves to an MCP
source, the call is routed to that source with the gate's `dispatch_token`
attached — which is what `ShaiTransport` validates on the outbound request.
`HarnessToolNode` does this for any tool name not in its local list, and
`gated_dispatch` does it when you omit `dispatch`. Dispatching an MCP tool
yourself without threading `gate.dispatch_token` into `MCPSource.call()`
leaves the request untokened: refused under `no_token_policy: strict`, and
uncorrelatable in the audit trail under `permissive`.


## LangGraph

```python
from harness.integrations.langgraph import HarnessToolNode, shai_tool
from langgraph.graph import StateGraph, MessagesState, END

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

tools = [search_docs]

harness   = await SHAI.from_yaml("config/harness.yaml")
agent_ctx = await harness.load_agent("config/agents/my_agent.yaml")
llm       = ChatOllama(model="qwen2.5:3b").bind_tools(tools)
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

## LangChain Agent Loop (v0.3+)

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

Requires `pip install "langchain>=0.3" langgraph`.

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
llm = ChatOllama(model="qwen2.5:3b").bind_tools(gated_tools)
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

## CrewAI

```python
from harness.integrations.crewai import wrap_tools, shai_tool

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

gated = await wrap_tools([search_docs], harness=harness, ctx=ctx)
# Pass `gated` as tools to your CrewAI Agent
```

## PydanticAI

```python
from harness.integrations.pydantic_ai import harness_tool, add_harness_middleware
from pydantic_ai import Agent

@harness_tool(tags=["read", "internal"])
async def search_docs(query: str) -> str: ...

agent = Agent(model="openai:gpt-4o", tools=[search_docs])
add_harness_middleware(agent, harness=harness, ctx=ctx)
```

## OpenAI Agents SDK

```python
from harness.integrations.openai_agents import wrap_tools
from agents import Agent, function_tool

@function_tool
async def search_docs(query: str) -> str: ...

gated = await wrap_tools([search_docs], harness=harness, ctx=ctx)
agent = Agent(name="assistant", tools=gated)
```

## Manual dispatch (any framework)

If your framework isn't listed, or you want full control:

```python
from langchain_core.messages import ToolMessage

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

            raw     = await dispatch(tc["name"], gate.redacted_args or tc["args"])
            tv      = await harness.scan_tool_result(str(raw), ctx)
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

- [connectors.md](connectors.md) — MCP sources, connector manifests, dispatch tokens
- [testing.md](testing.md) — writing tests against SHAI, `collect_events()`
- [`.claude/skills/integrations.md`](../.claude/skills/integrations.md) — same content in compact form
