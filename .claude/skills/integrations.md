# Framework Integrations Reference

All integrations expose the same `@shai_tool` decorator and accept the same
`tools` list. Pick the integration that matches your framework.

---

## @shai_tool — define once, use everywhere

```python
from harness.integrations.langchain import shai_tool   # any integration module

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str:
    """Search internal documentation."""
    return _search(query)

@shai_tool(tags=["external_write", "sensitive"])
async def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    return await _send(to, subject, body)

tools = [search_docs, send_email]
```

`@shai_tool` creates a `ShaiTool` — satisfies SHAI's Tool interface and
the target framework's tool interface. Sync and async functions both work.

---

## LangGraph — HarnessToolNode

Drop-in replacement for LangGraph's `ToolNode`.

```python
from harness.integrations.langgraph import HarnessToolNode, shai_tool
from langgraph.graph import StateGraph, MessagesState, END
from langchain_core.messages import AIMessage

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

tools = [search_docs]

harness   = await SHAI.from_yaml("config/harness.yaml")
agent_ctx = await harness.load_agent("config/agents/my_agent.yaml")
llm       = your_chat_model.bind_tools(tools)  # any LangChain-compatible chat model
tool_node = await HarnessToolNode.create(tools, harness, agent_ctx)

# HarnessToolNode.create() calls register_tools() internally
# Pass the same tools list to bind_tools() — one list, no duplication

async def agent_node(state):
    return {"messages": [await llm.ainvoke(state["messages"])]}

def should_continue(state):
    last = state["messages"][-1]
    return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

graph = StateGraph(MessagesState)
graph.add_node("agent", agent_node)
graph.add_node("tools", tool_node)
graph.set_entry_point("agent")
graph.add_conditional_edges("agent", should_continue)
graph.add_edge("tools", "agent")
app = graph.compile()
```

---

## LangChain Classic — wrap_tools()

For any LangChain version. Compatible with `create_react_agent` and custom loops.

```python
from harness.integrations.langchain import wrap_tools, shai_tool

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

tools = [search_docs]

harness     = await SHAI.from_yaml("config/harness.yaml")
agent_ctx   = await harness.load_agent("config/agents/my_agent.yaml")
gated_tools = await wrap_tools(tools, harness=harness, ctx=agent_ctx)

# wrap_tools() registers tools AND returns gated LangChain-compatible wrappers
llm = your_chat_model.bind_tools(gated_tools)  # any LangChain-compatible chat model
```

Denied calls raise `ToolException` — the agent sees the denial and continues.

---

## LangChain Agent Loop — ShaiMiddleware (langchain>=0.3)

Wires SHAI into `create_agent`'s middleware system. Cleanest integration
for LangChain Agent Loop users.

```python
from harness.integrations.langchain import ShaiMiddleware, shai_tool
from langchain.agents import create_agent

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

tools = [search_docs]

harness    = await SHAI.from_yaml("config/harness.yaml")
agent_ctx  = await harness.load_agent("config/agents/my_agent.yaml")
middleware = await ShaiMiddleware.create(tools, harness=harness, ctx=agent_ctx)

agent = create_agent(
    llm,
    tools=tools,
    middleware=[middleware],
)

with harness.collect_events() as events:
    result = await agent.ainvoke({"messages": [HumanMessage(question)]})
```

**ShaiMiddleware hooks:**
- `abefore_agent` → `scan_input`
- `awrap_tool_call` → `check_tool_call` + `scan_tool_result`
- `aafter_agent` → `scan_output`

Requires `pip install "langchain>=0.3" langgraph`.

---

## LangChain Manual Loop

For full control over tool dispatch and result scanning.
Works with any LangChain version.

```python
from langchain_core.messages import ToolMessage

tool_map = {t.name: t for t in gated_tools}

async def run_loop(llm, messages, harness, ctx):
    for _ in range(10):
        response = await llm.ainvoke(messages)
        messages.append(response)

        if not getattr(response, "tool_calls", None):
            return response.content  # final response

        for tc in response.tool_calls:
            name, args, call_id = tc["name"], tc["args"], tc["id"]
            raw = await tool_map[name]._async_call(**args)

            # Scan result before it re-enters LLM context
            tv = await harness.scan_tool_result(str(raw), ctx)
            result = tv.redacted_text or str(raw)
            if tv.blocked:
                result = "Tool result blocked by security policy"

            messages.append(ToolMessage(content=result, tool_call_id=call_id))
```

---

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

---

## CrewAI

```python
from harness.integrations.crewai import wrap_tools, shai_tool

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

gated = await wrap_tools([search_docs], harness=harness, ctx=ctx)
# Pass gated as tools to your CrewAI Agent
```

---

## PydanticAI

```python
from harness.integrations.pydantic_ai import harness_tool, add_harness_middleware
from pydantic_ai import Agent

@harness_tool(tags=["read", "internal"])
async def search_docs(query: str) -> str: ...

agent = Agent(model="<your-model>", tools=[search_docs])
add_harness_middleware(agent, harness=harness, ctx=ctx)
```

---

## OpenAI Agents SDK

```python
from harness.integrations.openai_agents import wrap_tools
from agents import Agent, function_tool

@function_tool
async def search_docs(query: str) -> str: ...

gated = await wrap_tools([search_docs], harness=harness, ctx=ctx)
agent = Agent(name="assistant", tools=gated)
```

---

## Choosing the right integration

| Scenario | Use |
|---|---|
| LangGraph with any LLM | `HarnessToolNode` |
| LangChain Agent Loop (`create_agent`, v0.3+) | `ShaiMiddleware` |
| LangChain classic (`create_react_agent`) | `wrap_tools` |
| Anthropic SDK raw loop | `gated_dispatch` |
| Any framework with manual tool dispatch | `check_tool_call` + `scan_tool_result` directly |

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


---

## Composed system prompts — no boundary, by design

There is no `scan_system_prompt`. A system prompt is authored by the party that
configures SHAI, so scanning it means scanning trusted text for attacks by its
own author.

What needs scanning is what gets assembled *into* it. RAG context, retrieved
memory, DB-stored instructions, and MCP-served prompt templates are untrusted
content landing in the most privileged position in the request. Scan each at
the boundary it actually crossed — `scan_tool_result`, `scan_file`,
`scan_input`; an MCP prompt template is tool output and takes
`scan_tool_result`. Scanning the assembled prompt does not work: by then the
untrusted fragment is indistinguishable from the operator's own instructions.

**Known limit:** content that crossed `scan_tool_result` and was allowed can
still be promoted into the system position, where it stops being data and
becomes instructions. The gate has no notion of trust elevation — text carries
no label saying where it may be placed. Keep retrieved content in user or
tool-result positions and treat promotion to instructions as an application
decision.
