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
llm       = ChatOllama(model="qwen2.5:3b").bind_tools(tools)
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
llm = ChatOllama(model="qwen2.5:3b").bind_tools(gated_tools)
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
            tv = await harness.scan_tool_result(str(raw), ctx, tool_name=name)
            result = tv.redacted_text or str(raw)
            if tv.blocked:
                result = "Tool result blocked by security policy"

            messages.append(ToolMessage(content=result, tool_call_id=call_id))
```

---

## Anthropic SDK

```python
from harness.integrations.anthropic_sdk import gated_dispatch, make_tool_result_from_denial

# In your tool dispatch loop
gate = await harness.check_tool_call(tool_name, tool_args, ctx)
if not gate.allowed:
    # Build a ToolResult block for the denial
    denial_block = make_tool_result_from_denial(gate, tool_use_id)
    messages.append({"role": "user", "content": [denial_block]})
else:
    result = await dispatch(tool_name, gate.redacted_args or tool_args)
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

agent = Agent(model="openai:gpt-4o", tools=[search_docs])
add_harness_middleware(agent, harness=harness, ctx=ctx)
```

---

## OpenAI Agents SDK

```python
from harness.integrations.openai_agents import make_before_tool_hook, wrap_tool
from agents import Agent, function_tool

@function_tool
async def search_docs(query: str) -> str: ...

hook = make_before_tool_hook(harness=harness, ctx=ctx)
agent = Agent(tools=[wrap_tool(search_docs, harness=harness, ctx=ctx)])
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
