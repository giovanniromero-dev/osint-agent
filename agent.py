"""
OSINT Agent — LangGraph + Playwright + DeepSeek
Passive reconnaissance from public sources. Saves findings as a markdown report.
"""
import asyncio
import os
import sys
from typing import Annotated
from typing_extensions import TypedDict

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from tools import OSINT_TOOLS, close_browser

load_dotenv()

MAX_STEPS = 50


# ── State ──────────────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    steps: int


# ── LLM ────────────────────────────────────────────────────────────────────────

def get_llm():
    return ChatOpenAI(
        model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
        temperature=0,
    ).bind_tools(OSINT_TOOLS)


# ── Nodes ──────────────────────────────────────────────────────────────────────

async def agent_node(state: AgentState):
    response = await get_llm().ainvoke(state["messages"])
    return {"messages": [response], "steps": state.get("steps", 0)}


async def tools_node(state: AgentState):
    result = await ToolNode(OSINT_TOOLS).ainvoke(state)
    return {**result, "steps": state.get("steps", 0) + 1}


# ── Routing ────────────────────────────────────────────────────────────────────

def route_agent(state: AgentState):
    if state.get("steps", 0) >= MAX_STEPS:
        print(f"\n[agent] Max steps ({MAX_STEPS}) reached.")
        return END
    return tools_condition(state)


def route_after_tools(state: AgentState):
    if state.get("steps", 0) >= MAX_STEPS:
        return END
    last = state["messages"][-1]
    if isinstance(last, ToolMessage) and "TASK_COMPLETE:" in last.content:
        return END
    return "agent"


# ── Graph ──────────────────────────────────────────────────────────────────────

def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tools_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", route_agent)
    graph.add_conditional_edges("tools", route_after_tools)
    return graph.compile()


# ── System Prompt ───────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert OSINT (Open Source Intelligence) analyst.
You gather information from public sources only — no unauthorized access, no exploitation.

TARGETS: person, company, domain, IP address, email address, username

AVAILABLE TOOLS:
Browser:
- navigate(url): Visit any URL
- get_text(): Read current page content
- get_links(): Extract all links from current page
- screenshot(): Save page as evidence
- search_web(query): Search DuckDuckGo

OSINT:
- whois_lookup(domain): Domain registration info, registrar, dates, emails
- dns_lookup(domain): A, MX, NS, TXT records
- cert_lookup(domain): Subdomains via SSL certificate transparency (crt.sh)
- ip_lookup(ip): Geolocation, ISP, ASN for an IP address
- extract_contacts(text): Pull emails and phones from any text block
- wayback_lookup(url): Check Wayback Machine for archived versions

Output:
- save_report(filename, content): Save findings as markdown in reports/
- finish(summary): End investigation with a summary

METHODOLOGY:
1. Identify target type (person / company / domain / IP)
2. Start broad: search_web to find initial leads
3. Go deep: follow each lead with specific OSINT tools
4. Cross-reference findings across sources
5. Extract all contacts, subdomains, IPs found
6. save_report() with complete findings before calling finish()

REPORT FORMAT (use this structure in save_report):
# OSINT Report: {target}
**Date:** {date}

## Summary
Brief overview of key findings.

## Domain / IP Intelligence
WHOIS, DNS, subdomains, hosting info.

## Contacts Found
Emails, phones extracted from public sources.

## Social & Web Presence
LinkedIn, GitHub, news mentions, social profiles.

## Sources
List every URL consulted.

RULES:
- Only public, legal sources
- Always call save_report() before finish()
- Document every source URL
- finish() summary: one paragraph of key findings"""


# ── Runner ──────────────────────────────────────────────────────────────────────

async def run_agent(task: str) -> str:
    graph = build_graph()

    print(f"\n{'='*55}")
    print(f"[osint] Target: {task}")
    print(f"{'='*55}\n")

    final_message = ""
    last_ai_message = ""

    async for event in graph.astream_events(
        {
            "messages": [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=task),
            ],
            "steps": 0,
        },
        config={"recursion_limit": 200},
        version="v2",
    ):
        kind = event["event"]

        if kind == "on_tool_start":
            tool_name  = event["name"]
            tool_input = event.get("data", {}).get("input", {})
            print(f"[tool] {tool_name}({tool_input})")

        elif kind == "on_tool_end":
            output = event.get("data", {}).get("output", "")
            if hasattr(output, "content"):
                output = output.content
            output_str = str(output)
            print(f"  → {output_str[:200]}")
            if "TASK_COMPLETE:" in output_str:
                final_message = output_str.replace("TASK_COMPLETE: ", "")

        elif kind == "on_chat_model_stream":
            chunk = event.get("data", {}).get("chunk")
            if chunk and hasattr(chunk, "content") and chunk.content:
                print(chunk.content, end="", flush=True)

        elif kind == "on_chat_model_end":
            output = event.get("data", {}).get("output")
            if output and hasattr(output, "content") and output.content:
                last_ai_message = output.content

    if not final_message:
        final_message = last_ai_message or ""

    print(f"\n\n{'='*55}")
    print(f"[osint] Done:\n\n{final_message}")
    print(f"{'='*55}\n")

    return final_message


# ── Main ────────────────────────────────────────────────────────────────────────

async def main():
    if len(sys.argv) > 1:
        task = " ".join(sys.argv[1:])
        try:
            await run_agent(task)
        finally:
            await close_browser()
        return

    try:
        while True:
            print("\n" + "="*55)
            print("  OSINT AGENT — Passive Reconnaissance")
            print("="*55)
            print("[1] New investigation")
            print("[q] Quit")
            print("="*55)

            choice = input("Select: ").strip().lower()

            if choice == "1":
                print("\nExamples:")
                print("  example.com")
                print("  Acme Corp")
                print("  John Smith CEO Acme")
                print("  8.8.8.8")
                target = input("\nTarget: ").strip()
                if target:
                    await run_agent(target)

            elif choice in ("q", "quit", "exit", "0"):
                print("[osint] Goodbye.")
                break

    finally:
        await close_browser()


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", category=ResourceWarning)
    asyncio.run(main())
