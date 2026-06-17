"""
OSINT Agent — LangGraph + Playwright + DeepSeek
Passive reconnaissance from public sources. Saves findings as a markdown report.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Annotated

from typing_extensions import TypedDict

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from config import get_logger, settings
from tools import OSINT_TOOLS, close_browser
import reporting

log = get_logger("osint.agent")


# ── State ──────────────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    steps: int


# ── LLM ────────────────────────────────────────────────────────────────────────

def get_llm():
    return ChatOpenAI(
        model=settings.deepseek_model,
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        temperature=settings.temperature,
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
    if state.get("steps", 0) >= settings.max_steps:
        log.info("Max steps (%d) reached.", settings.max_steps)
        return END
    return tools_condition(state)


def route_after_tools(state: AgentState):
    if state.get("steps", 0) >= settings.max_steps:
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
- dns_lookup(domain): A, AAAA, MX, NS, TXT records
- reverse_dns(ip): PTR record / hostname for an IP
- cert_lookup(domain): Subdomains via SSL certificate transparency (crt.sh)
- ip_lookup(ip): Geolocation, ISP, ASN for an IP address
- http_headers(url): Response headers + server/tech fingerprint
- robots_sitemap(domain): robots.txt sitemaps and disallowed paths
- github_recon(username): Public GitHub profile + recent repositories
- username_enum(username): Check presence of a username across common platforms
- extract_contacts(text): Pull emails and phones from any text block
- wayback_lookup(url): Check Wayback Machine for archived versions
- ssl_cert_info(domain): Live TLS certificate (issuer, validity, SANs)
- asn_lookup(asn): ASN org + announced IP prefixes (BGPView)
- port_scan_passive(ip): Passive open ports / CVEs via Shodan InternetDB (no scan)
- email_validate(email): Syntax + domain MX check (deliverability)
- gravatar_lookup(email): Public Gravatar profile / linked accounts for an email
- subdomain_bruteforce(domain): Resolve common subdomain names via DNS
- extract_metadata(url): Page title, description, Open Graph, author, favicon
- wayback_snapshots(url): List multiple historical Wayback captures (CDX)

Output:
- save_report(filename, content): Save findings as a markdown (.md) report in reports/
- finish(summary): End investigation with a summary

METHODOLOGY:
1. Identify target type (person / company / domain / IP / username)
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


LANGUAGE_NAMES = {"es": "Spanish", "en": "English"}


def language_directive(lang: str) -> str:
    name = LANGUAGE_NAMES.get(lang, "English")
    return (
        f"\n\nIMPORTANT: Write the entire report (save_report content) and the "
        f"finish() summary in {name}. Tool calls and URLs stay as-is, but all "
        f"prose, headings and explanations must be in {name}."
    )


# ── Runner ──────────────────────────────────────────────────────────────────────

async def run_agent(task: str, *, as_json: bool = False, language: str = "en") -> str:
    """Run an investigation and return the final summary."""
    graph = build_graph()
    system_prompt = SYSTEM_PROMPT + language_directive(language)

    if not as_json:
        print(f"\n{'='*55}")
        print(f"[osint] Target: {task}")
        print(f"{'='*55}\n")

    final_message = ""
    last_ai_message = ""
    tools_used: list[str] = []

    async for event in graph.astream_events(
        {
            "messages": [
                SystemMessage(content=system_prompt),
                HumanMessage(content=task),
            ],
            "steps": 0,
        },
        config={"recursion_limit": settings.recursion_limit},
        version="v2",
    ):
        kind = event["event"]

        if kind == "on_tool_start":
            tool_name = event["name"]
            tools_used.append(tool_name)
            if not as_json:
                tool_input = event.get("data", {}).get("input", {})
                print(f"[tool] {tool_name}({tool_input})")

        elif kind == "on_tool_end":
            output = event.get("data", {}).get("output", "")
            if hasattr(output, "content"):
                output = output.content
            output_str = str(output)
            if not as_json:
                print(f"  → {output_str[:200]}")
            if "TASK_COMPLETE:" in output_str:
                final_message = output_str.replace("TASK_COMPLETE: ", "")

        elif kind == "on_chat_model_stream":
            chunk = event.get("data", {}).get("chunk")
            if chunk and hasattr(chunk, "content") and chunk.content and not as_json:
                print(chunk.content, end="", flush=True)

        elif kind == "on_chat_model_end":
            output = event.get("data", {}).get("output")
            if output and hasattr(output, "content") and output.content:
                last_ai_message = output.content

    if not final_message:
        final_message = last_ai_message or ""

    if as_json:
        print(json.dumps({
            "target": task,
            "summary": final_message,
            "tools_used": tools_used,
        }, ensure_ascii=False, indent=2))
    else:
        print(f"\n\n{'='*55}")
        print(f"[osint] Done:\n\n{final_message}")
        print(f"{'='*55}\n")

    return final_message


async def run_batch(path: str, *, as_json: bool = False, language: str = "en") -> None:
    with open(path, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    log.info("Batch mode: %d targets from %s", len(targets), path)
    for target in targets:
        await run_agent(target, as_json=as_json, language=language)


# ── Interactive menu (i18n) ──────────────────────────────────────────────────────

# UI strings per language. The chosen language drives the whole interface.
T = {
    "es": {
        "ask_lang": "Idioma / Language:\n  [1] Espanol\n  [2] English",
        "ask_lang_prompt": "Selecciona [1/2]: ",
        "invalid": "Opcion no valida.",
        "title": "  AGENTE OSINT - Reconocimiento Pasivo",
        "menu1": "[1] Nueva investigacion",
        "menu2": "[2] Preguntar sobre un reporte",
        "menu3": "[3] Analisis de vulnerabilidades de un reporte",
        "menuq": "[q] Salir",
        "select": "Selecciona: ",
        "examples": "\nEjemplos:",
        "target": "\nObjetivo: ",
        "goodbye": "[osint] Hasta luego.",
        "no_reports": "\nNo hay reportes en reports/.",
        "available": "\nReportes disponibles:",
        "choose": "\nElige numero: ",
        "bad_sel": "Seleccion no valida.",
        "report": "\nReporte: ",
        "ask_hint": "Escribe tu pregunta (o 'q' para volver).",
        "question": "\nPregunta: ",
        "analyzing": "\nAnalizando: ",
        "saved": "[guardado] ",
        "error": "[error] ",
    },
    "en": {
        "ask_lang": "Idioma / Language:\n  [1] Espanol\n  [2] English",
        "ask_lang_prompt": "Select [1/2]: ",
        "invalid": "Invalid option.",
        "title": "  OSINT AGENT - Passive Reconnaissance",
        "menu1": "[1] New investigation",
        "menu2": "[2] Ask about an existing report",
        "menu3": "[3] Vulnerability analysis of a report",
        "menuq": "[q] Quit",
        "select": "Select: ",
        "examples": "\nExamples:",
        "target": "\nTarget: ",
        "goodbye": "[osint] Goodbye.",
        "no_reports": "\nNo reports found in reports/.",
        "available": "\nAvailable reports:",
        "choose": "\nChoose number: ",
        "bad_sel": "Invalid selection.",
        "report": "\nReport: ",
        "ask_hint": "Type your question ('q' to go back).",
        "question": "\nQuestion: ",
        "analyzing": "\nAnalyzing: ",
        "saved": "[saved] ",
        "error": "[error] ",
    },
}


def ask_language() -> str:
    """Ask the user for the language once. Returns 'es' or 'en'."""
    while True:
        print("\n" + T["en"]["ask_lang"])
        choice = input(T["en"]["ask_lang_prompt"]).strip().lower()
        if choice in ("1", "es", "espanol", "español"):
            return "es"
        if choice in ("2", "en", "english", "ingles", "inglés"):
            return "en"
        print(T["en"]["invalid"])


def list_reports() -> list:
    """Return saved .md reports, newest first."""
    if not settings.reports_dir.exists():
        return []
    return sorted(
        settings.reports_dir.glob("*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


async def answer_about_report(report_path, question: str) -> str:
    """Ask the LLM a question about a saved report and return the answer."""
    content = report_path.read_text(encoding="utf-8")
    llm = ChatOpenAI(
        model=settings.deepseek_model,
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        temperature=settings.temperature,
    )
    system = (
        "You are an OSINT analyst assistant. Answer questions strictly based on "
        "the provided report. If the report does not contain the answer, say so. "
        "Reply in the same language as the user's question."
    )
    messages = [
        SystemMessage(content=system),
        HumanMessage(content=f"REPORT:\n\n{content}\n\nQUESTION: {question}"),
    ]
    resp = await llm.ainvoke(messages)
    return resp.content


VULN_SYSTEM_PROMPT = (
    "You are a senior defensive security analyst performing a passive attack-surface "
    "review. Based ONLY on the OSINT report provided, identify POTENTIAL weaknesses and "
    "exposures, and give defensive hardening recommendations.\n\n"
    "STRICT RULES:\n"
    "- This is a theoretical, defensive assessment. Do NOT provide exploitation steps, "
    "payloads, commands, or any instructions to attack or gain unauthorized access.\n"
    "- Base every point on evidence in the report; do not invent findings. If something "
    "is uncertain, say so.\n"
    "- Reference known CVEs only if they appear in the report (e.g. Shodan data).\n"
    "- For each item give: the observation, why it could matter, and a defensive recommendation.\n\n"
    "Structure your answer in Markdown:\n"
    "# Vulnerability / Attack-Surface Analysis: {target}\n"
    "## Summary (risk overview)\n"
    "## Exposed Surface (subdomains, ports, services, dev/test environments)\n"
    "## Potential Weaknesses (with severity: Low / Medium / High)\n"
    "## Information Disclosure (emails, tech stack, internal naming)\n"
    "## Defensive Recommendations\n"
    "## Caveats (what could not be assessed passively)\n\n"
    "Write the analysis in {language_name}."
)


async def analyze_vulnerabilities(report_path, language: str = "en") -> str:
    """Generate a defensive vulnerability / attack-surface analysis from a report."""
    content = report_path.read_text(encoding="utf-8")
    language_name = LANGUAGE_NAMES.get(language, "English")
    llm = ChatOpenAI(
        model=settings.deepseek_model,
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        temperature=settings.temperature,
    )
    system = VULN_SYSTEM_PROMPT.format(target=report_path.stem, language_name=language_name)
    messages = [
        SystemMessage(content=system),
        HumanMessage(content=f"OSINT REPORT:\n\n{content}"),
    ]
    resp = await llm.ainvoke(messages)
    return resp.content


def pick_report(lang: str = "en"):
    """Show saved reports and let the user choose one. Returns a Path or None."""
    t = T[lang]
    reports = list_reports()
    if not reports:
        print(t["no_reports"])
        return None
    print(t["available"])
    for i, p in enumerate(reports[:30], 1):
        print(f"  [{i}] {p.name}")
    sel = input(t["choose"]).strip()
    if not sel.isdigit() or not (1 <= int(sel) <= len(reports)):
        print(t["bad_sel"])
        return None
    return reports[int(sel) - 1]


async def report_qa(lang: str = "en") -> None:
    """Interactive Q&A over an existing report."""
    t = T[lang]
    report_path = pick_report(lang)
    if report_path is None:
        return
    print(f"{t['report']}{report_path.name}")
    print(t["ask_hint"])
    while True:
        question = input(t["question"]).strip()
        if question.lower() in ("q", "quit", "exit", ""):
            return
        try:
            answer = await answer_about_report(report_path, question)
            print(f"\n{answer}")
        except Exception as exc:  # noqa: BLE001
            print(f"{t['error']}{exc}")


async def vuln_analysis(lang: str = "en") -> None:
    """Interactive: pick a report and produce a defensive vulnerability analysis."""
    t = T[lang]
    report_path = pick_report(lang)
    if report_path is None:
        return
    print(f"{t['analyzing']}{report_path.name} ...")
    try:
        analysis = await analyze_vulnerabilities(report_path, language=lang)
    except Exception as exc:  # noqa: BLE001
        print(f"{t['error']}{exc}")
        return
    print("\n" + analysis)
    out_name = f"{report_path.stem}_vuln-analysis"
    paths = reporting.save_report(out_name, analysis)
    print(f"\n{t['saved']}{paths['markdown']}")


async def interactive() -> None:
    lang = ask_language()
    t = T[lang]
    while True:
        print("\n" + "=" * 55)
        print(t["title"])
        print("=" * 55)
        print(t["menu1"])
        print(t["menu2"])
        print(t["menu3"])
        print(t["menuq"])
        print("=" * 55)

        choice = input(t["select"]).strip().lower()
        if choice == "1":
            print(t["examples"])
            print("  example.com")
            print("  Acme Corp")
            print("  John Smith CEO Acme")
            print("  8.8.8.8")
            target = input(t["target"]).strip()
            if target:
                await run_agent(target, language=lang)
        elif choice == "2":
            await report_qa(lang)
        elif choice == "3":
            await vuln_analysis(lang)
        elif choice in ("q", "quit", "exit", "0"):
            print(t["goodbye"])
            break


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="osint-agent",
        description="Passive OSINT reconnaissance agent (public sources only).",
    )
    parser.add_argument("target", nargs="*", help="Target: domain, IP, name, company or username.")
    parser.add_argument("--batch", metavar="FILE", help="Run targets from a file (one per line).")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--headless", action="store_true", help="Run the browser headless.")
    parser.add_argument("--model", help="Override the DeepSeek model name.")
    parser.add_argument("--max-steps", type=int, help="Override the max agent steps.")
    parser.add_argument("--lang", choices=["es", "en"], default="en",
                        help="Report language (default: en).")
    return parser.parse_args(argv)


def apply_overrides(args: argparse.Namespace) -> None:
    """Apply CLI overrides onto the (frozen) settings via object.__setattr__."""
    if args.headless:
        object.__setattr__(settings, "headless", True)
    if args.model:
        object.__setattr__(settings, "deepseek_model", args.model)
    if args.max_steps:
        object.__setattr__(settings, "max_steps", args.max_steps)


async def main() -> None:
    args = parse_args()
    apply_overrides(args)

    problems = settings.validate()
    if problems:
        for p in problems:
            log.error(p)
        sys.exit(1)

    try:
        if args.batch:
            await run_batch(args.batch, as_json=args.json, language=args.lang)
        elif args.target:
            await run_agent(" ".join(args.target), as_json=args.json, language=args.lang)
        else:
            await interactive()
    finally:
        await close_browser()


if __name__ == "__main__":
    import warnings

    warnings.filterwarnings("ignore", category=ResourceWarning)
    asyncio.run(main())
