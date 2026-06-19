"""
OSINT Agent — LangGraph + Playwright + DeepSeek
Passive reconnaissance from public sources. Saves findings as a markdown report.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Annotated

from typing_extensions import TypedDict

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme
from rich.text import Text

from config import get_logger, settings
from tools import OSINT_TOOLS, close_browser
import reporting

log = get_logger("osint.agent")

VERSION = "1.0.0"

theme = Theme({
    "banner":      "#00ff00 bold",
    "header":      "#00ff00 bold",
    "tool.name":   "#00ff00 bold",
    "tool.args":   "dim white",
    "tool.output": "dim white",
    "agent":       "white",
    "info":        "#00ff00",
    "success":     "#00ff00 bold",
    "warn":        "yellow",
    "error":       "red bold",
    "muted":       "dim",
})
console = Console(theme=theme)

BANNER = r"""
  ██████╗ ███████╗██╗███╗   ██╗████████╗ █████╗  ██████╗ ███████╗███╗   ██╗████████╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
 ██║   ██║███████╗██║██╔██╗ ██║   ██║   ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║   ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝

                  [ Passive Reconnaissance Framework ]
         LangGraph · DeepSeek · Public Sources Only · No Auth Required
"""

# ── Module groups for --modules flag ──────────────────────────────────────────

MODULE_GROUPS: dict[str, set[str]] = {
    "dns":     {"dns_lookup", "reverse_dns", "cert_lookup", "subdomain_bruteforce", "ssl_cert_info"},
    "whois":   {"whois_lookup"},
    "ip":      {"ip_lookup", "asn_lookup", "port_scan_passive", "reverse_dns"},
    "web":     {"navigate", "get_text", "get_links", "screenshot", "search_web",
                "http_headers", "robots_sitemap", "extract_metadata"},
    "email":   {"email_validate", "gravatar_lookup", "extract_contacts"},
    "social":  {"github_recon", "username_enum"},
    "archive": {"wayback_lookup", "wayback_snapshots"},
}
_ALWAYS_ACTIVE = {"save_report", "finish"}


def get_active_tools(modules_str: str | None = None) -> list:
    """Return OSINT_TOOLS filtered by --modules. Always includes save_report + finish."""
    if not modules_str:
        return OSINT_TOOLS
    requested = {m.strip().lower() for m in modules_str.split(",")}
    allowed = _ALWAYS_ACTIVE.copy()
    for m in requested:
        if m in MODULE_GROUPS:
            allowed.update(MODULE_GROUPS[m])
        else:
            console.print(f"[warn]⚠  Unknown module '{m}'. Valid: {', '.join(MODULE_GROUPS)}[/warn]")
    active = [t for t in OSINT_TOOLS if t.name in allowed]
    console.print(
        f"[muted]Modules: {', '.join(sorted(requested))} "
        f"→ {len(active)} tools active[/muted]\n"
    )
    return active


# ── State ──────────────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    steps: int


# ── LLM ────────────────────────────────────────────────────────────────────────

def get_llm(tools: list | None = None):
    tools = tools if tools is not None else OSINT_TOOLS
    return ChatOpenAI(
        model=settings.deepseek_model,
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        temperature=settings.temperature,
    ).bind_tools(tools)


# ── Nodes ──────────────────────────────────────────────────────────────────────

def _make_agent_node(tools: list):
    llm = get_llm(tools)  # created once per graph, not on every step
    async def agent_node(state: AgentState):
        response = await llm.ainvoke(state["messages"])
        return {"messages": [response], "steps": state.get("steps", 0)}
    return agent_node


def _make_tools_node(tools: list):
    async def tools_node(state: AgentState):
        result = await ToolNode(tools).ainvoke(state)
        return {**result, "steps": state.get("steps", 0) + 1}
    return tools_node


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

def build_graph(tools: list | None = None):
    tools = tools if tools is not None else OSINT_TOOLS
    graph = StateGraph(AgentState)
    graph.add_node("agent", _make_agent_node(tools))
    graph.add_node("tools", _make_tools_node(tools))
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


def type_directive(target_type: str) -> str:
    return f"\n\nTARGET TYPE HINT: The user has specified this target is a {target_type.upper()}. Start your investigation accordingly."


# ── Helpers ────────────────────────────────────────────────────────────────────

def _open_file(path: Path) -> None:
    """Open a file with the default OS application."""
    try:
        if platform.system() == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[warn]Could not open report: {exc}[/warn]")


def _latest_report() -> Path | None:
    if not settings.reports_dir.exists():
        return None
    reports = sorted(settings.reports_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return reports[0] if reports else None


# ── Runner ──────────────────────────────────────────────────────────────────────

async def run_agent(
    task: str,
    *,
    as_json: bool = False,
    language: str = "en",
    quiet: bool = False,
    delay: float = 0.0,
    open_report: bool = False,
    target_type: str | None = None,
    modules: str | None = None,
) -> str:
    """Run an investigation and return the final summary."""
    active_tools = get_active_tools(modules)
    graph = build_graph(active_tools)

    system_prompt = SYSTEM_PROMPT + language_directive(language)
    if target_type:
        system_prompt += type_directive(target_type)

    if not as_json and not quiet:
        console.print(Panel(
            f"[header]Target:[/header] {task}",
            border_style="#00ff00",
            expand=False,
        ))

    final_message = ""
    last_ai_message = ""
    tools_used: list[str] = []
    report_path: str | None = None

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
            if not as_json and not quiet:
                tool_input = event.get("data", {}).get("input", {})
                args_str = json.dumps(tool_input, ensure_ascii=False)[:120]
                console.print(f"  [tool.name]▶ {tool_name}[/tool.name] [tool.args]{args_str}[/tool.args]")

        elif kind == "on_tool_end":
            if delay > 0:
                await asyncio.sleep(delay)
            output = event.get("data", {}).get("output", "")
            if hasattr(output, "content"):
                output = output.content
            output_str = str(output)

            # capture report path from "Report saved: /path/to/file.md"
            if event["name"] == "save_report":
                m = re.search(r"Report saved:\s*(.+\.md)", output_str)
                if m:
                    report_path = m.group(1).strip()

            if not as_json and not quiet:
                preview = output_str[:200].replace("\n", " ")
                console.print(f"    [tool.output]↳ {preview}[/tool.output]")

            if "TASK_COMPLETE:" in output_str:
                final_message = output_str.replace("TASK_COMPLETE: ", "")

        elif kind == "on_chat_model_stream":
            chunk = event.get("data", {}).get("chunk")
            if chunk and hasattr(chunk, "content") and chunk.content and not as_json and not quiet:
                console.print(chunk.content, end="", style="agent")

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
            "report": report_path,
        }, ensure_ascii=False, indent=2))
    elif quiet:
        if report_path:
            print(report_path)
    else:
        console.print()
        console.print(Panel(final_message, title="[success]Done[/success]", border_style="green"))
        if report_path:
            console.print(f"[muted]Report saved:[/muted] [success]{report_path}[/success]")

    if open_report and report_path:
        _open_file(Path(report_path))
    elif open_report:
        r = _latest_report()
        if r:
            _open_file(r)

    return final_message


# ── Interactive menu (i18n) ──────────────────────────────────────────────────────

T = {
    "es": {
        "ask_lang": "Language:\n  [[#00ff00]1[/#00ff00]] Spanish\n  [[#00ff00]2[/#00ff00]] English",
        "ask_lang_prompt": "Select [1/2]: ",
        "invalid": "Opción no válida.",
        "title": "  AGENTE OSINT - Reconocimiento Pasivo",
        "menu1": "[[#00ff00]1[/#00ff00]] Nueva investigación",
        "menu2": "[[#00ff00]2[/#00ff00]] Consultar un reporte existente",
        "menu3": "[[#00ff00]3[/#00ff00]] Análisis de vulnerabilidades",
        "menuq": "[[#00ff00]q[/#00ff00]] Salir",
        "select": "Selecciona: ",
        "examples": "\nEjemplos:",
        "target": "\nObjetivo: ",
        "goodbye": "Hasta luego.",
        "no_reports": "\nNo hay reportes en reports/.",
        "available": "\nReportes disponibles:",
        "choose": "\nElige número: ",
        "bad_sel": "Selección no válida.",
        "report": "\nReporte: ",
        "ask_hint": "Escribe tu pregunta ('q' para volver).",
        "question": "\nPregunta: ",
        "analyzing": "\nAnalizando: ",
        "saved": "Guardado: ",
        "error": "Error: ",
    },
    "en": {
        "ask_lang": "Language:\n  [[#00ff00]1[/#00ff00]] Spanish\n  [[#00ff00]2[/#00ff00]] English",
        "ask_lang_prompt": "Select [1/2]: ",
        "invalid": "Invalid option.",
        "title": "  OSINT AGENT - Passive Reconnaissance",
        "menu1": "[[#00ff00]1[/#00ff00]] New investigation",
        "menu2": "[[#00ff00]2[/#00ff00]] Ask about an existing report",
        "menu3": "[[#00ff00]3[/#00ff00]] Vulnerability analysis of a report",
        "menuq": "[[#00ff00]q[/#00ff00]] Quit",
        "select": "Select: ",
        "examples": "\nExamples:",
        "target": "\nTarget: ",
        "goodbye": "Goodbye.",
        "no_reports": "\nNo reports found in reports/.",
        "available": "\nAvailable reports:",
        "choose": "\nChoose number: ",
        "bad_sel": "Invalid selection.",
        "report": "\nReport: ",
        "ask_hint": "Type your question ('q' to go back).",
        "question": "\nQuestion: ",
        "analyzing": "\nAnalyzing: ",
        "saved": "Saved: ",
        "error": "Error: ",
    },
}


def ask_language() -> str:
    """Ask the user for the language once. Returns 'es' or 'en'."""
    while True:
        console.print("\n" + T["en"]["ask_lang"])
        choice = input(T["en"]["ask_lang_prompt"]).strip().lower()
        if choice in ("1", "es", "spanish", "espanol", "español"):
            return "es"
        if choice in ("2", "en", "english", "ingles", "inglés"):
            return "en"
        console.print(f"[warn]{T['en']['invalid']}[/warn]")


def list_reports() -> list:
    if not settings.reports_dir.exists():
        return []
    return sorted(
        settings.reports_dir.glob("*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


async def answer_about_report(report_path, question: str) -> str:
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
    t = T[lang]
    reports = list_reports()
    if not reports:
        console.print(f"[warn]{t['no_reports']}[/warn]")
        return None
    console.print(t["available"])
    for i, p in enumerate(reports[:30], 1):
        console.print(f"  [[#00ff00]{i}[/#00ff00]] {p.name}")
    sel = input(t["choose"]).strip()
    if not sel.isdigit() or not (1 <= int(sel) <= len(reports)):
        console.print(f"[warn]{t['bad_sel']}[/warn]")
        return None
    return reports[int(sel) - 1]


async def report_qa(lang: str = "en") -> None:
    t = T[lang]
    report_path = pick_report(lang)
    if report_path is None:
        return
    console.print(f"{t['report']}[#00ff00]{report_path.name}[/#00ff00]")
    console.print(f"[muted]{t['ask_hint']}[/muted]")
    while True:
        question = input(t["question"]).strip()
        if question.lower() in ("q", "quit", "exit", ""):
            return
        try:
            answer = await answer_about_report(report_path, question)
            console.print(f"\n{answer}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[error]{t['error']}{exc}[/error]")


async def vuln_analysis(lang: str = "en") -> None:
    t = T[lang]
    report_path = pick_report(lang)
    if report_path is None:
        return
    console.print(f"[info]{t['analyzing']}[/info][#00ff00]{report_path.name}[/#00ff00] ...")
    try:
        analysis = await analyze_vulnerabilities(report_path, language=lang)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[error]{t['error']}{exc}[/error]")
        return
    console.print("\n" + analysis)
    out_name = f"{report_path.stem}_vuln-analysis"
    paths = reporting.save_report(out_name, analysis)
    console.print(f"\n[success]{t['saved']}[/success]{paths['markdown']}")


async def interactive() -> None:
    console.print(BANNER, style="bold white")
    lang = ask_language()
    t = T[lang]
    while True:
        console.print()
        console.print(Panel(
            f"{t['menu1']}\n{t['menu2']}\n{t['menu3']}\n{t['menuq']}",
            title=f"[header]{t['title']}[/header]",
            border_style="#00ff00",
        ))

        choice = input(t["select"]).strip().lower()
        if choice == "1":
            console.print(f"[muted]{t['examples']}[/muted]")
            console.print("  [muted]example.com  |  Acme Corp  |  john@example.com  |  8.8.8.8[/muted]")
            target = input(t["target"]).strip()
            if target:
                await run_agent(target, language=lang)
        elif choice == "2":
            await report_qa(lang)
        elif choice == "3":
            await vuln_analysis(lang)
        elif choice in ("q", "quit", "exit", "0"):
            console.print(f"[muted]{t['goodbye']}[/muted]")
            break


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="osint-agent",
        description="Passive OSINT reconnaissance agent (public sources only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  osint-agent example.com
  osint-agent "John Smith CEO Acme" --type person --lang es
  osint-agent 8.8.8.8 --modules ip,dns --quiet
  osint-agent example.com --output ./my-reports --open
        """,
    )
    parser.add_argument("target", nargs="*",
                        help="Target: domain, IP, email, person name, company or username.")
    parser.add_argument("-V", "--version", action="version",
                        version=f"osint-agent {VERSION}")
    parser.add_argument("--json", action="store_true",
                        help="Emit machine-readable JSON output.")
    parser.add_argument("--headless", action="store_true",
                        help="Run the browser headless.")
    parser.add_argument("--model",
                        help="Override the DeepSeek model name.")
    parser.add_argument("--max-steps", type=int,
                        help="Override the max agent steps (default: 50).")
    parser.add_argument("--lang", choices=["es", "en"], default="en",
                        help="Report language: es=Spanish, en=English (default: en).")
    parser.add_argument("--type",
                        choices=["domain", "ip", "email", "person", "username", "company"],
                        dest="target_type", metavar="TYPE",
                        help="Target type hint: domain, ip, email, person, username, company.")
    parser.add_argument("--modules", metavar="MODULES",
                        help=(
                            "Comma-separated tool modules to activate. "
                            "Available: dns, whois, ip, web, email, social, archive. "
                            "Example: --modules dns,whois,ip"
                        ))
    parser.add_argument("--output", metavar="DIR",
                        help="Directory where reports are saved (default: ./reports).")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Minimal output — only print the report path when done.")
    parser.add_argument("--open", action="store_true", dest="open_report",
                        help="Auto-open the report file after the investigation.")
    parser.add_argument("--delay", type=float, default=0.0, metavar="SECONDS",
                        help="Delay in seconds between tool calls (default: 0).")
    return parser.parse_args(argv)


def apply_overrides(args: argparse.Namespace) -> None:
    if args.headless:
        object.__setattr__(settings, "headless", True)
    if args.model:
        object.__setattr__(settings, "deepseek_model", args.model)
    if args.max_steps:
        object.__setattr__(settings, "max_steps", args.max_steps)
    if args.output:
        object.__setattr__(settings, "reports_dir", Path(args.output))


async def main() -> None:
    args = parse_args()
    apply_overrides(args)

    problems = settings.validate()
    if problems:
        for p in problems:
            console.print(f"[error]{p}[/error]")
        sys.exit(1)

    try:
        if args.target:
            await run_agent(
                " ".join(args.target),
                as_json=args.json,
                language=args.lang,
                quiet=args.quiet,
                delay=args.delay,
                open_report=args.open_report,
                target_type=args.target_type,
                modules=args.modules,
            )
        else:
            await interactive()
    finally:
        await close_browser()


def cli_main() -> None:
    """Entry point for `pip install -e .` → `osint-agent` command."""
    import warnings
    warnings.filterwarnings("ignore", category=ResourceWarning)
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
