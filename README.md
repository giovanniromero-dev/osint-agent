# OSINT Agent

**Passive OSINT reconnaissance powered by an AI agent — domains, IPs, emails, people, usernames and companies.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-ReAct-orange)](https://github.com/langchain-ai/langgraph)
[![License: GPL v2](https://img.shields.io/badge/license-GPLv2-green)](LICENSE)
[![Passive only](https://img.shields.io/badge/sources-public%20only-lightgrey)](https://github.com/giovanniromero-dev/osint-agent)

---

```
  ██████╗ ███████╗██╗███╗   ██╗████████╗ █████╗  ██████╗ ███████╗███╗   ██╗████████╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
 ██║   ██║███████╗██║██╔██╗ ██║   ██║   ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║   ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝
```

An AI agent built on **LangGraph** that autonomously selects and runs OSINT tools, reasons over results, and produces a structured Markdown report from public sources, without exploitation or active port scanning.

---

## What it does

You give it a target. The agent figures out what tools to run, in what order, and how to connect the findings into a coherent report. You don't write queries or chain commands manually.

```bash
osint-agent example.com
osint-agent 8.8.8.8 --modules ip,dns --lang es
osint-agent "John Smith CEO Acme" --type person
osint-agent admin@example.com --type email --open
```

---

## Features

- **26 passive tools** — WHOIS, DNS (5 record types in parallel), crt.sh, ip-api, Shodan InternetDB, BGPView ASN, Gravatar, Wayback Machine, GitHub recon, username enumeration across 10 platforms, subdomain bruteforce (40 words in parallel), TLS cert inspection, port/CVE passive lookup, email validation, page metadata, HTTP headers, robots.txt, contact extraction
- **AI agent loop** — LangGraph ReAct: the LLM decides which tools to call and stops when it has enough information
- **Browser automation** — Playwright (Chromium) for DuckDuckGo search and page navigation; polite by default (honors robots.txt, rate-limited, honest User-Agent), with optional opt-in stealth
- **Modular** — pick only the tool groups you need with `--modules dns,whois,ip`
- **Rich terminal output** — colored panels, live tool call display, progress
- **Bilingual** — reports and interface in English or Spanish (`--lang es`)
- **Report Q&A** — ask follow-up questions about any saved report
- **Defensive analysis** — get an attack-surface review from any report (no exploitation)
- **Docker-ready** — `docker run` with zero local install

---

## Quick start

### Option A — pip install

```bash
git clone https://github.com/giovanniromero-dev/osint-agent.git
cd osint-agent
pip install -e .
playwright install chromium

cp .env.example .env
# edit .env and add your DEEPSEEK_API_KEY

osint-agent example.com
```

### Option B — Docker (no Python setup)

```bash
docker build -t osint-agent .
docker run --env-file .env -v $(pwd)/reports:/app/reports osint-agent example.com
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your key:

```env
DEEPSEEK_API_KEY=your_key_here
DEEPSEEK_MODEL=deepseek-chat        # optional, this is the default
```

Get a free DeepSeek API key at [platform.deepseek.com](https://platform.deepseek.com).

Optional overrides (all have sensible defaults):

| Variable | Default | Description |
|---|---|---|
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | Override for local models |
| `DEEPSEEK_TEMPERATURE` | `0` | LLM temperature |
| `OSINT_HEADLESS` | `false` | Run browser headless |
| `OSINT_MAX_STEPS` | `50` | Max agent reasoning steps |
| `OSINT_REPORTS_DIR` | `./reports` | Directory where reports and screenshots are saved |
| `OSINT_CHROME_PROFILE_DIR` | `./chrome_profile` | Persistent browser profile directory |
| `OSINT_HTTP_TIMEOUT` | `10` | HTTP timeout in seconds |
| `OSINT_HTTP_RETRIES` | `3` | Retries on 429/5xx |
| `OSINT_LOG_LEVEL` | `INFO` | Logging verbosity |
| `OSINT_RESPECT_ROBOTS` | `true` | Honor robots.txt when navigating |
| `OSINT_ROBOTS_FAIL_CLOSED` | `false` | Block navigation when robots.txt cannot be fetched or parsed |
| `OSINT_REQUEST_DELAY` | `1.0` | Min seconds between page navigations |
| `OSINT_USER_AGENT` | `osint-agent/1.0 …` | User-Agent sent to sites |
| `OSINT_STEALTH` | `false` | Anti-bot fingerprint spoofing (authorized use only) |

---

## CLI reference

```
osint-agent [TARGET] [OPTIONS]

Arguments:
  TARGET              Domain, IP, email, person name, company, or username

Options:
  -V, --version       Show version
  --lang {en,es}      Report language (default: en)
  --type TYPE         Hint: domain | ip | email | person | username | company
  --modules MODULES   Comma-separated groups: dns,whois,ip,web,email,social,archive
  --output DIR        Report output directory (default: ./reports)
  --quiet, -q         Print only the report path when done
  --open              Open the report after the investigation
  --delay SECONDS     Delay between agent tool calls (default: 0)
  --json              Machine-readable JSON output
  --headless          Headless browser (no visible window)
  --model MODEL       Override the DeepSeek model
  --max-steps N       Override max agent steps

Responsible-use controls (override .env defaults / the chosen profile):
  --profile NAME      Scan profile: polite | balanced | aggressive (default: polite)
  --stealth           Enable anti-bot fingerprint spoofing (authorized targets only)
  --ignore-robots     Ignore robots.txt (default: respect it)
  --strict-robots     Block navigation if robots.txt cannot be read
  --request-delay S   Min seconds between page navigations (default: 1.0)
  --user-agent UA     Override the User-Agent sent to sites
```

### Scan profiles

A profile is a preset bundle of the controls above. Pick one with `--profile`
(or via the interactive menu). Individual flags always override the profile.

| Profile | Stealth | robots.txt | Delay | Max steps |
|---|---|---|---|---|
| `polite` *(default)* | off | respected | 1.0s | 50 |
| `balanced` | off | respected | 0.5s | 75 |
| `aggressive` | on | ignored | 0s | 100 |

```bash
osint-agent example.com --profile aggressive            # authorized targets only
osint-agent example.com --profile aggressive --request-delay 2   # preset + tweak
```

> The `aggressive` profile enables stealth and ignores robots.txt. Use it only on
> systems you own or are explicitly authorized to assess.

**Examples:**

```bash
osint-agent example.com
osint-agent example.com --lang es --open
osint-agent 8.8.8.8 --modules ip,dns --quiet
osint-agent "John Smith CEO Acme" --type person --lang es
osint-agent admin@company.com --type email
```

---

## Responsible use

This tool is provided for **lawful, authorized use only** — security research,
defensive assessments of assets you own or have explicit written permission to
analyze, education, and journalism. It collects only **publicly available**
information from public sources. It does make normal public web, DNS, HTTP and
TLS requests, but performs **no exploitation, intrusion, or active port
scanning**.

By design, the default behavior is polite:

- **Respects `robots.txt`** (`OSINT_RESPECT_ROBOTS=true` by default).
- Can fail closed when `robots.txt` cannot be checked (`--strict-robots` or
  `OSINT_ROBOTS_FAIL_CLOSED=true`).
- **Rate-limited** between requests (`OSINT_REQUEST_DELAY`, default 1s).
- **Identifies itself honestly** with a descriptive User-Agent.
- **Stealth / anti-bot fingerprinting is OFF by default** (`OSINT_STEALTH=false`).
  Enabling it may violate the Terms of Service of the sites you access; only do
  so for sources you are authorized to test.

You are solely responsible for ensuring your use complies with all applicable
laws (including data-protection rules such as the GDPR) and with the terms of
the services you query. The author accepts no liability for misuse or for any
damage arising from use of this software.

---

## License

Released under the **GNU General Public License v2.0** (GPLv2). See [LICENSE](LICENSE).
