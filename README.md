# OSINT Agent

Passive OSINT reconnaissance agent built with LangGraph, LangChain, Playwright, and DeepSeek.

The agent gathers information from public sources only, uses browser automation for web research, and saves investigation reports as Markdown (`.md`) files under `reports/`. You can choose the report language (Spanish or English) and ask follow-up questions about any saved report.

## Features

- Interactive, one-shot, or batch investigations from the command line (`argparse`).
- Optional machine-readable JSON output (`--json`) and headless mode (`--headless`).
- DeepSeek chat model integration through the OpenAI-compatible LangChain client.
- Centralized configuration (`config.py`) and structured logging.
- Shared HTTP client with retries, backoff, and a reusable session (`http_client.py`).
- Browser-based search and navigation with Playwright (stealth hardening included).
- Public-source OSINT helpers (no API keys required):
  - DuckDuckGo web search
  - WHOIS lookup
  - DNS lookup through Google DoH (A, AAAA, MX, NS, TXT)
  - Reverse DNS (PTR) lookup
  - Certificate Transparency lookup through `crt.sh`
  - IP geolocation through `ip-api.com`
  - HTTP header / tech fingerprinting
  - `robots.txt` and sitemap discovery
  - GitHub profile + repository recon (public API)
  - Username enumeration across common platforms
  - Contact extraction from text
  - Wayback Machine snapshot lookup (single + historical via CDX)
  - Live TLS certificate inspection (issuer, validity, SANs)
  - ASN lookup (org + announced prefixes, via BGPView)
  - Passive port / service / CVE lookup (Shodan InternetDB, no scan)
  - Email validation (syntax + domain MX check)
  - Gravatar profile lookup
  - Common-subdomain discovery via DNS
  - Page metadata extraction (title, Open Graph, author, favicon)
- Report generation in Markdown (`.md`), in Spanish or English (your choice).
- Interactive Q&A mode: ask questions about any previously generated report.
- Defensive vulnerability / attack-surface analysis from a saved report (no exploitation).
- Unit tests (`pytest`) covering the pure logic (config, reporting, tools).

## Requirements

- Python 3.10 or newer
- A DeepSeek API key
- Chrome or Playwright Chromium

No Node.js or `npm install` is required.

## Setup

From the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m playwright install chromium
```

If PowerShell blocks virtual environment activation, run this first in the same terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Configuration

Create a `.env` file in the project root:

```env
DEEPSEEK_API_KEY=your_deepseek_api_key
DEEPSEEK_MODEL=deepseek-chat
```

`DEEPSEEK_API_KEY` is required.

`DEEPSEEK_MODEL` is optional. If it is not set, the agent defaults to `deepseek-c
`DEEPSEEK_MODEL` is optional. If it is not set, the agent defaults to `deepseek-chat`.

Other optional environment variables (all have sensible defaults, see `config.py`):
`OSINT_HEADLESS`, `OSINT_MAX_STEPS`, `OSINT_HTTP_TIMEOUT`, `OSINT_HTTP_RETRIES`,
`OSINT_LOG_LEVEL`, `OSINT_NAV_TIMEOUT_MS`, `DEEPSEEK_BASE_URL`, `DEEPSEEK_TEMPERATURE`.

## Usage

Start the interactive menu:

```powershell
python agent.py
```

On launch it asks for the interface language (Spanish or English) **once**.
From then on, the whole menu, prompts, messages and generated reports use that
language. The menu offers:

- `[1] New investigation` — runs a new recon and writes the report in the
  chosen language.
- `[2] Ask about an existing report` — lists saved reports, lets you pick one,
  and answers your questions about its contents.
- `[3] Vulnerability analysis of a report` — produces a **defensive**
  attack-surface review from a saved report: potential weaknesses, information
  disclosure, and hardening recommendations. It is theoretical only — it never
  generates exploitation steps — and the analysis is saved as a new report.

Run a direct investigation:

```powershell
python agent.py "example.com"
python agent.py "8.8.8.8" --lang es
python agent.py "Acme Corp"
python agent.py "John Smith CEO Acme"
```

Useful flags:

```powershell
python agent.py example.com --lang es         # report in Spanish (default: en)
python agent.py example.com --headless        # no visible browser window
python agent.py example.com --json            # machine-readable output
python agent.py --batch targets.txt --lang es # one target per line
python agent.py example.com --model deepseek-chat --max-steps 30
```

The agent will open a browser window when it needs to search or inspect pages
(unless `--headless` is used).

## Project Layout

- `agent.py` — LangGraph agent, CLI, interactive menu, and report Q&A.
- `tools.py` — core OSINT tools exposed to the model.
- `osint_extra.py` — additional keyless OSINT tools.
- `config.py` — settings (env-driven) and logging.
- `http_client.py` — shared requests session with retries.
- `reporting.py` — Markdown report generation.
- `tests/` — `pytest` unit tests for the pure logic.

## Testing

```powershell
pip install pytest
python -m pytest -q
```

The tests cover only pure logic (config, report rendering, parsers) and do not
require network access, a browser, or an API key.

## Output

Generated files are written to:

- `reports/` for Markdown reports and screenshots
- `chrome_profile/` for the persistent browser profile

Both directories are ignored by Git because they can contain investigation
output, cookies, sessions, cache, or other local data.

## Safety And Scope

This project is intended for passive reconnaissance using public 