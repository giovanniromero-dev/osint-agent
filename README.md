# OSINT Agent

Passive OSINT reconnaissance agent built with LangGraph, LangChain, Playwright, and DeepSeek.

The agent gathers information from public sources only, uses browser automation for web research, and saves investigation reports as Markdown files under `reports/`.

## Features

- Interactive or one-shot investigations from the command line.
- DeepSeek chat model integration through the OpenAI-compatible LangChain client.
- Browser-based search and navigation with Playwright.
- Public-source OSINT helpers:
  - DuckDuckGo web search
  - WHOIS lookup
  - DNS lookup through Google DoH
  - Certificate Transparency lookup through `crt.sh`
  - IP geolocation through `ip-api.com`
  - Contact extraction from text
  - Wayback Machine snapshot lookup
- Markdown report generation with optional screenshots as evidence.

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

`DEEPSEEK_MODEL` is optional. If it is not set, the agent defaults to `deepseek-chat`.

## Usage

Start the interactive menu:

```powershell
python agent.py
```

Run a direct investigation:

```powershell
python agent.py "example.com"
python agent.py "8.8.8.8"
python agent.py "Acme Corp"
python agent.py "John Smith CEO Acme"
```

The agent will open a browser window when it needs to search or inspect pages.

## Output

Generated files are written to:

- `reports/` for Markdown reports and screenshots
- `chrome_profile/` for the persistent browser profile

Both directories are ignored by Git because they can contain investigation output, cookies, sessions, cache, or other local data.

## Safety And Scope

This project is intended for passive reconnaissance using public sources only. Do not use it for unauthorized access, exploitation, credential attacks, bypassing access controls, or scanning systems without permission.

## Troubleshooting

If dependencies are missing:

```powershell
pip install -r requirements.txt
```

If Playwright cannot launch a browser:

```powershell
python -m playwright install chromium
```

If the model call fails, check that `.env` exists and contains a valid `DEEPSEEK_API_KEY`.

If Chrome is not installed, the code falls back to Playwright Chromium.
