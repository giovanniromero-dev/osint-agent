"""
OSINT Agent Tools — Playwright + public APIs, no API keys required.
Sources: DuckDuckGo, crt.sh, ip-api.com, Google DoH, python-whois, Wayback Machine.
"""
import asyncio
import os
import re
import socket

import requests
from langchain_core.tools import tool
from playwright.async_api import async_playwright, BrowserContext, Page

# ── Dirs ───────────────────────────────────────────────────────────────────────

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

# ── Global browser state ───────────────────────────────────────────────────────

_browser: BrowserContext = None
_page: Page = None
_playwright_instance = None

CHROME_PROFILE_DIR = os.path.join(os.path.dirname(__file__), "chrome_profile")


# ── Stealth ────────────────────────────────────────────────────────────────────

async def apply_stealth(page: Page):
    await page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'plugins', {
            get: () => {
                var arr = [
                    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: '', length: 1 },
                    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '', length: 1 },
                    { name: 'Native Client', filename: 'internal-nacl-plugin', description: '', length: 2 }
                ];
                Object.setPrototypeOf(arr, PluginArray.prototype);
                return arr;
            }
        });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
        window.chrome = { runtime: {}, loadTimes: function(){return {};}, csi: function(){return {};}, app: {} };
        var _orig = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type) {
            var ctx = this.getContext('2d');
            if (ctx) {
                var d = ctx.getImageData(0,0,this.width||1,this.height||1);
                for (var i=0;i<d.data.length;i+=199) d.data[i]^=1;
                ctx.putImageData(d,0,0);
            }
            return _orig.apply(this,arguments);
        };
        var _gp = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(p) {
            if (p===37445) return 'Intel Inc.';
            if (p===37446) return 'Intel Iris Pro OpenGL Engine';
            return _gp.call(this,p);
        };
        Object.defineProperty(screen,'colorDepth',{get:()=>24});
    """)


# ── Browser lifecycle ──────────────────────────────────────────────────────────

async def ensure_browser() -> Page:
    global _browser, _page, _playwright_instance
    if _page is None:
        _playwright_instance = await async_playwright().start()
        try:
            context = await _playwright_instance.chromium.launch_persistent_context(
                user_data_dir=CHROME_PROFILE_DIR,
                channel="chrome",
                headless=False,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox", "--start-maximized"],
                no_viewport=True,
            )
            print("[browser] Launched Chrome with persistent profile")
        except Exception:
            print("[browser] Real Chrome not found — falling back to Chromium")
            context = await _playwright_instance.chromium.launch_persistent_context(
                user_data_dir=CHROME_PROFILE_DIR,
                headless=False,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
            )
        _page = await context.new_page()
        await apply_stealth(_page)
        _browser = context
    return _page


async def close_browser():
    global _browser, _page, _playwright_instance
    for obj, method in [(_page, "close"), (_browser, "close"), (_playwright_instance, "stop")]:
        try:
            if obj:
                await getattr(obj, method)()
        except Exception:
            pass
    _browser = None
    _page = None
    _playwright_instance = None


# ── Browser tools ──────────────────────────────────────────────────────────────

@tool
async def navigate(url: str) -> str:
    """Navigate to any URL. Use full URLs with https://"""
    try:
        page = await ensure_browser()
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        return f"Navigated to: {page.url} | Title: {await page.title()}"
    except Exception as e:
        return f"Error navigating to {url}: {e}"


@tool
async def get_text() -> str:
    """Get visible text content of the current page (first 6000 chars)."""
    try:
        page = await ensure_browser()
        text = await page.inner_text("body")
        return text[:6000] + "\n...[truncated]" if len(text) > 6000 else text
    except Exception as e:
        return f"Error: {e}"


@tool
async def get_links() -> str:
    """Extract all hyperlinks from the current page."""
    try:
        page = await ensure_browser()
        links = await page.eval_on_selector_all(
            "a[href]",
            "els => els.map(e => ({text: e.innerText.trim().slice(0,80), href: e.href})).filter(l => l.href.startsWith('http'))"
        )
        if not links:
            return "No links found."
        lines = [f"- {l['text'] or '(no text)'}: {l['href']}" for l in links[:60]]
        return f"Found {len(links)} links (showing up to 60):\n" + "\n".join(lines)
    except Exception as e:
        return f"Error extracting links: {e}"


@tool
async def screenshot() -> str:
    """Take a screenshot and save it as evidence in reports/."""
    try:
        page = await ensure_browser()
        os.makedirs(REPORTS_DIR, exist_ok=True)
        url_slug = re.sub(r'[^\w]', '_', page.url)[:40]
        path = os.path.join(REPORTS_DIR, f"screenshot_{url_slug}.png")
        await page.screenshot(path=path, full_page=False)
        return f"Screenshot saved: {path} | URL: {page.url}"
    except Exception as e:
        return f"Error taking screenshot: {e}"


@tool
async def search_web(query: str) -> str:
    """Search DuckDuckGo for any query. Returns titles, URLs and snippets."""
    try:
        page = await ensure_browser()
        search_url = f"https://duckduckgo.com/?q={requests.utils.quote(query)}&ia=web"
        await page.goto(search_url, wait_until="domcontentloaded", timeout=20000)
        await asyncio.sleep(2)

        results = await page.eval_on_selector_all(
            "[data-testid='result']",
            """els => els.slice(0,8).map(el => ({
                title: el.querySelector('h2')?.innerText || '',
                url:   el.querySelector('a[href]')?.href || '',
                snippet: el.querySelector('[data-result="snippet"]')?.innerText || ''
            }))"""
        )

        if not results:
            # Fallback: grab raw text
            text = await page.inner_text("body")
            return f"Search results (raw):\n{text[:3000]}"

        lines = []
        for r in results:
            lines.append(f"**{r['title']}**\n{r['url']}\n{r['snippet']}\n")
        return f"Search results for '{query}':\n\n" + "\n".join(lines)
    except Exception as e:
        return f"Error searching: {e}"


# ── OSINT tools ────────────────────────────────────────────────────────────────

@tool
def whois_lookup(domain: str) -> str:
    """WHOIS lookup for a domain — registration dates, registrar, name servers, registrant."""
    try:
        import whois
        w = whois.whois(domain)
        fields = {
            "domain":      w.domain_name,
            "registrar":   w.registrar,
            "created":     str(w.creation_date),
            "expires":     str(w.expiration_date),
            "updated":     str(w.updated_date),
            "name_servers": w.name_servers,
            "status":      w.status,
            "emails":      w.emails,
            "org":         w.org,
            "country":     w.country,
        }
        lines = [f"{k}: {v}" for k, v in fields.items() if v]
        return f"WHOIS for {domain}:\n" + "\n".join(lines)
    except Exception as e:
        return f"WHOIS error for {domain}: {e}"


@tool
def dns_lookup(domain: str) -> str:
    """DNS lookup — A, MX, NS records using Google DoH (no dependencies needed)."""
    results = []
    record_types = ["A", "MX", "NS", "TXT", "AAAA"]
    for rtype in record_types:
        try:
            r = requests.get(
                "https://dns.google/resolve",
                params={"name": domain, "type": rtype},
                timeout=5,
            )
            data = r.json()
            answers = data.get("Answer", [])
            if answers:
                vals = [a["data"] for a in answers]
                results.append(f"{rtype}: {', '.join(vals)}")
        except Exception:
            pass

    # Also try basic socket resolution
    try:
        ip = socket.gethostbyname(domain)
        results.insert(0, f"Resolved IP: {ip}")
    except Exception:
        pass

    return f"DNS records for {domain}:\n" + ("\n".join(results) if results else "No records found.")


@tool
def cert_lookup(domain: str) -> str:
    """
    Certificate Transparency lookup via crt.sh.
    Reveals subdomains registered in SSL certificates — no API key needed.
    """
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        entries = r.json()
        names = set()
        for e in entries:
            for name in e.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and domain in name:
                    names.add(name)
        if not names:
            return f"No certificates found for {domain}."
        sorted_names = sorted(names)
        return f"Subdomains found via crt.sh for {domain} ({len(sorted_names)} total):\n" + "\n".join(sorted_names[:50])
    except Exception as e:
        return f"cert_lookup error: {e}"


@tool
def ip_lookup(ip: str) -> str:
    """IP geolocation and ISP info via ip-api.com (free, no key needed)."""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data.get("status") == "fail":
            return f"Could not look up IP: {ip}"
        fields = ["country", "regionName", "city", "zip", "lat", "lon", "isp", "org", "as", "query"]
        lines = [f"{k}: {data.get(k, '')}" for k in fields if data.get(k)]
        return f"IP info for {ip}:\n" + "\n".join(lines)
    except Exception as e:
        return f"ip_lookup error: {e}"


@tool
def extract_contacts(text: str) -> str:
    """Extract email addresses and phone numbers from any block of text."""
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)))
    phones = list(set(re.findall(
        r"(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}", text
    )))
    phones = [p.strip() for p in phones if len(re.sub(r'\D', '', p)) >= 7]

    lines = []
    if emails:
        lines.append(f"Emails ({len(emails)}):\n" + "\n".join(f"  {e}" for e in emails))
    if phones:
        lines.append(f"Phones ({len(phones)}):\n" + "\n".join(f"  {p}" for p in phones[:20]))
    return "\n".join(lines) if lines else "No emails or phone numbers found."


@tool
def wayback_lookup(url: str) -> str:
    """Check if a URL has archived versions in the Wayback Machine."""
    try:
        r = requests.get(
            f"https://archive.org/wayback/available?url={url}",
            timeout=8,
        )
        data = r.json()
        snapshot = data.get("archived_snapshots", {}).get("closest", {})
        if snapshot.get("available"):
            return (
                f"Wayback Machine snapshot available:\n"
                f"  URL: {snapshot['url']}\n"
                f"  Timestamp: {snapshot['timestamp']}\n"
                f"  Status: {snapshot['status']}"
            )
        return f"No Wayback Machine snapshot found for: {url}"
    except Exception as e:
        return f"wayback_lookup error: {e}"


@tool
def save_report(filename: str, content: str) -> str:
    """
    Save investigation findings to a markdown file in reports/.
    filename: short name without extension (e.g. 'target_company_2026')
    content: full markdown content to save
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    safe = re.sub(r'[^\w\-]', '_', filename)
    path = os.path.join(REPORTS_DIR, f"{safe}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Report saved: {path}"



# ── Finish ─────────────────────────────────────────────────────────────────────

@tool
def finish(summary: str) -> str:
    """Call when the investigation is complete. summary: findings for the user."""
    return f"TASK_COMPLETE: {summary}"


# ── Tool registry ───────────────────────────────────────────────────────────────

OSINT_TOOLS = [
    # Browser
    navigate,
    get_text,
    get_links,
    screenshot,
    search_web,
    # OSINT
    whois_lookup,
    dns_lookup,
    cert_lookup,
    ip_lookup,
    extract_contacts,
    wayback_lookup,
    save_report,
    # Control
    finish,
]
