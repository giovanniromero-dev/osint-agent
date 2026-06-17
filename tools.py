"""
OSINT Agent Tools - Playwright + public APIs, no API keys required.

Sources: DuckDuckGo, crt.sh, ip-api.com, Google DoH, python-whois,
Wayback Machine, GitHub public API, robots.txt / sitemap.xml.
"""
from __future__ import annotations

import asyncio
import re
import socket
from typing import Optional
from urllib.parse import urlparse

from langchain_core.tools import tool
from playwright.async_api import async_playwright, BrowserContext, Page

from config import REPORTS_DIR, get_logger, settings
from http_client import get_json, http_get
import reporting
from osint_extra import EXTRA_TOOLS

log = get_logger("osint.tools")

# Global browser state
_browser: Optional[BrowserContext] = None
_page: Optional[Page] = None
_playwright_instance = None


_STEALTH_SCRIPT = """
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
"""


async def apply_stealth(page: Page) -> None:
    await page.add_init_script(_STEALTH_SCRIPT)


async def ensure_browser() -> Page:
    global _browser, _page, _playwright_instance
    if _page is not None:
        return _page

    _playwright_instance = await async_playwright().start()
    profile_dir = str(settings.chrome_profile_dir)
    common_args = ["--disable-blink-features=AutomationControlled", "--no-sandbox"]
    try:
        context = await _playwright_instance.chromium.launch_persistent_context(
            user_data_dir=profile_dir,
            channel="chrome",
            headless=settings.headless,
            args=common_args + ["--start-maximized"],
            no_viewport=not settings.headless,
        )
        log.info("Launched Chrome with persistent profile (headless=%s)", settings.headless)
    except Exception as exc:
        log.warning("Real Chrome not available (%s) - falling back to Chromium", exc)
        context = await _playwright_instance.chromium.launch_persistent_context(
            user_data_dir=profile_dir,
            headless=settings.headless,
            args=common_args,
            viewport={"width": 1280, "height": 800},
            user_agent=settings.user_agent,
        )
    _page = await context.new_page()
    await apply_stealth(_page)
    _browser = context
    return _page


async def close_browser() -> None:
    global _browser, _page, _playwright_instance
    for obj, method in [(_page, "close"), (_browser, "close"), (_playwright_instance, "stop")]:
        try:
            if obj:
                await getattr(obj, method)()
        except Exception:  # noqa: BLE001
            pass
    _browser = None
    _page = None
    _playwright_instance = None


def _clean_domain(value: str) -> str:
    """Normalize a domain or URL into a bare hostname."""
    value = value.strip()
    if "://" in value:
        value = urlparse(value).netloc or value
    value = value.split("/")[0].strip().lower()
    if value.startswith("www."):
        value = value[4:]
    return value


# Browser tools

@tool
async def navigate(url: str) -> str:
    """Navigate to any URL. Use full URLs with https://"""
    try:
        page = await ensure_browser()
        await page.goto(url, wait_until="domcontentloaded", timeout=settings.nav_timeout_ms)
        return f"Navigated to: {page.url} | Title: {await page.title()}"
    except Exception as e:  # noqa: BLE001
        return f"Error navigating to {url}: {e}"


@tool
async def get_text() -> str:
    """Get visible text content of the current page (first 6000 chars)."""
    try:
        page = await ensure_browser()
        text = await page.inner_text("body")
        return text[:6000] + "\n...[truncated]" if len(text) > 6000 else text
    except Exception as e:  # noqa: BLE001
        return f"Error: {e}"


@tool
async def get_links() -> str:
    """Extract all hyperlinks from the current page."""
    try:
        page = await ensure_browser()
        links = await page.eval_on_selector_all(
            "a[href]",
            "els => els.map(e => ({text: e.innerText.trim().slice(0,80), href: e.href}))"
            ".filter(l => l.href.startsWith('http'))",
        )
        if not links:
            return "No links found."
        lines = [f"- {l['text'] or '(no text)'}: {l['href']}" for l in links[:60]]
        return f"Found {len(links)} links (showing up to 60):\n" + "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return f"Error extracting links: {e}"


@tool
async def screenshot() -> str:
    """Take a screenshot and save it as evidence in reports/."""
    try:
        page = await ensure_browser()
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        url_slug = re.sub(r"[^\w]", "_", page.url)[:40]
        path = REPORTS_DIR / f"screenshot_{url_slug}.png"
        await page.screenshot(path=str(path), full_page=False)
        return f"Screenshot saved: {path} | URL: {page.url}"
    except Exception as e:  # noqa: BLE001
        return f"Error taking screenshot: {e}"


@tool
async def search_web(query: str) -> str:
    """Search DuckDuckGo for any query. Returns titles, URLs and snippets."""
    try:
        import requests as _rq

        page = await ensure_browser()
        search_url = f"https://duckduckgo.com/?q={_rq.utils.quote(query)}&ia=web"
        await page.goto(search_url, wait_until="domcontentloaded", timeout=settings.search_timeout_ms)
        await asyncio.sleep(2)

        results = await page.eval_on_selector_all(
            "[data-testid='result']",
            """els => els.slice(0,8).map(el => ({
                title: el.querySelector('h2')?.innerText || '',
                url:   el.querySelector('a[href]')?.href || '',
                snippet: el.querySelector('[data-result="snippet"]')?.innerText || ''
            }))""",
        )

        if not results:
            text = await page.inner_text("body")
            return f"Search results (raw):\n{text[:3000]}"

        lines = [f"**{r['title']}**\n{r['url']}\n{r['snippet']}\n" for r in results]
        return f"Search results for '{query}':\n\n" + "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return f"Error searching: {e}"


# OSINT tools

@tool
def whois_lookup(domain: str) -> str:
    """WHOIS lookup for a domain - registration dates, registrar, name servers, registrant."""
    domain = _clean_domain(domain)
    try:
        import whois

        w = whois.whois(domain)
        fields = {
            "domain": w.domain_name,
            "registrar": w.registrar,
            "created": str(w.creation_date),
            "expires": str(w.expiration_date),
            "updated": str(w.updated_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "country": w.country,
        }
        lines = [f"{k}: {v}" for k, v in fields.items() if v]
        return f"WHOIS for {domain}:\n" + "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return f"WHOIS error for {domain}: {e}"


@tool
def dns_lookup(domain: str) -> str:
    """DNS lookup - A, AAAA, MX, NS, TXT records using Google DoH."""
    domain = _clean_domain(domain)
    results: list[str] = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        data = get_json(
            "https://dns.google/resolve",
            params={"name": domain, "type": rtype},
            timeout=settings.http_timeout,
        )
        if data:
            answers = data.get("Answer", [])
            vals = [a["data"] for a in answers if "data" in a]
            if vals:
                results.append(f"{rtype}: {', '.join(vals)}")

    try:
        ip = socket.gethostbyname(domain)
        results.insert(0, f"Resolved IP: {ip}")
    except Exception:  # noqa: BLE001
        pass

    return f"DNS records for {domain}:\n" + ("\n".join(results) if results else "No records found.")


@tool
def reverse_dns(ip: str) -> str:
    """Reverse DNS (PTR) lookup - find the hostname associated with an IP address."""
    ip = ip.strip()
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        names = [host] + [a for a in aliases if a != host]
        return f"Reverse DNS for {ip}:\n" + "\n".join(names)
    except Exception as e:  # noqa: BLE001
        return f"No PTR record for {ip} ({e})"


@tool
def cert_lookup(domain: str) -> str:
    """
    Certificate Transparency lookup via crt.sh.
    Reveals subdomains registered in SSL certificates - no API key needed.
    """
    domain = _clean_domain(domain)
    entries = get_json(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
    if entries is None:
        return f"cert_lookup error: crt.sh did not return data for {domain}."
    names: set[str] = set()
    for e in entries:
        for name in (e.get("name_value", "") or "").split("\n"):
            name = name.strip().lower()
            if name and domain in name:
                names.add(name)
    if not names:
        return f"No certificates found for {domain}."
    sorted_names = sorted(names)
    return (
        f"Subdomains found via crt.sh for {domain} ({len(sorted_names)} total):\n"
        + "\n".join(sorted_names[:50])
    )


@tool
def ip_lookup(ip: str) -> str:
    """IP geolocation and ISP info via ip-api.com (free, no key needed)."""
    ip = ip.strip()
    data = get_json(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,regionName,city,zip,lat,lon,isp,org,as,reverse,query"},
        timeout=settings.http_timeout,
    )
    if not data or data.get("status") == "fail":
        return f"Could not look up IP: {ip}"
    fields = ["country", "regionName", "city", "zip", "lat", "lon", "isp", "org", "as", "reverse", "query"]
    lines = [f"{k}: {data.get(k, '')}" for k in fields if data.get(k)]
    return f"IP info for {ip}:\n" + "\n".join(lines)


@tool
def http_headers(url: str) -> str:
    """Fetch HTTP response headers for a URL and fingerprint server/tech where possible."""
    if "://" not in url:
        url = "https://" + url
    try:
        resp = http_get(url, timeout=settings.http_timeout, allow_redirects=True)
        interesting = [
            "server", "x-powered-by", "via", "x-aspnet-version", "x-generator",
            "content-type", "set-cookie", "strict-transport-security",
            "content-security-policy", "x-frame-options",
        ]
        lines = [f"Status: {resp.status_code}", f"Final URL: {resp.url}"]
        for h in interesting:
            if h in resp.headers:
                val = resp.headers[h]
                lines.append(f"{h}: {val[:200]}")
        return f"HTTP headers for {url}:\n" + "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return f"http_headers error for {url}: {e}"


@tool
def robots_sitemap(domain: str) -> str:
    """Fetch robots.txt and list sitemap URLs / disallowed paths for a domain."""
    domain = _clean_domain(domain)
    base = f"https://{domain}"
    out: list[str] = []
    try:
        resp = http_get(f"{base}/robots.txt", timeout=settings.http_timeout)
        if resp.status_code == 200 and resp.text.strip():
            body = resp.text
            sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", body)
            disallows = re.findall(r"(?im)^\s*disallow:\s*(\S+)", body)
            out.append(f"robots.txt ({len(body)} bytes) fetched from {base}/robots.txt")
            if sitemaps:
                out.append("Sitemaps:\n" + "\n".join(f"  {s}" for s in sitemaps[:20]))
            if disallows:
                uniq = sorted(set(disallows))
                out.append(f"Disallowed paths ({len(uniq)}):\n" + "\n".join(f"  {d}" for d in uniq[:30]))
        else:
            out.append(f"No robots.txt (HTTP {resp.status_code}).")
    except Exception as e:  # noqa: BLE001
        out.append(f"robots.txt error: {e}")
    return "\n".join(out)


@tool
def github_recon(username: str) -> str:
    """
    Look up a GitHub user or organization via the public API (no key).
    Returns profile info plus their most recently updated public repositories.
    """
    username = username.strip().lstrip("@")
    user = get_json(f"https://api.github.com/users/{username}", timeout=settings.http_timeout)
    if not user or "login" not in user:
        return f"No public GitHub account found for '{username}'."

    profile_fields = [
        ("login", user.get("login")),
        ("name", user.get("name")),
        ("type", user.get("type")),
        ("company", user.get("company")),
        ("location", user.get("location")),
        ("blog", user.get("blog")),
        ("email", user.get("email")),
        ("bio", user.get("bio")),
        ("public_repos", user.get("public_repos")),
        ("followers", user.get("followers")),
        ("created_at", user.get("created_at")),
        ("profile", user.get("html_url")),
    ]
    lines = [f"{k}: {v}" for k, v in profile_fields if v is not None]

    repos = get_json(
        f"https://api.github.com/users/{username}/repos",
        params={"sort": "updated", "per_page": 10},
        timeout=settings.http_timeout,
    )
    if isinstance(repos, list) and repos:
        lines.append("")
        lines.append("Top repositories (recently updated):")
        for r in repos[:10]:
            stars = r.get("stargazers_count", 0)
            lang = r.get("language") or "n/a"
            lines.append(f"  - {r.get('full_name')} (stars {stars}, {lang}) {r.get('html_url')}")
    return f"GitHub recon for {username}:\n" + "\n".join(lines)



_USERNAME_SITES = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Twitter/X": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "Reddit": "https://www.reddit.com/user/{u}",
    "Medium": "https://medium.com/@{u}",
    "Keybase": "https://keybase.io/{u}",
    "Dev.to": "https://dev.to/{u}",
    "Telegram": "https://t.me/{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
}


@tool
def username_enum(username: str) -> str:
    """
    Check whether a username exists on common public platforms by probing
    profile URLs. Reports likely-present (HTTP 200) vs not-found (404).
    """
    username = username.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._\-]{1,40}", username):
        return f"Refusing to probe unusual username '{username}'."
    found: list[str] = []
    missing: list[str] = []
    errors: list[str] = []
    for site, tmpl in _USERNAME_SITES.items():
        url = tmpl.format(u=username)
        try:
            resp = http_get(url, timeout=8, allow_redirects=True)
            if resp.status_code == 200:
                found.append(f"  [FOUND]     {site}: {url}")
            elif resp.status_code in (404, 410):
                missing.append(site)
            else:
                errors.append(f"  [HTTP {resp.status_code}] {site}: {url}")
        except Exception as e:  # noqa: BLE001
            errors.append(f"  [error] {site}: {e}")
    out = [f"Username enumeration for '{username}':"]
    if found:
        out.append("Likely present:\n" + "\n".join(found))
    if errors:
        out.append("Inconclusive:\n" + "\n".join(errors))
    if missing:
        out.append("Not found: " + ", ".join(missing))
    return "\n".join(out)


@tool
def extract_contacts(text: str) -> str:
    """Extract email addresses and phone numbers from any block of text."""
    emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)))
    phones = sorted(set(re.findall(
        r"(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}", text
    )))
    phones = [p.strip() for p in phones if len(re.sub(r"\D", "", p)) >= 7]

    lines = []
    if emails:
        lines.append(f"Emails ({len(emails)}):\n" + "\n".join(f"  {e}" for e in emails))
    if phones:
        lines.append(f"Phones ({len(phones)}):\n" + "\n".join(f"  {p}" for p in phones[:20]))
    return "\n".join(lines) if lines else "No emails or phone numbers found."


@tool
def wayback_lookup(url: str) -> str:
    """Check if a URL has archived versions in the Wayback Machine."""
    data = get_json(f"https://archive.org/wayback/available?url={url}", timeout=8)
    if data is None:
        return f"wayback_lookup error: no response for {url}"
    snapshot = data.get("archived_snapshots", {}).get("closest", {})
    if snapshot.get("available"):
        return (
            "Wayback Machine snapshot available:\n"
            f"  URL: {snapshot['url']}\n"
            f"  Timestamp: {snapshot['timestamp']}\n"
            f"  Status: {snapshot['status']}"
        )
    return f"No Wayback Machine snapshot found for: {url}"


@tool
def save_report(filename: str, content: str) -> str:
    """
    Save investigation findings as a timestamped markdown (.md) report in reports/.

    filename: short target name without extension (e.g. 'acme_corp')
    content: full markdown content to save
    """
    try:
        paths = reporting.save_report(filename, content)
        return f"Report saved: {paths['markdown']}"
    except Exception as e:  # noqa: BLE001
        return f"save_report error: {e}"


@tool
def finish(summary: str) -> str:
    """Call when the investigation is complete. summary: findings for the user."""
    return f"TASK_COMPLETE: {summary}"


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
    reverse_dns,
    cert_lookup,
    ip_lookup,
    http_headers,
    robots_sitemap,
    github_recon,
    username_enum,
    extract_contacts,
    wayback_lookup,
    save_report,
    # Control
    finish,
] + EXTRA_TOOLS
