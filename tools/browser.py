"""Browser-backed OSINT tools and polite-access controls."""
from __future__ import annotations

import asyncio
import os
import re
import time
from urllib import robotparser
from urllib.parse import quote as url_quote, urlparse

from langchain_core.tools import tool
from playwright.async_api import BrowserContext, Page, async_playwright

from config import get_logger, settings
from http_client import async_http_get

log = get_logger("osint.tools.browser")

_browser: BrowserContext | None = None
_page: Page | None = None
_playwright_instance = None
_BROWSER_LOCK: asyncio.Lock | None = None


def _get_browser_lock() -> asyncio.Lock:
    """Return a lazily-created asyncio.Lock for serialising browser access."""
    global _BROWSER_LOCK
    if _BROWSER_LOCK is None:
        _BROWSER_LOCK = asyncio.Lock()
    return _BROWSER_LOCK


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


# Browser-like UA used only when stealth mode is explicitly enabled.
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_LAST_NAV_AT = 0.0
_ROBOTS_CACHE: dict[str, robotparser.RobotFileParser | None] = {}


async def ensure_browser() -> Page:
    global _browser, _page, _playwright_instance
    if _page is not None:
        return _page

    _playwright_instance = await async_playwright().start()
    profile_dir = str(settings.chrome_profile_dir)
    common_args = []
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        common_args.append("--no-sandbox")
    if settings.stealth:
        common_args.append("--disable-blink-features=AutomationControlled")
    ua = _BROWSER_UA if settings.stealth else settings.user_agent
    try:
        context = await _playwright_instance.chromium.launch_persistent_context(
            user_data_dir=profile_dir,
            channel="chrome",
            headless=settings.headless,
            args=common_args + ["--start-maximized"],
            no_viewport=not settings.headless,
            user_agent=ua,
        )
        log.info(
            "Launched Chrome with persistent profile (headless=%s, stealth=%s)",
            settings.headless,
            settings.stealth,
        )
    except Exception as exc:
        log.warning("Real Chrome not available (%s) - falling back to Chromium", exc)
        context = await _playwright_instance.chromium.launch_persistent_context(
            user_data_dir=profile_dir,
            headless=settings.headless,
            args=common_args,
            viewport={"width": 1280, "height": 800},
            user_agent=ua,
        )
    _page = await context.new_page()
    if settings.stealth:
        await apply_stealth(_page)
    _browser = context
    return _page


async def close_browser() -> None:
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


async def _rate_limit() -> None:
    """Sleep so consecutive navigations are at least settings.request_delay apart."""
    global _LAST_NAV_AT
    delay = max(0.0, settings.request_delay)
    if delay:
        wait = delay - (time.monotonic() - _LAST_NAV_AT)
        if wait > 0:
            await asyncio.sleep(wait)
    _LAST_NAV_AT = time.monotonic()


async def _robots_allows(url: str) -> bool:
    """Return True if robots.txt permits fetching url. No-op if disabled."""
    if not settings.respect_robots:
        return True
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return True
        host = f"{parsed.scheme}://{parsed.netloc}"
        if host not in _ROBOTS_CACHE:
            rp = None
            try:
                resp = await async_http_get(f"{host}/robots.txt", timeout=settings.http_timeout)
                if resp is not None and resp.status_code == 200 and resp.text.strip():
                    rp = robotparser.RobotFileParser()
                    rp.parse(resp.text.splitlines())
            except Exception:
                rp = None
            _ROBOTS_CACHE[host] = rp
        rp = _ROBOTS_CACHE[host]
        return (not settings.robots_fail_closed) if rp is None else rp.can_fetch(settings.user_agent, url)
    except Exception:
        return not settings.robots_fail_closed


@tool
async def navigate(url: str) -> str:
    """Navigate to any URL. Use full URLs with https://"""
    if "://" not in url:
        url = "https://" + url
    async with _get_browser_lock():
        try:
            if not await _robots_allows(url):
                return (
                    f"Blocked by robots.txt: {url}. This site disallows automated "
                    "access to that path. Set OSINT_RESPECT_ROBOTS=false to override "
                    "(only for sources you are authorized to access)."
                )
            await _rate_limit()
            page = await ensure_browser()
            await page.goto(url, wait_until="domcontentloaded", timeout=settings.nav_timeout_ms)
            return f"Navigated to: {page.url} | Title: {await page.title()}"
        except Exception as e:
            return f"Error navigating to {url}: {e}"


@tool
async def get_text() -> str:
    """Get visible text content of the current page (first 6000 chars)."""
    async with _get_browser_lock():
        try:
            page = await ensure_browser()
            text = await page.inner_text("body")
            return text[:6000] + "\n...[truncated]" if len(text) > 6000 else text
        except Exception as e:
            return f"Error: {e}"


@tool
async def get_links() -> str:
    """Extract all hyperlinks from the current page."""
    async with _get_browser_lock():
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
        except Exception as e:
            return f"Error extracting links: {e}"


@tool
async def screenshot() -> str:
    """Take a screenshot and save it as evidence in reports/."""
    async with _get_browser_lock():
        try:
            page = await ensure_browser()
            settings.reports_dir.mkdir(parents=True, exist_ok=True)
            url_slug = re.sub(r"[^\w]", "_", page.url)[:40]
            path = settings.reports_dir / f"screenshot_{url_slug}.png"
            await page.screenshot(path=str(path), full_page=False)
            return f"Screenshot saved: {path} | URL: {page.url}"
        except Exception as e:
            return f"Error taking screenshot: {e}"


@tool
async def search_web(query: str) -> str:
    """Search DuckDuckGo for any query. Returns titles, URLs and snippets."""
    async with _get_browser_lock():
        try:
            await _rate_limit()
            page = await ensure_browser()
            search_url = f"https://duckduckgo.com/?q={url_quote(query)}&ia=web"
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
        except Exception as e:
            return f"Error searching: {e}"
