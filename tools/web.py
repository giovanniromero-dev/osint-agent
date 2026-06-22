"""Static web-fetch OSINT tools."""
from __future__ import annotations

import re

from langchain_core.tools import tool

from config import settings
from http_client import async_http_get
from .common import _clean_domain


@tool
async def http_headers(url: str) -> str:
    """Fetch HTTP response headers for a URL and fingerprint server/tech where possible."""
    if "://" not in url:
        url = "https://" + url
    try:
        resp = await async_http_get(url, timeout=settings.http_timeout, allow_redirects=True)
        interesting = [
            "server", "x-powered-by", "via", "x-aspnet-version", "x-generator",
            "content-type", "set-cookie", "strict-transport-security",
            "content-security-policy", "x-frame-options",
        ]
        lines = [f"Status: {resp.status_code}", f"Final URL: {resp.url}"]
        for h in interesting:
            if h in resp.headers:
                lines.append(f"{h}: {resp.headers[h][:200]}")
        return f"HTTP headers for {url}:\n" + "\n".join(lines)
    except Exception as e:
        return f"http_headers error for {url}: {e}"


@tool
async def robots_sitemap(domain: str) -> str:
    """Fetch robots.txt and list sitemap URLs / disallowed paths for a domain."""
    domain = _clean_domain(domain)
    base = f"https://{domain}"
    out: list[str] = []
    try:
        resp = await async_http_get(f"{base}/robots.txt", timeout=settings.http_timeout)
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
    except Exception as e:
        out.append(f"robots.txt error: {e}")
    return "\n".join(out)


@tool
async def extract_metadata(url: str) -> str:
    """
    Fetch a page and extract metadata: <title>, meta description, Open Graph
    tags, generator, author and favicon. Static fetch (no JS execution).
    """
    if "://" not in url:
        url = "https://" + url
    try:
        resp = await async_http_get(url, timeout=settings.http_timeout, allow_redirects=True)
        html = resp.text
    except Exception as e:
        return f"extract_metadata error for {url}: {e}"

    lines = [f"url: {resp.url}"]
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if title:
        lines.append(f"title: {title.group(1).strip()[:200]}")

    for prop in ("description", "author", "generator"):
        m = re.search(
            rf'<meta[^>]+name=["\']{prop}["\'][^>]+content=["\'](.*?)["\']',
            html,
            re.I | re.S,
        )
        if m:
            lines.append(f"{prop}: {m.group(1).strip()[:200]}")

    og = re.findall(
        r'<meta[^>]+property=["\']og:([\w:]+)["\'][^>]+content=["\'](.*?)["\']',
        html,
        re.I | re.S,
    )
    for name, content in og[:10]:
        lines.append(f"og:{name}: {content.strip()[:160]}")

    fav = re.search(
        r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\'](.*?)["\']',
        html,
        re.I,
    )
    if fav:
        lines.append(f"favicon: {fav.group(1).strip()}")

    return "Page metadata:\n" + "\n".join(lines)
