"""
Additional OSINT tools - all use public sources and require no API key.

Sources: BGPView (ASN), Shodan InternetDB (passive ports/CVEs),
Gravatar, Google DoH (subdomain checks), live TLS socket, page metadata.

All tools are async — network I/O runs in executor or with asyncio.gather.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import ssl
from urllib.parse import urlparse

from langchain_core.tools import tool

from config import get_logger, settings
from http_client import async_get_json, async_http_get

log = get_logger("osint.extra")


def _clean_domain(value: str) -> str:
    """Normalize a domain or URL into a bare hostname."""
    value = value.strip()
    if "://" in value:
        value = urlparse(value).netloc or value
    value = value.split("/")[0].strip().lower()
    if value.startswith("www."):
        value = value[4:]
    return value


@tool
async def ssl_cert_info(domain: str) -> str:
    """
    Inspect the live TLS certificate of a domain (port 443).
    Returns issuer, subject, validity dates and Subject Alternative Names.
    """
    domain = _clean_domain(domain)
    try:
        loop = asyncio.get_running_loop()

        def _get_cert():
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=settings.http_timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()

        cert = await loop.run_in_executor(None, _get_cert)
    except Exception as e:  # noqa: BLE001
        return f"ssl_cert_info error for {domain}: {e}"

    def _join(seq):
        return ", ".join(v for pair in seq for (k, v) in pair)

    issuer = _join(cert.get("issuer", []))
    subject = _join(cert.get("subject", []))
    sans = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]
    lines = [
        f"subject: {subject}",
        f"issuer: {issuer}",
        f"valid_from: {cert.get('notBefore')}",
        f"valid_until: {cert.get('notAfter')}",
        f"serial: {cert.get('serialNumber')}",
    ]
    if sans:
        lines.append(f"alt_names ({len(sans)}): " + ", ".join(sans[:30]))
    return f"TLS certificate for {domain}:\n" + "\n".join(lines)


@tool
async def asn_lookup(asn: str) -> str:
    """
    Look up an Autonomous System (ASN) via BGPView - org name and announced
    IP prefixes. Accepts 'AS15169' or '15169'.
    """
    num = re.sub(r"[^0-9]", "", asn)
    if not num:
        return f"Invalid ASN: {asn}"

    data, prefixes = await asyncio.gather(
        async_get_json(f"https://api.bgpview.io/asn/{num}", timeout=settings.http_timeout),
        async_get_json(f"https://api.bgpview.io/asn/{num}/prefixes", timeout=settings.http_timeout),
    )

    if not data or data.get("status") != "ok":
        return f"No data for AS{num}."
    d = data.get("data", {})
    lines = [
        f"asn: AS{num}",
        f"name: {d.get('name')}",
        f"description: {d.get('description_short')}",
        f"country: {d.get('country_code')}",
        f"website: {d.get('website')}",
    ]
    lines = [ln for ln in lines if not ln.endswith(": None")]

    if prefixes and prefixes.get("status") == "ok":
        v4 = prefixes.get("data", {}).get("ipv4_prefixes", [])
        if v4:
            lines.append(f"\nIPv4 prefixes ({len(v4)}):")
            for p in v4[:25]:
                lines.append(f"  {p.get('prefix')} ({p.get('name') or ''})")
    return f"ASN lookup for AS{num}:\n" + "\n".join(lines)


@tool
async def port_scan_passive(ip: str) -> str:
    """
    Passive port / service / CVE lookup via Shodan InternetDB (free, no key).
    Does NOT scan the target - returns data Shodan already collected.
    """
    ip = ip.strip()
    data = await async_get_json(f"https://internetdb.shodan.io/{ip}", timeout=settings.http_timeout)
    if not data:
        return f"No InternetDB data for {ip} (or host not indexed)."
    if data.get("detail"):
        return f"InternetDB: {data['detail']} ({ip})"
    lines = []
    if data.get("ports"):
        lines.append("open ports: " + ", ".join(str(p) for p in data["ports"]))
    if data.get("hostnames"):
        lines.append("hostnames: " + ", ".join(data["hostnames"]))
    if data.get("cpes"):
        lines.append("cpes: " + ", ".join(data["cpes"][:15]))
    if data.get("vulns"):
        lines.append("known vulns (CVE): " + ", ".join(data["vulns"][:30]))
    if data.get("tags"):
        lines.append("tags: " + ", ".join(data["tags"]))
    return f"Passive port/service data for {ip}:\n" + ("\n".join(lines) if lines else "No exposed services indexed.")


@tool
async def email_validate(email: str) -> str:
    """
    Validate an email: check syntax and whether the domain has MX records.
    Does NOT send any email or verify the mailbox exists.
    """
    email = email.strip()
    if not re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", email):
        return f"Invalid email syntax: {email}"
    domain = email.rsplit("@", 1)[1].lower()
    data = await async_get_json(
        "https://dns.google/resolve",
        params={"name": domain, "type": "MX"},
        timeout=settings.http_timeout,
    )
    mx = [a["data"] for a in (data.get("Answer", []) if data else []) if "data" in a]
    lines = [f"email: {email}", "syntax: valid", f"domain: {domain}"]
    if mx:
        lines.append(f"mx_records ({len(mx)}): " + ", ".join(mx[:10]))
        lines.append("deliverable_domain: likely (has MX)")
    else:
        lines.append("deliverable_domain: no MX records found")
    return "Email validation:\n" + "\n".join(lines)


@tool
async def gravatar_lookup(email: str) -> str:
    """
    Check whether an email has a public Gravatar profile (avatar / identity).
    Uses the MD5 hash of the email as Gravatar's public API expects.
    """
    email = email.strip().lower()
    if "@" not in email:
        return f"Invalid email: {email}"
    h = hashlib.md5(email.encode("utf-8")).hexdigest()
    avatar_url = f"https://www.gravatar.com/avatar/{h}?d=404"
    profile_url = f"https://www.gravatar.com/{h}.json"

    try:
        avatar_resp, profile_data = await asyncio.gather(
            async_http_get(avatar_url, timeout=settings.http_timeout),
            async_get_json(profile_url, timeout=settings.http_timeout),
        )
    except Exception as e:  # noqa: BLE001
        return f"Gravatar lookup error for {email}: {e}"

    has_avatar = avatar_resp is not None and avatar_resp.status_code == 200
    lines = [f"email: {email}", f"hash: {h}", f"has_avatar: {has_avatar}"]
    if has_avatar:
        lines.append(f"avatar_url: https://www.gravatar.com/avatar/{h}")
    if isinstance(profile_data, dict) and profile_data.get("entry"):
        entry = profile_data["entry"][0]
        if entry.get("displayName"):
            lines.append(f"display_name: {entry['displayName']}")
        if entry.get("aboutMe"):
            lines.append(f"about: {entry['aboutMe'][:200]}")
        accounts = entry.get("accounts", [])
        if accounts:
            lines.append("linked_accounts: " + ", ".join(
                f"{a.get('shortname')}:{a.get('url')}" for a in accounts[:10]
            ))
    return "Gravatar lookup:\n" + "\n".join(lines)


_SUBDOMAIN_WORDS = [
    "www", "mail", "smtp", "imap", "pop", "webmail", "ns1", "ns2", "dns",
    "vpn", "remote", "portal", "admin", "dev", "staging", "test", "api",
    "app", "blog", "shop", "store", "cdn", "static", "assets", "img",
    "git", "gitlab", "jenkins", "ci", "docs", "support", "help", "status",
    "dashboard", "secure", "login", "auth", "sso", "cloud", "ftp", "db",
]


@tool
async def subdomain_bruteforce(domain: str) -> str:
    """
    Discover live subdomains by resolving common labels via DNS (Google DoH).
    All labels are checked in parallel for speed.
    """
    domain = _clean_domain(domain)

    async def _check(word: str) -> str | None:
        host = f"{word}.{domain}"
        data = await async_get_json(
            "https://dns.google/resolve",
            params={"name": host, "type": "A"},
            timeout=6,
        )
        if data and data.get("Answer"):
            ips = [a["data"] for a in data["Answer"] if a.get("type") == 1]
            if ips:
                return f"  {host} -> {', '.join(ips)}"
        return None

    results = await asyncio.gather(*[_check(w) for w in _SUBDOMAIN_WORDS])
    found = [r for r in results if r]
    if not found:
        return f"No common subdomains resolved for {domain}."
    return f"Resolved subdomains for {domain} ({len(found)}):\n" + "\n".join(found)


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
    except Exception as e:  # noqa: BLE001
        return f"extract_metadata error for {url}: {e}"

    lines = [f"url: {resp.url}"]
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if title:
        lines.append(f"title: {title.group(1).strip()[:200]}")

    for prop in ("description", "author", "generator"):
        m = re.search(
            rf'<meta[^>]+name=["\']{prop}["\'][^>]+content=["\'](.*?)["\']',
            html, re.I | re.S,
        )
        if m:
            lines.append(f"{prop}: {m.group(1).strip()[:200]}")

    og = re.findall(
        r'<meta[^>]+property=["\']og:([\w:]+)["\'][^>]+content=["\'](.*?)["\']',
        html, re.I | re.S,
    )
    for name, content in og[:10]:
        lines.append(f"og:{name}: {content.strip()[:160]}")

    fav = re.search(
        r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\'](.*?)["\']',
        html, re.I,
    )
    if fav:
        lines.append(f"favicon: {fav.group(1).strip()}")

    return "Page metadata:\n" + "\n".join(lines)


@tool
async def wayback_snapshots(url: str) -> str:
    """
    List multiple historical Wayback Machine snapshots for a URL (first and
    most recent captures, plus a yearly sample) using the CDX API.
    """
    data = await async_get_json(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": url,
            "output": "json",
            "fl": "timestamp,statuscode,original",
            "collapse": "timestamp:4",
            "limit": "200",
        },
        timeout=15,
    )
    if not data or len(data) <= 1:
        return f"No Wayback snapshots found for {url}."
    rows = data[1:]
    seen_years: set[str] = set()
    yearly: list[tuple[str, str]] = []
    for ts, code, orig in rows:
        year = ts[:4]
        if year not in seen_years:
            seen_years.add(year)
            yearly.append((ts, code))
    lines = [
        f"total snapshots (approx, yearly-collapsed): {len(rows)}",
        f"first: {rows[0][0]}  last: {rows[-1][0]}",
        "years captured: " + ", ".join(sorted(seen_years)),
        "sample snapshot URLs:",
    ]
    for ts, code in yearly[:12]:
        lines.append(f"  https://web.archive.org/web/{ts}/{url}  (HTTP {code})")
    return f"Wayback snapshots for {url}:\n" + "\n".join(lines)


EXTRA_TOOLS = [
    ssl_cert_info,
    asn_lookup,
    port_scan_passive,
    email_validate,
    gravatar_lookup,
    subdomain_bruteforce,
    extract_metadata,
    wayback_snapshots,
]
