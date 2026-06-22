"""Domain, DNS, certificate, and subdomain OSINT tools."""
from __future__ import annotations

import asyncio
import socket
import ssl

from langchain_core.tools import tool

from config import settings
from http_client import async_get_json
from .common import _clean_domain


@tool
async def whois_lookup(domain: str) -> str:
    """WHOIS lookup for a domain - registration dates, registrar, name servers, registrant."""
    domain = _clean_domain(domain)
    try:
        import whois

        loop = asyncio.get_running_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
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
    except Exception as e:
        return f"WHOIS error for {domain}: {e}"


@tool
async def dns_lookup(domain: str) -> str:
    """DNS lookup - A, AAAA, MX, NS, TXT records using Google DoH."""
    domain = _clean_domain(domain)

    async def _fetch(rtype: str):
        return rtype, await async_get_json(
            "https://dns.google/resolve",
            params={"name": domain, "type": rtype},
            timeout=settings.http_timeout,
        )

    responses = await asyncio.gather(*[_fetch(t) for t in ("A", "AAAA", "MX", "NS", "TXT")])
    results: list[str] = []
    for rtype, data in responses:
        if data:
            vals = [a["data"] for a in data.get("Answer", []) if "data" in a]
            if vals:
                results.append(f"{rtype}: {', '.join(vals)}")

    try:
        loop = asyncio.get_running_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        results.insert(0, f"Resolved IP: {ip}")
    except Exception:
        pass

    return f"DNS records for {domain}:\n" + ("\n".join(results) if results else "No records found.")


@tool
async def reverse_dns(ip: str) -> str:
    """Reverse DNS (PTR) lookup - find the hostname associated with an IP address."""
    ip = ip.strip()
    try:
        loop = asyncio.get_running_loop()
        host, aliases, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        names = [host] + [a for a in aliases if a != host]
        return f"Reverse DNS for {ip}:\n" + "\n".join(names)
    except Exception as e:
        return f"No PTR record for {ip} ({e})"


@tool
async def cert_lookup(domain: str) -> str:
    """
    Certificate Transparency lookup via crt.sh.
    Reveals subdomains registered in SSL certificates - no API key needed.
    """
    domain = _clean_domain(domain)
    entries = await async_get_json(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
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
    except Exception as e:
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
