"""Public tool registry for the OSINT agent."""
from __future__ import annotations

from config import settings
from http_client import async_get_json, async_http_get

from .archive import wayback_lookup, wayback_snapshots
from .browser import (
    _ROBOTS_CACHE,
    _robots_allows,
    close_browser,
    get_links,
    get_text,
    navigate,
    screenshot,
    search_web,
)
from .common import _clean_domain
from .control import finish, save_report
from .dns import (
    _SUBDOMAIN_WORDS,
    cert_lookup,
    dns_lookup,
    reverse_dns,
    ssl_cert_info,
    subdomain_bruteforce,
    whois_lookup,
)
from .identity import (
    email_validate,
    extract_contacts,
    github_recon,
    gravatar_lookup,
    username_enum,
)
from .passive_security import asn_lookup, ip_lookup, port_scan_passive
from .web import extract_metadata, http_headers, robots_sitemap

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

OSINT_TOOLS = [
    navigate,
    get_text,
    get_links,
    screenshot,
    search_web,
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
    finish,
] + EXTRA_TOOLS

__all__ = [
    "EXTRA_TOOLS",
    "OSINT_TOOLS",
    "_ROBOTS_CACHE",
    "_SUBDOMAIN_WORDS",
    "_clean_domain",
    "_robots_allows",
    "asn_lookup",
    "async_get_json",
    "async_http_get",
    "cert_lookup",
    "close_browser",
    "dns_lookup",
    "email_validate",
    "extract_contacts",
    "extract_metadata",
    "finish",
    "get_links",
    "get_text",
    "github_recon",
    "gravatar_lookup",
    "http_headers",
    "ip_lookup",
    "navigate",
    "port_scan_passive",
    "reverse_dns",
    "robots_sitemap",
    "save_report",
    "screenshot",
    "search_web",
    "settings",
    "ssl_cert_info",
    "subdomain_bruteforce",
    "username_enum",
    "wayback_lookup",
    "wayback_snapshots",
    "whois_lookup",
]
