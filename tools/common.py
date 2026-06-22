"""Shared helpers for OSINT tools."""
from __future__ import annotations

from urllib.parse import urlparse


def _clean_domain(value: str) -> str:
    """Normalize a domain or URL into a bare hostname."""
    value = value.strip()
    if "://" in value:
        value = urlparse(value).netloc or value
    value = value.split("/")[0].strip().lower()
    if value.startswith("www."):
        value = value[4:]
    return value
