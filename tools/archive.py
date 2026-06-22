"""Wayback Machine OSINT tools."""
from __future__ import annotations

from langchain_core.tools import tool

from http_client import async_get_json


@tool
async def wayback_lookup(url: str) -> str:
    """Check if a URL has archived versions in the Wayback Machine."""
    data = await async_get_json(f"https://archive.org/wayback/available?url={url}", timeout=8)
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
