"""Passive IP, ASN, service, and vulnerability intelligence tools."""
from __future__ import annotations

import asyncio
import re

from langchain_core.tools import tool

from config import settings
from http_client import async_get_json


@tool
async def ip_lookup(ip: str) -> str:
    """IP geolocation and ISP info via ip-api.com (free, no key needed)."""
    ip = ip.strip()
    data = await async_get_json(
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
