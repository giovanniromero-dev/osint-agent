"""Identity, social, email, and contact OSINT tools."""
from __future__ import annotations

import asyncio
import hashlib
import re

from langchain_core.tools import tool

from config import settings
from http_client import async_get_json, async_http_get


@tool
async def github_recon(username: str) -> str:
    """
    Look up a GitHub user or organization via the public API (no key).
    Returns profile info plus their most recently updated public repositories.
    """
    username = username.strip().lstrip("@")
    user, repos = await asyncio.gather(
        async_get_json(f"https://api.github.com/users/{username}", timeout=settings.http_timeout),
        async_get_json(
            f"https://api.github.com/users/{username}/repos",
            params={"sort": "updated", "per_page": 10},
            timeout=settings.http_timeout,
        ),
    )
    if not user or "login" not in user:
        return f"No public GitHub account found for '{username}'."

    profile_fields = [
        ("login", user.get("login")), ("name", user.get("name")),
        ("type", user.get("type")), ("company", user.get("company")),
        ("location", user.get("location")), ("blog", user.get("blog")),
        ("email", user.get("email")), ("bio", user.get("bio")),
        ("public_repos", user.get("public_repos")), ("followers", user.get("followers")),
        ("created_at", user.get("created_at")), ("profile", user.get("html_url")),
    ]
    lines = [f"{k}: {v}" for k, v in profile_fields if v is not None]

    if isinstance(repos, list) and repos:
        lines.append("\nTop repositories (recently updated):")
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
async def username_enum(username: str) -> str:
    """
    Check whether a username exists on common public platforms.
    All platforms are probed in parallel for speed.
    """
    username = username.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._\-]{1,40}", username):
        return f"Refusing to probe unusual username '{username}'."

    async def _check(site: str, tmpl: str) -> tuple[str, str, int | None, str]:
        url = tmpl.format(u=username)
        try:
            resp = await async_http_get(url, timeout=8, allow_redirects=True)
            return site, url, resp.status_code, ""
        except Exception as e:
            return site, url, None, str(e)

    checks = await asyncio.gather(*[_check(s, t) for s, t in _USERNAME_SITES.items()])

    found, missing, errors = [], [], []
    for site, url, code, err in checks:
        if code == 200:
            found.append(f"  [FOUND]       {site}: {url}")
        elif code in (404, 410):
            missing.append(site)
        elif err:
            errors.append(f"  [error]       {site}: {err}")
        else:
            errors.append(f"  [HTTP {code}]  {site}: {url}")

    out = [f"Username enumeration for '{username}':"]
    if found:
        out.append("Likely present:\n" + "\n".join(found))
    if errors:
        out.append("Inconclusive:\n" + "\n".join(errors))
    if missing:
        out.append("Not found: " + ", ".join(missing))
    return "\n".join(out)


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
    except Exception as e:
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
