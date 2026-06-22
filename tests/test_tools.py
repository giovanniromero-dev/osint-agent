"""Unit tests for pure tool logic (no network/browser)."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools
from tools import browser


def _invoke(t, **kwargs):
    """Call a LangChain @tool's underlying function directly."""
    if getattr(t, "func", None) is not None:
        return t.func(**kwargs)
    if getattr(t, "coroutine", None) is not None:
        return asyncio.run(t.coroutine(**kwargs))
    return t.invoke(kwargs)


def test_clean_domain():
    assert tools._clean_domain("https://www.example.com/path") == "example.com"
    assert tools._clean_domain("Example.COM") == "example.com"
    assert tools._clean_domain("sub.example.com/x") == "sub.example.com"


def test_extract_contacts_finds_email():
    out = _invoke(tools.extract_contacts, text="reach me at a@b.com or c@d.org")
    assert "a@b.com" in out
    assert "c@d.org" in out


def test_extract_contacts_none():
    out = _invoke(tools.extract_contacts, text="nothing here")
    assert "No emails" in out


def test_username_enum_rejects_bad_input():
    out = _invoke(tools.username_enum, username="bad name with spaces")
    assert "Refusing" in out


def test_tool_registry_no_duplicates():
    names = [t.name for t in tools.OSINT_TOOLS]
    assert len(names) == len(set(names))


def test_expected_tools_present():
    names = {t.name for t in tools.OSINT_TOOLS}
    for expected in ("github_recon", "username_enum", "http_headers", "robots_sitemap", "reverse_dns"):
        assert expected in names


def test_robots_allows_fail_open_when_unavailable(monkeypatch):
    async def fail_get(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(browser, "async_http_get", fail_get)
    browser._ROBOTS_CACHE.clear()
    original_respect = browser.settings.respect_robots
    original_fail_closed = browser.settings.robots_fail_closed
    try:
        object.__setattr__(browser.settings, "respect_robots", True)
        object.__setattr__(browser.settings, "robots_fail_closed", False)
        assert asyncio.run(browser._robots_allows("https://example.com/private")) is True
    finally:
        object.__setattr__(browser.settings, "respect_robots", original_respect)
        object.__setattr__(browser.settings, "robots_fail_closed", original_fail_closed)
        browser._ROBOTS_CACHE.clear()


def test_robots_allows_fail_closed_when_configured(monkeypatch):
    async def fail_get(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(browser, "async_http_get", fail_get)
    browser._ROBOTS_CACHE.clear()
    original_respect = browser.settings.respect_robots
    original_fail_closed = browser.settings.robots_fail_closed
    try:
        object.__setattr__(browser.settings, "respect_robots", True)
        object.__setattr__(browser.settings, "robots_fail_closed", True)
        assert asyncio.run(browser._robots_allows("https://example.com/private")) is False
    finally:
        object.__setattr__(browser.settings, "respect_robots", original_respect)
        object.__setattr__(browser.settings, "robots_fail_closed", original_fail_closed)
        browser._ROBOTS_CACHE.clear()


def test_navigate_adds_https_for_bare_host(monkeypatch):
    seen = {}

    async def allows(url):
        seen["url"] = url
        return False

    monkeypatch.setattr(browser, "_robots_allows", allows)
    out = _invoke(tools.navigate, url="example.com")
    assert seen["url"] == "https://example.com"
    assert "Blocked by robots.txt" in out
