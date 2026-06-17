"""Unit tests for pure tool logic (no network/browser)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools


def _invoke(t, **kwargs):
    """Call a LangChain @tool's underlying function directly."""
    return t.func(**kwargs) if hasattr(t, "func") else t.invoke(kwargs)


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
