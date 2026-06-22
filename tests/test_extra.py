"""Unit tests for osint_extra pure logic (no live network needed)."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import osint_extra


def _invoke(t, **kwargs):
    if getattr(t, "func", None) is not None:
        return t.func(**kwargs)
    if getattr(t, "coroutine", None) is not None:
        return asyncio.run(t.coroutine(**kwargs))
    return t.invoke(kwargs)


def test_clean_domain():
    assert osint_extra._clean_domain("https://www.Example.com/x") == "example.com"


def test_email_validate_rejects_bad_syntax():
    out = _invoke(osint_extra.email_validate, email="not-an-email")
    assert "Invalid email syntax" in out


def test_gravatar_rejects_non_email():
    out = _invoke(osint_extra.gravatar_lookup, email="nope")
    assert "Invalid email" in out


def test_asn_lookup_rejects_non_numeric():
    out = _invoke(osint_extra.asn_lookup, asn="ASxyz")
    assert "Invalid ASN" in out


def test_extra_tools_registered():
    names = {t.name for t in osint_extra.EXTRA_TOOLS}
    expected = {
        "ssl_cert_info", "asn_lookup", "port_scan_passive", "email_validate",
        "gravatar_lookup", "subdomain_bruteforce", "extract_metadata", "wayback_snapshots",
    }
    assert expected <= names


def test_subdomain_wordlist_nonempty():
    assert len(osint_extra._SUBDOMAIN_WORDS) > 10


def test_full_registry_count_and_unique():
    import tools
    names = [t.name for t in tools.OSINT_TOOLS]
    assert len(names) == len(set(names))   # no duplicates
    assert len(names) == 26                  # 18 original + 8 new
