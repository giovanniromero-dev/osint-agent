"""Unit tests for the reporting module (pure, no network/browser)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import reporting


def test_slugify_basic():
    assert reporting.slugify("Acme Corp!") == "acme_corp"
    assert reporting.slugify("example.com") == "example_com"
    assert reporting.slugify("  multiple   spaces ") == "multiple_spaces"
    assert reporting.slugify("") == "report"


def test_slugify_max_len():
    assert len(reporting.slugify("a" * 200, max_len=10)) == 10


def test_timestamp_format():
    ts = reporting.timestamp()
    assert len(ts) == 15 and "_" in ts  # YYYYMMDD_HHMMSS


def test_save_report_creates_md_only(tmp_path):
    content = "# OSINT Report: test\n\n## Summary\nHello world."
    paths = reporting.save_report("test target", content, reports_dir=tmp_path)
    md = Path(paths["markdown"])
    assert md.exists()
    assert md.suffix == ".md"
    assert md.read_text(encoding="utf-8") == content
    # no HTML file should be created
    assert list(tmp_path.glob("*.html")) == []
