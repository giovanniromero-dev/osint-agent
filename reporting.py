"""
Report generation for the OSINT Agent.

Takes markdown content produced by the agent and writes a single timestamped
.md file under reports/.
"""
from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path

from config import REPORTS_DIR, get_logger

log = get_logger("osint.reporting")


def slugify(value: str, max_len: int = 60) -> str:
    """Filesystem-safe slug from an arbitrary target string."""
    value = value.strip().lower()
    value = re.sub(r"[^\w\-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value[:max_len] or "report"


def timestamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def save_report(target: str, content: str, *, reports_dir: Path | None = None) -> dict[str, str]:
    """
    Write the markdown report to reports/.

    Returns a dict with the 'markdown' absolute path.
    """
    reports_dir = Path(reports_dir or REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)

    base = f"{slugify(target)}_{timestamp()}"
    md_path = reports_dir / f"{base}.md"
    md_path.write_text(content, encoding="utf-8")

    log.info("Report saved: %s", md_path.name)
    return {"markdown": str(md_path)}
