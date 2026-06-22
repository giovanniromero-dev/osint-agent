"""Control and reporting tools used by the agent loop."""
from __future__ import annotations

from langchain_core.tools import tool

import reporting


@tool
def save_report(filename: str, content: str) -> str:
    """
    Save investigation findings as a timestamped markdown (.md) report in reports/.

    filename: short target name without extension (e.g. 'acme_corp')
    content: full markdown content to save
    """
    try:
        paths = reporting.save_report(filename, content)
        return f"Report saved: {paths['markdown']}"
    except Exception as e:
        return f"save_report error: {e}"


@tool
def finish(summary: str) -> str:
    """Call when the investigation is complete. summary: findings for the user."""
    return f"TASK_COMPLETE: {summary}"
