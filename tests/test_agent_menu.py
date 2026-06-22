"""Tests for agent menu helpers (no network)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent


def test_language_directive():
    assert "Spanish" in agent.language_directive("es")
    assert "English" in agent.language_directive("en")
    assert "English" in agent.language_directive("xx")  # fallback


def test_vuln_prompt_is_defensive():
    p = agent.VULN_SYSTEM_PROMPT.lower()
    assert "defensive" in p
    assert "do not provide exploitation" in p
    assert "{target}" in agent.VULN_SYSTEM_PROMPT
    assert "{language_name}" in agent.VULN_SYSTEM_PROMPT


def test_menu_functions_exist():
    for fn in ("pick_report", "analyze_vulnerabilities", "vuln_analysis",
               "report_qa", "answer_about_report", "list_reports", "ask_language"):
        assert hasattr(agent, fn), fn


def test_list_reports_empty(tmp_path):
    original = agent.settings.reports_dir
    object.__setattr__(agent.settings, "reports_dir", tmp_path)
    try:
        assert agent.list_reports() == []
    finally:
        object.__setattr__(agent.settings, "reports_dir", original)


def test_apply_overrides_preserves_zero_max_steps_for_validation():
    original = agent.settings.max_steps
    args = agent.parse_args(["example.com", "--max-steps", "0"])
    try:
        agent.apply_overrides(args)
        assert agent.settings.max_steps == 0
    finally:
        object.__setattr__(agent.settings, "max_steps", original)


def test_apply_overrides_enables_strict_robots():
    original = agent.settings.robots_fail_closed
    args = agent.parse_args(["example.com", "--strict-robots"])
    try:
        agent.apply_overrides(args)
        assert agent.settings.robots_fail_closed is True
    finally:
        object.__setattr__(agent.settings, "robots_fail_closed", original)
