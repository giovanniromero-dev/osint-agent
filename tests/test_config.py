"""Unit tests for config loading."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config


def test_settings_load_defaults():
    s = config.Settings.load()
    assert s.deepseek_model
    assert s.max_steps > 0
    assert s.http_retries >= 0


def test_validate_flags_missing_key():
    s = config.Settings(deepseek_api_key=None)
    problems = s.validate()
    assert any("DEEPSEEK_API_KEY" in p for p in problems)


def test_validate_ok_with_key():
    s = config.Settings(deepseek_api_key="x")
    assert s.validate() == []


def test_validate_rejects_invalid_runtime_limits():
    s = config.Settings(
        deepseek_api_key="x",
        max_steps=0,
        recursion_limit=0,
        nav_timeout_ms=0,
        search_timeout_ms=0,
        http_timeout=0,
        http_retries=-1,
        http_backoff=-1,
        request_delay=-1,
    )
    problems = "\n".join(s.validate())
    assert "OSINT_MAX_STEPS" in problems
    assert "OSINT_RECURSION_LIMIT" in problems
    assert "OSINT_NAV_TIMEOUT_MS" in problems
    assert "OSINT_SEARCH_TIMEOUT_MS" in problems
    assert "OSINT_HTTP_TIMEOUT" in problems
    assert "OSINT_HTTP_RETRIES" in problems
    assert "OSINT_HTTP_BACKOFF" in problems
    assert "OSINT_REQUEST_DELAY" in problems


def test_get_logger_returns_logger():
    log = config.get_logger("test")
    assert log.name == "test"
