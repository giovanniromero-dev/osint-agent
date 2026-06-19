"""
Central configuration and logging for the OSINT Agent.

All tunables live here so the rest of the codebase never reads os.getenv
directly. Values come from environment variables (optionally loaded from a
.env file) with sane defaults.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ── Paths ────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
CHROME_PROFILE_DIR = BASE_DIR / "chrome_profile"


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    """Runtime configuration. Immutable; build once with Settings.load()."""

    # LLM
    deepseek_api_key: str | None = None
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com"
    temperature: float = 0.0

    # Agent loop
    max_steps: int = 50
    recursion_limit: int = 200

    # Browser
    headless: bool = False
    nav_timeout_ms: int = 30000
    search_timeout_ms: int = 20000

    # Responsible-use controls
    # Stealth (anti-bot fingerprint spoofing) is OFF by default. Only enable it
    # for sources you are authorized to test; it can violate sites' Terms of
    # Service. When off, the agent identifies itself honestly and behaves politely.
    stealth: bool = False
    respect_robots: bool = True
    request_delay: float = 1.0  # seconds to wait between page navigations

    # HTTP (network helpers)
    http_timeout: int = 10
    http_retries: int = 3
    http_backoff: float = 0.6
    # Honest, identifiable User-Agent used by default. Stealth mode swaps in a
    # browser-like UA (see tools.py).
    user_agent: str = (
        "osint-agent/1.0 (+https://github.com/giovanniromero-dev/osint-agent)"
    )

    # Logging
    log_level: str = "INFO"

    # Derived paths (not from env)
    reports_dir: Path = field(default=REPORTS_DIR)
    chrome_profile_dir: Path = field(default=CHROME_PROFILE_DIR)

    @classmethod
    def load(cls) -> "Settings":
        return cls(
            deepseek_api_key=os.getenv("DEEPSEEK_API_KEY"),
            deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            temperature=float(os.getenv("DEEPSEEK_TEMPERATURE", "0") or 0),
            max_steps=_get_int("OSINT_MAX_STEPS", 50),
            recursion_limit=_get_int("OSINT_RECURSION_LIMIT", 200),
            headless=_get_bool("OSINT_HEADLESS", False),
            nav_timeout_ms=_get_int("OSINT_NAV_TIMEOUT_MS", 30000),
            search_timeout_ms=_get_int("OSINT_SEARCH_TIMEOUT_MS", 20000),
            stealth=_get_bool("OSINT_STEALTH", False),
            respect_robots=_get_bool("OSINT_RESPECT_ROBOTS", True),
            request_delay=float(os.getenv("OSINT_REQUEST_DELAY", "1.0") or 1.0),
            http_timeout=_get_int("OSINT_HTTP_TIMEOUT", 10),
            http_retries=_get_int("OSINT_HTTP_RETRIES", 3),
            http_backoff=float(os.getenv("OSINT_HTTP_BACKOFF", "0.6") or 0.6),
            user_agent=os.getenv(
                "OSINT_USER_AGENT",
                "osint-agent/1.0 (+https://github.com/giovanniromero-dev/osint-agent)",
            ),
            log_level=os.getenv("OSINT_LOG_LEVEL", "INFO").upper(),
        )

    def validate(self) -> list[str]:
        """Return a list of human-readable problems (empty == OK)."""
        problems = []
        if not self.deepseek_api_key:
            problems.append(
                "DEEPSEEK_API_KEY is not set. Create a .env file with "
                "DEEPSEEK_API_KEY=your_key (see README)."
            )
        return problems


# Module-level singleton — import this everywhere.
settings = Settings.load()


# ── Logging ──────────────────────────────────────────────────────────────────

_CONFIGURED = False


def setup_logging(level: str | None = None) -> None:
    """Configure root logging once. Safe to call multiple times."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(
        level=getattr(logging, (level or settings.log_level), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet down noisy third-party loggers.
    for noisy in ("httpx", "urllib3", "playwright", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)
