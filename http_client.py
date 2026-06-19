"""
Shared HTTP client with a reusable session, sane defaults and retries.

Sync: http_get() / get_json()  — for simple helpers
Async: async_http_get() / async_get_json() — for async tools (run in executor)
"""
from __future__ import annotations

import asyncio

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover - very old urllib3
    Retry = None

from config import get_logger, settings

log = get_logger("osint.http")

_session: requests.Session | None = None


def get_session() -> requests.Session:
    """Return a process-wide session with retry/backoff configured."""
    global _session
    if _session is not None:
        return _session

    session = requests.Session()
    session.headers.update({"User-Agent": settings.user_agent})

    if Retry is not None:
        retry = Retry(
            total=settings.http_retries,
            backoff_factor=settings.http_backoff,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

    _session = session
    return session


def http_get(url: str, *, timeout: int | None = None, **kwargs) -> requests.Response:
    """Synchronous GET with shared session, default timeout and logging."""
    timeout = timeout or settings.http_timeout
    log.debug("GET %s", url)
    return get_session().get(url, timeout=timeout, **kwargs)


def get_json(url: str, *, timeout: int | None = None, **kwargs):
    """Synchronous GET and parse JSON, returning None on any failure."""
    try:
        resp = http_get(url, timeout=timeout, **kwargs)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("get_json failed for %s: %s", url, exc)
        return None


# ── Async wrappers ─────────────────────────────────────────────────────────────

async def async_http_get(url: str, *, timeout: int | None = None, **kwargs) -> requests.Response:
    """Non-blocking GET — runs http_get in a thread-pool executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: http_get(url, timeout=timeout, **kwargs))


async def async_get_json(url: str, *, timeout: int | None = None, **kwargs):
    """Non-blocking GET + JSON parse — runs get_json in a thread-pool executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: get_json(url, timeout=timeout, **kwargs))
