"""
Shared HTTP client with a reusable session, sane defaults and retries.

Every network helper in tools.py should use http_get() instead of calling
requests directly, so timeouts, retries and the User-Agent are consistent.
"""
from __future__ import annotations

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
    """GET with shared session, default timeout and logging."""
    timeout = timeout or settings.http_timeout
    log.debug("GET %s", url)
    resp = get_session().get(url, timeout=timeout, **kwargs)
    return resp


def get_json(url: str, *, timeout: int | None = None, **kwargs):
    """GET and parse JSON, returning None on any failure."""
    try:
        resp = http_get(url, timeout=timeout, **kwargs)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # noqa: BLE001 - helpers should never raise
        log.warning("get_json failed for %s: %s", url, exc)
        return None
