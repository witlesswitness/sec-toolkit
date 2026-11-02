"""Shared HTTP helper: one session, consistent timeout, uniform error surfacing."""
from __future__ import annotations

import requests

_session: requests.Session | None = None


def _clean_err(exc: Exception) -> str:
    """Condense verbose requests/urllib3 exceptions into a short, readable reason."""
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "connection timed out"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "read timed out"
    if isinstance(exc, requests.exceptions.ProxyError):
        return "network unreachable (proxy refused)"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection failed / host unreachable"
    if isinstance(exc, requests.exceptions.HTTPError):
        code = getattr(getattr(exc, "response", None), "status_code", "?")
        return f"HTTP {code}"
    return str(exc)[:120]


def session(user_agent: str) -> requests.Session:
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({"User-Agent": user_agent, "Accept": "application/json"})
    return _session


def get_json(url: str, cfg, *, headers: dict | None = None, params: dict | None = None):
    """GET and return (json_or_None, status_code, error_str). Never raises."""
    try:
        r = session(cfg.user_agent).get(
            url, headers=headers, params=params, timeout=cfg.http_timeout
        )
        if r.status_code == 404:
            return None, 404, None
        r.raise_for_status()
        return r.json(), r.status_code, None
    except requests.RequestException as exc:
        return None, getattr(getattr(exc, "response", None), "status_code", None), _clean_err(exc)
    except ValueError as exc:  # JSON decode
        return None, None, f"invalid JSON: {exc}"


def post_json(url: str, cfg, *, json_body=None, data=None, headers: dict | None = None):
    try:
        r = session(cfg.user_agent).post(
            url, json=json_body, data=data, headers=headers, timeout=cfg.http_timeout
        )
        r.raise_for_status()
        return r.json(), r.status_code, None
    except requests.RequestException as exc:
        return None, getattr(getattr(exc, "response", None), "status_code", None), _clean_err(exc)
    except ValueError as exc:
        return None, None, f"invalid JSON: {exc}"


def get_text(url: str, cfg, *, headers: dict | None = None):
    try:
        r = session(cfg.user_agent).get(url, headers=headers, timeout=cfg.http_timeout)
        r.raise_for_status()
        return r.text, r.status_code, None
    except requests.RequestException as exc:
        return None, getattr(getattr(exc, "response", None), "status_code", None), _clean_err(exc)
