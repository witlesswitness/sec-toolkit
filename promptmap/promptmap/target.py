"""The target under test: a configurable HTTP endpoint.

You describe your LLM app's HTTP API in a small JSON config, and promptmap sends each
attack prompt through it and reads back the model's reply. Example config:

{
  "url": "https://myapp.example.com/api/chat",
  "method": "POST",
  "headers": {"Authorization": "Bearer ${MYAPP_TOKEN}", "Content-Type": "application/json"},
  "body_template": {"messages": [{"role": "user", "content": "{{prompt}}"}]},
  "response_path": "choices.0.message.content",
  "timeout": 30
}

Notes:
  * {{prompt}}  in body_template is replaced with the attack text.
  * {{canary}}  (optional) is replaced with the run's canary secret — put it in a
    system-prompt field if your API lets you set one, so exfiltration tests have
    something real to try to extract.
  * ${ENVVAR}   anywhere in headers/url is expanded from the environment, so secrets
    stay out of the config file.
  * response_path is a dotted path into the JSON response ("a.b.0.c"). Omit it to use
    the whole response body as text.
"""
from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass

import requests

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: str) -> str:
    def repl(m):
        return os.environ.get(m.group(1), "")
    return _ENV_RE.sub(repl, value)


def _deep_expand(obj):
    if isinstance(obj, str):
        return _expand_env(obj)
    if isinstance(obj, dict):
        return {k: _deep_expand(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_expand(v) for v in obj]
    return obj


def _fill_placeholders(obj, prompt: str, canary: str):
    """Replace {{prompt}} and {{canary}} inside any string in the structure."""
    if isinstance(obj, str):
        return obj.replace("{{prompt}}", prompt).replace("{{canary}}", canary)
    if isinstance(obj, dict):
        return {k: _fill_placeholders(v, prompt, canary) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill_placeholders(v, prompt, canary) for v in obj]
    return obj


def _dig(data, path: str):
    if not path:
        return data
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


@dataclass
class TargetConfig:
    url: str
    method: str = "POST"
    headers: dict | None = None
    body_template: object = None
    response_path: str = ""
    timeout: int = 30

    @classmethod
    def from_file(cls, path: str) -> "TargetConfig":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return cls(
            url=raw["url"],
            method=raw.get("method", "POST"),
            headers=raw.get("headers") or {},
            body_template=raw.get("body_template"),
            response_path=raw.get("response_path", ""),
            timeout=int(raw.get("timeout", 30)),
        )


class HttpTarget:
    """Sends a prompt to the configured endpoint and returns the model's reply text."""

    def __init__(self, cfg: TargetConfig):
        self.cfg = cfg
        self._session = requests.Session()

    def send(self, prompt: str, canary: str = "") -> tuple[str | None, str | None]:
        """Return (reply_text, error). Never raises."""
        url = _expand_env(self.cfg.url)
        headers = _deep_expand(self.cfg.headers or {})
        body = _fill_placeholders(copy.deepcopy(self.cfg.body_template), prompt, canary)
        body = _deep_expand(body)
        try:
            if self.cfg.method.upper() == "GET":
                r = self._session.get(url, headers=headers, params=body, timeout=self.cfg.timeout)
            else:
                r = self._session.request(
                    self.cfg.method.upper(), url, headers=headers, json=body, timeout=self.cfg.timeout
                )
            r.raise_for_status()
        except requests.RequestException as exc:
            return None, str(exc)[:200]

        # Try JSON + response_path; fall back to raw text.
        try:
            data = r.json()
            extracted = _dig(data, self.cfg.response_path)
            if extracted is None:
                return (json.dumps(data) if not self.cfg.response_path else None,
                        None if not self.cfg.response_path else f"response_path '{self.cfg.response_path}' not found")
            return (extracted if isinstance(extracted, str) else json.dumps(extracted)), None
        except ValueError:
            return r.text, None


EXAMPLE_CONFIG = {
    "url": "https://myapp.example.com/api/chat",
    "method": "POST",
    "headers": {
        "Authorization": "Bearer ${MYAPP_TOKEN}",
        "Content-Type": "application/json",
    },
    "body_template": {
        "messages": [
            {"role": "system", "content": "You are a helpful assistant. Secret: {{canary}}"},
            {"role": "user", "content": "{{prompt}}"},
        ]
    },
    "response_path": "choices.0.message.content",
    "timeout": 30,
}
