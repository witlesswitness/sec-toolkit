"""Transcript model + loader.

A trace is a JSON file describing one agent run. Flexible shape — the loader
normalizes a few common layouts into a list of Steps. Accepted input:

  {
    "task": "optional description of the agent's assigned task",
    "steps": [
      {"type": "reasoning", "content": "the model's chain-of-thought for this step"},
      {"type": "tool_call", "tool": "http_get", "input": {"url": "..."}, "output": "..."},
      {"type": "message", "role": "assistant", "content": "..."}
    ]
  }

Also accepted: a bare JSON list of steps, or a list of {role, content} chat messages
(tool calls expressed as content are still scanned textually).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Step:
    index: int
    kind: str                 # "reasoning" | "tool_call" | "message" | "other"
    tool: str = ""
    role: str = ""
    text: str = ""            # reasoning/message text
    tool_input: str = ""      # stringified tool input
    tool_output: str = ""     # stringified tool output
    raw: dict = field(default_factory=dict)

    @property
    def searchable(self) -> str:
        return " ".join(x for x in (self.text, self.tool, self.tool_input, self.tool_output) if x)


@dataclass
class Trace:
    task: str
    steps: list[Step]


def _stringify(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return str(v)


def _normalize_step(i: int, s: dict) -> Step:
    kind = (s.get("type") or s.get("kind") or "").lower()
    tool = s.get("tool") or s.get("name") or s.get("tool_name") or ""
    role = s.get("role") or ""
    content = s.get("content")
    if kind in ("reasoning", "thought", "thinking", "cot"):
        return Step(i, "reasoning", text=_stringify(content or s.get("reasoning")), raw=s)
    if kind in ("tool_call", "tool", "action", "function_call") or tool:
        return Step(
            i, "tool_call", tool=tool,
            tool_input=_stringify(s.get("input") or s.get("arguments") or s.get("args")),
            tool_output=_stringify(s.get("output") or s.get("result") or s.get("observation")),
            raw=s,
        )
    if kind in ("message", "msg") or role:
        return Step(i, "message", role=role, text=_stringify(content), raw=s)
    # Fallback: dump everything into text so detectors can still scan it.
    return Step(i, "other", text=_stringify(s), raw=s)


def load_trace(path: str) -> Trace:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return parse_trace(data)


def parse_trace(data) -> Trace:
    task = ""
    if isinstance(data, dict):
        task = data.get("task") or data.get("goal") or data.get("objective") or ""
        raw_steps = data.get("steps") or data.get("messages") or data.get("trace") or []
    elif isinstance(data, list):
        raw_steps = data
    else:
        raw_steps = []
    steps = [_normalize_step(i, s if isinstance(s, dict) else {"content": s})
             for i, s in enumerate(raw_steps)]
    return Trace(task=task, steps=steps)
