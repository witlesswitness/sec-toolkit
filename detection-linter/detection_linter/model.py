"""Shared types."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Issue:
    severity: str   # "error" | "warning" | "info"
    code: str
    message: str
    hint: str = ""


@dataclass
class RuleReport:
    path: str
    kind: str       # "sigma" | "yara" | "unknown"
    name: str
    issues: list[Issue] = field(default_factory=list)
    parsed_ok: bool = True

    @property
    def errors(self):
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self):
        return [i for i in self.issues if i.severity == "warning"]
