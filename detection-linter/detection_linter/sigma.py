"""Sigma rule linting.

Checks the structural and quality issues that trip people up most often:
  * required fields (title, logsource, detection, condition)
  * a 'condition' that references selections that don't exist (and vice-versa)
  * missing/invalid level, status, and malformed logsource
  * overly broad detections (selection with a single very common field, or a bare
    'condition: selection' with one trivial match)
  * missing title/id/description hygiene fields (warnings)

Uses PyYAML when available; falls back to a tiny YAML-subset parser otherwise.
"""
from __future__ import annotations

import re

from .model import Issue, RuleReport

_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
_VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
_COMMON_BROAD_FIELDS = {"image", "parentimage", "commandline"}


def _load_yaml(text: str):
    try:
        import yaml
        return yaml.safe_load(text), None
    except ImportError:
        return _mini_yaml(text), None
    except Exception as exc:
        return None, f"YAML parse error: {str(exc)[:120]}"


def _mini_yaml(text: str):
    """Very small YAML-subset parser: nested maps by indentation, scalars and
    simple inline lists. Enough to lint typical Sigma rules without PyYAML.
    """
    root: dict = {}
    stack = [(-1, root)]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1] if stack else root
        if line.startswith("- "):
            parent.setdefault("__list__", []).append(line[2:].strip())
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip()
            if val == "":
                child: dict = {}
                if isinstance(parent, dict):
                    parent[key] = child
                stack.append((indent, child))
            else:
                if val.startswith("[") and val.endswith("]"):
                    val = [v.strip() for v in val[1:-1].split(",") if v.strip()]
                if isinstance(parent, dict):
                    parent[key] = val
    return root


def lint_sigma(path: str, text: str) -> RuleReport:
    rep = RuleReport(path=path, kind="sigma", name="")
    data, err = _load_yaml(text)
    if err or not isinstance(data, dict):
        rep.parsed_ok = False
        rep.issues.append(Issue("error", "parse", err or "top-level YAML is not a mapping"))
        return rep

    rep.name = str(data.get("title") or "(untitled)")

    # Required fields
    for field_name in ("title", "logsource", "detection"):
        if field_name not in data:
            rep.issues.append(Issue("error", "missing-field", f"Required field '{field_name}' is missing."))

    # Hygiene (warnings)
    if "id" not in data:
        rep.issues.append(Issue("warning", "no-id", "No 'id' (UUID) — recommended for tracking.",
                                "Add a stable UUID so the rule can be referenced across versions."))
    if "description" not in data:
        rep.issues.append(Issue("warning", "no-description", "No 'description'."))
    level = str(data.get("level", "")).lower()
    if "level" not in data:
        rep.issues.append(Issue("warning", "no-level", "No 'level' set."))
    elif level not in _VALID_LEVELS:
        rep.issues.append(Issue("error", "bad-level", f"level '{level}' is not one of {sorted(_VALID_LEVELS)}."))
    status = str(data.get("status", "")).lower()
    if status and status not in _VALID_STATUS:
        rep.issues.append(Issue("warning", "bad-status", f"status '{status}' is not a standard value."))

    # logsource sanity
    ls = data.get("logsource")
    if isinstance(ls, dict):
        if not any(k in ls for k in ("category", "product", "service")):
            rep.issues.append(Issue("warning", "thin-logsource",
                                    "logsource has none of category/product/service — rule may match too broadly."))
    elif "logsource" in data:
        rep.issues.append(Issue("error", "bad-logsource", "logsource should be a mapping."))

    # detection / condition consistency
    detection = data.get("detection")
    if isinstance(detection, dict):
        condition = detection.get("condition")
        selections = [k for k in detection.keys() if k != "condition"]
        if not condition:
            rep.issues.append(Issue("error", "no-condition", "detection has no 'condition'."))
        if not selections:
            rep.issues.append(Issue("error", "no-selection", "detection defines no selection blocks."))
        if isinstance(condition, str) and selections:
            # identifiers referenced in the condition
            referenced = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", condition))
            keywords = {"and", "or", "not", "of", "them", "all", "1", "any"}
            referenced -= keywords
            named = {r for r in referenced if not r.isdigit()}
            undefined = [r for r in named if r not in selections and r not in ("them",) and "*" not in r]
            # allow 'all of them', 'X of selection*'
            undefined = [u for u in undefined if not any(s.startswith(u.rstrip("*")) for s in selections)]
            for u in undefined:
                rep.issues.append(Issue("error", "undefined-selection",
                                        f"condition references '{u}', which is not a defined selection."))
            used = {s for s in selections if re.search(rf"\b{re.escape(s)}\b", condition) or "*" in condition}
            unused = [s for s in selections if s not in used]
            for s in unused:
                rep.issues.append(Issue("warning", "unused-selection",
                                        f"selection '{s}' is defined but not used by the condition."))
            # Overly broad: condition is just one selection with a single broad field
            if condition.strip() in selections:
                sel = detection.get(condition.strip())
                if isinstance(sel, dict) and len(sel) == 1:
                    only = next(iter(sel)).split("|")[0].lower()
                    if only in _COMMON_BROAD_FIELDS:
                        rep.issues.append(Issue("warning", "broad-detection",
                                                f"Detection matches on a single broad field ('{only}') — expect noise.",
                                                "Add a more specific condition (e.g. combine with CommandLine args)."))
    elif "detection" in data:
        rep.issues.append(Issue("error", "bad-detection", "detection should be a mapping."))

    if not rep.issues:
        rep.issues.append(Issue("info", "ok", "No issues found."))
    return rep
