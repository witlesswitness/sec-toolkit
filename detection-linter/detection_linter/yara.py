"""YARA rule linting (static, no libyara dependency).

Checks the mistakes that most often make YARA rules noisy, slow, or broken:
  * balanced braces; presence of a 'condition'
  * strings defined but never referenced in the condition (and vice-versa)
  * a condition of just 'all of them' / a single short string (over-broad)
  * very short ASCII strings without 'wide'/'nocase' context (false-positive prone)
  * missing 'meta' block (hygiene)
  * unanchored '$' regex strings that can be catastrophically slow (heuristic)

This is a lightweight linter, not a YARA compiler; it reasons over the rule text.
"""
from __future__ import annotations

import re

from .model import Issue, RuleReport

_RULE_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
_STRING_DEF_RE = re.compile(r"^\s*(\$[A-Za-z0-9_]*)\s*=", re.MULTILINE)


def lint_yara(path: str, text: str) -> RuleReport:
    rep = RuleReport(path=path, kind="yara", name="")

    m = _RULE_RE.search(text)
    rep.name = m.group(1) if m else "(unnamed)"
    if not m:
        rep.issues.append(Issue("error", "no-rule", "No 'rule <name>' declaration found."))

    if text.count("{") != text.count("}"):
        rep.issues.append(Issue("error", "unbalanced-braces", "Unbalanced '{' / '}' — rule won't compile."))

    if "condition:" not in text:
        rep.issues.append(Issue("error", "no-condition", "No 'condition:' section — rule won't compile."))

    if "meta:" not in text:
        rep.issues.append(Issue("warning", "no-meta", "No 'meta:' block (author/description/reference).",
                                "Add a meta block for provenance and triage."))

    # strings vs condition usage
    string_ids = _STRING_DEF_RE.findall(text)
    cond_match = re.search(r"condition:\s*(.*)", text, re.DOTALL)
    condition = cond_match.group(1) if cond_match else ""
    cond_refs = set(re.findall(r"\$[A-Za-z0-9_]*", condition))
    uses_them = "them" in condition or "of ($" in condition or "any of" in condition or "all of" in condition

    for sid in string_ids:
        base = sid
        referenced = (base in cond_refs) or uses_them or (base == "$" and "$" in condition)
        # wildcard refs like $a*
        if not referenced and any(r.endswith("*") and base.startswith(r[:-1]) for r in cond_refs):
            referenced = True
        if not referenced:
            rep.issues.append(Issue("warning", "unused-string",
                                    f"String '{sid}' is defined but not referenced in the condition."))

    for ref in cond_refs:
        if ref == "$":
            continue
        if ref not in string_ids and not any(s.startswith(ref.rstrip("*")) for s in string_ids):
            rep.issues.append(Issue("error", "undefined-string",
                                    f"Condition references '{ref}', which is not defined in strings:."))

    # over-broad condition
    cond_norm = re.sub(r"\s+", " ", condition).strip().rstrip("}").strip()
    if cond_norm in ("all of them", "any of them") and len(string_ids) <= 1:
        rep.issues.append(Issue("warning", "broad-condition",
                                "Condition matches on a single/any string — likely noisy.",
                                "Require multiple strings or add file-size/type constraints."))

    # short ascii strings (FP-prone)
    for sm in re.finditer(r'(\$[A-Za-z0-9_]*)\s*=\s*"([^"]*)"((?:\s+\w+)*)', text):
        sid, val, mods = sm.group(1), sm.group(2), sm.group(3)
        if len(val) <= 3 and "wide" not in mods and "fullword" not in mods:
            rep.issues.append(Issue("warning", "short-string",
                                    f"String {sid}=\"{val}\" is very short — prone to false positives.",
                                    "Lengthen it, add 'fullword', or combine with other strings."))

    # naive catastrophic-regex heuristic
    for sm in re.finditer(r'(\$[A-Za-z0-9_]*)\s*=\s*/([^/]+)/', text):
        rx = sm.group(2)
        if re.search(r"(\.\*){2,}|(\.\+){2,}|\(\.\*\)\+", rx):
            rep.issues.append(Issue("warning", "slow-regex",
                                    f"Regex string {sm.group(1)} has nested wildcards — can be very slow.",
                                    "Anchor the pattern or bound the repetition."))

    if not rep.issues:
        rep.issues.append(Issue("info", "ok", "No issues found."))
    return rep
