# detection-linter

Lint your Sigma and YARA detection rules for the mistakes that make them noisy, slow,
or broken — before they land in production. Static checks run with **no setup**; an
optional **AI layer** explains what a rule catches and suggests evasions to test it
against, so you can harden it.

Python 3.10+. PyYAML is recommended for Sigma but optional (a built-in fallback parser
covers typical rules).

## Quick look (no setup)

```bash
python -m detection_linter --demo
```

Lints four built-in rules — a clean and a flawed Sigma rule, a clean and a flawed YARA
rule — so you can see what it flags.

## Usage

```bash
python -m detection_linter rules/my_rule.yml
python -m detection_linter rules/              # recurse a directory
python -m detection_linter 'rules/**/*.yar'    # globs
python -m detection_linter rules/ --format json -o lint.json
```

Exits non-zero if any rule has an error-level issue, so it drops into CI as a
pre-merge check.

## What it checks

**Sigma (.yml / .yaml)**

- Required fields (`title`, `logsource`, `detection`) and a valid `condition`.
- `condition` references a selection that doesn't exist — or a selection is defined but
  never used.
- Invalid `level` / non-standard `status`; thin `logsource` (no category/product/service).
- Over-broad detection (a single common field like `Image` with nothing else).
- Hygiene: missing `id` (UUID), missing `description`.

**YARA (.yar / .yara)**

- Balanced braces and a present `condition:` (won't-compile errors).
- Strings defined but never referenced (and condition references to undefined strings).
- Over-broad `all of them` / `any of them` with a single string.
- Very short ASCII strings without `fullword`/`wide` (false-positive prone).
- Nested-wildcard regex (e.g. `(.*)+`) that can be catastrophically slow.
- Hygiene: missing `meta:` block.

Severity is `error` (blocks compile / clearly wrong), `warning` (noisy or risky), or
`info`. Tune the checks in `detection_linter/sigma.py` and `detection_linter/yara.py`.

## The optional AI layer

```bash
pip install anthropic
export ANTHROPIC_API_KEY=...
python -m detection_linter rules/my_rule.yml --ai
```

For each rule it adds a short explanation of the behavior the rule targets and 2–4
plausible evasions to test against — framed for hardening your own detections. Without a
key it's skipped cleanly.

## Limits

- This is a linter, not a compiler or a backtest. It reasons over rule text; it won't
  tell you whether a rule fires on real data. Run it alongside `sigma` / `yarac` for
  authoritative compilation.
- The Sigma checks cover the common structure; exotic condition syntax (aggregations,
  `| count`, correlation rules) is only partially understood.
- The slow-regex check is a heuristic for obvious nested quantifiers, not a full ReDoS
  analysis.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # PyYAML recommended; anthropic only for --ai
```

## License

MIT — see [LICENSE](LICENSE).
