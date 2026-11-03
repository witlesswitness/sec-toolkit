"""Scan engine: working tree, git history, and commit metadata.

All scanning is local — it reads files on disk and shells out to `git` for history.
No network, no authentication, nothing leaves the machine.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field

from .entropy import entropy_findings
from .patterns import SEVERITY_RANK, default_detectors

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
              "dist", "build", ".tox", ".idea"}
_MAX_FILE_BYTES = 2_000_000
_MAX_LINE = 4000


def redact(value: str, kind: str) -> str:
    """Show enough to recognize a finding, never the whole secret."""
    if kind == "pii":
        return value  # emails/IPs are the finding; showing them is the point
    v = value
    if len(v) <= 8:
        return v[:2] + "…" + v[-2:]
    return v[:4] + "…" + v[-4:] + f" (len {len(v)})"


@dataclass
class Finding:
    severity: str
    detector: str
    kind: str
    location: str      # "worktree" | "history" | "commit-msg" | "commit-meta"
    where: str         # path / commit sha / ref
    line_no: int
    redacted: str

    def sort_key(self):
        return (SEVERITY_RANK.get(self.severity, 9), self.location, self.where, self.line_no)


def _scan_line(line, detectors, want_entropy, entropy_threshold):
    """Yield (detector_name, kind, severity, redacted) for a single line."""
    line = line[:_MAX_LINE]
    for det in detectors:
        for m in det.regex.finditer(line):
            sev = det.severity
            if det.classify:
                override = det.classify(m)
                if override is None:
                    continue  # detector says this isn't a real hit (e.g. bad IP)
                sev = override
            val = m.group(det.group) if det.group else m.group(0)
            yield det.name, det.kind, sev, redact(val, det.kind)
    if want_entropy:
        for tok, e in entropy_findings(line, entropy_threshold):
            yield f"High-entropy string (H={e})", "secret", "medium", redact(tok, "secret")


def _is_binary(path):
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(1024)
        return b"\x00" in chunk
    except OSError:
        return True


def scan_worktree(repo, detectors, want_entropy, entropy_threshold):
    findings = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, repo)
            try:
                if os.path.getsize(path) > _MAX_FILE_BYTES or _is_binary(path):
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        for det, kind, sev, red in _scan_line(line, detectors, want_entropy, entropy_threshold):
                            findings.append(Finding(sev, det, kind, "worktree", rel, i, red))
            except OSError:
                continue
    return findings


def _git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                          errors="replace")


def is_git_repo(repo):
    r = _git(repo, "rev-parse", "--is-inside-work-tree")
    return r.returncode == 0 and r.stdout.strip() == "true"


def scan_history(repo, detectors, want_entropy, entropy_threshold):
    """Scan added lines across all history via `git log --all -p`."""
    findings = []
    r = _git(repo, "log", "--all", "--no-color", "-p", "-U0",
             "--pretty=format:%x01COMMIT%x01%H")
    if r.returncode != 0:
        return findings
    cur = "(unknown)"
    cur_path = "(unknown)"
    for raw in r.stdout.splitlines():
        if raw.startswith("\x01COMMIT\x01"):
            cur = raw.split("\x01")[2][:12]
            continue
        if raw.startswith("+++ b/"):
            cur_path = raw[6:]
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            content = raw[1:]
            for det, kind, sev, red in _scan_line(content, detectors, want_entropy, entropy_threshold):
                findings.append(Finding(sev, det, kind, "history", f"{cur}:{cur_path}", 0, red))
    return findings


def scan_commit_metadata(repo, detectors, want_entropy, entropy_threshold):
    """Scan commit messages and author/committer names+emails across all history."""
    findings = []
    sep = "\x1f"
    rec = "\x1e"
    fmt = sep.join(["%H", "%an", "%ae", "%cn", "%ce", "%B"]) + rec
    r = _git(repo, "log", "--all", "--no-color", f"--pretty=format:{fmt}")
    if r.returncode != 0:
        return findings
    for record in r.stdout.split(rec):
        record = record.strip("\n")
        if not record:
            continue
        parts = record.split(sep)
        if len(parts) < 6:
            continue
        sha, an, ae, cn, ce, body = parts[0][:12], parts[1], parts[2], parts[3], parts[4], parts[5]
        # author/committer identity line
        meta_blob = f"{an} <{ae}> {cn} <{ce}>"
        for det, kind, sev, red in _scan_line(meta_blob, detectors, want_entropy, entropy_threshold):
            findings.append(Finding(sev, det, kind, "commit-meta", sha, 0, red))
        for i, line in enumerate(body.splitlines(), 1):
            for det, kind, sev, red in _scan_line(line, detectors, want_entropy, entropy_threshold):
                findings.append(Finding(sev, det, kind, "commit-msg", sha, i, red))
    return findings


@dataclass
class ScanResult:
    repo: str
    findings: list = field(default_factory=list)
    scanned: list = field(default_factory=list)   # which locations were scanned
    git: bool = False


def scan_repo(repo, *, history=True, aggressive_pii=False, entropy=False,
              entropy_threshold=4.0):
    detectors = default_detectors(aggressive_pii=aggressive_pii)
    result = ScanResult(repo=os.path.abspath(repo))
    result.git = is_git_repo(repo)

    result.findings += scan_worktree(repo, detectors, entropy, entropy_threshold)
    result.scanned.append("worktree")

    if history and result.git:
        result.findings += scan_history(repo, detectors, entropy, entropy_threshold)
        result.findings += scan_commit_metadata(repo, detectors, entropy, entropy_threshold)
        result.scanned += ["history", "commit messages/metadata"]

    # de-duplicate identical findings (same det+loc+where+redacted), keep first
    seen = set()
    deduped = []
    for f in result.findings:
        key = (f.detector, f.location, f.where, f.redacted, f.line_no)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    deduped.sort(key=lambda f: f.sort_key())
    result.findings = deduped
    return result
