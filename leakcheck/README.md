# leakcheck

Scan a local git repo for leaked **secrets** and **PII** — not just in the current
files, but in the **full commit history** and **commit messages/metadata**, where
accidentally-committed credentials usually survive long after they're "deleted."

Secrets are always shown **redacted** (`ghp_…aaaa`, `AKIA…MPLE`), severity-ranked, and
the tool exits non-zero when a high-risk secret is found, so it drops into CI.

Python 3.10+, standard library only (uses the `git` CLI for history). No network, no
API keys — everything is read locally.

> **Scan repos you own or are authorized to assess.** leakcheck is for finding *your*
> exposure (or a client's, with permission) before someone else does. It is not a
> scraper for harvesting other people's secrets from public repositories. If you ever
> find a real secret in a repo you don't own, disclose it to the owner / GitHub rather
> than using it.

## Quick look (no setup)

```bash
python -m leakcheck --demo
```

The demo builds a throwaway repo with planted **fake** secrets — including one that's
added then "removed" in a later commit (so it survives only in history) and one pasted
into a commit message — and scans it.

## Usage

```bash
python -m leakcheck /path/to/repo                 # working tree + history + commit metadata
python -m leakcheck /path/to/repo --no-history    # working tree only (fast)
python -m leakcheck /path/to/repo --format json -o findings.json
python -m leakcheck /path/to/repo --entropy       # also flag high-entropy strings
python -m leakcheck /path/to/repo --aggressive-pii  # also phone/SSN-style patterns
```

Exit code is `1` if any critical/high secret is found, else `0`.

## What it detects

**Secrets (default, high precision)** — private key blocks, AWS access key IDs, GitHub
tokens (classic + fine-grained PATs), Stripe live keys, Slack tokens, Google API keys
and OAuth client IDs, SendGrid/Twilio/npm tokens, JWTs, and a conservative
`key = "value"` assignment pattern.

**PII (default)** — email addresses and IP addresses (public IPs ranked above
private/loopback), in files, history, and commit author/committer metadata.

**Opt-in** — `--entropy` adds high-entropy string detection for unknown key shapes
(more coverage, more noise; tune with `--entropy-threshold`). `--aggressive-pii` adds
phone-number and SSN-style patterns (higher false-positive rate).

## Where it looks

| Location | What's scanned |
|---|---|
| Working tree | Current files (skips `.git`, `node_modules`, venvs, binaries, large files) |
| Git history | Lines **added** across all commits (`git log --all -p`) — catches secrets removed in a later commit |
| Commit messages | The full message body of every commit |
| Commit metadata | Author/committer names and emails |

## If it finds something real

1. **Rotate/revoke** the credential immediately — assume a committed secret is
   compromised, even in a private repo.
2. **Remove it from history**, not just the latest commit (e.g. `git filter-repo`),
   then force-push. Deleting the file in a new commit is not enough — it lives in
   history, which is exactly what this tool demonstrates.
3. For PII, decide what needs scrubbing and do the same history rewrite.

## Limits

- Pattern-based detection: high-precision patterns miss custom/unknown secret formats
  (use `--entropy` for broader, noisier coverage), and any detector can occasionally
  false-positive — confirm before acting.
- History scanning reads added lines via `git log -p`; an enormous history can be slow.
- It reports exposure; it does not rotate keys or rewrite history for you.
- Not a replacement for GitHub's own push-protection / secret scanning — a complement
  you can run locally and in CI.

## License

MIT — see [LICENSE](LICENSE).
