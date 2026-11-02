# logtriage

Point it at a log file and it parses the lines, extracts indicators (IPs, domains,
URLs, file hashes, emails), flags notable events (auth failures, privilege use, new
accounts, outbound connections), tallies brute-force sources, and builds a timeline —
the manual grep-and-correlate pass, done in one command.

Standard library only. No keys, no network, Python 3.10+.

## Quick look (no setup)

```bash
python -m logtriage --demo
```

The built-in sample is a small SSH brute-force with follow-on activity; the output
shows the failed-auth tally, the extracted indicators (tagged internal/external), and
the attack timeline.

## Usage

```bash
python -m logtriage /var/log/auth.log
cat app.log | python -m logtriage                 # from stdin
python -m logtriage server.log --external-only    # ignore private/loopback IPs
python -m logtriage server.log --format json -o triage.json
```

### Pairs with ioc-enrich

`--format iocs` prints a plain list of the external indicators, one per line — pipe it
straight into [ioc-enrich](../ioc-enrich) to OSINT-enrich everything the log turned up:

```bash
python -m logtriage server.log --format iocs | python -m ioc_enrich --stdin
```

## What it recognizes

- **Log formats** — syslog / auth.log, ISO-8601-prefixed lines, JSON lines, and a
  plain fallback for anything else. Timestamps are normalized to UTC where present
  (syslog has no year, so the current year is assumed).
- **Indicators** — IPv4 (tagged internal vs. external by whether the address is
  globally routable), domains, URLs, md5/sha1/sha256 hashes, and emails. Defanged
  indicators are refanged first.
- **Events** — auth failure/success, privilege use (sudo/root), new accounts,
  errors/quarantine, and network/transfer lines.
- **Brute force** — failed-auth counts per source IP, flagged at 5+.

## Output

- `text` (default) — summary, failed-auth-by-IP, indicators by frequency, and the
  timeline.
- `json` — the same, structured, for piping into other tooling.
- `iocs` — just the external indicators, one per line, for enrichment.

## Limits

- Parsing is best-effort across common formats; an unusual format still yields
  indicators and events, just without parsed timestamps.
- Event tagging is keyword-based and English-oriented — tune the patterns in
  `logtriage/triage.py` for your stack.
- Documentation IP ranges (TEST-NET) count as internal because the standard library
  classifies them as non-global; real public attacker IPs classify as external.
- This is a triage aid to point you at what matters, not a SIEM or a verdict.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
# no third-party dependencies
```

## License

MIT — see [LICENSE](LICENSE).
