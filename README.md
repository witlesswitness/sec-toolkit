# sec-toolkit

Small, open-source security tools — practical on day one, documented, and free to use.
Each lives in its own folder with its own README; this page indexes them.

All of these are defensive / blue-team tools. Most run with no API keys and no network;
where an optional AI layer or third-party source helps, it's opt-in and degrades
cleanly when it's absent.

| Tool | What it does | Keys needed |
|------|--------------|-------------|
| [**ioc-enrich**](ioc-enrich/) | Paste an IP, domain, URL, hash, or email → a copy-pasteable OSINT table for a SOC report. Refangs defanged input; enriches the host a URL points at. | None to start; optional VT / AbuseIPDB / abuse.ch / OTX |
| [**headercheck**](headercheck/) | Analyze raw email headers for spoofing: SPF/DKIM/DMARC, sender mismatches, lookalike domains, relay-hop timeline. | None (offline) |
| [**promptmap**](promptmap/) | Fire known prompt-injection & jailbreak payloads at your own LLM app's endpoint; report which got through. Exits non-zero on a breach, for CI. | None for canary/rule checks; optional LLM judge |
| [**agent-trace-monitor**](agent-trace-monitor/) | Flag suspicious behavior in an LLM agent's transcript: exfiltration, secret access, destructive actions, goal drift, concealment. | None for rule checks; optional LLM monitor |
| [**logtriage**](logtriage/) | Parse logs → extract indicators, flag events, tally brute-force sources, build a timeline. Pipes external indicators into ioc-enrich. | None (offline) |
| [**detection-linter**](detection-linter/) | Lint Sigma & YARA rules for common mistakes: undefined selections, over-broad matches, unused strings, catastrophic regex. | None for static checks; optional AI explain/evasion |
| [**leakcheck**](leakcheck/) | Scan a repo you control for leaked secrets & PII across the working tree, full git history, and commit messages. Redacted, severity-ranked, CI-friendly. | None (offline) |

## Quick start

Every tool runs the same way — clone, enter its folder, and try its demo with no setup:

```bash
git clone https://github.com/witlesswitness/sec-toolkit.git
cd sec-toolkit

# each tool has a zero-setup demo:
python -m ioc_enrich --demo
python headercheck/headercheck.py headercheck/samples/spoofed.eml
python -m promptmap --demo vulnerable
python -m agent_trace_monitor --demo malicious
python -m logtriage --demo
python -m detection_linter --demo
python -m leakcheck --demo
```

Most tools need only Python 3.10+. A few have an optional dependency (listed in the
tool's own `requirements.txt`) for an opt-in feature; the core always works without it.

## How they fit together

`logtriage` extracts the external indicators from a log and hands them to `ioc-enrich`
for enrichment, so a raw log becomes an enriched picture in two commands:

```bash
python -m logtriage server.log --format iocs | python -m ioc_enrich --stdin
```

`promptmap` and `agent-trace-monitor` are the two AI-security tools: one tests an LLM
app's resistance to injection from the outside, the other inspects an agent's own
transcript for misbehavior. `headercheck` and `detection-linter` are focused
single-purpose utilities for email forensics and detection engineering.

## Writing & license

Each tool has a write-up at [charlestimmons.com/tools](https://www.charlestimmons.com/tools/).
Everything here is MIT-licensed — use it, fork it, send a PR.

---

*These are triage and testing aids, not verdict engines. They surface and format
evidence; a human makes the call. Run the LLM-security tools only against systems you
own or are authorized to test.*
