# ioc-enrich

Paste in an indicator — an IP, domain, URL, file hash, or email — and get a clean,
copy-pasteable **OSINT table** for your SOC report or ticket. It auto-detects the
indicator type, refangs defanged input (`hxxps://evil[.]com` → `https://evil.com`),
and fans out to free/open-source intelligence sources concurrently.

The core sources need **no API keys at all**. A few optional ones light up if you
add free keys. Any source that's missing a key, rate-limited, or unreachable is
shown as a labeled row — the report always renders.

## Example

```
$ ioc-enrich 185[.]220[.]101[.]47
=================================================================
 IOC: 185.220.101.47   TYPE: ipv4   (input: 185[.]220[.]101[.]47)
=================================================================
SOURCE             FIELD                       VALUE
-----------------  --------------------------  -------------------------
ip-api             Location                    Frankfurt, Hesse, Germany
                   ASN                         AS205100 F3 Netze e.V.
                   Flags                       hosting
Shodan InternetDB  Open ports                  22, 443, 9001, 9030
                   Tags                        tor
GreyNoise          Classification              malicious
Tor exit list      Tor exit node               YES
AbuseIPDB          [skipped]                   no ABUSEIPDB_API_KEY
```

Try it with no setup:

```bash
python -m ioc_enrich --demo
```

## Sources

**Zero-key (always on):**

| Source | Indicator types | What you get |
|---|---|---|
| ip-api | IP | Geo, ASN, ISP/org, hosting & proxy flags, reverse DNS |
| Shodan InternetDB | IP | Open ports, software (CPEs), tags, known CVEs |
| GreyNoise Community | IP | Noise / known-scanner classification |
| Tor exit list | IP | Whether the IP is a Tor exit node |
| DNS | domain, IP | A/AAAA/MX/NS/TXT records; reverse DNS |
| RDAP / WHOIS | domain | Registrar, creation date, **domain age**, status |
| crt.sh | domain | Certificate-transparency subdomains |
| CIRCL hashlookup | hash | Whether the file hash is a known (often legitimate) file |

**Optional (free key unlocks each):**

| Source | Env var | Indicator types |
|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | IP, domain, URL, hash |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP |
| abuse.ch (URLhaus / ThreatFox / MalwareBazaar) | `ABUSECH_API_KEY` | IP, domain, URL, hash |
| AlienVault OTX | `OTX_API_KEY` | IP, domain, URL, hash |

One abuse.ch key covers all three of its services.

## Install

```bash
cd ioc-enrich
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# optional: add free API keys
cp .env.example .env
```

Python 3.10+. Core runs on `requests` alone; `dnspython` and `tldextract` improve
DNS and URL handling and are in `requirements.txt`.

## Usage

```bash
# One or more indicators as arguments (defanged is fine)
python -m ioc_enrich 8.8.8.8 evil[.]com hxxps://bad[.]site/login

# From a file, one per line (# comments allowed)
python -m ioc_enrich --file samples/iocs.txt

# From stdin (pipe IOCs from another tool)
cat iocs.txt | python -m ioc_enrich --stdin

# Formats: text (default), json, csv
python -m ioc_enrich --file samples/iocs.txt --format csv -o report.csv

# See the output format with no network / no keys
python -m ioc_enrich --demo
```

### URL pivoting

When you enrich a URL, the tool also enriches the host it points at (domain or IP)
and shows those rows under a `↳ host ·` sub-heading — so the report captures *where
the link actually goes*, the single most useful pivot in link triage.

## How it's built

```
indicator string
      │
   classify.py   ── detect type + refang defanged input
      │
   enrich.py     ── concurrent fan-out to every applicable source
      │              (+ URL → host pivot)
      ▼
   sources/*     ── one small, self-contained module per OSINT source,
      │              each returning a uniform SourceResult (ok/empty/skipped/error)
      ▼
   render.py     ── aligned plain-text table (or JSON / CSV)
```

Adding a source is ~30 lines: subclass `Source`, declare which `supported` IOC types
it handles, implement `query()` returning a `SourceResult`, and register it in
`sources/__init__.py`.

## Notes & limits

- This is enrichment, not a verdict engine. It gathers and formats evidence; the
  analyst decides. (CIRCL hashlookup in particular reports *known-file*, not
  *malicious* — a miss there is not a clean bill of health.)
- Free tiers have rate limits (e.g. GreyNoise Community ~100/day unauthenticated,
  ip-api 45/min). Large batches may hit them; add keys or slow down.
- Email indicators have few free, keyless sources; the tool pivots to the email's
  domain for enrichment.
- A natural next step is an optional AI layer: hand the collected OSINT to an LLM to
  draft the analyst assessment and suggest pivots. Deliberately left out of v1.

## Troubleshooting

**`ModuleNotFoundError: No module named 'requests'` (or `dns`, or `tldextract`)**
The dependencies aren't installed in the Python you're running. This is the most
common issue, usually because the virtual environment isn't active or packages were
installed into a different interpreter. Fix:

```bash
cd ioc-enrich
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -c "import requests, dns, tldextract; print('deps OK')"
```

Note that `--demo` runs even without these installed (it does no network calls), so
"demo works but a real lookup fails" almost always points at missing dependencies.
Each new terminal tab needs `source .venv/bin/activate` again.

**Every source shows `[error] network unreachable` / `connection failed`**
Outbound HTTPS is being blocked — common on corporate networks, VPNs, or firewalls.
Confirm with `curl -s https://rdap.org/domain/example.com | head -c 100`. If that
fails too, it's the network, not the tool.

**`[skipped] no API key` on VirusTotal / AbuseIPDB / abuse.ch / OTX**
Expected — those are optional. Add keys to `.env` to enable them. The zero-key
sources still run.

**`No module named ioc_enrich`**
Run from the repo root (the folder containing the `ioc_enrich/` directory).

## Data sources & attribution

This tool queries public OSINT services. Please review and respect each service's
terms of use and rate limits; for anything beyond occasional personal use, check
whether attribution or a (free) account is required.

- [Shodan InternetDB](https://internetdb.shodan.io/)
- [GreyNoise Community API](https://www.greynoise.io/)
- [Tor Project bulk exit list](https://check.torproject.org/)
- [ip-api.com](https://ip-api.com/)
- [RDAP](https://about.rdap.org/) via rdap.org
- [crt.sh](https://crt.sh/) (certificate transparency)
- [CIRCL hashlookup](https://hashlookup.circl.lu/)
- [VirusTotal](https://www.virustotal.com/) *(optional key)*
- [AbuseIPDB](https://www.abuseipdb.com/) *(optional key)*
- [abuse.ch](https://abuse.ch/) — URLhaus, ThreatFox, MalwareBazaar *(optional key)*
- [AlienVault OTX](https://otx.alienvault.com/) *(optional key)*

## License

MIT — see [LICENSE](LICENSE).
