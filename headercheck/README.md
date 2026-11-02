# headercheck

Analyze raw email headers for spoofing and authentication tells. Paste headers in,
get a plain-text report: SPF/DKIM/DMARC results, sender/reply-to/return-path
mismatches, display-name spoofing, lookalike domains, and the Received-hop timeline.

Everything runs locally — **no network, no API keys, standard library only.** One
file, Python 3.10+.

## Usage

```bash
# An .eml file or a text file of raw headers
python headercheck.py message.eml

# Paste headers from the clipboard (macOS)
pbpaste | python headercheck.py

# From a file via flag
python headercheck.py --file headers.txt
```

Getting the raw headers out of your mail client: Gmail → "Show original"; Outlook →
message → Properties → Internet headers; Apple Mail → View → Message → Raw Source.

## Example

```
 FINDINGS
 ----------------------------------------
 [!] DKIM failed.
 [!] DMARC failed.
 [!] From domain resembles 'paypal' without being its real domain.
 [~] SPF softfail.
 [~] Reply-To domain ['account-recovery-desk.ru'] differs from From domain (mailer-paypa1.ru).
 [~] Display name references 'paypal' but the sending domain is mailer-paypa1.ru.
```

Markers: `[!]` alert · `[~]` warning · `[i]` info · `[+]` ok.

## What it checks

- **Authentication** — SPF, DKIM, DMARC, parsed from `Authentication-Results` and
  `Received-SPF`.
- **Address mismatches** — From vs Reply-To vs Return-Path registrable domains. A
  Reply-To or Return-Path pointing somewhere other than the From domain is a classic
  redirect/spoof tell.
- **Display-name spoofing** — a brand name or a different email address sitting in the
  display name while the real sending domain is something else.
- **Lookalike / homoglyph / punycode** — From domains that imitate a known brand
  (`micros0ft-support.com`, `paypa1.ru`, `xn--` punycode).
- **Received-hop timeline** — the relay chain oldest-to-newest, with per-hop delays
  and the originating IPs.

## Limits

- Headers can be forged, and only hops added by servers you trust are trustworthy.
  Treat findings as signals to weigh, not proof.
- Registrable-domain matching uses the last two labels (no Public Suffix List), so a
  few multi-part TLDs (e.g. `co.uk`) are approximated. Extend if that matters to you.
- The brand/lookalike lists in `headercheck.py` (`COMMON_TARGETS`, `LEGIT_DOMAINS`)
  are a starting set — add the brands and domains relevant to your environment.

## License

MIT — see [LICENSE](LICENSE).
