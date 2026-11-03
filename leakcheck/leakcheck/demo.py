"""Build a throwaway git repo with planted FAKE secrets for --demo and tests.

Every value here is fabricated (documentation-style) — none are live credentials.
The point is to exercise the detectors, including a secret that is added in one
commit and 'removed' in a later commit so it only survives in history.

Note: the fake tokens are assembled from fragments at runtime rather than written
as literals, so this source file itself doesn't trip secret scanners / push
protection (and leakcheck won't flag this file when scanning its own repo). The
generated throwaway repo contains the fully-assembled strings for the scan to find.
"""
from __future__ import annotations

import subprocess
import tempfile

# Assemble fake secrets from parts so no full token literal appears in this source.
_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
_GHP1 = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
_GHP2 = "ghp_" + "ZZZZ1111222233334444555566667777aaaa"
_STRIPE = "sk_live_" + "0123456789abcdefghijklmno"
_BEGIN = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
_END = "-----END " + "OPENSSH PRIVATE KEY-----"


def _run(repo, *args):
    subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)


def build_demo_repo() -> str:
    d = tempfile.mkdtemp(prefix="leakcheck_demo_")
    _run(d, "init", "-q")
    _run(d, "config", "user.email", "dev@example.com")
    _run(d, "config", "user.name", "Demo Dev")

    # commit 1: a config file that leaks several secrets
    with open(f"{d}/config.py", "w") as fh:
        fh.write(
            f'AWS_ACCESS_KEY_ID = "{_AWS}"\n'
            f'GITHUB_TOKEN = "{_GHP1}"\n'
            f'STRIPE = "{_STRIPE}"\n'
            'api_key = "s3cr3t-pa55word-value-1234"\n'
            'ADMIN_EMAIL = "admin@internal.example.com"\n'
            'DB_HOST = "203.0.113.200"\n'
        )
    _run(d, "add", "-A")
    _run(d, "commit", "-q", "-m", "Add config (oops, with keys)")

    # commit 2: "remove" the secret file — but it still lives in history
    _run(d, "rm", "-q", "config.py")
    with open(f"{d}/README.md", "w") as fh:
        fh.write("# Demo\n\nSee notes.\n")
    _run(d, "add", "-A")
    # secret pasted into the commit MESSAGE this time
    _run(d, "commit", "-q", "-m", f"Remove config\n\ntemp key was {_GHP2} left in notes")

    # commit 3: a clean-looking file that still has a private key block
    with open(f"{d}/deploy.sh", "w") as fh:
        fh.write("#!/bin/sh\necho deploying\n")
    with open(f"{d}/id_rsa", "w") as fh:
        fh.write(f"{_BEGIN}\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAA\n{_END}\n")
    _run(d, "add", "-A")
    _run(d, "commit", "-q", "-m", "Add deploy script")
    return d
