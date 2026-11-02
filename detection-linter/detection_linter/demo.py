"""Write built-in sample rules (one clean, one flawed, per type) for --demo."""
from __future__ import annotations

import os
import tempfile

_SIGMA_BAD = """\
title: Suspicious Process
detection:
  selection:
    Image: '*'
  condition: selection and missing_sel
level: supercritical
"""

_SIGMA_GOOD = """\
title: Suspicious PowerShell EncodedCommand
id: 7e2d9f54-0b1a-4c3d-9e8f-1a2b3c4d5e6f
status: experimental
description: Detects PowerShell launched with an encoded command, a common obfuscation.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: high
"""

_YARA_BAD = """\
rule BadExample
{
    strings:
        $a = "ex"
        $unused = "never referenced"
        $re = /.*foo.*bar.*/
    condition:
        all of them
"""

_YARA_GOOD = """\
rule Good_Example_Dropper
{
    meta:
        author = "ctimmons"
        description = "Example: three distinct markers of a known dropper"
    strings:
        $s1 = "DropperConfigBlock" fullword
        $s2 = "C:\\\\ProgramData\\\\svc\\\\payload.bin" wide
        $s3 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        2 of ($s*)
}
"""


def write_samples() -> list[str]:
    d = tempfile.mkdtemp(prefix="detlint_demo_")
    files = []
    for name, content in (
        ("flawed.yml", _SIGMA_BAD), ("good.yml", _SIGMA_GOOD),
        ("flawed.yar", _YARA_BAD), ("good.yar", _YARA_GOOD),
    ):
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        files.append(path)
    return files
