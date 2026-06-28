---
title: "Green Goblin"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: forensics
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, forensics, ai-assisted]
draft: false
summary: "A 5 GiB Windows 11 RAM dump hides five flag fragments across classic OS internals (Registry, kernel symlink, NTFS ADS, Event Log, named memory section); carving and reversing the dropper reveals the fixed bytes, which decode with ROT47."
icon: "🧪"
---

## Summary
A 5 GiB Windows 11 24H2 raw memory dump where the Green Goblin's "Dark Energy" is split into five fragments (R, KO, D, EL, M) planted across Windows internals and buried under thousands of decoy artifacts. The win is to recover and reverse the dropper PE so its planting functions name the real artifacts and their fixed bytes, which then decode with ROT47.

## Solution
When I saw "5 GiB RAM dump" plus the R/KO/D/EL/M hints I called the play: memory forensics with five canonical Windows hiding spots, and almost certainly a noise problem rather than an encoding problem. So I set the direction and let the model do the grinding.

First I had the model triage the image. It confirmed Windows 11 build 26100 via `windows.info`, then diffed `pslist` against `psscan` — that exposed the decoy storm (24 `PING.EXE` spawned in a 23-second window, plus terminated `lsass`/`explorer` only visible to the pool scan). The model's instinct was to start grepping artifacts; I corrected course, because every noise routine stamps `N01S3_` and you drown. The right move, which I prompted explicitly, was: don't grep the dump, carve the binary and read the code that plants the artifacts.

The model ran a `strings` sweep to find the dropper (`GreenGoblin.exe`, internal name "GreenPlasma"), located it with `windows.filescan`, dumped it with `windows.dumpfiles`, and — because the PE shipped with DWARF symbols — recovered function names in radare2. I asked it to isolate the real check from the decoys: `wmain` calls `GenerateNoise()` first, then five fixed-name routines (`GenerateRegistryArtifact`, `NtCreateSymbolicLinkObject`, `GenerateADSArtifact`, `GenerateEventLogArtifact`, `GenerateMemoryArtifact`). I had it disassemble each of the five and pull the fixed 6-byte value each writes. Noticing every byte sat in the printable `0x21–0x75` band and the noise marker `N01S3}` was itself leetspeak, I told it the encoding was ROT47, and verified the concatenation produced a clean flag.

The five real fragments, in the given order R · KO · D · EL · M:

| Frag | Mechanism | Bytes (ASCII) | ROT47 |
|------|-----------|---------------|-------|
| R  | Registry value `HKCU\...\CloudFiles\DiagnosticData` | `` '`%L`0 `` | `V1T{1_` |
| KO | Kernel object symlink → `\BaseNamedObjects\9cGb0c` | `9cGb0c` | `h4v3_4` |
| D  | NTFS ADS `...\config.ini:hidden` | `` 03`809 `` | `_b1g_h` |
| EL | Fake Application Error event, faulting-module path | `cC50C_` | `4rd_r0` |
| M  | Named section `Local\9cGb0c` at `+0x250` | `_dEbCN` | `05t3r}` |

```python
def rot47(s):
    return ''.join(
        chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
        for c in s
    )

frags = {
    'R':  "'`%L`0",
    'KO': "9cGb0c",
    'D':  "03`809",
    'EL': "cC50C_",
    'M':  "_dEbCN",
}

flag = ''.join(rot47(frags[k]) for k in ['R', 'KO', 'D', 'EL', 'M'])
print(flag)
# V1T{1_h4v3_4_b1g_h4rd_r005t3r}
```

The difficulty was entirely separating signal from noise; the encoding was plain ROT47.

## Flag
```
V1T{1_h4v3_4_b1g_h4rd_r005t3r}
```
