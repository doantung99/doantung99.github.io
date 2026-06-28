---
title: "China Crack 202"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: crypto
difficulty: easy
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, crypto, ai-assisted]
icon: "🔐"
draft: false
summary: "A password-protected archive whose ZIP/7z password was reused verbatim from last year's 'tryna crack' challenge — recover it from the title hint, extract, and read the flag off the decrypted artifact."
---

## Summary
A password-locked archive challenge: the hint nudged at a previous challenge with a similar name, and the trick was that the archive password was reused verbatim from the V1t CTF 2025 "tryna crack" task. No brute force — pivot from the title, reuse the historical password, extract, and read the flag off the recovered artifact.

## Solution
When I saw a protected archive plus a hint pointing at "a previous challenge with a similar name," I called the type immediately: this is a password-reuse pivot, not a cracking job. I set that direction and refused to let the model burn time on a brute-force script. My first prompt to the LLM was deliberately narrow — "given the title lineage, what's the most likely password source?" — and it correctly surfaced the V1t CTF 2025 "tryna crack" archive password `D4mn_br0_H0n3y_p07_7yp3_5h1d`.

The model's first instinct was to spin up John/hashcat against the archive; I caught that wrong turn and redirected it to just try the historical password directly. It worked. From there the model did the grinding — extracting, enumerating recovered files, and identifying the decrypted artifact that carried the flag text plus the hash-like suffix `dffdf21a13908662e27d8c5c875809e4`. I verified by assembling the visible challenge text with that suffix and confirming the `v1t{...}` casing.

```bash
#!/usr/bin/env bash
set -e

PASS='D4mn_br0_H0n3y_p07_7yp3_5h1d'   # reused from V1t CTF 2025 "tryna crack"

# 1) Extract the protected archive (7z layer)
7z x -p"$PASS" China_Crack_01.7z -oextracted
# If a nested layer is a ZIP, the same password applies:
# unzip -P "$PASS" extracted/protected.zip -d extracted

# 2) Enumerate everything that came out
find extracted -type f -maxdepth 3 -exec file {} \;

# 3) The flag lives inside the recovered artifact (printed in an image, not stored as text).
#    Visible text: v1t{Tryna_cRacK_iS_BaCk_MtfK_<suffix>}
#    Suffix derived from the password material:
echo "v1t{Tryna_cRacK_iS_BaCk_MtfK_dffdf21a13908662e27d8c5c875809e4}"
```

The rendered output showed `V1T{...}` in uppercase, but the accepted format is lowercase `v1t{...}` — a small gotcha worth flagging.

## Flag
```
v1t{Tryna_cRacK_iS_BaCk_MtfK_dffdf21a13908662e27d8c5c875809e4}
```
