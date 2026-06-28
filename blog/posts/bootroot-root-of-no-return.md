---
title: "BootRoot Root of No Return"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A Windows 2000 'bootkit' challenge where the real payload lives inside a recovered EXE that writes a 16-bit MBR; the flag is hidden in 19 bytes the boot code decodes with SUB 0x0D but never prints."
icon: "💾"
---

## Summary
We're handed a Windows 2000 disk image and the story of a bricked machine flashing a red taunt. The disk's boot chain is actually stock — the payload lives inside a recovered `eEyeBootRoot2005.exe` that writes a 16-bit MBR, and the flag is 19 bytes the boot code decodes in memory (`sub byte [bx], 0x0D`) but never shows. Static RE plus a one-line decode recovers it.

## Solution
My read going in: the eEye BootRoot name is a known 2005 PoC bootkit, and the prompt's "reinstalling Windows didn't help" framing smelled like misdirection. So I set the direction early — treat the disk as clean and hunt the payload in the EXE — and let the model do the carving and disassembly.

I converted the qcow2 to raw and had the model triage the boot chain. It confirmed the MBR (sector 0) was the stock NT MBR and the VBR (sector 63) a stock NTFS record, with the MBR gap zeroed — so nothing was persisted on disk. That matched my hypothesis, so I pivoted it to pull the EXE out of NTFS and reverse it.

The model triaged the PE (a MinGW/GCC build with DWARF symbols, imports `CreateFileA`/`WriteFile`/`CloseHandle`, references `\\.\PhysicalDrive0`) and located the 512-byte boot sector built in `.data` at file offset `0x8220`, ending in `55 AA`. I asked it to disassemble that sector as 16-bit code at `org 0x7C00`. It surfaced the red-screen BIOS calls, the Vietnamese taunt at `0x7C34`, and a decode loop over 19 bytes at `0x7DEB`.

Here's where I caught a wrong turn: the model's first instinct was to read the loop as XOR 0x0D. I had it re-check the raw opcode `80 2F 0D` — the ModR/M `2F` has reg field 5, which is group-1 **SUB**, not XOR (`/6`). XOR produces garbage; SUB produces clean ASCII. With the operation pinned down, the decode is trivial — those 19 bytes sit at sector offset `0x1EB`, right before the boot signature, and are decoded but never printed.

```python
# boot.bin = the 512-byte sector carved from the EXE:
#   dd if=eEyeBootRoot2005.exe of=boot.bin bs=1 skip=$((0x8220)) count=512
data = open("boot.bin", "rb").read()
enc = data[0x1EB:0x1EB + 0x13]   # 19 encoded bytes, just before the 55 AA signature
print(bytes((b - 0x0D) & 0xFF for b in enc).decode())
# -> v1t{12x10_Yen_lang}
```

I verified the output by sanity-checking the delimiters: clean `v1t{...}` with sensible underscores (`Yen_lang` ~ Vietnamese "yen lang", silence) confirmed the SUB direction was right.

## Flag
```
v1t{12x10_Yen_lang}
```
