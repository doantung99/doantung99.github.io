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
summary: "Carve a recovered bootkit installer out of a Windows 2000 disk image, disassemble the 512-byte MBR it writes, and reverse a tiny in-memory SUB-0x0D loop to recover a flag the boot code never prints."
icon: "💾"
---

## Summary

`BootRoot` hands you a Windows 2000 `qcow2` disk and a story about a machine "bricked" by a recovered `eEyeBootRoot2005.exe` (a nod to the real eEye BootRoot bootkit from Black Hat 2005). The disk itself is a decoy: its MBR and VBR are stock, so the payload lives entirely inside the recovered EXE, which writes a custom 512-byte boot sector to `\\.\PhysicalDrive0`. The core technique is static RE of that embedded 16-bit boot sector, where a `loop` runs `sub byte [bx], 0x0D` over 19 bytes that are decoded in memory but **never displayed** — so the only way to the flag is to reproduce the subtraction by hand.

This was a human-AI collaboration. The LLM did the grinding: it disassembled the 16-bit blob, traced the BIOS interrupts, and ran the decode arithmetic. My job was prompting and judgment: I recognized the "bootkit installer + embedded MBR" shape, pointed the model at the right artifact instead of letting it rabbit-hole on disk forensics, and caught the one mistake that would have produced a garbage flag (reading the decode op as XOR instead of SUB).

## Solution

### Reading the shape of the problem before touching a disassembler

The brief gives away more than it looks. "Bricked, reinstalling Windows didn't help, recovered `eEyeBootRoot2005.exe` executed right before death" plus a red-screen taunt is the signature of a **bootkit installer**: a normal user-mode program whose only purpose is to overwrite the master boot record so the malicious code runs before the OS. The real eEye BootRoot (Soeder & Permeh, 2005) does exactly this — it hooks `INT 13h` during boot. So before any tooling, the hypothesis is: the EXE opens the physical drive and writes a 512-byte sector, and the interesting logic is inside that sector, not the EXE's C runtime.

That hypothesis is what kept the whole solve cheap. It tells you which 512 bytes matter out of a 115 KB binary, and it tells you the disk image is probably a red herring. Both turned out true.

### Step 1 - convert and confirm the disk is a decoy

The image is `qcow2`; convert to raw so we can carve sectors and walk the filesystem with ordinary tools:

```bash
qemu-img convert -f qcow2 -O raw V1t_win2k_disk.qcow2 disk.raw
```

Now check the boot chain. This is the step that saves hours, because it proves where the payload is *not*:

- **MBR (sector 0)** is the stock Windows NT MBR. The boot code begins `33 C0 8E D0 BC 00 7C` (the classic `xor ax,ax; mov ss,ax; mov sp,0x7c00` prologue) and contains the strings `Invalid partition table`, `Error loading operating system`, `Missing operating system`. That is Microsoft's, not the attacker's.
- **VBR (sector 63, the NTFS partition start)** is a stock NTFS boot record — `NTLDR is missing`, etc.
- **Sectors 1-62** (the "MBR gap" where bootkits love to hide stage-2 code) are all zero.

The taunt string is nowhere in plaintext on the disk either. Conclusion: the disk is clean; "reinstalling didn't help" is pure narrative flavor. The payload only ever existed inside the recovered installer. **Intended path = static RE of the EXE, not disk forensics.** This is the dead-end I most needed to steer the model away from, because "Windows 2000 disk image" screams forensics and an LLM will happily volunteer `tsk_recover`, registry hive parsing, and Volatility plugins for an hour.

### Step 2 - carve the EXE out of NTFS

`7z` reads both the partition table and the NTFS volume directly, no mounting required:

```bash
7z l disk.raw                          # shows partition 0.ntfs at offset 32256 (= sector 63 * 512)
dd if=disk.raw of=ntfs.img bs=512 skip=63
7z e ntfs.img "Documents and Settings/test/Desktop/eEyeBootRoot2005.exe" -o./extracted
```

```
eEyeBootRoot2005.exe : PE32 executable (console) Intel 80386, for MS Windows  (115873 bytes)
```

### Step 3 - what the EXE actually does

The binary is a **MinGW/GCC** build compiled with `-g`, so it still carries DWARF `.debug_*` sections and even the original `main.cpp` reference. That is a gift — symbols make the C-level logic legible immediately. The imports are minimal and damning: `CreateFileA`, `WriteFile`, `CloseHandle`, plus a reference to the string `\\.\PhysicalDrive0`. There is no encryption library, no networking, nothing. The EXE opens the raw physical drive and writes a single 512-byte boot sector. It installs an MBR. Hypothesis confirmed.

Where is that sector? It is a static blob in `.data`:

- file offset `0x8220`, virtual address `0x409220`
- the `55 AA` boot signature sits at file offset `0x841E` (`= 0x8220 + 0x1FE`), exactly where a valid boot sector's signature belongs

`main()` references `0x409220` repeatedly and hands it to `WriteFile`. So the 512 bytes at `0x8220` *are* the malicious MBR. Carve them:

```bash
dd if=eEyeBootRoot2005.exe of=boot.bin bs=1 skip=$((0x8220)) count=512
```

### Step 4 - disassemble the embedded boot sector (16-bit, org 0x7C00)

A boot sector is loaded by the BIOS at linear `0x7C00` and runs in 16-bit real mode. You must tell the disassembler both facts or the addresses and operands come out wrong:

```bash
r2 -q -a x86 -b 16 -m 0x7c00 -c "e asm.bits=16; pd 40 @ 0x7c00" boot.bin
```

```asm
7c00  mov ah, 6          ; INT 10h AH=6 -> scroll/clear window
7c02  mov al, 0          ;   AL=0 -> clear the entire window
7c04  mov bh, 0x4F       ;   attribute 0x4F = RED background, white text  <- the "red screen"
7c06  mov cx, 0          ;   top-left  (row 0, col 0)
7c09  mov dx, 0x184f     ;   bottom-right (row 0x18=24, col 0x4F=79)
7c0c  int 0x10
7c0e  mov ah, 2          ; INT 10h AH=2 -> set cursor position
...
7c18  mov si, 0x7c34     ; -> "Bo may de dia chi lai roi, co gioi thi tim toi va chan bo may de"
7c1b  lodsb              ; teletype-print the taunt until NUL
7c1c  or al, al
7c1e  je 0x7c26
7c20  mov ah, 0x0e       ; INT 10h AH=0Eh -> teletype output
7c22  int 0x10
7c24  jmp 0x7c1b
7c26  mov bx, 0x7deb     ; decode target
7c29  mov cx, 0x13       ; 19 bytes
7c2c  sub byte [bx], 0x0d ; <-- DECODE LOOP: subtract 0x0D from each byte
7c2f  inc bx
7c30  loop 0x7c2c
7c32  jmp 0x7c32         ; halt forever  (this is what "bricks" the boot)
```

Read top to bottom this is a complete little program:

1. `INT 10h / AH=06h` clears the screen with attribute `0x4F` — red background, white foreground. That is the "red screen" from the story, encoded as a single attribute byte.
2. A `lodsb` + `INT 10h / AH=0Eh` loop teletypes the Vietnamese taunt at `0x7C34`: *"Bo may de dia chi lai roi, co gioi thi tim toi va chan bo may de"* — roughly "I left my address; if you're any good, come find me and stop me." This is the visible message.
3. The payload: `mov bx,0x7deb; mov cx,0x13; sub byte [bx],0x0d; inc bx; loop` decodes 19 bytes in place.
4. `jmp $` spins forever, so the machine never boots. That is the "brick."

The crucial observation: **the decode loop writes its result into memory but nothing ever prints it.** The taunt-printing loop already finished before the decode runs, and after decoding the CPU just halts. So the decoded 19 bytes are pure CTF payload — visible only to someone who reverses the loop. That is the flag.

### Step 5 - locate the encoded bytes and reverse the loop

The sector loads at `0x7C00`, and the loop targets `0x7DEB`. Convert to a file offset within `boot.bin`:

```
0x7DEB - 0x7C00 = 0x1EB        (offset within the 512-byte sector)
```

Within the full EXE that is `0x8220 + 0x1EB = 0x840B` — the 19 bytes sitting immediately before the `55 AA` signature, exactly the "spare" space at the end of a boot sector where you would tuck hidden data. Length `0x13 = 19` bytes.

Now the one subtlety that decides success or failure: **the decode is SUB, not XOR.** The raw opcode bytes are `80 2F 0D`. In `80 /n`, the ModR/M byte `2F` has reg field = `101b = 5`, and group-1 reg `/5` is **SUB**; `/6` would be XOR. Getting this backwards is the natural LLM mistake here, because a "single-byte transform over a buffer with constant `0x0D`" pattern-matches to XOR in any model's training distribution. XOR with `0x0D` produces garbage; SUB produces clean printable ASCII with `v1t{` and `}` delimiters. The disassembler, the opcode decode, and the output all agree — it is subtraction.

### End-to-end script

This takes the carved EXE to the printed flag, doing the carve math and the decode in one place. The encoded bytes are read straight out of the EXE so nothing is hardcoded except the well-justified offsets.

```python
#!/usr/bin/env python3
# BootRoot - recover the flag from the embedded boot sector.
# Input: eEyeBootRoot2005.exe (carved from the NTFS volume on the qcow2).

EXE = "eEyeBootRoot2005.exe"

# The 512-byte malicious boot sector is a static .data blob.
SECTOR_FILE_OFF = 0x8220             # file offset of the boot sector inside the EXE
LOAD_BASE       = 0x7C00            # BIOS loads a boot sector here in real mode

# Decode loop from the disassembly:
#   mov bx, 0x7DEB ; mov cx, 0x13 ; sub byte [bx], 0x0D ; inc bx ; loop
DECODE_VADDR = 0x7DEB               # in-memory address the loop walks
DECODE_LEN   = 0x13                # 19 bytes
DELTA        = 0x0D                # SUB constant (opcode 80 2F 0D = SUB, reg field /5 -- NOT XOR)

with open(EXE, "rb") as f:
    exe = f.read()

# Sanity check: the boot signature must be at sector offset 0x1FE.
sector = exe[SECTOR_FILE_OFF:SECTOR_FILE_OFF + 512]
assert sector[0x1FE:0x200] == b"\x55\xAA", "boot signature 55 AA not found - wrong offset"

# Map the in-memory decode address back to a sector offset, then read the encoded bytes.
sector_off = DECODE_VADDR - LOAD_BASE       # 0x7DEB - 0x7C00 = 0x1EB
enc = sector[sector_off:sector_off + DECODE_LEN]
# enc = 83 3e 81 88 3e 3f 85 3e 3d 6c 66 72 7b 6c 79 6e 7b 74 8a

flag = bytes((b - DELTA) & 0xFF for b in enc).decode("ascii")
print(flag)
```

Output:

```
v1t{12x10_Yen_lang}
```

The result carries the `v1t{`/`}` delimiters and clean underscores, which is the verification signal that the SUB direction was right. `Yen_lang` reads as the Vietnamese *"yen lang"* ("silence"), fitting the bootkit's "no return" theme.

## Flag

```
v1t{12x10_Yen_lang}
```

## Lessons learned - prompting the AI

This challenge is a great template for how to drive an LLM through a "bootkit installer + hidden boot-sector payload" problem fast. The model is excellent at the mechanical parts (disassembly, opcode decoding, byte arithmetic) and reliably bad at one thing (it pattern-matches single-byte transforms to XOR). Steer accordingly.

**1. Set the hypothesis before letting it explore.** The single most valuable prompt was the one that named the shape and forbade the wrong direction:

> "This is a recovered bootkit *installer* (`eEyeBootRoot2005.exe`) plus a Windows 2000 disk image. First verify whether the disk's MBR (sector 0) and NTFS VBR (sector 63) are stock or modified — check for `Invalid partition table` / `NTLDR is missing` strings and the `33 C0 8E D0` MBR prologue. If they're stock, the disk is a decoy and the payload is a 512-byte boot sector embedded in the EXE's `.data`. Do NOT run Volatility, registry, or filesystem-timeline forensics until we've ruled out the static-RE path."

That one paragraph collapsed the search space. Without the explicit "do not run forensics," the model wanted to treat "Windows 2000 image" as a memory/disk forensics challenge and would have burned the session on `tsk_recover`, hive parsing, and timeline analysis.

**2. Pin the disassembly mode, or every address is wrong.** Boot sectors are 16-bit real mode at org `0x7C00`. I told the model exactly that:

> "Carve 512 bytes at file offset `0x8220` from the EXE (the `55 AA` signature should land at `0x841E`). Disassemble as 16-bit x86 with origin `0x7C00`. Identify every `INT 10h` call by AH value, and find any in-memory write/decode loop — give me the target address, byte count, and the exact opcode bytes of the transform instruction."

Asking for "the exact opcode bytes of the transform instruction" is what set up the SUB-vs-XOR catch. If you let the model just *describe* the loop in prose, it will write "XORs each byte with 0x0D" and you will never know.

**3. The dead-ends to name explicitly:**
- Forensics tooling on the disk — it is stock. Tell the model the MBR/VBR are Microsoft's and move on.
- Assuming XOR for the decode loop. Make the model decode the actual ModR/M: in `80 /n`, reg field `/5` = SUB, `/6` = XOR. The opcode here is `80 2F 0D`, and `2F` -> reg `101b` = 5 = SUB.
- Trying to find the flag string on disk or in the EXE in plaintext — it is encoded, only materialized in memory at runtime, and never printed.

**4. How I caught the mistakes and verified.** When the model first produced an XOR-with-`0x0D` decode, the output was non-printable garbage with no `v1t{`. That failed output *is* the verification: a CTF flag must be printable ASCII and start with `v1t{`. I fed that back —

> "That output is garbage and has no `v1t{` prefix. Recheck the transform opcode `80 2F 0D` — decode the ModR/M reg field and tell me whether it's SUB or XOR, then redo the decode."

— and the model self-corrected to SUB, which immediately produced `v1t{12x10_Yen_lang}`. The double check at the end (signature `55 AA` at offset `0x1FE`, plus the `v1t{...}` delimiters in the result) confirmed both the offset math and the operation. My judgment was the loop: *if the decoded bytes aren't printable and brace-delimited, the transform or offset is wrong* — and I refused to accept the first answer that violated that.

**Fast-path prompt recipe for next time:** "Recovered bootkit installer writes a 512-byte MBR — verify the disk's MBR/VBR are stock (decoy), carve the boot sector from `.data` (`55 AA` at +0x1FE), disassemble as 16-bit org 0x7C00, find the in-memory decode loop, and decode the actual ModR/M (`80 /5` = SUB, not XOR) — flag is the buffer the loop writes but never prints, so it must come out as printable `v1t{...}`."
