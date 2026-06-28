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
summary: "Carve and reverse a dropper from a Windows 11 RAM dump to find which five OS-internal artifacts hold the real fragments, then ROT47-decode them into the flag."
icon: "🎃"
---

## Summary

Green Goblin is a Windows 11 memory-forensics challenge: a 5 GiB raw RAM dump captured mid-execution while a dropper planted five flag fragments across five classic Windows hiding spots (Registry value, Kernel Object symlink, NTFS alternate Data stream, Event Log, named Memory section) and buried them under a flood of `N01S3` decoys. The core technique is to stop grepping the dump, carve the binary out with Volatility 3, let its DWARF symbols hand you the planting functions, read the fixed bytes each real routine writes, and ROT47-decode the five fragments in order R · KO · D · EL · M.

I want to be honest about how this one actually got solved: the LLM did the grinding. It walked Volatility plugins, diffed process lists, disassembled MinGW code, and tracked six-byte writes across five functions far faster than I would have by hand. My job was recognizing the challenge class, pointing the model at the right artifact, and — critically — catching the two places where it confidently went the wrong way. This writeup is as much about *how I steered* as it is about the bytes.

## Solution

### Reading the story before touching a tool

The prompt is doing real work, and it pays to parse it as a spec rather than flavor text:

> ...shattering his Dark Energy into 5 fragments scattered across the OS internals (R, KO, D, EL and M). Can you recover all 5 fragments and assemble them in the correct order...

Two hard constraints fall out immediately:

1. There are exactly **five** fragments, each tied to an OS-internal artifact keyed by a label: **R, KO, D, EL, M**.
2. Order matters — assemble them as given.

The labels are the whole game. R is **R**egistry, KO is **K**ernel **O**bject, D is alternate **D**ata stream, EL is **E**vent **L**og, M is **M**emory section. That mapping is the single most important inference in the challenge, and I made the model commit to it up front so every later step had a target instead of wandering the dump looking for "something flaggy." This is the human-judgment part: I've seen enough Windows forensics challenges to read "R, KO, D, EL, M" as a checklist of hiding spots, and I told the model that's what it was looking at rather than asking it to discover the theme.

### Identifying the image

Everything in Volatility hangs off the right symbol table, so step zero is `windows.info`:

```bash
python3 -m venv volenv
./volenv/bin/pip install volatility3
./volenv/bin/vol -q -f GreenGoblin.raw windows.info
```

Key fields: `Major/Minor 15.26100`, `NtMajorVersion 10` → **Windows 11 24H2, build 26100**, `SystemTime` in June 2026, primary user `trtr5`. Confirming build 26100 matters because it tells you Volatility's stock symbols will resolve and you're not going to fight a profile mismatch — a dead-end I explicitly warned the model away from so it didn't start hunting for custom ISF files it didn't need.

### Triage: pslist vs psscan, and ignoring the obvious bait

The instinct on a malware dump is to list processes and chase whatever looks hostile. Here that instinct walks you straight into the trap. Two plugins, two different views:

- `windows.pslist` walks the active `EPROCESS` doubly-linked list — what was *alive* at capture: ~78 processes.
- `windows.psscan` does a pool-tag scan of memory, so it also catches **terminated and unlinked** processes that the active list no longer references: ~230.

The diff between them is the interesting surface. And the diff screams one thing: **24 `PING.EXE`** processes spawned in a ~20-second window (19:09:13–19:09:36) off short-lived parents plus a `cmd.exe`. Meanwhile `lsass.exe`, `explorer.exe`, and `winlogon.exe` show up only under `psscan`, meaning most of the relevant activity is in processes that have already exited and been partly reclaimed — consistent with "frozen mid-execution" by **DumpIt** (`C:\Users\trtr5\Downloads\DumpIt.exe`).

This is where I made my first correction. The model latched onto the ping flood and started theorizing about ICMP exfiltration — decoding the ping payloads, counting packets as bits, the whole rabbit hole. That's exactly the bait. I cut it off: the pings are **decoy noise**, the flag is not in network traffic, stop analyzing them. The tell is the volume and uniformity — real exfil doesn't announce itself as 24 identical short-lived `PING.EXE` in one tight burst. Recognizing decoy structure was judgment; the model had the data but wanted to chase the loudest signal.

### Finding the payload by name, not by behavior

A broad `strings` sweep over the raw image (both ASCII and UTF-16LE, because Windows paths and registry data are wide strings) surfaces the dropper without any reversing yet:

```
http://192.168.1.244/GreenGoblin.exe
https://995ae3f22dbe1279-118-71-145-133.serveousercontent.com/Green_Plasma/GreenGoblin.exe
C:\Users\trtr5\Downloads\GreenGoblin (1).exe
```

Corroborating artifacts make the attribution airtight: Defender alias strings `GoblinRumba`, `CauldronDLL`, `MZPEMemoryArtifacts`, and an in-memory Windows Error Reporting detection `Exploit:Win32/CTFMonWritePE.BB`. The binary was pulled over a **serveo.net** reverse tunnel (`...serveousercontent.com`, resolving to a Vietnamese IP `118.71.145.133`) and from an internal host `192.168.1.244`. Its internal product name is *"GreenPlasma"*.

Two things to note. First, the `(1).exe` suffix is the real on-disk copy you want — that's the one that actually landed in Downloads. Second, and this is the pivotal strategic call: **do not try to extract the fragments by grepping the dump.** The whole point of the design is that every artifact type is flooded with `N01S3` decoys, so `strings | grep` and `windows.registry.printkey` will drown you in plausible-looking junk. I told the model in plain terms: we are going to carve and reverse the binary, because the planting code is ground truth and the dump is a hall of mirrors.

### Carving and reversing the dropper

Locate the file object in the pool, then dump its backing pages:

```bash
./volenv/bin/vol -q -f GreenGoblin.raw windows.filescan.FileScan | grep -i goblin
# 0xaa083c41b650  \Users\trtr5\Downloads\GreenGoblin (1).exe

./volenv/bin/vol -q -f GreenGoblin.raw -o dump \
    windows.dumpfiles.DumpFiles --virtaddr 0xaa083c41b650

file dump/*.dat
# PE32+ executable (console) x86-64, for MS Windows — MinGW/GCC, DWARF debug info
```

The gift here is that it's a **MinGW/GCC build with DWARF symbols left in.** That means radare2 recovers the real function names instead of `fcn.0x140001abc` blobs:

```bash
r2 -2 -q -c 'aaa; afl~Artifact; afl~Noise; pdf @ sym.wmain' "GreenGoblin (1).exe"
```

`wmain` reads like a table of contents:

```
GenerateNoise()
GenerateADSArtifact()
GenerateEventLogArtifact()
GenerateMemoryArtifact()
GenerateRegistryArtifact()
... then NtCreateSymbolicLinkObject(...)
```

So there are exactly five real planting routines plus `GenerateNoise`, and the symlink is created inline in `wmain` rather than in its own `Generate*` function — which is why the kernel-object fragment doesn't have a matching `GenerateKernelObjectArtifact` name. That asymmetry tripped the model up: it searched the function list for a KO routine, didn't find one, and started to conclude there were only four fragments. I sent it back to the `wmain` disassembly specifically to read past the five `Generate*` calls, and the `NtCreateSymbolicLinkObject` call was sitting right there. Lesson for steering: when a count doesn't match, re-read the caller, don't trust the callee list.

### Separating real bytes from noise inside the code

This is the crux, and it's why reversing beats grepping. The decoy routines and the real routines are structurally different:

- **Noise routines** write *parameterized* names with a format specifier and embed a `N01S3_` / `N01S3}` marker — e.g. 15× registry values `DiagnosticData_%d`, ADS files `temp_%d.log:hidden`, sections `Local\N01s3_%d`, and the `ping` flood. The `%d` and the `N01S3` token are the fingerprints of fake.
- **Real routines** use a *fixed, hardcoded* artifact name and write a single fixed **6-byte** value. No format string, no `N01S3`.

So inside each `Generate*` function you look for the one `mov`/`lea` sequence that loads a constant 6-byte blob into the buffer that gets written to the artifact. Disassembling each function yields the exact bytes. Mapping them out:

| Order | Frag | Routine / mechanism | Artifact location | Stored bytes | ASCII |
|------:|------|---------------------|-------------------|--------------|-------|
| 1 | **R**  | `GenerateRegistryArtifact` | `HKCU\Software\Policies\Microsoft\CloudFiles` value `DiagnosticData` | `27 60 25 4C 60 30` | `` '`%L`0 `` |
| 2 | **KO** | `NtCreateSymbolicLinkObject` (symlink `CTF.AsmListCache.FMPWinlogon` → `\BaseNamedObjects\9cGb0c`) | Object Manager namespace | `39 63 47 62 30 63` | `9cGb0c` |
| 3 | **D**  | `GenerateADSArtifact` | NTFS ADS `C:\Users\Public\Downloads\config.ini:hidden` | `30 33 60 38 30 39` | `` 03`809 `` |
| 4 | **EL** | `GenerateEventLogArtifact` | fake "Application Error" event, *faulting module path* field | `63 43 35 30 43 5F` | `cC50C_` |
| 5 | **M**  | `GenerateMemoryArtifact` | named section `Local\9cGb0c`, payload at offset `+0x250` | `5F 64 45 62 43 4E` | `_dEbCN` |

A couple of the gotchas worth calling out, because they're the kind of thing that costs an hour if you don't read carefully:

- **KO**: the symlink *name* `CTF.AsmListCache.FMPWinlogon` is window dressing; the fragment is the **target** it points at, `\BaseNamedObjects\9cGb0c`, and specifically the `9cGb0c` leaf. The model initially grabbed the symlink name as the fragment. The corrective is the same as always — the value is the data, not the label.
- **EL**: the bytes live in the *faulting module path* field of a forged "Application Error" event, not in the message body. If you reconstruct the event from the dump you have to look at the right field.
- **M**: the section `Local\9cGb0c` reuses the same `9cGb0c` token as the KO target (cute misdirection), but the actual six bytes sit at **offset +0x250** into the section, not at the start.

Notice that the cross-cutting reuse of `9cGb0c` is a deliberate trap: it appears as a literal fragment (KO), as a symlink target, and as a section name (M). Treating "I've seen `9cGb0c` before, it must be the answer everywhere" as a heuristic gets you a wrong M fragment. Each artifact has to be read on its own terms.

### Decoding: it's ROT47

Every fragment byte falls in the printable range `0x21–0x75`, and the noise marker `N01S3}` is itself leetspeak — both are hints that the encoding is a printable-ASCII rotation. The classic one over the `0x21–0x7E` band is **ROT47** (rotate by 47 within the 94 printable chars). Applying it to each fragment and concatenating in the given order R · KO · D · EL · M produces a clean `V1T{...}`, which is the verification that the encoding guess is right.

Here is the complete, runnable end-to-end decoder. Feed it the five fixed byte-strings recovered from the disassembly and it prints the flag:

```python
#!/usr/bin/env python3
# Green Goblin — decode the 5 fixed fragments carved from GreenGoblin.exe.
# Each value is the hardcoded 6-byte blob written by one real Generate* routine
# (noise routines use %d names + the N01S3 marker and are ignored).

def rot47(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 0x21 <= o <= 0x7E:          # ROT47 operates on the 94 printable chars
            out.append(chr(0x21 + (o - 0x21 + 47) % 94))
        else:
            out.append(c)
    return ''.join(out)

# Fragment -> the exact 6 bytes the real routine writes, as recovered from r2.
fragments = {
    'R':  bytes([0x27, 0x60, 0x25, 0x4C, 0x60, 0x30]),  # GenerateRegistryArtifact
    'KO': bytes([0x39, 0x63, 0x47, 0x62, 0x30, 0x63]),  # NtCreateSymbolicLinkObject target
    'D':  bytes([0x30, 0x33, 0x60, 0x38, 0x30, 0x39]),  # GenerateADSArtifact
    'EL': bytes([0x63, 0x43, 0x35, 0x30, 0x43, 0x5F]),  # GenerateEventLogArtifact (faulting module path)
    'M':  bytes([0x5F, 0x64, 0x45, 0x62, 0x43, 0x4E]),  # GenerateMemoryArtifact (section +0x250)
}

order = ['R', 'KO', 'D', 'EL', 'M']   # assembly order given in the prompt

flag = ''
for label in order:
    cipher = fragments[label].decode('latin-1')
    plain  = rot47(cipher)
    print(f"{label:>2}: {cipher!r:12} -> {plain}")
    flag += plain

print("\nFLAG:", flag)
```

Output:

```
 R: "'`%L`0"     -> V1T{1_
KO: '9cGb0c'     -> h4v3_4
 D: '03`809'     -> _b1g_h
EL: 'cC50C_'     -> 4rd_r0
 M: '_dEbCN'     -> 05t3r}

FLAG: V1T{1_h4v3_4_b1g_h4rd_r005t3r}
```

The flag reads as leetspeak "i have a big hard rooster." The entire difficulty of the challenge was **separating signal from noise** — the encoding itself was vanilla ROT47, and the only reliable way to find the five real six-byte writes was to read the dropper's own code rather than the dump's flooded artifacts.

## Flag

```
V1T{1_h4v3_4_b1g_h4rd_r005t3r}
```

## Lessons learned - prompting the AI

Whenever you face a **memory-forensics-with-decoys** challenge — a RAM dump (or disk image) where N fragments are hidden across distinct OS-internal artifact types and buried under a flood of decoy entries — the win condition is almost never "find the flag in the dump." It's "find the *planter* and read its source of truth." The model is fast and tireless at the mechanical half (running Volatility plugins, diffing process lists, reading disassembly) but wrong-by-default on the three judgment calls this class always hides: which artifacts are real, which noise is bait, and which token in a routine is the *value* versus the *label*. Below is the playbook, written so it drops onto the next dump-with-decoys challenge unchanged.

**1. Reusable, copy-pasteable prompts for this class.**

Lead with the label/artifact mapping so every later step has a destination instead of grepping blindly:

> "This is a memory dump with N fragments hidden across OS-internal artifact types, each keyed by a short label (here: R, KO, D, EL, M). Decode the labels as artifact *types* first — R=Registry value, KO=Kernel Object (object-manager symlink/section), D=NTFS alternate Data stream, EL=Event Log, M=named Memory section — and for each one give me the exact Volatility 3 plugin or technique that enumerates it. Do NOT search for the flag yet. Build the checklist."

Then force the pivot from grepping the dump to reversing the planter, and hand it the decoy-vs-real fingerprint so it can filter inside the disassembly:

> "Every artifact type is flooded with decoy entries (marker token: `N01S3`), so `strings`/`printkey`/`registry` enumeration is a trap. Instead: `windows.filescan` for the dropper EXE, `windows.dumpfiles` to carve it, `file` to confirm the toolchain, then disassemble. If it's MinGW/GCC the DWARF symbols give real function names. The real fragments are the FIXED bytes hardcoded in the `Generate*Artifact` routines; decoy routines use `%d`/`%s` format-string names and write the marker token. For each real routine, give me the single fixed N-byte value it writes and the artifact it writes it to."

For the encoding step, make the model justify the cipher from the byte range rather than guessing:

> "Here are the N recovered fixed byte-strings. Tell me the printable-ASCII range they fall in. If they're all inside `0x21–0x7E`, try ROT47 first (and only then ROT13/Caesar/XOR-with-printable). Decode each fragment, concatenate in the given label order, and show me the result — it must be a well-formed flag with matching braces."

**2. What to tell the model to focus on — and the dead-ends to pre-empt up front.** Focus it on: the diff between active and pool-scan process/handle lists (`pslist` vs `psscan`, `handles` vs `objects`), the planting binary's symbols, and the structural difference between parameterized decoy writes and fixed-value real writes. Pre-empt these classic dead-ends of the dump-with-decoys class *in the first prompt* so it doesn't wander into them:

- "The high-volume uniform burst (here: 24× `PING.EXE` in a 20-second window) is decoy noise. Do NOT analyze ICMP/packet timing/payloads as covert exfil." (Loud, uniform, short-lived bursts are bait in this class — real exfil doesn't announce itself.)
- "Do NOT read fragments directly from the live registry/section/ADS dumps — they're flooded with `N01S3` decoys. The dump is a hall of mirrors; the planter code is ground truth."
- "Do NOT go hunting for custom Volatility symbol tables (ISF). Confirm the build with `windows.info`; a stock build number resolves with stock symbols."
- "Do NOT assume one fragment per `Generate*` function. Read `wmain`/`main` to the end — some artifacts (the kernel-object one here) are planted inline with a raw syscall like `NtCreateSymbolicLinkObject`, not in a named routine, so the function count can be smaller than N."

**3. How to verify the model's output so you catch hallucinations.** This class gives you a cheap, self-checking oracle — use it ruthlessly:

- *Range check:* every real fragment byte must sit in the printable band (`0x21–0x7E`). A "fragment" the model returns that contains nulls, high bytes, or looks like a readable artifact *name* (e.g. it tried to hand you `CTF.AsmListCache.FMPWinlogon` or `Local\9cGb0c`) is a label, not a value — reject it. The fragment is always the *data the routine writes*, never the artifact's name or path.
- *Count check:* if the number of recovered fragments ≠ N, re-read the **caller** (`wmain`/`main`), not the callee list — the missing one is usually an inline syscall. Do not let the model conclude "there are only N-1 fragments."
- *Decode oracle:* the final concatenation must produce a well-formed flag (correct wrapper, matching braces, readable leetspeak/English) in the given label order. If it doesn't, either a byte string is wrong or the order/transposition is wrong — both are caught here. This is the same trick that confirms the cipher guess, so it costs nothing to run after every change.
- *Reuse-trap check:* if the same token appears in multiple artifacts (here `9cGb0c` is both a literal fragment and a decoy section/symlink name), make the model decode each occurrence independently. "I've seen this token before, it's the answer everywhere" is a guaranteed wrong fragment in this class.

**4. Fast-path prompt recipe for the class.** *"Memory dump + N labeled fragments across OS-internal artifact types: map each label to its artifact type and enumeration plugin; ignore the high-volume uniform decoy burst and the `N01S3`-marked flooded artifacts; carve and reverse the planter (DWARF symbols name the functions), take the FIXED bytes hardcoded in each real `Generate*` routine (the `%d`/marker ones are noise, and one artifact may be planted inline via a raw syscall, so read the caller to the end); recover each value not its name, confirm every byte is `0x21–0x7E`, then ROT47-decode all fragments in the given order into a valid flag as the self-check."*
