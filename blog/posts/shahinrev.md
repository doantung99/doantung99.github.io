---
title: "ShahInRev"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A stripped Linux ELF with anti-debug and decoy strings hid a VM-style checker over an 8-byte value; recover the inner hex that drives the accumulator to a hardcoded constant."
icon: "🛠️"
---

## Summary
ShahInRev shipped a stripped 64-bit PIE ELF that hides the real flag behind a `TracerPid` anti-debug check, a `.shahin.note` section full of decoy flags, and a VM-like checker over 8 input bytes. The job was to ignore the noise, model the checker's constraints, and recover the 16 lowercase hex characters that make its 64-bit accumulator land on `0x3a9b7baa7c919ec8`.

## Solution
I clocked this as a "stripped ELF crackme with deliberate distraction" the moment I saw the anti-debug and decoy hints, so I set the direction early: do everything statically, and trust nothing that `strings` surfaces. My job was steering and verification; the model did the grinding through the disassembly.

First I had the model triage the binary and confirm the shape of the problem: `file` and `nm -D` told us it was PIE, stripped, and imported only a handful of libc calls (`fopen`/`fgets`/`strtoul`/`snprintf`/`strlen`), with `/proc/self/status` and `TracerPid:` strings pointing straight at a debugger check. I asked it to dump the custom `.shahin.note` section, which is where I caught the first trap — it wanted to treat `V1t{deadbeefcafebabe}` and `V1t{0000000000000000}` as candidates. I corrected course: those are planted decoys, the real check is in code.

Next I had it isolate the input format from the real logic. The front-end check is mechanical — length 21, `V1t{` prefix, `}` suffix, and 16 lowercase hex characters in between — so the unknown is exactly 8 bytes. Then I asked the model to reverse the actual validator and stop describing it as a string compare. It's a small VM: the 8 decoded bytes are copied into a state buffer, lookup tables are loaded from `.rodata`, and a loop applies arithmetic/XOR/rotations/substitutions/swaps while folding a 64-bit accumulator. The load-bearing constraint is the final comparison:

```asm
movabs rax, 0x3a9b7baa7c919ec8
cmp    rbx, rax
sete   al
```

I had the model reconstruct the VM constraints and solve for the input that drives the accumulator to that constant; it produced the 8 bytes `7e 4c 91 a0 d3 b8 6f 25`. I verified by running the binary normally (no debugger, so the `TracerPid` check stays happy) and confirmed the decoys fail:

```bash
# Triage (static only — keep TracerPid happy by never attaching a debugger)
file Shahinrev
nm -D Shahinrev
readelf -x .shahin.note Shahinrev   # planted decoy flags — ignore

# Real input: V1t{ + 16 lowercase hex (8 bytes) + }
# VM accumulator target: 0x3a9b7baa7c919ec8  ->  bytes 7e 4c 91 a0 d3 b8 6f 25
INNER=$(printf '%02x%02x%02x%02x%02x%02x%02x%02x' 0x7e 0x4c 0x91 0xa0 0xd3 0xb8 0x6f 0x25)
FLAG="V1t{${INNER}}"

chmod +x Shahinrev
./Shahinrev "$FLAG"                      # -> accepted
echo "$FLAG"                             # -> V1t{7e4c91a0d3b86f25}

# Sanity: decoys are rejected
./Shahinrev 'V1t{deadbeefcafebabe}'      # -> no
./Shahinrev 'V1t{0000000000000000}'      # -> no
```

## Flag
```
V1t{7e4c91a0d3b86f25}
```
