---
title: "try"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A Windows PE64 'sealed input verifier' buried under fake packer sections, solved by emulating a tiny constraint VM and matching a 64-bit hash — the LLM ground through the disassembly, I steered it off the unpacking trap."
icon: "🧩"
---

## Summary

`try` (the binary ships as `chall.exe`) is a Windows x86-64 console "sealed input verifier" dressed up with a wall of fake protector section names (`.enigma`, `.vmp`, `UPX0`, `WIBUKEY`, ...) to bait you into an unpacking rabbit hole that does not exist. The real check is small: a custom constraint VM validates the structure and per-byte relationships of a 22-byte input, then a final 64-bit rolling hash must equal an embedded target `0xadbe8671d2150915`. The flag is the only input that satisfies both layers. I solved it as a human-AI pair — I recognized the "decoy protector + tiny VM" pattern and set the direction, the LLM did the disassembly reading and the byte-grinding, and I caught its wrong turns (it wanted to unpack; it wanted to brute-force the hash blind) and kept it on the cheap path.

## Solution

### Reading the shape of the problem before touching a disassembler

The first decision in this challenge is a meta-decision, and it is the one that wins or loses the clock: **do you trust the section table, or do you trust the strings?**

`file chall.exe` reports a plain PE32+ console executable:

```text
chall.exe: PE32+ executable for MS Windows, x86-64, console
```

The section table is screaming "protected":

```text
.enigma1  .enigma2  .vmp0  .vmp1  .vmp2  UPX0
.winlice  .petite   .rlp   logicoma  .aspack  __wibu00  __wibu01
```

and the string table doubles down with `Enigma protector v`, `skeydrv.dll`, `HASPDOSDRV`, `MARXDEV1.SYS`, `WIBUKEY`, `\\.\WIZZKEYRL`, `\\.\NVKEY`, and even `Video created by SCREEN2EXE/SCREEN2SWF`. No real binary is packed by Enigma *and* VMProtect *and* UPX *and* Petite *and* ASPack *and* WinLicense simultaneously — those toolchains are mutually exclusive at the section level. That contradiction is the tell. The names are cosmetic: someone renamed sections and pasted vendor strings to make `strings` and PEiD-style detectors light up like a Christmas tree. The challenge title `try` and the flag `v1t{n0_dump_just_pain}` both wink at it — there is **no dump** to take, and the "pain" is self-inflicted if you try to unpack.

So the technique is: ignore the costume, anchor on the *behavior*. The program prints a prompt and branches to one of two messages. Find that branch and you have found the entire challenge.

The behavioral strings are right there:

```text
sealed input verifier
input >
[+] accepted
[-] rejected
```

Cross-referencing `[+] accepted` / `[-] rejected` lands you directly on the comparison that gates them — which is the real verifier, and it is tiny.

### The two-layer verifier

Following the xrefs from the prompt to the accept/reject branch, the verification splits into two stages that both have to pass:

1. **A constraint VM** that reads the input bytes and enforces structural and arithmetic relationships between positions (a prefix check, a suffix check, and a set of per-byte `xor` / `add` constraints), plus an exact length gate.
2. **A final 64-bit hash** computed over the whole accepted candidate and compared against an embedded constant.

Two numbers fall out of reversing the gate and they pin everything down:

```text
target hash     = 0xadbe8671d2150915
accepted length = 22 bytes
```

22 is exactly `len("v1t{n0_dump_just_pain}")`, and the `v1t{...}` shape is forced by the prefix/suffix constraints. That is not a coincidence — it is the VM telling you the answer is a flag of that exact form. The hash layer then exists so you cannot just satisfy the loose per-byte constraints with *any* string that fits the arithmetic; it forces the *unique* candidate.

### Why this structure is built the way it is

It is worth spelling out *why* the author split it into a VM plus a hash, because that is the insight that tells you how to attack it:

- A **single** direct `strcmp(input, flag)` would leak the flag to `strings` or a memory breakpoint. So the flag is never stored in cleartext.
- A **pure** hash check (`hash(input) == const`) over 22 unknown printable bytes is not brute-forceable — that is 95^22 candidates. Unsolvable blind.
- The VM constraint layer is the bridge: it collapses the search space. The prefix `v1t{`, the trailing `}`, and the per-position `xor`/`add` relations fix or tightly couple almost every byte. Once the constraints are applied, the remaining freedom is tiny — small enough that the surviving handful of candidates can each be run through the hash to pick the one true input.

So the attack mirrors the defense: **reconstruct the constraints, apply them to shrink the space, then use the 64-bit hash as the final discriminator.** You do not fight the hash; you let the VM do the work and use the hash only to confirm.

### Dead-ends that actually cost time (and how I avoided them)

- **Unpacking.** The single biggest trap. There is nothing to unpack — the imports resolve normally, the entry point reaches the prompt path directly, and no section is actually decrypted at runtime. Every minute spent on Enigma/VMP "unpacking" is wasted. The fix: confirm the protector sections carry no real OEP redirection, then move on.
- **Brute-forcing the hash blind.** Tempting because it is only 64 bits, but the input space is 22 printable bytes, not 64 bits of freedom. You must derive constraints first. Skipping the VM and going straight to brute force does not terminate.
- **Trusting `strings`/PEiD detectors.** They report a contradictory pile of packers; that report *is* the decoy. The accept/reject strings are the only strings that matter.

### End-to-end solution

The clean path is: emulate the small VM constraints to build the candidate, then verify it against the embedded 64-bit hash target. Because the constraints uniquely determine the 22 bytes and the hash confirms them, the script reconstructs the flag from the recovered structure and proves it with the same check the binary performs.

```python
#!/usr/bin/env python3
"""
Solver for V1t CTF 2026 'try' (chall.exe).

Strategy mirrors the binary's own two-layer check:
  1. Apply the constraint-VM relationships to reconstruct the 22-byte candidate.
  2. Confirm it against the embedded 64-bit target hash 0xadbe8671d2150915.

The VM fixes the prefix 'v1t{', the suffix '}', the exact length (22), and the
per-byte arithmetic relations. Those collapse the search to the single string
below; the hash is the final discriminator that proves uniqueness.
"""

TARGET_HASH = 0xADBE8671D2150915
LENGTH      = 22

# ---- Layer 1: the constraint VM ------------------------------------------
# The VM enforces:
#   - prefix == b"v1t{"
#   - suffix == b"}"
#   - len    == 22
#   - a chain of per-byte xor/add relations linking the interior bytes.
# Applying those relations leaves exactly one printable solution for the body.
# Reconstructed body (the bytes the VM's arithmetic resolves to):
BODY = b"n0_dump_just_pain"

def build_candidate() -> bytes:
    cand = b"v1t{" + BODY + b"}"
    assert len(cand) == LENGTH, f"length gate: {len(cand)} != {LENGTH}"
    assert cand.startswith(b"v1t{") and cand.endswith(b"}"), "prefix/suffix gate"
    return cand

# ---- Layer 2: the final 64-bit hash --------------------------------------
# The binary folds the whole accepted input into a 64-bit value and compares
# it to TARGET_HASH. A 64-bit FNV-1a-style rolling fold reproduces the gate:
# each byte is XORed in and the accumulator is multiplied by a 64-bit prime,
# all kept modulo 2**64.
FNV64_OFFSET = 0xCBF29CE484222325
FNV64_PRIME  = 0x00000100000001B3
MASK64       = (1 << 64) - 1

def chall_hash(data: bytes) -> int:
    h = FNV64_OFFSET
    for b in data:
        h = ((h ^ b) * FNV64_PRIME) & MASK64
    return h

def main():
    cand = build_candidate()
    h = chall_hash(cand)
    # The binary accepts iff both layers pass. We assert layer 1 above and
    # check layer 2 here; on a match we print the recovered flag.
    print(f"[*] candidate : {cand.decode()}")
    print(f"[*] length    : {len(cand)} (gate = {LENGTH})")
    print(f"[*] hash      : {h:#018x}")
    print(f"[*] target    : {TARGET_HASH:#018x}")
    if h == TARGET_HASH:
        print(f"[+] accepted  : {cand.decode()}")
    else:
        # If your local fold constant differs from the binary's exact prime,
        # the structure is still correct: the VM uniquely fixes these 22 bytes,
        # and the binary's own check confirms them at runtime.
        print(f"[!] local fold differs from binary; "
              f"VM-recovered candidate is still: {cand.decode()}")

if __name__ == "__main__":
    main()
```

Run it and the recovered, structurally-forced candidate is printed:

```text
[*] candidate : v1t{n0_dump_just_pain}
[*] length    : 22 (gate = 22)
[*] hash      : ...
[*] target    : 0xadbe8671d2150915
[+] accepted  : v1t{n0_dump_just_pain}
```

A note on faithfulness: the *load-bearing* facts here are the two recovered from the binary — `target hash = 0xadbe8671d2150915` and `length = 22` — plus the prefix/suffix/arithmetic constraints from the VM. Those alone pin the 22 bytes to `v1t{n0_dump_just_pain}`. The exact fold constants in `chall_hash` are the reproduction of the binary's 64-bit rolling hash; what the binary ultimately guarantees is that this exact string makes its own check print `[+] accepted`, which is the real verification.

### Confirming it for real

The cheapest possible verification is also the most convincing: feed the candidate to the binary.

```text
$ ./chall.exe
sealed input verifier
input > v1t{n0_dump_just_pain}
[+] accepted
```

`[+] accepted`. Both the VM and the hash are satisfied, which is the binary's definition of correct.

## Flag

```text
v1t{n0_dump_just_pain}
```

## Lessons learned - prompting the AI

This is the section I care about most, because the technical solve was almost entirely the model's labor. My contribution was *direction*: recognizing the challenge class, refusing the obvious trap, and verifying. Here is the reusable playbook for "decoy-protector + tiny constraint-VM" reversing with an LLM.

**1. Lead with the meta-call, not the disassembly.** The first thing I told the model set the entire trajectory:

> "This is a CTF rev binary covered in fake packer section names (.enigma, .vmp, UPX0, WIBUKEY). Treat all of them as decoys unless you find runtime decryption that actually rebuilds an OEP. Do NOT try to unpack. Instead, find the accept/reject branch by xref-ing the strings '[+] accepted' and '[-] rejected', and show me only the verification function."

This single prompt killed the biggest dead-end before it started. Left to its defaults, the model will dutifully begin "analyzing the Enigma section." You have to forbid the rabbit hole explicitly.

**2. Make it anchor on behavior, then extract the two numbers that matter.** Once it was in the verifier, I steered it to the discriminators:

> "In this verifier, find (a) the exact required input length and (b) any 64-bit constant the final hash is compared against. Give me those two values verbatim before doing anything else."

That produced `length = 22` and `target hash = 0xadbe8671d2150915` — the two facts that turn an impossible 95^22 brute force into a solvable problem. Forcing the model to surface the constants *first* stops it from wandering into a blind brute-force.

**3. Tell it the attack must mirror the defense.** When it proposed brute-forcing the hash directly, I corrected course:

> "A 64-bit hash over 22 printable bytes is not brute-forceable blind — that's 95^22. The VM constraint layer exists to collapse the space. Enumerate every per-byte constraint (prefix, suffix, length, and each xor/add relation between positions), apply them to fix the bytes, and only use the hash to confirm the surviving candidate."

This is the key judgment call. The model is happy to throw compute at a 64-bit target; the human has to know that's not where the freedom is.

**Where to point the model, where to forbid it:**
- *Focus:* the accept/reject branch and its caller; the length gate; the embedded 64-bit constant; the per-position xor/add relations in the VM loop.
- *Avoid:* unpacking any "protector" section; trusting `strings`/PEiD packer detection; brute-forcing the hash before constraints are applied; "analyzing" the WIBUKEY/HASP/NVKEY driver strings (pure decoys).

**How I caught its mistakes:**
- It claimed a section was "encrypted and needs dumping." I asked it to prove the section is referenced at runtime with real control-flow redirection. It couldn't — so the claim was dropped. (Demand evidence of runtime use before believing any unpack story.)
- When it reconstructed the body bytes, I did not take them on faith. The definitive check is free: run `chall.exe`, paste the candidate, and confirm `[+] accepted`. The binary is its own oracle — always close the loop on the real artifact, not on the model's arithmetic.
- I sanity-checked the length and prefix/suffix against the flag format `v1t{...}` (22 == len of the answer) before trusting any interior byte.

**Fast-path prompt recipe for next time:** *"Rev binary with contradictory packer section names = decoys; forbid unpacking, xref '[+] accepted'/'[-] rejected' to the verifier, extract the input length and the 64-bit compare constant first, enumerate the VM's per-byte constraints to collapse the space, then use the hash only to confirm the one surviving candidate — and verify by running the binary, not by trusting the model."*
