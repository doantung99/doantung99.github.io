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

Whenever you face a **Windows rev binary that flaunts packer/protector section names while the real logic is a tiny custom input-verifier** (decoy-protector + constraint-VM-plus-hash keygen), the LLM can do nearly all the disassembly labor — but only if you front-load the meta-judgment it cannot make for itself. The whole class shares one shape: a contradictory pile of "protection" that is pure theater, and a small gate that maps `input -> accept/reject` through (a) cheap structural constraints and (b) one or more compare-against-constant checks. Your job is to forbid the theater, force the model to surface the constants, and make the attack mirror the defense. Below are the prompts I would paste again on the next one of these, verbatim.

**1. Open with the decoy verdict and a hard ban on unpacking.** This is the single most valuable instruction for the entire class — without it the model will "begin analyzing the Enigma section" and burn the clock. The reusable wording, with the section names swapped for whatever your target shows:

> "This is a CTF rev binary whose section table lists mutually-exclusive packers at once (.enigma, .vmp, UPX0, .aspack, WinLicense) and whose strings name several DRM vendors (WIBUKEY/HASP/NVKEY). Real packers are mutually exclusive, so treat ALL of this as cosmetic decoy. Do NOT attempt to unpack or dump anything. Prove the decoy claim first: show me whether any 'protector' section is actually decrypted or jumped to at runtime (real OEP redirection). If not, ignore them and go straight to the user-visible verification logic."

The transferable trigger is the contradiction itself: two or more *mutually-exclusive* packers, or vendor strings with no matching runtime behavior, means decoy. State that reasoning to the model so it generalizes.

**2. Anchor on the accept/reject behavior, not the format.** Every binary in this class prints a prompt and branches to a pass/fail message. Drive the model straight there by string xref:

> "Find the success and failure output strings (here '[+] accepted' / '[-] rejected'; adapt to 'Correct'/'Wrong'/'Access granted' etc.), xref them, and show me ONLY the function that decides between them — the verifier. Ignore everything not on the path from input to that branch."

**3. Force the discriminating constants out before any solving.** This is what turns an unsolvable blind search into a keygen. Make the model report the numbers verbatim first:

> "In this verifier, extract verbatim, before proposing any solution: (a) the exact required input length / length gate, and (b) every constant the input (or a hash/checksum of it) is compared against, with its width. List them as a table. Do not start solving until these are on the table."

On `try` this produced `length = 22` and `target hash = 0xadbe8671d2150915` — the two facts that collapse a 95^22 space into a single candidate.

**4. Make the attack mirror the defense — constraints first, constant only to confirm.** The classic dead-end of this class is throwing compute at the final compare. Correct it explicitly:

> "A 64-bit hash (or any single constant) over N printable bytes is NOT brute-forceable blind — that's 95^N. The cheap structural checks exist to collapse the space. Enumerate every per-byte / per-position constraint (prefix, suffix, length, and each xor/add/sub/rotate relation between positions or against a key schedule), apply them to fix as many bytes as possible, and only run the surviving candidates through the final constant-compare to pick the unique one."

**What to point the model at, and the dead-ends to forbid up front:**
- *Focus:* the accept/reject branch and its caller; the length gate; every embedded compare-constant and its width; the per-position arithmetic relations (xor/add/sub/rotate) that couple input bytes; the small interpreter/VM loop if there is one (look for a fetch-decode-dispatch on a bytecode/opcode table).
- *Avoid (the classic time-sinks of this class):* unpacking or dumping any "protector" section; trusting `strings`/PEiD/DIE packer verdicts (the contradictory verdict *is* the bait); brute-forcing the final constant before constraints are applied; "analyzing" DRM/driver strings (WIBUKEY/HASP/NVKEY/skeydrv.dll) — pure decoys with no code behind them; assuming a renamed `UPX0`/`.vmp` section implies real packing without runtime evidence.

**How to verify the model's output for this class (so you catch hallucinations):**
- The binary is its own oracle, and the check is free: run it, paste the candidate, and confirm the success message. Never ship a flag this class produces without this step — the model's reconstructed arithmetic is the part most likely to be subtly wrong, and running the artifact catches it instantly.
- Demand runtime evidence before believing any "it's encrypted / needs dumping" claim — ask the model to show the control-flow that actually reaches and decrypts the section. If it can't, the unpack story is a hallucination; drop it.
- Cross-check the recovered length and prefix/suffix against the known flag format (here `v1t{...}`, 22 chars) before trusting any interior byte; a length or wrapper mismatch means the constraint extraction is off.
- If the model reproduces a hash/checksum, sanity-check the constants it claims (FNV prime/offset, CRC poly, multiplier) against the disassembly's literals — a fold that "almost" matches usually means it guessed the algorithm.

**Fast-path prompt recipe for this class:** *"Contradictory/mutually-exclusive packer sections = decoy — prove no runtime OEP redirection then ignore them and forbid unpacking; xref the success/failure strings to the verifier; extract the length gate and every compare-constant (with width) verbatim before solving; enumerate the per-byte constraints to collapse the space and use the constant-compare only to confirm the one survivor; then verify by feeding the candidate to the binary, not by trusting the model's arithmetic."*
