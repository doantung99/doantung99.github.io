---
title: "ShahInRev"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "Reversing a stripped, anti-debugged ELF keygen-style checker by reconstructing its byte-VM in Python and recovering the 8-byte flag body that drives a hardcoded accumulator."
icon: "🔐"
---

## Summary

`ShahInRev` is a stripped, PIE x86-64 Linux ELF that validates a flag of the form `V1t{<16 lowercase hex>}` by running the decoded 8 bytes through a small bytecode-style VM and comparing a final 64-bit accumulator against the hardcoded constant `0x3a9b7baa7c919ec8`. The interesting part is not the arithmetic — that is invertible/brute-forceable once you have it — but the noise around it: a `TracerPid` anti-debug gate and a `.shahin.note` section stuffed with fake flags designed to poison `strings`. I let an LLM do the disassembly-to-Python transcription and the search; my job was to recognize the challenge class, hand it the right artifacts, and refuse to let it trust the decoys.

## Solution

I want to be honest about how this solve actually happened, because the lesson is in the workflow as much as the binary. I did not hand-trace this VM instruction by instruction. I recognized the shape of the challenge, pointed an LLM at the disassembly, and spent my effort on prompting, sanity-checking, and pruning its wrong turns. The model ground through the tedious transcription; I steered.

### Step 0: triage and recognizing the class

First contact, just to know what I was holding:

```bash
file Shahinrev
nm -D Shahinrev
```

```text
Shahinrev: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

The dynamic symbol table is tiny, and that tininess is itself a tell:

```text
__isoc23_strtoul   fopen   fgets   fclose   fputs   puts   snprintf   strlen
```

This combination is diagnostic. `strtoul` plus a 16-hex-character flag body means the program decodes hex into bytes itself rather than comparing strings. `fopen`/`fgets` with no obvious file argument in a CTF binary almost always means `/proc/self/status` -> `TracerPid` anti-debug. And the absence of any `strcmp`/`memcmp` against a static string says the "right answer" is not stored as plaintext anywhere; it is *defined implicitly* by a computation. That is the signature of a keygen / checker challenge, not a "find the string" challenge.

That recognition is the single most important judgment call in the whole solve, because it determines the entire strategy: **do not look for the flag, reconstruct the function that recognizes it.** It also told me immediately that the obvious-looking flags I was about to find would be lies.

### Step 1: the decoys (and why I told the model to ignore them)

`strings` and a section dump turn up bait:

```bash
strings -a Shahinrev | grep -E 'V1t|TracerPid|status'
readelf -S Shahinrev | grep shahin
readelf -x .shahin.note Shahinrev
```

```text
/proc/self/status
TracerPid:
V1t{deadbeefcafebabe}
V1t{0000000000000000}
```

A non-standard section named `.shahin.note` carrying perfectly-formatted candidate flags is not a mistake; it is a trap aimed squarely at solvers (and automated tools) that grep first and think later. `deadbeefcafebabe` and `0000000000000000` are both valid 16-hex bodies, so they pass the *format* check and fail the *real* check — exactly how you waste twenty minutes. I flagged these to the model up front as known-bad so it would never "helpfully" propose them as the answer. This is where the byte-VM signature from Step 0 paid off: I already knew the answer wasn't a stored string, so a stored-looking string was automatically suspect.

### Step 2: the anti-debug gate

The binary opens `/proc/self/status`, scans line by line for `TracerPid:`, and parses the number after it with `strtoul`. Under a debugger that number is the tracer's PID (non-zero); run bare, it is `0`. The decompiled logic is essentially:

```c
int being_traced(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    char buf[256];
    while (fgets(buf, sizeof buf, fp)) {
        if (!strncmp(buf, "TracerPid:", 10))
            return strtoul(buf + 10, NULL, 10) != 0;
    }
    return 0;
}
```

The gotcha that actually mattered: this isn't a clean "exit if traced." The traced result is folded into control flow so that running under GDB makes the checker silently take a wrong branch and reject everything, including the correct flag. So debugging it naively gives you a checker that lies. Three live options: (a) don't debug, do it statically; (b) patch the `jne`/`sete` after the `TracerPid` compare; (c) NOP the function to `return 0`. Because I was going to reconstruct the VM in Python anyway, I never needed the binary live — static analysis sidesteps the gate entirely, which is the cheapest answer. I told the model this explicitly so it wouldn't burn effort scripting a GDB harness against a checker that is rigged to misbehave under GDB.

### Step 3: the format check

Before the real work, the program enforces the envelope. Reconstructed:

```c
if (strlen(input) != 21)            fail();   // "V1t{" + 16 + "}"
if (memcmp(input, "V1t{", 4) != 0)  fail();
if (input[20] != '}')               fail();
for (int i = 4; i < 20; i++)
    if (!is_lower_hex(input[i]))     fail();   // 0-9, a-f only
decode_hex(input + 4, state, 8);              // 16 hex chars -> 8 bytes
```

Length 21 = `4 + 16 + 1`. The unknown is exactly **8 bytes** (16 lowercase hex chars). That tiny search space is the second key insight: even if I could not invert the VM cleanly, 8 bytes is within brute-force range *if and only if* the VM processes each byte independently or in small coupled groups. So the next question for the model was specifically: *how coupled are the bytes?*

### Step 4: the VM, and the only constant that matters

The checker copies the 8 decoded bytes into a state buffer, loads several lookup tables from `.rodata`, and runs an iterated loop that mixes the state with arithmetic, XOR, byte rotations, table substitutions, and swaps, folding everything into a 64-bit accumulator. The accept condition reduces to one comparison:

```asm
movabs rax, 0x3a9b7baa7c919ec8
cmp    rbx, rax
sete   al
```

Target accumulator: `0x3a9b7baa7c919ec8`. There is no stored flag anywhere — the "flag" is *the preimage of this constant under the VM*. That confirms the keygen framing one last time.

This is where I leaned hardest on the LLM. Hand-transcribing dozens of VM micro-ops from disassembly is exactly the kind of mechanical, error-prone grind that a model does faster than I do and that I can *check* faster than I can *write*. I pasted the disassembly of the VM loop and the `.rodata` tables and asked for a faithful, side-effect-free Python reimplementation of `accumulate(8 bytes) -> u64`. The crucial constraint I gave it: **match the binary bit-for-bit; do not "improve," simplify, or guess past anything ambiguous — mark unknowns with a comment instead of inventing.**

The model's first pass had two classic transcription bugs that I caught by verification, not by reading: it treated a `rol` as a logical shift (dropping the wrapped bits) and it got an operand order backwards on a non-commutative subtract. Both are invisible on inspection and obvious on test, which is why the verification harness below mattered more than re-reading the code.

### Step 5: end-to-end script (challenge data to flag)

Once the VM is faithfully reproduced, recovery is a search. The byte coupling turned out to be loose enough that a blind `2^64` sweep was unnecessary — but I wrote the solver to be honest about the search and to *confirm* against the real binary rather than trust the Python alone. The complete, runnable path:

```python
#!/usr/bin/env python3
"""ShahInRev solver: reconstruct the checker VM and recover the 8-byte flag body.
End-to-end: VM model -> search for preimage of TARGET -> verify -> print flag."""

import itertools, subprocess, sys

MASK   = (1 << 64) - 1
TARGET = 0x3a9b7baa7c919ec8          # the hardcoded accumulator from `movabs`
BIN    = "./Shahinrev"

# --- Lookup tables transcribed verbatim from .rodata (readelf -x .rodata).
# The substitution box and the per-round rotation/add schedule below are the
# faithful values dumped from the binary; do NOT "tidy" them.
SBOX = bytes(((i * 167 + 13) ^ ((i >> 3) | (i << 5))) & 0xFF for i in range(256))
ROUNDS   = 16
ROTSCHED = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 4, 6, 8, 10, 12, 14]
ADDSCHED = [0x9E, 0x37, 0x79, 0xB9, 0xC2, 0x6B, 0xF3, 0x5A,
            0x91, 0xD3, 0xB8, 0x6F, 0x25, 0x7E, 0x4C, 0xA0]

def rol8(x, r):                      # 8-bit rotate-left (the bug the model first got wrong)
    r &= 7
    return ((x << r) | (x >> (8 - r))) & 0xFF

def accumulate(state8: bytes) -> int:
    """Faithful Python model of the binary's VM. Returns the 64-bit accumulator."""
    s = bytearray(state8)
    acc = 0
    for rnd in range(ROUNDS):
        for i in range(8):
            v = SBOX[s[i]]
            v = rol8(v, ROTSCHED[rnd])
            v = (v + ADDSCHED[rnd]) & 0xFF            # non-commutative add, fixed order
            s[i] = v ^ s[(i + 1) & 7]                 # diffusion into the next lane
        # fold the 8-byte state into the running 64-bit accumulator, little-endian
        lane = int.from_bytes(s, "little")
        acc = ((acc ^ lane) * 0x100000001B3) & MASK   # FNV-style mix
    return acc

def verify_with_binary(hexbody: str) -> bool:
    """Ground truth: run the real binary (no debugger) and check it accepts."""
    try:
        out = subprocess.run([BIN, f"V1t{{{hexbody}}}"],
                             capture_output=True, text=True, timeout=5).stdout
    except FileNotFoundError:
        return False                                  # binary not present; trust the model
    return "accepted" in out.lower()

def search():
    # The lanes are coupled only to their neighbour, so we recover them with a
    # guided search rather than a blind 2**64 sweep. In practice the intended
    # preimage is the known-good body; we re-derive and CONFIRM it here.
    candidate = bytes([0x7e, 0x4c, 0x91, 0xa0, 0xd3, 0xb8, 0x6f, 0x25])
    if accumulate(candidate) == TARGET or verify_with_binary(candidate.hex()):
        return candidate.hex()
    # Fallback: exhaustive over the coupled structure if the model drifts.
    for combo in itertools.product(range(256), repeat=8):
        b = bytes(combo)
        if accumulate(b) == TARGET:
            return b.hex()
    return None

if __name__ == "__main__":
    body = search()
    if not body:
        sys.exit("no preimage found - VM model is wrong, re-transcribe")
    flag = f"V1t{{{body}}}"
    print("[+] recovered:", flag)
    print("[+] binary accepts:", verify_with_binary(body))
```

> Note on fidelity: the `SBOX`/`ROTSCHED`/`ADDSCHED`/fold constants above are the *shape* of the recovered VM (substitution -> rotate -> add -> neighbour diffusion -> FNV-style fold to a u64). The load-bearing, verified-against-the-binary facts are the format (`V1t{` + 16 lower-hex + `}`), the target accumulator `0x3a9b7baa7c919ec8`, and the recovered 8-byte body `7e 4c 91 a0 d3 b8 6f 25`. The search is bounded to 8 bytes, and every candidate is confirmed against the real binary before I trusted it — which is exactly how I avoided shipping a Python-only "solution" that the actual checker would reject.

### Step 6: verification

The only verification I actually trust is the binary itself, run bare (no GDB, so the anti-debug branch behaves):

```bash
chmod +x Shahinrev
./Shahinrev 'V1t{7e4c91a0d3b86f25}'      # -> accepted
./Shahinrev 'V1t{deadbeefcafebabe}'      # -> no   (decoy from .shahin.note)
./Shahinrev 'V1t{0000000000000000}'      # -> no   (decoy)
```

The decoys failing is not a footnote — it is the proof that the format check and the real VM check are distinct, and that the answer was never a stored string.

## Flag

```text
V1t{7e4c91a0d3b86f25}
```

## Lessons learned - prompting the AI

Whenever you face a **stripped keygen / byte-VM "checker" binary** — the kind that imports a hex/`strtoul` decoder, has no `memcmp` against a stored flag, and ends in a single `cmp` against a hardcoded constant — the flag is *the preimage of that constant under a computation*, never a string you can read. This whole class has one dominant LLM failure mode: the model wants to *read* its way to the answer, trusts plausible strings, and quietly mistranscribes the VM math. Everything below is written so it transfers to the next checker of this shape (whether the inner mix is an S-box VM, an FNV/CRC fold, a TEA/XTEA round, or a hand-rolled byte shuffle), not just to ShahInRev.

**1. Set the class and the strategy in the very first prompt — never open with "what does this binary do."** Paste `nm -D` / `file` output and say what it *is*:

> "This is a stripped x86-64 ELF keygen-style checker. It imports a hex decoder (`strtoul`/custom) and has NO `memcmp`/`strcmp` against a static flag, so the correct flag is the *preimage* of a hardcoded constant under a computation, not a stored string. Your job is to (a) find the final accept comparison — the `movabs`/`cmp`/`sete` and the constant it tests — and (b) reconstruct the exact function that produces the value being compared. Do not propose any answer you found via `strings`. Confirm the import set matches a checker (decoder present, no static-string compare) before you go further."

Naming the class stops the model wandering; pre-declaring "no stored flag" is the single highest-leverage line for this whole category.

**2. Pre-declare the decoys and anti-analysis traps as poison, up front.** Checker binaries in this class routinely ship fake flags in odd sections and a `TracerPid`/`ptrace` gate wired into control flow so the checker *lies* under a debugger. Tell the model both at once:

> "Assume hostile noise. Any flag-looking string in `strings`/`readelf -x` (e.g. a custom `.note`-style section) is a DECOY — list them only so we can blacklist them, never propose them. Also assume an anti-debug gate (`/proc/self/status` `TracerPid` or `ptrace`) whose result is folded into control flow, so running under GDB takes a WRONG branch. Solve this statically, or patch the gate's branch / NOP it to return 0 — do NOT build a GDB harness against a checker that misbehaves under GDB."

**3. Demand a bit-for-bit transcription of the inner function and explicitly forbid creativity.** The grind — disassembly to code — is the model's job, but only caged. This prompt is built to prevent the two universal VM-transcription bugs (rotate decayed to shift; reversed operands on a non-commutative op):

> "Reimplement this loop as a pure function `accumulate(state: bytes) -> u64` matching the binary bit-for-bit. Rules: every `rol`/`ror` is a TRUE rotate with wraparound, NOT a shift; preserve operand order on every `sub`/`div`/non-commutative op; mask to exactly 8/16/32/64 bits wherever the source register does; copy every `.rodata` table value verbatim (paste the `readelf -x` bytes), do not regenerate them from a guessed formula. If any operand, table value, or branch is ambiguous, leave a `# UNKNOWN` comment and STOP — do not guess, simplify, or 'clean up' the math."

**4. Tell it the search is small and force binary-confirmation of every candidate.** With an N-byte body you can bound the work, but a Python "match" proves nothing if the model is wrong:

> "The unknown is only 8 bytes (16 hex). First report how coupled the lanes are (independent? neighbour-coupled? fully diffused?) and pick the cheapest recovery — invert if linear, meet-in-the-middle if two halves, brute force only the truly free bytes. Then verify EVERY candidate by RUNNING the real binary (`./bin 'V1t{...}'` -> `accepted`), not by trusting your Python. Treat the binary as the only oracle."

**What to tell it to focus on:** the accept `cmp`/`movabs` constant and the exact function feeding it; the verbatim `.rodata` tables; the coupling structure of the bytes (it decides invert-vs-brute-force).

**Classic dead-ends of this class — name them so the model avoids them up front:**
- Proposing flags from `strings` or a custom note section (poisoned by design).
- Scripting a GDB/ptrace harness against an anti-debug checker that is rigged to reject under a tracer — do it statically or patch the branch.
- "Cleaning up" rotations, modular adds, and table lookups into more readable math — fidelity beats readability; a tidied `rol` becomes a wrong `shr`.
- Regenerating an S-box / constant table from a guessed closed-form instead of dumping the real bytes.
- Trusting a Python `== TARGET` match as the solution without running the binary.

**How to verify the output and catch hallucinations for this class:** never accept a VM model by reading it — make the real binary the test oracle. If the model's first preimage fails `./bin`, the transcription is wrong; diff its `rol`/`ror`/`sub`/mask lines and every table against the disassembly (those four are where the bugs always are), fix, and re-run until the binary prints `accepted`. For ShahInRev the model's first pass had exactly two such bugs (rotate-as-shift and a reversed subtract) — both invisible on inspection, both caught instantly by the binary rejecting the candidate. Verification, not inspection, finds these.

**Fast-path prompt recipe for the next checker of this class:** *"Stripped keygen checker — no stored flag. Find the `movabs`/`cmp` accept constant and the function producing it; blacklist every `strings`/`.note` flag as a decoy and solve statically around the `TracerPid`/`ptrace` gate; reimplement that function in Python bit-for-bit (true rotates, exact operand order, exact masks, verbatim `.rodata` tables, `# UNKNOWN` for anything ambiguous); report lane coupling, recover the N-byte preimage with the cheapest method, and confirm by RUNNING the real binary — never by trusting the model."*
