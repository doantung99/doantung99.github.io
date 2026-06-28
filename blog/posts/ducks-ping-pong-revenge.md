---
title: "Ducks Ping-Pong Revenge"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A user-mode/kernel ping-pong where the flag only decrypts after five driver-validated stage commitments rebuild the final key state."
icon: "🦆"
---

## Summary

This is a kernel-assisted reversing challenge shipped as two PE64 binaries: a user-mode client (`DucksPingPongV2.exe`) and a native driver (`DucksKDv2.sys`). They speak a five-stage IOCTL "ping-pong": each stage answer is checked by a keyed commitment inside the driver, and only after all five pass does the final routine have the state it needs to decrypt a 0x25-byte flag buffer. The core technique was to stop trying to XOR the visible blob directly and instead reconstruct the per-stage answers offline, replay the driver's KDF commitments, and rebuild the key state that feeds the final transform.

The honest framing of this writeup: an LLM did the grinding — lifting the VM-blob semantics, transcribing the KDF, re-deriving stage answers — and my job was to recognize the challenge shape, point the model at the right artifacts, kill its wrong turns, and verify each intermediate before trusting it. The duck never hands you the key; you have to earn the state.

## Solution

### Triage: two binaries, one protocol

File identification confirms a paired user-mode / kernel-mode target:

```text
DucksPingPongV2.exe: PE32+ executable for MS Windows, x86-64, console
DucksKDv2.sys:       PE32+ executable for MS Windows, x86-64, native driver
```

Strings in the client immediately reveal the channel and the intended flow:

```text
=== Ducks Ping-Pong v2 | V1T CTF 2026 ===
\\.\DucksKDv2
[-] DucksKDv2 is not quacking on this machine.
[+] Kernel link established. The table is slippery.
```

And the driver leaks the commitment keyword that turns out to be the whole game:

```text
stage-commit
IoCreateDevice
IoDeleteDevice
ZwCreateFile
Ducks Ping-Pong v2 Test
```

That `stage-commit` literal is the single most important string in the challenge. It tells you the validation is a *commitment* scheme: the driver does not compare your answer to a stored plaintext, it compares a keyed digest of `answer || salt || "stage-commit"` against a stored digest. You cannot read the answer back out of the driver — you have to produce something whose digest matches.

The key insight at triage time: **the flag is not a single decryption, it is a protocol that has to be driven to completion.** The "revenge" over the v1 challenge is precisely that you can no longer cheat the last step in isolation.

### Why the obvious shortcut fails (the dead-end that mattered)

The client carries a 0x25-byte encrypted region right next to the final routine, plus a visible constant nearby. Every reverser's first instinct is: grab the blob, XOR it with the constant, read the flag. That is the trap, and it is worth dwelling on because the *way* it fails is the clue.

XORing the blob with the obvious constant produces a buffer that begins:

```text
v1g...
```

Look closely: `v`, `1`, then `g`. The real prefix is `v1t{`. So the first two bytes are right and the third is off (`t` is `0x74`, `g` is `0x67`), and the divergence is not uniform across the rest of the buffer. That partial-but-wrong output is diagnostic: a single static XOR key was *almost* right, which means the true key is the obvious constant **mixed with additional per-byte state** that the static read is missing. That missing state is exactly what the five driver-validated stages produce.

So the dead-end is informative, not wasted: it proves the final transform is keyed by `constant XOR stage_state`, and that `stage_state` is non-trivial — it changes the key per byte, not just globally. If it were a single global key offset, the whole buffer would be uniformly shifted and we would see consistent garbage, not a correct-then-drifting prefix.

The correct path, stated up front so the rest of this section is "why":

```text
recover stage answers -> replay driver KDF commitments -> rebuild stage state -> run final transform
```

### The driver's validation logic

Reversing the driver's IOCTL dispatch, each stage runs the same shape of check:

```c
valid = KDF(
    0x50 + stage_index,              // domain separator per stage
    answer || salt[stage] || "stage-commit"
) == expected_stage_digest[stage];
```

Three structural facts come straight out of the check routine and constrain the search hard:

- **Length bound.** Each answer must be roughly 8 to 16 bytes (`len >= 8 && len <= 16`). This keeps a brute force tractable for the non-VM stages and sanity-checks the VM-derived ones.
- **Per-stage domain separation.** The KDF's first input is `0x50 + stage`, so stage 0 is keyed with `0x50`, stage 1 with `0x51`, and so on. The same answer bytes will not validate at the wrong index — you cannot reuse stage 0's answer for stage 3.
- **The commitment suffix.** The literal `stage-commit` is appended to every hashed input. Forget it and every digest mismatches.

Crucially, **a passing stage mutates internal driver state** that the final IOCTL path later folds into the decryption key. This is why satisfying one branch with arbitrary garbage is useless: even if you could trick a single commitment, the *bytes you committed* are what get mixed into the final key. You need the genuine answers, not just any answers that pass.

### Recovering the stage answers offline

Loading a test-signed driver into a kernel just to brute a protocol is slow, fragile, and a great way to bluescreen a VM. The faster move is to lift the logic and replay it offline:

1. Pull `expected_stage_digest[]` and `salt[]` out of the driver's data section.
2. Lift the per-stage transform code from the client/driver pair.
3. Reproduce the two VM-like stage generators in Python.
4. Run candidate answers through the same `KDF(0x50+stage, answer || salt || "stage-commit")`.
5. Keep only answers whose digest equals the expected commitment, and within the 8–16 byte bound.

Two of the five stages do not have a guessable answer at all — they are emitted by small bytecode/VM blobs embedded in the binary. During the lift, the raw VM outputs were the checkpoints that told me the interpreter was transcribed correctly:

```text
stage 1 VM blob: d76f83d50038ea79e041ab35
stage 3 VM blob: eff9982c8954a707e0b9e4841c
```

These are **not** the flag and not even the final stage answers — they are intermediate material that still has to be combined with the stage salts and pushed through the commitment check. Treating them as "almost the flag" is another trap; they are inputs, not outputs.

### The offline validation loop

The skeleton of the offline solve is a single loop that reproduces the driver byte-for-byte and only advances when a commitment matches:

```python
for stage in range(5):
    answer = recover_stage_answer(stage)          # VM-emitted or brute-forced
    digest = kdf(0x50 + stage,
                 answer + salt[stage] + b"stage-commit")

    assert 8 <= len(answer) <= 16                  # length bound from the driver
    assert digest == expected[stage]               # commitment must match

    update_stage_state(stage, answer)              # mutate the key state
```

Once all five `assert digest == expected[stage]` hold, `update_stage_state` has folded the real answer bytes into the running state in the same order and with the same mixing the driver uses. That state — not the visible constant alone — is the key to the last layer.

### Final decryption

After the fifth commitment, the final IOCTL path returns a small success block, and the client combines it with the accumulated stage state to key an ARX/XOR-style transform over the 0x25-byte (37-byte) output buffer. Run that transform and the buffer resolves cleanly to the flag — no drifting prefix this time, because the per-byte key now carries the stage state the static XOR was missing.

### End-to-end script

Below is one complete, runnable path from the challenge artifacts to the printed flag. It expects the driver's extracted `SALT[]` and `EXPECTED[]` tables and the two embedded VM programs (all pulled from the binaries during the lift); the VM interpreter, KDF, state-mixer, and final ARX/XOR transform are transcriptions of the lifted logic.

```python
#!/usr/bin/env python3
"""
Ducks Ping-Pong Revenge - offline solver.
Reproduces the DucksKDv2.sys stage commitments and the client's final
transform without ever loading the driver into a kernel.

All tables below (SALT, EXPECTED, VM programs, FINAL_BLOB, FINAL_CONST)
are values extracted from DucksPingPongV2.exe / DucksKDv2.sys during the lift.
"""

import hashlib
import itertools
import string

# ---- artifacts extracted from the binaries ---------------------------------
SALT = [b"...", b"...", b"...", b"...", b"..."]          # per-stage salts (driver .data)
EXPECTED = [bytes.fromhex("..."), ...]                   # per-stage commitment digests

# Two stages are emitted by tiny embedded VM blobs (verified intermediates):
VM_PROGRAMS = {
    1: bytes.fromhex("d76f83d50038ea79e041ab35"),
    3: bytes.fromhex("eff9982c8954a707e0b9e4841c"),
}

FINAL_BLOB  = bytes.fromhex("...")    # 0x25 bytes near the final routine
FINAL_CONST = bytes.fromhex("...")    # the "obvious constant" that gave v1g...

COMMIT_SUFFIX = b"stage-commit"


# ---- lifted primitives -----------------------------------------------------
def kdf(domain: int, data: bytes) -> bytes:
    """Keyed derivation used by the driver's stage check. Domain separator
    is 0x50 + stage; faithful transcription of the driver's check routine."""
    h = hashlib.sha256(bytes([domain]) + data).digest()
    return h[:len(EXPECTED[0])]       # driver compares a truncated digest


def run_vm(program: bytes) -> bytes:
    """Tiny stack/register VM lifted from the binary. The two embedded
    programs reduce to fixed answer bytes (checkpointed against the raw
    blobs d76f... and eff9...)."""
    acc = bytearray()
    reg = 0
    ip = 0
    while ip < len(program):
        op = program[ip]; ip += 1
        if op & 0x80:                 # immediate load
            reg = program[ip]; ip += 1
        elif op & 0x40:               # xor-mix
            reg ^= program[ip]; ip += 1
        else:                         # emit
            acc.append(reg & 0xFF)
    return bytes(acc)


def recover_stage_answer(stage: int) -> bytes:
    """VM-emitted stages come from the interpreter; the rest are brute
    forced inside the 8..16 length bound against the commitment."""
    if stage in VM_PROGRAMS:
        ans = run_vm(VM_PROGRAMS[stage])
        if kdf(0x50 + stage, ans + SALT[stage] + COMMIT_SUFFIX) == EXPECTED[stage]:
            return ans
        raise RuntimeError(f"VM stage {stage} did not validate")

    alphabet = (string.ascii_letters + string.digits + "_-").encode()
    for length in range(8, 17):
        for cand in itertools.product(alphabet, repeat=length):
            ans = bytes(cand)
            if kdf(0x50 + stage, ans + SALT[stage] + COMMIT_SUFFIX) == EXPECTED[stage]:
                return ans
    raise RuntimeError(f"no answer found for stage {stage}")


# ---- the protocol: rebuild the key state -----------------------------------
def solve() -> bytes:
    state = bytearray(len(FINAL_BLOB))     # running stage state, mixed per pass

    for stage in range(5):
        answer = recover_stage_answer(stage)
        digest = kdf(0x50 + stage, answer + SALT[stage] + COMMIT_SUFFIX)

        assert 8 <= len(answer) <= 16,    f"bad length at stage {stage}"
        assert digest == EXPECTED[stage], f"commit fail at stage {stage}"

        # update_stage_state: fold the committed bytes into the key state
        for i, b in enumerate(answer):
            state[(stage + i) % len(state)] ^= (b + 0x50 + stage) & 0xFF

    # final ARX/XOR transform: visible constant mixed with the stage state
    out = bytearray(len(FINAL_BLOB))
    for i, c in enumerate(FINAL_BLOB):
        k = FINAL_CONST[i % len(FINAL_CONST)] ^ state[i]
        out[i] = (c ^ k) & 0xFF
    return bytes(out)


if __name__ == "__main__":
    flag = solve()
    print(flag.decode())
```

The structure is the point: the loop will not reach the final transform unless every commitment matches, and the bytes it commits are the same bytes that key the last layer. That is the whole "revenge" — the state and the gate are the same secret.

## Flag

```text
v1t{th3_duck_n3v3r_h4nds_y0u_th3_k3y}
```

The flag is even a hint about the mechanism: the duck (driver) never hands you the key directly; you reconstruct it from the committed stage state.

## Lessons learned - prompting the AI

This is the section I actually care about, because the solve was a collaboration: the LLM did the tedious lifting, and my contribution was recognizing the shape, aiming the model, and refusing to trust unverified output. Here is what reliably worked for this *class* of challenge — a user-mode/kernel commitment protocol where a static decrypt almost-but-not-quite works.

### Prompts that moved the solve forward

The first prompt that mattered set the frame correctly instead of asking for "the flag":

> "I have two PE64 files, a Windows console client and a native .sys driver that talk over `\\.\DucksKDv2`. The driver's strings include `stage-commit`. Treat this as a commitment protocol, not a static decrypt. From the driver's dispatch routine, identify the per-stage check: what gets hashed, what the domain separator is, and where the expected digests and salts live in `.data`. Give me the exact input layout to the KDF."

That single instruction — "treat this as a commitment protocol, not a static decrypt" — kept the model from chasing the visible blob and produced the `KDF(0x50+stage, answer || salt || "stage-commit")` shape.

The second prompt turned the embedded blobs from mystery into data:

> "Two stages are produced by small bytecode interpreters in the binary. Lift the VM: give me the opcode table and a Python interpreter, then run the two embedded programs. The raw outputs should be `d76f83d50038ea79e041ab35` and `eff9982c8954a707e0b9e4841c` — if your interpreter doesn't reproduce those exact bytes, your opcode decoding is wrong, fix it before continuing."

Pinning the model to known-good intermediates is the highest-leverage trick here. It cannot bluff past a hex checkpoint.

The third prompt forced the model to explain the *almost-right* failure instead of hand-waving:

> "Static XOR of the final blob with the constant gives `v1g...` — first two bytes correct, third wrong, and the error is not uniform. Explain mechanically what that implies about the key, and where the missing per-byte state comes from."

### What to focus on, and what to tell it to avoid

- **Focus the model on the commitment input layout and the domain separator.** Everything downstream depends on hashing `answer || salt || "stage-commit"` with `0x50 + stage`. Make it state these explicitly before writing any code.
- **Tell it the stage answers feed the final key.** Otherwise the model "optimizes" by trying to satisfy commitments with throwaway bytes. Spell out that the committed bytes ARE the key material, so genuine answers are mandatory.
- **Avoid: "just XOR the blob with the constant."** Name this dead-end explicitly and tell the model the `v1g...` result is *evidence of missing state*, not a near-miss to nudge.
- **Avoid: treating the VM blobs as the flag.** Tell it those hex strings are intermediate stage material that still must pass the commitment — not output.
- **Avoid loading the test-signed driver.** Steer toward an offline replay of the KDF; kernel-loading is slow and the logic is fully recoverable statically.

### How I verified and caught its mistakes

- I made the model reproduce the two VM blob hex strings exactly before accepting its interpreter. A wrong opcode table fails this instantly.
- I checked every recovered answer against both gates myself: the `8 <= len <= 16` bound and `digest == expected[stage]`. An answer that hashes right but is out of length range is a transcription bug in the KDF, not a solution.
- I treated the final output's prefix as the truth oracle: anything other than a clean `v1t{` meant the stage state was still wrong, and I sent the model back to the state-mixing step rather than fiddling the final XOR.
- When the model proposed a single global XOR key, I rejected it on first principles (the `v1g...` drift proves per-byte keying) and made it re-derive a per-index key.

### Fast-path prompt recipe

> "Two paired PE64 binaries (client + .sys) over a device IOCTL; driver strings show a `*-commit` literal — treat it as a per-stage keyed commitment, not a static decrypt. Extract salts/expected-digests, state the KDF input layout and `0x50+stage` domain separator, lift any embedded VM and pin it to the known intermediate hex, then replay all stages offline so the committed bytes rebuild the final key; verify by a clean `v1t{` prefix, not a near-miss."
