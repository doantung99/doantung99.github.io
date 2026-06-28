---
title: "Diddy License Checker"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: misc
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "A Linux ELF crackme that derives an AES-128-CBC key and IV from innocent-looking inputs, hides the ciphertext behind a repeating-XOR mask, and double hex-encodes the flag."
icon: "🦆"
---

## Summary

`diddy` is a Linux x86-64 crackme that reconstructs its flag from a hard-coded blob through a multi-stage AES-128-CBC pipeline where the key, IV, and ciphertext are all derived from seemingly harmless inputs. The whole challenge is misdirection: a Fibonacci-mod-9 "lucky number" is secretly the IV, the companion license file hex-decodes straight into the AES key, and the "license name" does double duty as both a URL path and a repeating-XOR mask. Peel those layers, AES-decrypt, hex-decode once more, and the flag falls out. I drove this as a human-AI collaboration: the LLM read the disassembly and ground through the byte math, and my contribution was recognizing the challenge class, pointing the model at the right structures, and rejecting its wrong turns.

## Solution

I clocked this as a classic multi-stage derivation crackme the moment I saw a binary that "asks for a few inputs and checks a license" — so I set the direction up front: find every derivation step, prove which inputs feed the key / IV / ciphertext, and reproduce the pipeline in Python rather than patch the check. I handed the ELF and the companion `license-for-user-deadbeef-diddy` file to the model and had it triage the binary first, then steered it toward isolating the real crypto from the noise.

### What you start with

Two files:

- `diddy` — a Linux x86-64 ELF crackme.
- `license-for-user-deadbeef-diddy` — a 32-character companion file that looks like garbage but is load-bearing.

Running the binary, it prompts for a "pet", a "lucky number", and a "license name", then accepts or rejects you. Crucially, nothing prints the flag on a wrong guess. That is the first tell that the flag is **reconstructed** from those inputs, not merely **compared** against them. The distinction matters: a comparison crackme you can often beat with one correct string; a reconstruction crackme means every input feeds a transform, so you must recover the whole pipeline before any byte of the flag even exists. I made that the working hypothesis and pointed the model at it.

The base64 string `aHR0cDovL3YxdC5zaXRlLw==` is embedded in the binary and decodes to `http://v1t.site/`. That hints the program *would* talk to a backend, but for the base `diddy` the flag is fully derivable offline — the network path is a red herring for the crackme itself, and telling the model to ignore it saved a lot of wasted effort.

### Mapping the pipeline

The core insight is that this is a **multi-stage key/IV derivation crackme**. The three prompts are not the secret; they are the *seeds* for deriving AES parameters and for unmasking an embedded ciphertext. Reversing the binary, the pipeline is:

1. **`pet = "duck"` is a gate check.** Diddy, duck. It just has to match; it does not feed the crypto. (This is exactly the kind of input an LLM will over-think and try to derive a key from — see Lessons learned.)

2. **The "lucky number" is the AES IV.** The expected value is the string `"0"` followed by `fib(1..31) % 9`, i.e. the Fibonacci sequence modulo 9, concatenated as digits:

   ```
   01123584371808876415628101123584
   ```

   That is 32 hex characters = 16 bytes = exactly one AES block. The "lucky number" framing is pure misdirection; the digits **are** the IV. My judgment call here was noticing that a 32-hex string is precisely 16 bytes and flagging it as the IV rather than a throwaway prompt. It parses cleanly because `x % 9` is always in `0..8`, so every character is a valid hex nibble and `unhexlify` accepts the whole string.

3. **The "license name" does double duty.** The expected name is `license-for-user-deadbeef-diddy` (31 chars). The binary uses it:
   - as the URL path component `http://v1t.site/<name>` (the network branch), and
   - as a **repeating-XOR key** over an embedded integer array.

   The model initially treated the license name as *only* a URL path. I caught that and pushed it to check whether the same string was reused elsewhere — and it was, as the XOR key. Recognizing that one string is reused for two unrelated purposes is the crux of the unmasking step and easy to miss reading code linearly.

4. **The AES key comes from the companion file.** `license-for-user-deadbeef-diddy` (the file) contains 32 hex chars:

   ```
   7631745f3433355f6b33795f66726672  →  unhexlify  →  "v1t_435_k3y_frfr"
   ```

   That ASCII string `v1t_435_k3y_frfr` is exactly 16 bytes — the **AES-128 key**. The naming is self-documenting once you see it: `v1t`, `435` (AES), `k3y`, `frfr`.

5. **The ciphertext is hidden in an int32 array, masked by XOR.** At `.data 0x4120` there are 96 little-endian `int32` values. Only the **low byte** of each matters; collecting those 96 low bytes gives a 96-byte buffer. XOR that buffer against the repeating license name, and the result is **ASCII hex** — 96 hex characters that `unhexlify` to a 48-byte AES ciphertext (three blocks).

The gotcha that actually bit: it is tempting to treat the array as raw bytes, or to forget the low-byte extraction, or to XOR in the wrong order. The array is `int32`, stored little-endian, and only the least-significant byte carries signal — the upper three bytes are noise. Get the endianness or byte-selection wrong and the XOR output is not valid hex, which is a useful built-in oracle: **if the masked output is not all `[0-9a-f]`, you took a wrong turn.** I turned that into an assertion so the model would self-correct before burning the whole pipeline on a bad buffer.

### The decryption, end to end

With all five facts pinned down, the recovery is mechanical:

- key = `v1t_435_k3y_frfr` (from the companion file's hex)
- iv = `01123584371808876415628101123584` (Fibonacci-mod-9 lucky number)
- ciphertext = `unhexlify( low_bytes(arr) XOR (license_name repeated) )`
- plaintext = AES-128-CBC decrypt → this is itself an ASCII-hex string
- flag = `unhexlify(plaintext)`

The double hex-decode is the final twist: AES gives you back not the flag but the *hex of the flag*, so you decode once more. This is a deliberate layer — if you stop at the AES output you see something like `7631747b...337d` and might think the decrypt failed, when in fact `76 31 74 7b ... 7d` is `v1t{...}`.

Here is the complete, runnable end-to-end script. The only challenge-specific data you must lift from the binary is the 96 `int32` values at `0x4120`; everything else is derived in code.

```python
#!/usr/bin/env python3
# diddy crackme - offline flag recovery
# Requires: pip install pycryptodome
import binascii
from Crypto.Cipher import AES

# --- Stage 1: the IV is the "lucky number" = "0" + fib(1..31) % 9 ---
def fib_mod9_iv():
    a, b = 0, 1
    digits = "0"                 # the literal leading "0" the binary prepends
    for _ in range(1, 32):       # fib(1)..fib(31)
        digits += str(b % 9)
        a, b = b, a + b
    return digits

iv_hex = fib_mod9_iv()
assert iv_hex == "01123584371808876415628101123584", iv_hex
iv = binascii.unhexlify(iv_hex)          # 16 bytes

# --- Stage 2: the AES-128 key is the companion file's hex, decoded ---
# Contents of file `license-for-user-deadbeef-diddy`:
companion_hex = "7631745f3433355f6b33795f66726672"
key = binascii.unhexlify(companion_hex)  # b"v1t_435_k3y_frfr", 16 bytes
assert key == b"v1t_435_k3y_frfr"

# --- Stage 3: unmask the ciphertext ---
# 96 little-endian int32 values pulled from .data @ 0x4120.
# Only the LOW byte of each int32 carries the ciphertext-hex.
ARR_INT32 = [
    # ... 96 int32 values lifted from the binary at 0x4120 ...
    # (paste the dword array here; e.g. via:  objdump -s -j .data diddy
    #  or in a debugger:  x/96dw 0x4120)
]
assert len(ARR_INT32) == 96, "need exactly 96 int32s from 0x4120"

low_bytes = bytes(x & 0xFF for x in ARR_INT32)     # 96 bytes

name = b"license-for-user-deadbeef-diddy"          # repeating-XOR key (31 bytes)
masked = bytes(low_bytes[i] ^ name[i % len(name)]  # un-XOR -> ASCII hex
               for i in range(len(low_bytes)))

# Oracle: a correct un-mask is 96 chars of valid lowercase hex.
assert all(c in b"0123456789abcdef" for c in masked), \
    "un-XOR is not valid hex -> wrong endianness / byte selection / key"

ct = binascii.unhexlify(masked)                    # 48 bytes = 3 AES blocks

# --- Stage 4: AES-128-CBC decrypt -> ASCII hex -> hex-decode -> flag ---
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)    # itself an ASCII-hex string
flag = binascii.unhexlify(pt.strip(b"\x00 \n\r"))  # decode ONCE more

print(flag.decode())                               # -> v1t{435_f1b0_w3bs1t3}
```

The flag's internal logic is its own confirmation that the pipeline was reversed correctly: `435` = AES, `f1b0` = fibo (the IV), `w3bs1t3` = website (the `v1t.site` URL branch). Every component of the crackme is named in the answer.

A note on the companion Revenge challenge: `diddy_revenge` builds a URL like `https://{agency}.gov/static/{md5(password)}/{ID}/{agency}-seal.png`, fetches it, and reconstructs a 33-byte flag by plucking 33 hard-coded byte offsets out of the returned PNG. That flag lives server-side and is out of scope here — this writeup is the base `diddy`, which is fully solvable offline. The Revenge has its own writeup.

## Flag

```
v1t{435_f1b0_w3bs1t3}
```

## Lessons learned - prompting the AI

**Challenge class: the multi-stage key/IV derivation crackme.** Whenever you face a *reconstruction* crackme — a small binary that takes a few innocuous inputs ("pet", "lucky number", "serial", "username"), never prints the flag on a wrong guess, and clearly *builds* the answer from a symmetric-crypto pipeline (AES/RC4/XOR) seeded by those inputs — the winning move is almost never raw reversing skill. It is prompting an LLM to read the disassembly while *you* supply the structure: name the class, force a role-assignment for every input and blob, and reject the model's first wrong instinct. The prompts below are written to work on the *next* crackme of this shape, not just `diddy`.

**Open by naming the class and forcing a role table.** Do not ask "what does this binary do." Ask the model to commit to a structured mapping, because the whole game is figuring out which seed feeds the key vs. the IV vs. the mask:

> "This is a multi-stage symmetric-crypto crackme that *reconstructs* a flag, not a string-compare. List every user input and every embedded constant/array. For each, give it exactly one role from {gate check, cipher key, cipher IV/nonce, XOR/mask key, KDF seed, URL/path component, unused decoy}, and note its byte-length. A single value MAY have two roles — flag any reuse. Cite the address/offset where each is consumed."

The "a single value may have two roles" clause is the load-bearing line. On `diddy` it surfaced that the license name is *both* a URL path and a repeating-XOR key — without it the model picks the first use it reads and stops. On the next crackme it catches the same reuse pattern (a username that is also the RC4 key, a serial that is also the IV).

**Make the model declare byte-type before it computes.** Embedded arrays are the most common place these LLMs hallucinate. Force the interpretation explicitly and demand a sample:

> "The blob at <addr> is an array of <int32/int16/byte> values, <little/big>-endian. Tell me which bytes actually carry data (e.g. only `x & 0xFF` of each int32) and which are padding/noise. Apply that extraction, then XOR with <the mask seed> repeated. Show me the first 16 output bytes BEFORE doing anything else with them."

**Tell it the self-check, and what 'correct' looks like at each stage.** This class hands you free oracles — use them in the prompt so the model self-corrects instead of marching a bad buffer through three more stages:

> "After the XOR un-mask the output must be 96 chars of valid lowercase hex; if it isn't, you have the endianness, byte-selection, or mask seed wrong — stop and fix that before decrypting. After AES the plaintext will itself be ASCII (here, hex), not the literal flag yet."

**Dead-ends of this class to forbid up front.** These recur across derivation crackmes, so paste them in pre-emptively:

- **The network/URL branch is usually a decoy for the offline tier.** Say: "There is a URL/HTTP branch (here `http://v1t.site/`); the base challenge is fully offline — do NOT propose fetching anything, the flag is derivable locally." LLMs love to suggest `curl`-ing the host and stall there.
- **Gate inputs are not crypto seeds.** Say: "The `pet`/gate input only has to match a constant; it does NOT feed the key, IV, or mask — stop trying to derive a key from it." Models over-fit and try to KDF every input.
- **An ASCII-looking decrypt is not a failed decrypt.** Say: "If the AES/RC4 output looks like printable hex or base64 (e.g. starts `7631747b…`), that is an *encoding layer*, not failure — decode it ONE more time (`76 31 74` is `v1t`)." The final decode is the layer models most want to skip and call it done.

**How to verify the model's output (catch the hallucinations).** Three cheap, class-general checks, each of which caught a wrong turn here:

1. **Length invariants as asserts, not vibes.** Key and IV must be exactly the cipher's block/key size (16 here); the masked buffer must be a clean multiple producing a whole number of cipher blocks (96 hex → 48 bytes → 3 blocks). Make the model emit `assert len(...) == N` at every stage; a mismatch localizes the broken stage instantly.
2. **The "printable/valid-encoding" oracle after each un-mask.** "All bytes in `[0-9a-f]`" (or "all printable ASCII") distinguishes the one correct endianness/byte-selection/seed combination from every common mistake — this is the single most discriminating test for the class.
3. **Semantic back-check from the recovered flag.** When the flag's tokens map one-to-one onto the stages you reversed (here `435`=AES, `f1b0`=fibo IV, `w3bs1t3`=the URL branch), the reversing was *correct*, not lucky. If the flag has parts that correspond to nothing you derived, you got a coincidental decrypt — re-audit.

**Fast-path prompt recipe for this class:** "Treat this as a multi-stage symmetric-crypto reconstruction crackme: build a role table mapping every input and embedded blob to {gate, key, IV, mask, KDF seed, URL, decoy} with byte-lengths (flag any value used twice); declare each blob's byte-type and endianness and extract only the data-bearing bytes; assert the length at every stage; use 'output must be valid hex / printable' as the oracle after each un-mask; treat the network branch as offline-irrelevant; and don't stop until a final decode yields `v1t{...}`."
