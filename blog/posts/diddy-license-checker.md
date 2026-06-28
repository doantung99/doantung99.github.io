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

This is the part I actually care about, because the technique that won here was *prompting*, not raw reversing. The LLM read the disassembly and ground through the byte math; my job was to recognize the challenge class, point the model at the right structures, and refuse its wrong answers. Here is what reproducibly worked.

**Frame the class up front, then make the model enumerate "what feeds what."** The single most useful instruction was forcing the model to separate *gate inputs* from *crypto-seed inputs*:

> "This is a multi-stage AES crackme, not a string-compare. For each of the three prompts (pet, lucky number, license name), tell me exactly one role: is it a gate check, the AES key, the AES IV, an XOR key, or a URL component? A single input may have TWO roles. Cite the offset where it's used."

That immediately surfaced the two facts that unlock everything: the license name is reused as both a URL path *and* a repeating-XOR key, and the "lucky number" is the IV. Without the explicit "an input may have two roles" nudge, the model picked the first use it saw (URL path) and stopped.

**Tell it where the data is and how to interpret it — don't let it guess the type.** The array at `0x4120` is `int32` little-endian and only the low byte matters. Left alone, the model treated it as raw bytes and produced garbage:

> "The blob at 0x4120 is 96 little-endian int32s. Extract ONLY the low byte of each (x & 0xFF) to get 96 bytes, then XOR with the repeating license name. The result must be 96 chars of valid lowercase hex — if it isn't, you have the endianness or byte-selection wrong. Show me the first 16 bytes before continuing."

The "must be valid hex, show me 16 bytes first" clause does real work: it gives the model a built-in oracle and a checkpoint so it self-corrects before committing the whole pipeline to a bad buffer.

**Dead-ends to explicitly forbid.** Three places the model wandered, and what I told it to avoid:

- The `http://v1t.site/` base64 string — I said "the network branch is a red herring for the base crackme; do NOT try to fetch anything, the flag is fully offline." Otherwise it kept proposing to curl the site.
- The `pet="duck"` input — I told it "the pet is a gate only; it does not feed any crypto, stop trying to derive a key from it."
- Stopping at the AES output — the model declared victory at `7631747b...337d` and called it a failed decrypt. I said "that output is ASCII hex; `76 31 74` is `v1t`. Hex-decode it ONE more time." The double-decode was the layer it most wanted to skip.

**How I verified / caught mistakes.** Three cheap checks, each of which caught at least one wrong turn:

1. **Length checks as invariants.** IV must be 16 bytes, key must be 16 bytes, masked buffer must be 96 hex chars → 48-byte (3-block) ciphertext. Any mismatch means a stage is wrong; I made the model assert these rather than trust them.
2. **The "valid hex" oracle** after the XOR un-mask. This single check distinguishes a correct low-byte / endianness / key combination from every common mistake.
3. **Semantic confirmation from the flag itself.** Once I had `v1t{435_f1b0_w3bs1t3}`, the components (AES / fibo / website) map one-to-one onto the three stages I'd reversed. When the recovered flag *explains* the challenge, you know the reversing was right, not lucky.

**Fast-path prompt recipe for next time:** "Treat this as a multi-stage key/IV derivation crackme: for every input and every embedded blob, tell me its role and byte-type, assert the length at each stage, use 'output must be valid hex / printable' as an oracle, ignore the network branch as offline-irrelevant, and don't stop until a final hex-decode yields `v1t{...}`."
