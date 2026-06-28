---
title: "Diddy License Checker Revenge"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: misc
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "A multi-stage Linux crackme that rebuilds its flag from a Fibonacci-derived AES IV, an XOR-masked ciphertext, and a hex-encoded key — plus its revenge twin that assembles the flag from bytes of a server-side PNG."
icon: "🦆"
---

## Summary

`diddy` is a Linux x86-64 crackme that derives a whole AES-CBC pipeline from "innocent" inputs — a Fibonacci-mod-9 "lucky number" that is secretly the IV, a license-name string reused as both a URL path and a repeating-XOR key, and a companion file whose hex decodes straight to the AES key. The companion challenge `diddy_revenge` reverses cleanly but never stores its flag locally: it plucks 33 bytes from a PNG fetched at runtime from a `.gov` URL. I drove an LLM to do the static reversing and the byte-plumbing; my job was recognizing the challenge type, feeding it the right artifacts, and catching the two places its instinct was flat wrong.

## Solution

This is the kind of challenge where the binary is small but the *data flow* is the puzzle. There's no clever anti-debug, no obfuscated control flow. The difficulty is that the key, the IV, and the ciphertext are each manufactured from a different "decoy" input, and you have to recognize each one for what it really is before any of it lines up. That recognition is exactly the part a human is good at and a model needs steering on — so the workflow was: I name what I think each blob *is*, the model proves or disproves it against the disassembly, and we converge.

### Reading the binary's intent first

The binary asks for a few inputs and then "checks a license." Decompiling it (I had the model work from the Ghidra pseudocode) shows it never compares your input against a stored secret. Instead it *reconstructs* a flag from a hard-coded blob, using your inputs as cryptographic material. That is the first key insight, and it's a judgment call, not something you can grep for: **the inputs are not validated, they are consumed as key/IV/path.** Once you frame it that way, the rest is just identifying which input feeds which slot.

There are three "decoy" inputs:

- `pet = "duck"` — a soft gate / flavor, the "are you a real player" check (Diddy, duck — the theme).
- a "lucky number" string,
- a "license name" string.

And one embedded backend, base64'd in the binary:

```
aHR0cDovL3YxdC5zaXRlLw==  ->  http://v1t.site/
```

### Decoy #1 — the "lucky number" is the AES IV

The binary builds the "lucky number" as the literal character `"0"` followed by `fib(1..31) % 9`. Working that out:

```
0 1 1 2 3 5 8 4 3 7 1 8 0 8 8 7 6 4 1 5 6 2 8 1 0 1 1 2 3 5 8 4
```

concatenated:

```
01123584371808876415628101123584
```

That's a 32-character string. The moment you see *32 hex-ish characters being fed into a crypto setup*, the right read is "this is 16 bytes" — i.e. an AES IV. And indeed the binary hex-decodes it into the 16-byte IV. The Fibonacci-mod-9 sequence is pure misdirection; its only job is to deterministically produce those 32 nibbles so the IV is reproducible without ever being written down. Classic crackme move: **a number with a cute story attached is actually a raw cryptographic parameter.**

### Decoy #2 — the license name is BOTH a URL path AND an XOR key

The "license name" is:

```
license-for-user-deadbeef-diddy        (31 characters)
```

It gets used twice, which is the second insight and the easiest thing to miss:

1. As the URL path: `http://v1t.site/license-for-user-deadbeef-diddy`.
2. As a **31-byte repeating-XOR key** applied over an embedded integer array.

The double-use is deliberate — it makes the string look like "just the name in the URL," so you don't think to also treat it as key material.

### Decoy #3 — the companion file's hex IS the AES key

The challenge ships a companion file `license-for-user-deadbeef-diddy` containing 32 hex chars:

```
7631745f3433355f6b33795f66726672
```

Hex-decode that and it spells ASCII:

```
v1t_435_k3y_frfr
```

That 16-byte ASCII string is the **AES-128 key**. (It's also a self-hint: `435` = "AES" leetspeak, which later shows up in the flag — a nice consistency check that the key is right.)

### The embedded ciphertext: low bytes, then unmask, then unhex

The ciphertext is the fiddliest part and the place an LLM is most likely to fumble the plumbing, so it's worth being precise about the layout:

- At `.data 0x4120` there are **96 little-endian int32 values**. Only the **low byte** of each int32 is meaningful — so you collapse 96 int32s to 96 bytes. (The int32 padding is just noise to make the blob look bigger and less obviously like ASCII.)
- Those 96 bytes are masked with the license name via repeating XOR. Unmasking (`arr[i] ^ name[i % 31]`) yields **96 ASCII hex characters**.
- Those 96 hex characters decode to **48 bytes** of actual AES ciphertext (48 is a clean multiple of the 16-byte block size — another sanity check).

### Putting the pipeline together

The full chain:

```
fib%9 string        -> hex-decode -> 16-byte IV
companion file hex  -> hex-decode -> 16-byte AES key ("v1t_435_k3y_frfr")
96 int32 @ 0x4120   -> low bytes  -> 96 bytes
   XOR license name -> 96 ASCII hex chars
   hex-decode       -> 48-byte ciphertext
AES-128-CBC decrypt(ct, key, iv) -> ASCII-hex plaintext
   hex-decode once more -> v1t{...}
```

The final twist — and the last place to not give up early — is that the AES plaintext is *itself* an ASCII-hex string, not the flag directly. You have to hex-decode one more time. If you stop at the AES output you'll see `7631747b...337d` and think it failed; decode it and `7631747b` is `v1t{`, `337d` is `3}`.

### End-to-end script

This is the single runnable path from challenge data to printed flag. `int32_array_at_0x4120` is the 96 little-endian int32s pulled out of `.data` at `0x4120` (extract with your disassembler or by reading the section bytes); everything else is hard data from above.

```python
#!/usr/bin/env python3
# diddy crackme solver: reconstruct the flag from the embedded pipeline.
from Crypto.Cipher import AES
import binascii

# --- Stage 0: the 96 little-endian int32s at .data 0x4120 ---------------------
# Pull these out of the binary's .data section at offset 0x4120 (96 * 4 bytes).
# Only the low byte of each int32 carries data; the rest is padding noise.
int32_array_at_0x4120 = [
    # ... 96 little-endian int32 values extracted from the binary ...
]
assert len(int32_array_at_0x4120) == 96

arr = bytes(x & 0xFF for x in int32_array_at_0x4120)          # 96 bytes

# --- Stage 1: license name = repeating-XOR key (also the URL path) ------------
name = b"license-for-user-deadbeef-diddy"                     # 31 bytes
masked = bytes(arr[i] ^ name[i % len(name)] for i in range(len(arr)))  # 96 ASCII hex chars
ct = binascii.unhexlify(masked)                               # -> 48-byte ciphertext
assert len(ct) % 16 == 0                                      # block-size sanity check

# --- Stage 2: AES key from the companion file's hex ---------------------------
# companion file `license-for-user-deadbeef-diddy` contains:
#   7631745f3433355f6b33795f66726672  ->  "v1t_435_k3y_frfr"
key = binascii.unhexlify("7631745f3433355f6b33795f66726672")  # b"v1t_435_k3y_frfr"
assert key == b"v1t_435_k3y_frfr"

# --- Stage 3: IV from the Fibonacci-mod-9 "lucky number" ----------------------
# "0" + (fib(1..31) % 9) = 01123584371808876415628101123584
iv = binascii.unhexlify("01123584371808876415628101123584")   # 16 bytes

# --- Stage 4: AES-128-CBC decrypt -> ASCII-hex -> hex-decode -> flag ----------
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)              # e.g. b"7631747b...337d"
flag = binascii.unhexlify(pt.strip())                        # -> b"v1t{...}"
print(flag.decode())
```

The flag's three tokens each map back to a stage, which is the author's way of telling you you solved it the intended way: `435` = AES, `f1b0` = the Fibonacci IV, `w3bs1t3` = the `v1t.site` URL path / website.

### diddy_revenge — fully reversed, but the flag lives on the server

The "revenge" twin reverses just as cleanly, and the reversing is genuinely satisfying — but it ends at a wall that no amount of static analysis can climb, and recognizing that wall *early* is itself the lesson. The binary builds this URL:

```
https://{agency}.gov/static/{md5(password)}/{ID}/{agency}-seal.png
```

Notes that matter:

- `agency` is used **twice** (subdomain and the seal filename), the same double-use trick as the license name in `diddy`.
- `md5(password)` is a directory component — so the password gates *which* path you fetch, not a local comparison you can brute.
- `ID` is a path segment, likely tied to the `deadbeef-diddy` user identity from the first challenge.

It then `curl`s the URL with `FOLLOWLOCATION` (it follows redirects), and enforces two checks before it will proceed:

- the response must be **HTTP 200**, and
- the PNG must be **at least 9439 bytes**.

Only then does it assemble the flag:

```c
for (i = 0; i < 33; i++)
    flag[i] = seal_png[OFFSETS[i]];   // 33 hard-coded byte offsets into the PNG
// sanity-checks that flag starts with "v1t"; it never prints the flag
```

So the entire flag is **33 bytes scattered through the server-side `<agency>-seal.png`**, picked out by 33 hard-coded offsets. The binary contains the *recipe* (the offsets, the URL template, the size/status gates) but not the *ingredient* (the actual PNG). To finish it you would need the real `<agency>-seal.png` — which means the correct `agency`, `ID`, and `password` from the challenge prose — then run the saved extractor with the 33 offsets against the downloaded bytes. By the time I worked through it, `v1t.site` was behind a Cloudflare JS challenge and the asset was unreachable, so this half stays at "mechanism understood, flag not extracted offline."

The takeaway worth internalizing: when a flag is **assembled from bytes of a remote asset**, reversing tells you *which bytes* and *from where* — it can never give you the flag without the asset. Time spent in the disassembler after that point is wasted; the remaining work is network/recon, not RE.

## Flag

**`diddy` (recovered):**

```
v1t{435_f1b0_w3bs1t3}
```

**`diddy_revenge` (NOT recovered offline — partial):** The revenge binary's logic is fully reversed (URL template, MD5-of-password path component, HTTP 200 + ≥9439-byte gates, and the 33 hard-coded offsets that pluck the flag out of `<agency>-seal.png`). The flag itself is **server-side**: it is 33 bytes of a PNG fetched at runtime, never stored in the binary. With the live asset unreachable (behind Cloudflare-JS) and no local copy of the correct `<agency>-seal.png`, the flag could not be assembled offline.

## Lessons learned - prompting the AI

Whenever you face a **"reconstruct-the-flag" crackme** — a small binary that builds an AES/XOR/encoding pipeline out of your inputs and embedded blobs instead of comparing your input to a stored secret — the LLM is great at turning pseudocode into a runnable pipeline and at the byte arithmetic, but it needs you for the *role-assignment* leaps and for catching confidently-wrong plumbing. The prompts below are written so they transfer to the next binary of this class (key/IV/XOR/ciphertext/URL hidden behind "decoy" inputs), not just `diddy`.

**1. Force role-classification before pasting any code.** This is the prompt that decides the whole solve, and it works on any crackme of this shape:

> "This is a crackme that does NOT validate input — it reconstructs the flag from hard-coded blobs using my inputs as cryptographic material. List every user input and every embedded constant/array, and for each one tell me its most likely ROLE — AES key, IV, repeating-XOR key, ciphertext, salt, or URL component — and justify the assignment from the decompilation. Do not propose a 'correct input that passes a check'; there is no check."

The phrase "there is no check" is the load-bearing part — it stops the model from hunting for a comparison/`strcmp` that doesn't exist, which is the #1 dead-end for this class. Steer it off two more classic dead-ends up front: (a) **do not brute-force or guess any input string** — in this family the "name"/"license"/"serial" is almost always reused verbatim (e.g. as a filename, URL path, AND an XOR key), so tell it to treat such strings as *known and multi-purpose*; (b) **do not assume a cute numeric sequence is just flavor** — a Fibonacci/factorial/"lucky number" routine usually exists only to deterministically regenerate a raw crypto parameter (here, the IV).

**2. Make it count bytes after every transform and assert the block-size invariant.** Layered encodings are where the model slips, so demand a length at each stage and give it a free oracle:

> "Trace the embedded array at <offset> to the AES ciphertext. Print the byte count after EACH transform: int32 -> low byte, repeating-XOR with the <N>-byte key, then hex-decode. The final ciphertext MUST be a multiple of 16 — if it isn't, you made a step wrong, so go back and re-derive it."

The "multiple of 16" assertion is reusable on every block-cipher challenge and instantly catches the most common mistake: treating a padded int32 array as raw little-endian bytes instead of extracting the low byte (which here turned 96 ints into the wrong length, not a clean 48). Also bake in the *terminal* gotcha of this class explicitly, because models love to stop one step early:

> "After AES-CBC decrypt, assume the plaintext is ITSELF ASCII-hex and hex-decode it one more time before declaring success or failure."

Without that line the model sees `7631747b...337d`, calls the key wrong, and quits — when it's already `v1t{...3}` in hex.

**3. Recognize and announce the "flag lives off-box" wall early.** Some twins (like `diddy_revenge`) reverse perfectly but assemble the flag from a *remote* asset. The moment you see the binary fetch a URL and index into the response, stop reversing and tell the model to as well:

> "If the flag is assembled from bytes of a fetched/remote asset (it indexes into an HTTP response), do NOT keep scanning the binary for a flag string — it isn't there. Extract only the URL template (note any value reused in multiple path/host segments), the status/size gates, and the list of byte offsets. Then tell me what real-world inputs I still need to fetch the asset."

This converts a doomed RE session into a clear recon TODO (here: the correct `agency`, `ID`, and `password` to fetch `<agency>-seal.png`). Catching it early is the difference between a finished writeup and hours re-reading `.data`.

**How to verify the model's output for this class (catch hallucinations):** lean on the challenge's built-in oracles instead of asking "are you sure." (a) **Decode-to-readable check** — a recovered key/IV should usually decode to ASCII that means something (`v1t_435_k3y_frfr`); if a step yields noise, that step's role assignment is wrong. (b) **Block-size check** — ciphertext length divisible by 16 gates all the XOR/unhex plumbing. (c) **Self-consistency check** — the final flag's tokens should map back to the stages you identified (`435`->AES, `f1b0`->Fibonacci IV, `w3bs1t3`->the website URL); when the story closes on itself you solved it the intended way. If any of the three fails, the failing stage tells you exactly which transform or role to re-derive — far more reliable than trusting the model's confidence.

**Fast-path prompt recipe for this class:** *"Treat this as flag-reconstruction, not input-validation (there is no check). Classify every input and embedded blob by crypto role — key/IV/XOR/ciphertext/URL — and treat any reused 'name/serial' as a known multi-purpose constant. Trace the embedded blob to ciphertext, printing the byte count after every transform and asserting the result is a multiple of 16, then AES-CBC decrypt and hex-decode the plaintext one EXTRA time. If the flag is indexed out of a remote asset's bytes, stop reversing and report only the URL template, the gates, and the byte offsets."*
