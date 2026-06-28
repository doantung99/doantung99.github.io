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

This was a "the LLM did the grinding, I did the steering" solve. The model was excellent at translating pseudocode into a working pipeline and at the byte arithmetic; it needed me for the *interpretation* leaps and for noticing when it confidently produced garbage. Here's what actually moved it forward.

**1. Frame the challenge type before pasting any code.** The single most useful prompt I gave, before any disassembly:

> "This is a crackme that does NOT validate input — it reconstructs the flag from a hard-coded blob using my inputs as crypto material. For each input (pet, lucky number, license name) and each embedded blob, tell me whether it's most likely an AES key, an IV, a XOR key, ciphertext, or a URL component, and justify from the decompilation."

That reframing stopped the model from going down the "find the correct license string that passes the check" rabbit hole — there is no such check. It immediately started classifying blobs by *role*, which is the whole game here.

**2. Make it name the layered encodings explicitly and count bytes at each stage.** The plumbing is where it slipped. My prompt:

> "Trace the embedded array at 0x4120 to the AES ciphertext. State the byte count after EACH transform: int32 -> low byte, XOR with the 31-byte name, then unhex. The final ciphertext must be a multiple of 16 — if it isn't, you got a step wrong."

The "must be a multiple of 16" constraint is a free oracle. The model's first attempt forgot the *low-byte* extraction and treated the int32s as raw little-endian bytes, producing a length that wasn't a clean 48 — the length check caught it instantly. I also told it explicitly: **the AES plaintext is itself ASCII-hex; decode it one more time** — without that nudge it stopped at `7631747b...` and declared the key wrong.

**3. Tell it which dead-ends to avoid.** I explicitly steered it off two wrong paths:

> "Do NOT brute-force or guess the license name; it's the literal companion filename and it's reused as the XOR key — treat it as known. And do NOT try to recover diddy_revenge's flag from the binary: it is bytes of a remote PNG. Only extract the URL template, the size/status gates, and the 33 offsets."

The second one is the important judgment call. The model wanted to keep searching the binary for a flag string in `diddy_revenge`. I had to recognize that the flag was never *in* the binary and tell it to stop — otherwise it burns the whole session re-reading `.data` looking for something that isn't there.

**How I verified / caught mistakes:** three concrete checks. (a) The companion hex decoding to readable ASCII `v1t_435_k3y_frfr` is self-verifying — if it had decoded to noise, wrong key. (b) Ciphertext length being a multiple of 16 gated the XOR/unhex plumbing. (c) The final flag's tokens (`435` / `f1b0` / `w3bs1t3`) each map to a pipeline stage (AES / Fibonacci IV / website URL), which is the author's built-in "you did it the intended way" confirmation. When all three line up, you're done — no need to ask the model "are you sure."

**Fast-path prompt recipe for next time:** *"Treat this crackme as flag-reconstruction, not input-validation. Classify each input/blob by crypto role (key/IV/XOR/ciphertext/URL), trace the embedded blob to ciphertext while printing the byte count after every transform and asserting the result is a multiple of 16, then AES-CBC decrypt and hex-decode the plaintext one extra time. If the flag is assembled from a remote asset's bytes, stop reversing and extract only the URL template plus the byte offsets."*
