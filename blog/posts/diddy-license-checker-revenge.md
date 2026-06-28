---
title: "Diddy License Checker Revenge"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: misc
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "A crackme whose 'revenge' variant assembles its flag from 33 hard-coded byte offsets of a server-side PNG fetched at runtime — fully reversed, but the flag stays remote."
icon: "🔑"
---

## Summary
A license-checker crackme that derives its key material from "innocent" inputs (a Fibonacci-mod-9 "lucky number" as the AES IV, the license name as both a URL path and an XOR key). The `diddy_revenge` companion reverses cleanly, but its flag is never in the binary: it is reconstructed from 33 hard-coded byte offsets into a PNG fetched live from the server.

## Solution
I went in expecting a multi-stage key-derivation crackme, so my first move was to set the direction rather than start disassembling by hand. I handed the ELF to the model and asked it to triage the binary and lay out the input pipeline. It pulled the pieces apart: `pet = "duck"`, a "lucky number" that turned out to be `"0"` followed by `fib(1..31) % 9` (i.e. the 32-hex string `01123584371808876415628101123584`) doubling as the AES IV, and the license name `license-for-user-deadbeef-diddy` used twice — once as the URL path `http://v1t.site/<name>` and once as a repeating-XOR key over an embedded `int32` array.

My judgment call was on the key. The companion file `license-for-user-deadbeef-diddy` is 32 hex chars; I prompted the model to stop treating it as opaque and just hex-decode it, which gives the ASCII AES-128 key `v1t_435_k3y_frfr`. From there I had it script the full decrypt: take the low byte of each of the 96 int32s, XOR with the license name, hex-decode that into 48 bytes of ciphertext, AES-CBC decrypt, then hex-decode the plaintext once more.

```python
from Crypto.Cipher import AES
import binascii

# 96 little-endian int32s from .data 0x4120; take the LOW byte of each
arr  = bytes(low_byte(x) for x in int32_array_at_0x4120)   # 96 bytes
name = b"license-for-user-deadbeef-diddy"                   # 31-byte repeating-XOR key

# (arr XOR name) is ASCII hex; decode it to the 48-byte ciphertext
masked = bytes(arr[i] ^ name[i % len(name)] for i in range(len(arr)))
ct     = binascii.unhexlify(bytes(masked))                  # 48 bytes

key = b"v1t_435_k3y_frfr"
iv  = binascii.unhexlify("01123584371808876415628101123584")
pt  = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)            # ASCII hex "7631747b...337d"
print(binascii.unhexlify(pt.strip()).decode())             # -> v1t{435_f1b0_w3bs1t3}
```

That nails the base `diddy` flag (`435` = AES, `f1b0` = fibo, `w3bs1t3` = website). Then I pointed the model at the harder `diddy_revenge` variant. It reversed the URL builder to:

```
https://{agency}.gov/static/{md5(password)}/{ID}/{agency}-seal.png
```

The binary `curl`s that (with `FOLLOWLOCATION`), demands HTTP 200 and a PNG of at least 9439 bytes, then plucks the flag straight out of the image bytes:

```c
for (i = 0; i < 33; i++) flag[i] = seal_png[OFFSETS[i]];  // 33 hard-coded offsets
// verifies flag starts with "v1t"; never prints it
```

This is where I caught the model trying to "decrypt" something that was never encrypted — there is no local secret to crack. My correction was to recognize that reversing only tells you *which* bytes to read; the flag is literally 33 bytes lifted from the remote `<agency>-seal.png`. With the genuine PNG (correct agency/ID/password, `ID` likely tied to user `deadbeef-diddy`), you save the file and run the extractor with the 33 hard-coded `OFFSETS`. Since `v1t.site` is now behind Cloudflare-JS and the asset isn't local, that final fetch couldn't be completed offline.

## Flag
```
Not recovered offline — the diddy_revenge flag is server-side: 33 bytes selected by hard-coded offsets from the live <agency>-seal.png. Logic fully reversed; the remote asset is required to assemble it. (The base diddy flag is v1t{435_f1b0_w3bs1t3}.)
```
