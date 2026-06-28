---
title: "Diddy License Checker"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A Linux ELF crackme that derives an AES-CBC key/IV from 'innocent' inputs (a Fibonacci-mod-9 lucky number and a license file), then masks the ciphertext with a repeating-XOR over the license name; reverse the pipeline to recover the flag offline."
icon: "🦆"
---

## Summary
`diddy` is a Linux x86-64 ELF crackme that reconstructs its flag from a hard-coded blob through a multi-stage AES-CBC pipeline, where the key, IV, and ciphertext are all derived from seemingly harmless inputs. The core technique is recognizing that the "lucky number" is the IV (Fibonacci mod 9), the companion license file hex-decodes to the AES key, and the license name doubles as a repeating-XOR mask, then replaying the whole chain offline.

## Solution

I clocked this as a classic multi-stage crackme the moment I saw a binary that "asks for inputs and checks a license," so I set the direction up front: find every derivation step, prove which inputs feed the key/IV/ciphertext, and reproduce the pipeline in Python rather than patch the check. I fed the ELF and the companion `license-for-user-deadbeef-diddy` file to the model and had it triage the binary first, then asked it to isolate the real crypto from the noise.

1. **Map the inputs.** The model dumped the comparison logic and surfaced three constants: `pet = "duck"`, a "lucky number" built as `"0"` then `fib(1..31) % 9` (giving `01123584371808876415628101123584`), and the license name `license-for-user-deadbeef-diddy`. My judgment call here was spotting that the 32-hex "lucky number" is exactly 16 bytes — i.e. the **AES IV** — not a throwaway prompt. The model initially treated the license name as just a URL path (`http://v1t.site/<name>`); I caught that and pushed it to check whether the same string was reused, and it was: also a **31-byte repeating-XOR key**.

2. **Recover the key and ciphertext.** I asked the model to hex-decode the companion file; `7631745f3433355f6b33795f66726672` decodes to the ASCII `v1t_435_k3y_frfr` — a clean 16-byte AES-128 key. It then pulled the 96 little-endian int32s from `.data` (around `0x4120`), took the low byte of each to get a 96-byte array, XOR'd it under the repeating license-name key to produce 48 ASCII-hex chars, and `unhexlify`'d that into the 48-byte ciphertext.

3. **Decrypt and verify.** AES-CBC decrypt yields another ASCII-hex string; hex-decoding it once more prints the flag. I verified the output matched `v1t{...}` format before trusting it.

```python
from Crypto.Cipher import AES
import binascii

# 96 little-endian int32s lifted from .data ~0x4120; take the LOW byte of each.
# (values recovered from the binary's embedded array)
int32_array_at_0x4120 = [ ... ]  # 96 entries, low byte is what matters
arr = bytes(x & 0xFF for x in int32_array_at_0x4120)          # 96 bytes

name = b"license-for-user-deadbeef-diddy"                     # 31-byte repeating-XOR key

# Unmask: (arr XOR name) is itself 96 ASCII-hex chars -> 48-byte ciphertext
masked = bytes(arr[i] ^ name[i % len(name)] for i in range(len(arr)))
ct = binascii.unhexlify(masked)                               # 48 bytes

key = b"v1t_435_k3y_frfr"                                     # from license file hex-decode
iv = binascii.unhexlify("01123584371808876415628101123584")  # fib(1..31)%9, the IV

pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)               # ASCII-hex "7631747b...337d"
flag = binascii.unhexlify(pt.strip())                         # -> v1t{...}
print(flag.decode())
```

The flag name is its own hint: `435` = AES, `f1b0` = fibo (the IV), `w3bs1t3` = website (the reused license-name URL path).

## Flag
```
v1t{435_f1b0_w3bs1t3}
```
