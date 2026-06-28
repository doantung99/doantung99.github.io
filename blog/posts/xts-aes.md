---
title: "XTS-AES"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: hardware
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, hardware, ai-assisted]
draft: false
summary: "Reverse a leaked ESP32-S3 provisioning firmware to re-derive a read-protected flash-encryption key from readable device data, then decrypt the XTS-AES flash dump to recover the flag."
icon: "🔐"
---

## Summary

This is an ESP32-S3 flash-encryption challenge: we get a 4 MB SPI-flash dump encrypted with hardware XTS-AES-128, an eFuse summary showing the key is read-protected, and a "leaked" provisioning firmware. The whole game is that the read-protected key is *not* random — a leaked KDF re-derives it deterministically from readable device data (MAC + `BLOCK_USR_DATA`). Re-implement that derivation, reproduce the key, then decrypt the flash with Espressif's quirky XTS-AES addressing to read the flag out of the `flagdata` partition.

I want to be honest up front about how I solved this: an LLM did almost all of the grinding — reading the Xtensa disassembly, recalling Espressif's exact XTS data-unit format, writing the `cryptography` boilerplate. My job was recognizing the challenge shape, pointing the model at the right artifacts in the right order, catching the two places it confidently went wrong, and verifying every claim against ground truth before I trusted it. That division of labor is the whole story, so the prompting section at the end is the part I actually care about.

## Solution

### Reading the shape before touching anything

Three files ship with the challenge:

| File | What it is |
|------|-----------|
| `flash_dump.bin` | 4 MB SPI-flash dump of an ESP32-S3 with flash encryption ON (XTS-AES-128) |
| `efuse_sum.json` | `espefuse.py summary --format json` of that exact chip |
| `leaked_debug_firmware.bin` | Xtensa ELF, *"V1T PROVISIONING TOOL v2.1"* |

The moment I saw "encrypted flash + read-protected key + a *leaked* provisioning tool," the structure was obvious: this is a key-recovery problem, not a cryptanalysis problem. You are not meant to break XTS-AES. You are meant to notice that the device's "secret" key is derived from things you can read, and that the derivation code was handed to you. So the plan wrote itself:

1. Confirm from the eFuse summary that the key is read-protected *and* that the readable per-device fields exist.
2. Reverse the leaked firmware to recover the exact KDF (algorithm + every constant).
3. Re-run the KDF on the readable fields to reproduce the 32-byte key.
4. Decrypt the flash the way Espressif does it (this is the subtle part), find the flag partition, read it.

This ordering matters. Each step produces a checkable artifact that gates the next one, which is exactly what you want when an LLM is doing the work — you never let it run three inferential steps deep without a ground-truth check in between.

### Step 1 — eFuse recon: confirm the key is "secret" but the inputs aren't

`efuse_sum.json` is annoying: espefuse prefixes the JSON with banner text, so a naive `json.load` fails. Strip everything before the first `{`. The fuses that matter:

```
SPI_BOOT_CRYPT_CNT : Enable          # flash encryption is ON
KEY_PURPOSE_0      : XTS_AES_128_KEY # BLOCK_KEY0 holds the XTS-AES-128 key
BLOCK_KEY0         : readable=False  # RD_DIS set -> key cannot be read back
SECURE_BOOT_EN     : False           # no secure boot in the way
MAC                : d0:cf:13:2f:36:c8
BLOCK_USR_DATA     : ee d8 22 f5 40 24 e4 90 e5 9c a5 e6 70 78 4a 5d aa 1f 04 fd 07 78 73 53 ...
OPTIONAL_UNIQUE_ID : b5 da f6 15 64 cd b2 6d 2f 10 8d c7 ce a3 af cd
```

The key insight is the contrast on this one screen: `BLOCK_KEY0` is `readable=False` (the actual XTS key is gone), but `MAC` and `BLOCK_USR_DATA` are right there in the clear. If the KDF turns out to consume only readable fields, the read-protection is cosmetic. So before reversing anything, I already knew what I was hunting for in the firmware: a function whose inputs are the MAC and the user-data block.

Two gotchas to note for later: only the **first 24 bytes** of `BLOCK_USR_DATA` are used (the firmware strings literally say "reading BLOCK_USR_DATA (24 bytes)"), and the MAC is consumed as raw 6 bytes, not as the human-readable colon string. Both are easy to get subtly wrong, and both break the key silently if you do.

### Step 2 — reversing the leaked KDF

`strings` on the firmware is the single highest-value command in the whole challenge. It dumps the algorithm in human-readable form:

```
V1T PROVISIONING TOOL v2.1
target device MAC: %02x:%02x:%02x:%02x:%02x:%02x
reading BLOCK_USR_DATA (24 bytes)... ok
computing intermediate key material...
  step 1: hmac-sha256 digest (32 bytes)
  step 2: pbkdf2-hmac-sha256 (%d rounds, %d-byte output)
burning derived key to BLOCK_KEY0
  key_purpose  : XTS_AES_128_KEY
writing flag data to partition 'flagdata'... ok
```

So the structure is `key = PBKDF2(HMAC-SHA256(...))`. But the strings tell you the *shape*, not the *constants* — and PBKDF2 with the wrong salt, wrong iteration count, or wrong HMAC key gives you 32 bytes of garbage with no error. You have to recover the exact numbers from the code.

This is where Xtensa fights back. Constants on Xtensa aren't immediates baked into instructions; they live in a **literal pool** and get loaded via `l32r` (PC-relative load of a 32-bit literal). radare2 does not resolve those references for you, so the disassembly is full of `l32r a8, 0x...` loads pointing at addresses whose contents you have to go read manually. The trick that unsticks this: take the known format strings, compute their little-endian virtual addresses, and grep the literal region for those byte patterns. That locates the literal pool the KDF uses, around vaddr `0x42000b20`, and it contains the giveaways:

* the SHA-256 IV words (`6a09e667 …`) and a pointer to the K-table → confirms it's genuinely SHA-256 under the hood;
* a **16-byte constant** at `0x3c028b90` = `855780fc45bce8878d68f0040630cdbb` → this is the HMAC key;
* `0x00001770` = **6000** and `0x00001000` = **4096** → two candidate iteration counts.

That last pair is the first real dead-end, and it's worth dwelling on because it's exactly the kind of thing an LLM will guess wrong. There are *two* round-number literals in the pool, 6000 and 4096. The strings say PBKDF2 takes `%d rounds`. Which one is the iteration count? You cannot tell from constants alone — you have to read the KDF function at `vaddr 0x420096a4` and see which literal is moved into the iterations argument register at the PBKDF2 call site. It's **4096**. (6000 lives elsewhere and is a decoy as far as the key is concerned.) Picking 6000 produces a perfectly valid-looking 32-byte key that decrypts to nothing.

Reading the function `0x420096a4`, the call signature is `(USR_DATA, 24, MAC, 6, out, 32)`, and it does exactly two things:

1. **HMAC-SHA256** — `digest = HMAC-SHA256(key = 855780fc45bce8878d68f0040630cdbb, msg = BLOCK_USR_DATA[:24])`
2. **PBKDF2-HMAC-SHA256** — `key32 = PBKDF2(password = digest, salt = MAC[:6], iterations = 4096, dklen = 32)`

The HMAC digest becomes the *password* for PBKDF2, and the **MAC is the salt** (not the password, not unused). That role assignment is the second easy-to-invert mistake. The resulting 32 bytes are what got burned into BLOCK_KEY0 as the XTS-AES-128 key:

```
3c0c3d36a5f470de0bb31bffb7cf4e1f2cc68b04868d0482c408a218976797ce
```

### Step 3 — Espressif's XTS-AES is not textbook XTS

Here is the part that's genuinely Espressif-specific and where general "AES-XTS" knowledge actively misleads you. The S2/S3/C3 family does flash encryption with AES-XTS, but with its own addressing and a byte-reversal quirk that does not exist in standard XTS. The authoritative reference is `espsecure.py` in `esptool 5.3.0` — the same version that produced this dump — and the rules are:

* the **data unit is 128 bytes** (`0x80`), not the 512 you'd assume from disk encryption;
* per unit, the **tweak** = `struct.pack("<I", flash_address & ~0x7F) + b"\x00"*12` — the unit-aligned flash address as a little-endian u32, zero-padded to 16 bytes;
* each 128-byte block is **byte-reversed**, AES-XTS'd with that tweak, then the output is **byte-reversed again**;
* the 32-byte key is used as-is (XTS-AES-128 means two 128-bit halves, which the library splits internally).

Skip the byte-reversal and you get noise. Use a 512-byte unit and you get noise. Feed the colon-string MAC into the KDF and you get noise. Every one of these fails *silently* — there is no padding error, no MAC check, just wrong bytes — so you are entirely dependent on a known-plaintext sanity check to tell signal from noise.

That check exists: decrypt flash offset `0x0` and you should see the ESP image magic byte `0xE9` followed by a sane IRAM entry point. With the recovered key, offset `0x0` decrypts to `e9 03 02 2f f4 88 3c 40 …` — magic `0xE9`, entry `0x403c88f4`. That is the moment the whole chain is confirmed: key right, KDF right, XTS implementation right. I did not move on until I saw that byte.

### Step 4 — find the flag partition and read it

The partition table lives in plaintext at flash `0x8000` (Espressif leaves the partition table unencrypted by default), so you can parse it without the key. It lists a custom partition:

```
flagdata   type=1(data)  subtype=0x40  off=0x113000  size=0x1000
```

That region is XTS-encrypted. Decrypt `flash[0x113000:0x114000]` with the recovered key and the flag is sitting at the very start of the partition.

### End-to-end script

This runs from the three challenge files to the printed flag. It only assumes the `cryptography` package and the three constants recovered from reversing (the 16-byte HMAC key, iteration count 4096, and the `flagdata` offset). Everything else is read from the files.

```python
#!/usr/bin/env python3
import json, re, struct, hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---- 0. inputs from the challenge files ----
FLASH = open("flash_dump.bin", "rb").read()

raw = open("efuse_sum.json").read()
efuse = json.loads(raw[raw.index("{"):])          # strip espefuse banner

def fuse_bytes(name):
    # espefuse json stores values as space-separated hex; tolerate either form
    v = efuse[name]["value"] if isinstance(efuse[name], dict) else efuse[name]
    return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", v))

MAC = fuse_bytes("MAC")[:6]                        # d0 cf 13 2f 36 c8
USR = fuse_bytes("BLOCK_USR_DATA")[:24]           # first 24 bytes only

# ---- 1. constants recovered by reversing leaked_debug_firmware.bin ----
HMAC_KEY = bytes.fromhex("855780fc45bce8878d68f0040630cdbb")  # literal @ 0x3c028b90
ITER     = 4096                                               # 0x1000 (NOT 6000)

# ---- 2. re-derive the read-protected XTS key ----
digest = hmac.new(HMAC_KEY, USR, hashlib.sha256).digest()     # step 1
key32  = hashlib.pbkdf2_hmac("sha256", digest, MAC, ITER, 32) # step 2 (MAC = salt)
print("[*] recovered XTS key:", key32.hex())

# ---- 3. Espressif XTS-AES flash decryption (esptool 5.3.x semantics) ----
def xts_dec(key, flash_address, indata):
    be  = default_backend()
    pad = flash_address % 0x80                     # align to 128-byte unit
    data = b"\x00" * pad + indata
    data += b"\x00" * ((-len(data)) % 0x80)        # pad up to a whole unit
    fa, out = flash_address, []
    for i in range(0, len(data), 0x80):
        tweak = struct.pack("<I", fa & ~0x7F) + b"\x00" * 12
        fa += 0x80
        dec = Cipher(algorithms.AES(key), modes.XTS(tweak),
                     backend=be).decryptor()
        out.append(dec.update(data[i:i+0x80][::-1])[::-1])  # byte-reverse both ways
    return b"".join(out)[pad: pad + len(indata)]

# ---- 4. sanity check: flash @0x0 must start with ESP image magic 0xE9 ----
head = xts_dec(key32, 0x0, FLASH[0x0:0x80])
assert head[0] == 0xE9, "wrong key/XTS impl: no 0xE9 image magic"
print("[*] image magic OK, entry =", hex(struct.unpack("<I", head[4:8])[0]))

# ---- 5. decrypt the flagdata partition (off=0x113000, size=0x1000) ----
flag_region = xts_dec(key32, 0x113000, FLASH[0x113000:0x114000])
flag = flag_region.split(b"\x00", 1)[0].decode()
print("[+] FLAG:", flag)
```

Running it walks straight to the flag bytes at the start of the partition:

```
0x113000: 56 31 54 7b 37 68 31 35 5f 35 68 31 64 5f 6b 31  V1T{7h15_5h1d_k1
0x113010: 6e 64 34 5f 68 34 72 64 5f 31 6b 6e 30 77 7d 00  nd4_h4rd_1kn0w}.
```

One last gotcha worth flagging: the flag is stored **uppercase** `V1T{...}` even though the challenge's stated format is `v1t{...}`. Submit exactly what's in the partition.

## Flag

```
V1T{7h15_5h1d_k1nd4_h4rd_1kn0w}
```

("this shi(d) kinda hard, i know.")

## Lessons learned - prompting the AI

This challenge is a perfect case study in the human-steers / model-grinds split, because every individual step is something an LLM can do faster than me (read Xtensa, recall Espressif's XTS quirk, write `cryptography` boilerplate) but the *sequencing* and *failure detection* are pure judgment. Here's the reusable playbook for ESP32 flash-encryption / leaked-KDF challenges.

**1. Open by forcing the model to classify, not solve.** My first prompt was deliberately about strategy, not code:

> "Here are three files: an encrypted ESP32-S3 flash dump, an espefuse summary, and a leaked 'provisioning tool' firmware. Don't write any decryption code yet. Tell me what *class* of challenge this is and what the intended solve path is, in order, with a checkable artifact at each step."

This stops the model from diving into "let me try to brute-force the key" nonsense and gets it to articulate the key-recovery-from-readable-inputs structure. It also produces the gated plan that makes verification cheap.

**2. Make it extract constants from the binary, then make it prove which ones matter.** The strings give the algorithm shape for free, but the constants are the trap. The prompt that moved the solve:

> "From the literal pool around 0x42000b20, list every numeric constant and what role it plays. There are two round numbers, 6000 and 4096 — read the function at 0x420096a4 and tell me specifically which register holds the PBKDF2 iteration count at the call site, with the disassembly line. Do not guess from 'which looks more like an iteration count.'"

The model's first instinct was to pick 6000 (it "looked like a reasonable round count"). Forcing it to point at the actual call-site argument register flipped it to 4096. **Tell the model explicitly to avoid reasoning from plausibility and to cite the instruction that consumes the constant.** The same discipline fixed the HMAC/PBKDF2 role assignment: I made it state, given the call signature `(USR,24,MAC,6,out,32)`, which argument is password and which is salt — it had them backwards on the first pass (MAC as password) and self-corrected when asked to map args onto the PBKDF2 prototype.

**3. Demand the Espressif-specific XTS, not textbook XTS.** General LLM knowledge of "AES-XTS" is disk-encryption XTS (512-byte units, no byte reversal) and it will write that confidently. I anchored it to the source of truth:

> "This is ESP32-S3 flash encryption, not generic XTS. Reproduce the exact data-unit size, tweak construction, and any byte-reversal that espsecure.py / esptool 5.3 uses for decrypt_flash_data. If you're unsure of the unit size or reversal, say so — do not invent it."

Adding "say so, do not invent it" is what kept it from hand-waving the byte-reversal, which is the single most-skipped detail and the one that silently produces garbage.

**Verification — how I caught the mistakes.** Every silent-failure step got a ground-truth gate I could check without trusting the model:

- After key derivation, I did **not** ask "is this right?" I had it decrypt flash `0x0` and assert byte `0xE9`. A wrong iteration count or wrong salt role sails through key derivation and only dies here, so this one assert catches both KDF mistakes at once.
- I sanity-checked that the entry point (`0x403c88f4`) is a plausible IRAM address, not just that the magic byte matched — a single matching byte can be a coincidence.
- I read the partition table myself from the plaintext `0x8000` region rather than trusting the model's recollection of where `flagdata` lives.

The meta-lesson: in a challenge full of *silent* failures, the human's entire value is inserting cheap, objective checkpoints between the model's inferential leaps and refusing to advance until one passes. The model is fast; you are the assertion.

**Fast-path prompt recipe for next time:** *"Classify the challenge and give me a gated solve path; extract every binary constant and cite the instruction that consumes each one (no plausibility guesses); use the vendor-exact crypto (say if unsure, don't invent); after each step give me one ground-truth assert I can run before continuing."*
