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
summary: "An encrypted ESP32-S3 flash dump whose read-protected XTS-AES key is deterministically derivable from readable eFuse data via a leaked provisioning firmware's KDF."
icon: "🔐"
---

## Summary
We get an encrypted ESP32-S3 SPI-flash dump (flash encryption ON, XTS-AES-128) plus an eFuse summary and a "leaked" provisioning firmware. The hardware key is read-protected in eFuse, but the leaked tool derives it deterministically from *readable* device data (MAC + `BLOCK_USR_DATA`), so we reverse the KDF, rebuild the key, and decrypt the `flagdata` partition.

## Solution

I recognized this as the classic embedded trap: a "secure" key that's read-protected in fuses but actually reproducible if its derivation leaks. So I set the direction up front — find the KDF in the provisioning binary, recover the constants, then run ESP32's flash-encryption math in reverse. The model did the grinding; my job was steering and verifying.

**1. Triage the inputs.** I handed the model `efuse_sum.json` and asked it to strip the espefuse banner and pull the security-relevant fuses. It confirmed `SPI_BOOT_CRYPT_CNT=Enable`, `KEY_PURPOSE_0=XTS_AES_128_KEY`, `BLOCK_KEY0 readable=False`, and — crucially — the readable per-device values: `MAC=d0:cf:13:2f:36:c8` and `BLOCK_USR_DATA`. That readable data is the KDF input.

**2. Isolate the real KDF, not the banner.** `strings` on `leaked_debug_firmware.bin` (a stripped Xtensa ELF) showed the derivation as `PBKDF2(HMAC-SHA256(...))`. I told the model to ignore the human-readable log lines and actually pin the constants in the binary — radare2 won't auto-resolve Xtensa `l32r` literal-pool references, so I steered it to scan `.flash.text` for the little-endian addresses of those format strings and read the literal pool that holds them (around vaddr `0x42000b20`). It came back with the SHA-256 IV (`6a09e667…`), a 16-byte HMAC key constant `855780fc45bce8878d68f0040630cdbb`, and the integers `6000` and `4096`. The model first guessed 6000 was the iteration count; I had it re-check the KDF function at `0x420096a4`, where the call signature `(USR_DATA, 24, MAC, 6, out, 32)` makes clear the PBKDF2 salt is the 6-byte MAC and the iteration count is **4096**.

**3. Rebuild the key and run ESP32's XTS quirks in reverse.** I had the model implement Espressif's flash-encryption scheme exactly: 128-byte data units, a tweak of `address & ~0x7F` packed little-endian, and the byte-reversal before/after each AES-XTS block. I verified the key by checking that flash offset `0x0` decrypts to the `0xE9` ESP image magic before trusting it on the `flagdata` partition (`off=0x113000`, from the plaintext partition table at `0x8000`).

```python
import struct, hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Step 1+2: reverse the leaked KDF -> recover the read-protected XTS key ---
K16    = bytes.fromhex("855780fc45bce8878d68f0040630cdbb")          # HMAC key constant
USR    = bytes.fromhex("eed822f54024e490e59ca5e670784a5daa1f04fd07787353")  # BLOCK_USR_DATA[0:24]
MAC    = bytes.fromhex("d0cf132f36c8")                              # device MAC (PBKDF2 salt)
digest = hmac.new(K16, USR, hashlib.sha256).digest()
key32  = hashlib.pbkdf2_hmac("sha256", digest, MAC, 4096, 32)       # XTS-AES-128 key

# --- ESP32-S3 flash XTS-AES decrypt (128-byte unit + byte-reversal quirk) ---
def xts_dec(key, flash_address, indata):
    be = default_backend(); out = []
    pad_left = flash_address % 0x80
    data = b"\x00" * pad_left + indata
    data += b"\x00" * ((-len(data)) % 0x80)
    fa = flash_address
    for i in range(0, len(data), 0x80):
        tweak = struct.pack("<I", fa & ~0x7F) + b"\x00" * 12; fa += 0x80
        c = Cipher(algorithms.AES(key), modes.XTS(tweak), backend=be).decryptor()
        out.append(c.update(data[i:i + 0x80][::-1])[::-1])
    return b"".join(out)[pad_left: pad_left + len(indata)]

flash = open("flash_dump.bin", "rb").read()
assert xts_dec(key32, 0x0, flash[0x0:0x80])[0] == 0xE9          # ESP image magic -> key confirmed
flagdata = xts_dec(key32, 0x113000, flash[0x113000:0x114000])  # flagdata partition
print(flagdata.split(b"\x00", 1)[0].decode())
```

This prints the flag straight out of the decrypted partition (`V1T{...}`, stored uppercase even though the prompt shows lowercase `v1t{}`).

## Flag
```
V1T{7h15_5h1d_k1nd4_h4rd_1kn0w}
```
