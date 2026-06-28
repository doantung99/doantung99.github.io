---
title: "Scary Duck"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: forensics
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, forensics, ai-assisted]
draft: false
summary: "An MP4 with an appended password-protected ZIP, whose password is split between a binary block in the last frame and FSK tones in the last audio, then a final Base62 unwrap of the decrypted plaintext."
icon: "🦆"
---

## Summary
We got a single MP4 that hid a password-protected ZIP appended after the video data. The password was split in two halves — an inverted 8x4 binary block in the last frame and eight frequency-mapped tones in the last three seconds of audio — and the decrypted payload still needed one more Base62 unwrap to reveal the flag. I steered, the model did the carving and decoding.

## Solution
I pegged this as a layered media-stego challenge the moment I saw a short MP4 that was "too big," so I set the direction: assume something is appended, then assume the visible/audible hints near the end carry a key. I had the model triage the container first — `ffprobe` plus a byte scan turned up a `PK\x03\x04` signature at offset `9124676`, and `dd` carved out `embedded.zip` (containing `solver.py` and `flag.enc`, password-protected).

Then I split the recovery into two prompts. First, "pull the last frame and read the black/white block as bits" — the model extracted `last_frame.png`, cropped the rectangle to an 8x4 grid, and read `29 11 d0 22`. It initially handed me those raw bytes as the password half; I caught that and pointed it back to the challenge's expectation of *inverted* bits, giving `d6ee2fdd`. Second, "spectrogram the last 3 seconds and map the tones" — eight tones spaced 150 Hz from 600 Hz decode via `(freq-600)/150` into `0b8b243e`. Concatenated: `0b8b243ed6ee2fdd`.

That hex string is both the ZIP password and the raw 8-byte XOR key. I had the model invert `solver.py`'s pipeline (base64 -> XOR -> reverse), which produced `-0day-...-RCE-`; I recognized the middle as Base62 and had it do the final decode. One script that runs end to end:

```python
#!/usr/bin/env python3
import base64, subprocess
from pathlib import Path
from PIL import Image

# --- Step 1: carve the appended ZIP from the MP4 ---
blob = Path("challenge.mp4").read_bytes()
off = blob.find(b"PK\x03\x04")
Path("embedded.zip").write_bytes(blob[off:])

# --- Step 2: password = audio half + visual half ---
# Visual half: inverted bytes of the 8x4 binary block in the last frame.
visual_block = [0x29, 0x11, 0xd0, 0x22]          # read from last_frame_8x4.png
visual = bytes((~b) & 0xFF for b in visual_block).hex()   # -> d6ee2fdd

# Audio half: eight FSK tones, value = (freq - 600) / 150 -> hex digit.
tones = [600, 2250, 1800, 2250, 900, 1200, 1050, 2700]
audio = "".join(f"{(f - 600)//150:x}" for f in tones)     # -> 0b8b243e

password = audio + visual                          # 0b8b243ed6ee2fdd
key = bytes.fromhex(password)

# --- Step 3: extract the protected ZIP with that password ---
subprocess.run(["unzip", "-o", "-P", password, "embedded.zip", "-d", "extracted"], check=True)

# --- Step 4: invert solver.py pipeline (base64 -> xor -> reverse) ---
ct = Path("extracted/flag.enc").read_bytes().strip()
raw = base64.b64decode(ct)
xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
mid = xored[::-1].decode()                          # -0day-<base62>-RCE-

# --- Step 5: final Base62 unwrap of the middle segment ---
s = mid.split("-")[2]
alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
n = 0
for c in s:
    n = n * 62 + alphabet.index(c)
flag = n.to_bytes((n.bit_length() + 7) // 8, "big")
print(flag.decode())
```

## Flag
```
V1T{7h47_dUck_l00k_5c4ry_7h0}
```
