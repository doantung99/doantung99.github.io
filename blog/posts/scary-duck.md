---
title: "Scary Duck"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: misc
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "An MP4 with an appended password-protected ZIP whose password is split across a 1-bit image block and an 8-tone audio sequence, with the flag hidden behind XOR + reverse + Base62."
icon: "🦆"
---

## Summary

Scary Duck is a layered stego/forensics puzzle that ships as a single MP4. Hidden in the file is an appended, password-protected ZIP, and the password is split into two halves carried by two different media channels: the upper bytes encoded as eight discrete audio tones in the final three seconds, and the lower bytes encoded as a tiny inverted black-and-white pixel grid in the last frame. Recover both halves, unzip, then peel back the encoder's own pipeline (Base64 -> XOR with that same password -> byte-reverse) and a final Base62 layer to print the flag.

The honest framing of this writeup: the LLM did the grinding — pixel thresholding, frequency-to-hex arithmetic, modular-XOR loops, Base62 big-integer conversion. My job was recognizing the challenge shape, pointing the model at the right artifact at each step, and catching the two places where it confidently went the wrong way. I steered; it solved.

## Solution

### Step 0 — Reading the shape of the problem

The first judgment call is the cheapest and the most important: deciding *what kind* of challenge this is before touching a single tool. A misc/forensics MP4 that is suspiciously large is almost always a carrier file with something appended past the end of the real media stream. Players overthink this constantly — they go hunting for steganography inside frames before checking whether the container even ends where it claims to.

So my opening prompt to the model set the frame deliberately, and told it explicitly *not* to jump to frame-stego yet:

> "I have an MP4 from a forensics CTF. Before any pixel or audio stego, check the boring stuff first: is the file bigger than the media warrants, and is there a non-MP4 file signature appended after the `moov`/`mdat` data? Search the raw bytes for archive magic (`PK\x03\x04`, `Rar!`, `7z`, gzip) and report the offset and the trailing byte count."

That keeps the model on the highest-probability path instead of burning time on a red herring.

### Step 1 — Finding the appended ZIP

`ffprobe challenge.mp4` shows a short clip, but the on-disk size is far larger than a clip that length should be. That size mismatch is the tell. A raw byte scan for the local-file-header magic confirms it:

```python
from pathlib import Path
p = Path("challenge.mp4").read_bytes()
print(p.find(b"PK\x03\x04"))   # -> 9124676
print(len(p))                  # -> 9125580
```

The ZIP local file header `PK\x03\x04` lives at offset `9124676`, and the file is `9125580` bytes long. Everything from that offset to EOF is a complete ZIP appended to a valid MP4. MP4 players happily ignore trailing bytes, and ZIP readers happily ignore leading bytes (ZIP is parsed from its end-of-central-directory record backwards), so the same blob is simultaneously a valid video and a valid archive. Carve it out:

```bash
dd if=challenge.mp4 of=embedded.zip bs=1 skip=9124676 status=none
unzip -l embedded.zip
```

Contents:

```text
solver.py
flag.enc
```

The archive is encrypted. `unzip -l` lists names fine (the central directory file names aren't encrypted), but extracting demands a password. That password is not in the archive — it's hidden back in the *media* part of the file. This is the core mechanic of the challenge: the video is the key, the trailer is the lock.

### Step 2 — The visual half of the password (last frame -> inverted bits)

Pull the final frame. `-sseof -0.1` seeks to 0.1s before end-of-file, and `-update 1` keeps overwriting a single output image so you land on the genuine last decodable frame:

```bash
ffmpeg -sseof -0.1 -i challenge.mp4 -update 1 last_frame.png
```

The frame contains a small black/white rectangle. The key insight is that it is not decorative — it's a low-resolution bitmap where each cell is one bit. The whole block is 8 cells wide by 4 cells tall: 32 bits = 4 bytes. The work is to crop *exactly* the block, downsample to the logical 8x4 grid with nearest-neighbour (so cells don't blur into each other), and threshold to 1-bit:

```python
from PIL import Image
img = Image.open("last_frame.png").convert("L")
# crop coordinates found by eye on the full-res frame
crop = img.crop((x1, y1, x2, y2)).resize((8, 4), Image.Resampling.NEAREST)
crop.save("last_frame_8x4.png")
```

Reading the thresholded grid row by row gives:

```text
00101001
00010001
11010000
00100010
```

Each row is a byte:

```text
29 11 d0 22
```

Here is the first place the model needed steering, and the first dead-end worth naming. The naive reading `2911d022` is *wrong*. The challenge inverts the bits of this block. I only caught it because `2911d022` produced a password that failed to unzip — the verification step (does the ZIP actually open?) is what flagged the mistake, not cleverness. Bitwise-NOT each byte:

```text
~29 = d6
~11 = ee
~d0 = 2f
~22 = dd
```

Visual half of the password: `d6ee2fdd`.

The gotcha generalises: when a stego value "looks like data but isn't accepted," try the obvious transforms — invert, reverse, endian-swap — and let the lock (the password check) be your oracle. Don't theorise about which one; the unzip either works or it doesn't.

### Step 3 — The audio half (last 3 seconds -> tone frequencies -> hex)

The other half lives in sound. Carve the final three seconds to a clean mono WAV and render a spectrogram:

```bash
ffmpeg -sseof -3 -i challenge.mp4 -vn -ac 1 -ar 44100 last3.wav
sox last3.wav -n spectrogram -o last3_spectrogram.png
```

The spectrogram shows eight distinct horizontal bars in sequence — eight pure tones, each one a symbol. Reading their frequencies left to right:

```text
600, 2250, 1800, 2250, 900, 1200, 1050, 2700 Hz
```

The structure is the insight: the tones are quantised on a 150 Hz grid starting at 600 Hz. That is a deliberate encoding, not noise. Each tone maps to a single hex digit with a clean linear formula:

```text
value = (frequency - 600) / 150
```

Decoding:

```text
600  -> 0      2250 -> b      1800 -> 8      2250 -> b
900  -> 2      1200 -> 4      1050 -> 3      2700 -> e
```

Audio half: `0b8b243e`.

This is the second place steering mattered. My first instinct (and the model's) was to assume DTMF or some standard tone alphabet. Wrong frame. Once I told the model "these are evenly spaced custom tones, find the base frequency and the step, then map each to a digit," the 150 Hz grid fell out immediately. The lesson: don't make the model pattern-match to a famous scheme; make it *measure the structure that's actually there.*

The full 16-hex-digit ZIP password is audio-then-visual:

```text
0b8b243e d6ee2fdd  ->  0b8b243ed6ee2fdd
```

### Step 4 — Open the lock

```bash
unzip -P 0b8b243ed6ee2fdd embedded.zip -d extracted
```

It opens. That successful extraction is the verification that *both* halves — including the bit-inversion in Step 2 — are correct. Inside:

```text
solver.py
flag.enc
```

`solver.py` is the gift: it documents the exact encoder used to produce `flag.enc`:

```python
@base64_layer
@xor_layer
@reverse_layer
def encode(data: bytes) -> bytes:
    return data
```

Decorators apply bottom-up at call time, so encoding ran `reverse -> xor -> base64`. To decode you invert in the opposite order: **Base64-decode, then XOR, then reverse.** And the XOR key is the same 16-hex-digit password, read as 8 raw bytes:

```text
0b 8b 24 3e d6 ee 2f dd
```

### Step 5 — The final Base62 layer, and the complete script

Running the three inverse layers does *not* immediately give a `V1T{...}` string. It gives:

```text
-0day-I05Dqrhk0WASzcVa4EovsSduXJpFxRpKbjORsM9-RCE-
```

This was the third potential dead-end. It is tempting to declare victory or to start brute-forcing — but the `-0day-...-RCE-` wrapper is a frame, and the high-entropy middle (mixed-case alphanumerics, no symbols) is a textbook Base62-encoded big integer. Strip the wrapper, Base62-decode the core to bytes, and the flag appears. Here is the single end-to-end script, from the raw challenge file to the printed flag:

```python
#!/usr/bin/env python3
"""Scary Duck — full solve: challenge.mp4 -> flag."""
import base64, subprocess
from pathlib import Path

# --- Step 1: carve the appended ZIP ---------------------------------------
data = Path("challenge.mp4").read_bytes()
off = data.find(b"PK\x03\x04")
Path("embedded.zip").write_bytes(data[off:])

# --- Step 2 & 3: reconstruct the 16-hex password --------------------------
# Visual half (last_frame 8x4 grid), bit-INVERTED:
visual_rows = ["00101001", "00010001", "11010000", "00100010"]
visual = bytes((~int(r, 2)) & 0xFF for r in visual_rows)        # d6 ee 2f dd

# Audio half: eight tones on a 150 Hz grid from 600 Hz -> hex digits:
tones = [600, 2250, 1800, 2250, 900, 1200, 1050, 2700]
audio = bytes.fromhex("".join(f"{(f - 600)//150:x}" for f in tones))  # 0b 8b 24 3e

key = audio + visual                                            # 0b8b243ed6ee2fdd
password = key.hex()

# --- Step 4: extract the password-protected ZIP ---------------------------
subprocess.run(["unzip", "-o", "-P", password, "embedded.zip", "-d", "extracted"],
               check=True)

# --- Step 5: undo encoder pipeline (b64 -> xor -> reverse), then Base62 ---
ct  = Path("extracted/flag.enc").read_bytes().strip()
raw = base64.b64decode(ct)
xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
intermediate = xored[::-1].decode()                            # -0day-...-RCE-

core = intermediate.split("-0day-")[1].split("-RCE-")[0]
alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
n = 0
for c in core:
    n = n * 62 + alphabet.index(c)
flag = n.to_bytes((n.bit_length() + 7) // 8, "big").decode()
print(flag)
```

Output:

```text
V1T{7h47_dUck_l00k_5c4ry_7h0}
```

## Flag

```text
V1T{7h47_dUck_l00k_5c4ry_7h0}
```

## Lessons learned - prompting the AI

This challenge is a "chain of independent decoders" puzzle: carve, decode-image, decode-audio, reverse-an-encoder, decode-Base62. The whole class rewards a human who keeps the model on the highest-probability path and uses each lock as a verification oracle. Here is what actually moved the solve, and how I caught the model when it drifted.

**1. Frame the file as a carrier before allowing any frame-stego.** My first prompt explicitly forbade the glamorous path:

> "Before any pixel or audio stego, check the boring stuff first: is the file bigger than the media warrants, and is there a non-MP4 signature appended after the media data? Search the raw bytes for `PK\x03\x04`, `Rar!`, `7z`, gzip; report the offset and trailing byte count."

Models love to jump straight to LSB-stealing or DCT analysis. Telling it to *exhaust the trivial container tricks first* (appended archive, polyglot) saves the most time on misc/forensics MP4s.

**2. Make the model measure structure, not pattern-match to famous schemes.** For the audio it wanted DTMF; for the image it wanted ASCII. Both wrong. The prompt that worked:

> "These eight tones are evenly spaced on a frequency grid, and the image is a small 1-bit bitmap, not text. For the audio: find the base frequency and the step size, then map each tone to a single hex digit. For the image: downsample to the exact cell grid with nearest-neighbour, threshold to 1-bit, read each row as one byte."

This forces it to derive `value = (freq - 600) / 150` and the 8x4 = 4-byte layout from the data itself, instead of forcing the data into a scheme it half-remembers.

**3. Use the lock as the oracle, and try the obvious transforms when a value is rejected.** The bit-inversion in the image block is invisible until the unzip fails. My correction prompt:

> "`2911d022` does not open the ZIP. Don't theorise — just try the standard transforms of those 4 bytes (bitwise-NOT, byte-reverse, nibble-swap) and tell me which one produces a password that successfully extracts."

The model proposed bitwise-NOT, got `d6ee2fdd`, and the extraction succeeded. **I verified by whether the ZIP opened, not by whether the bytes looked plausible** — that is the single most important habit for this challenge class. Every layer has a hard pass/fail check (does it unzip? does it Base64-decode? does the result decode as UTF-8?), so never accept an "it should be this" from the model without running the check.

**Dead-ends to tell the model to AVOID up front:** frame-by-frame LSB stego (it's an appended ZIP, not in-frame); DTMF/standard tone tables (it's a custom 150 Hz grid); declaring `-0day-...-RCE-` the flag or brute-forcing it (the middle is plain Base62); and trusting decorator order blindly — remind it that stacked decorators apply bottom-up, so decode is top-down (`base64 -> xor -> reverse`).

**Fast-path prompt recipe for next time:** *"Treat this media file as a carrier: carve any appended archive first; for each hidden value, measure the encoding's structure (grid spacing, cell layout) rather than assuming a known scheme; chain decoders by inverting whatever the included encoder script does; and after every layer run its natural pass/fail check (unzip / b64 / utf-8 decode) before moving on — never accept a 'looks right'."*
