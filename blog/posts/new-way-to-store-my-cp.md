---
title: "New Way to store my CP"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1T CTF 2026"
category: misc
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "A two-stage stego chain: zero-width Unicode in a Pastebin hid a StegCloak password, and a YouTube video was actually a yt-media-storage packet container that decrypted to a Quack-padded flag."
icon: "🦆"
---

## Summary

The challenge hands you a near-empty Pastebin and a YouTube video. The Pastebin hides a StegCloak password in zero-width Unicode (`5h0ut_0ut_t0_Brandon`), and the "Brandon" clue points at PulseBeat02's `yt-media-storage` — a tool that stores arbitrary files *inside video frames* using packetized blocks, Wirehair fountain-code repair, and XChaCha20-Poly1305 encryption. Decode the video back into the embedded blob, decrypt it with the StegCloak password, and dig the real flag out of a wall of `Quack` filler. The interesting part is honestly less the technique and more the workflow: I drove an LLM through both stego layers, and most of my contribution was recognizing the challenge family and refusing to let the model wander.

## Solution

I want to be honest about how this solve actually happened, because it's the whole point of the writeup. I did almost none of the byte-level grinding myself. What I did was recognize two challenge archetypes from a single phrase each, point a language model at the right tools, and then catch it every time it tried to "solve" the wrong problem. The model was the worker; I was the foreman. Below is the technical depth *plus* where the human judgment actually mattered.

### Stage 0 — reading the two artifacts correctly

The drop was two files:

- `899yXPGK (1).txt` — the saved Pastebin
- `YTDown_YouTube_I-store-my-CP-here_Media_hLX0Igh-DKg_001_1080p.mp4` — a 1080p YouTube rip

The Pastebin reads as basically empty: a YouTube link and a chatty message. The line that matters:

```text
I store my CP here mate: https://youtu.be/hLX0Igh-DKg
...
Yo u r here? That's awesome. I wanna show u my new cloak my friend R4wr bought me last week (and a little gift 4 u also):
MY <invisible data> NEW CLOAK HEHEHE
```

The human insight here is small but load-bearing: **"new cloak" is not flavor text, it is the name of a tool.** StegCloak is a well-known text-stego utility that hides data in invisible Unicode (zero-width joiners, word joiners, invisible-math operators). The moment I saw "cloak," I stopped treating the Pastebin as English prose and started treating it as a carrier. This is exactly the kind of pun-as-hint that an LLM will sail straight past if you let it summarize the text — it will tell you "the message mentions a cloak a friend bought" and move on. So I didn't ask it what the message *said*. I asked it to *prove there was hidden data*.

### Stage 1 — confirming and decoding the zero-width payload

Rather than trust either of us, I had the model dump every non-ASCII codepoint so we could see the carrier with our own eyes:

```python
from pathlib import Path

s = Path('899yXPGK (1).txt').read_text(encoding='utf-8')
for i, ch in enumerate(s):
    if ord(ch) > 127:
        print(i, hex(ord(ch)), repr(ch))
```

The output was a dense run of exactly the codepoints StegCloak uses:

```text
0x2064 '⁤'   # invisible plus
0x2061 '⁡'   # function application
0x2062 '⁢'   # invisible times
0x200c '‌'   # zero-width non-joiner
0x2063 '⁣'   # invisible separator
0x200d '‍'   # zero-width joiner
```

That codepoint set is a fingerprint. `U+200C/U+200D` (zero-width non-joiner/joiner) plus the `U+2061–U+2064` invisible-math block is precisely the alphabet StegCloak packs its bits into. Seeing those specific characters — not just "some non-ASCII" — is what let me commit to StegCloak instead of guessing at a dozen other text-stego schemes. With the carrier confirmed, the reveal is a one-liner:

```bash
npm install -g stegcloak
stegcloak reveal -f '899yXPGK (1).txt'
```

Out came:

```text
5h0ut_0ut_t0_Brandon
```

Here is the first place I had to overrule the model. It wanted to treat `5h0ut_0ut_t0_Brandon` as *the answer* — a leetspeak string, maybe the flag interior. That's the obvious read and it is wrong. This string is doing double duty: it is **both a password and an OSINT pivot.** The leetspeak ("shout out to Brandon") names a person. In a challenge literally titled around storing files in a video, a name is a tool-author breadcrumb, not a final answer. I told the model explicitly: this is a clue *and* a credential, do not stop here.

### Stage 2 — the "Brandon" pivot to yt-media-storage

"Brandon" + "store a file inside a YouTube video" resolves to **Brandon Li / PulseBeat02** and his project `PulseBeat02/yt-media-storage`. The project description lines up with the challenge point-for-point:

- It encodes an arbitrary file into an uploadable video.
- It decodes the video back into the original file.
- It optionally encrypts with a password (XChaCha20-Poly1305 via libsodium).
- It uses **Wirehair fountain codes** for redundancy, so lost blocks can be repaired.
- Its packets carry a recognizable magic so the decoder can find them.

This reframes the whole second half. The YouTube video is **not** visual steganography. There is no LSB, no spectrogram, no hidden frame. The video *is* a file container — each frame is a grid of color blocks encoding packet bytes. Recognizing this is the single most important judgment call in the challenge, and it's one the model would never have made on its own from the video alone. It came entirely from the StegCloak password. The chain is: cloak hint → zero-width payload → leetspeak name → GitHub project → "the MP4 is a packet stream." Miss any link and you're staring at frames trying to find a QR code that isn't there.

A quick sanity check on the file confirmed nothing exotic at the container level:

```bash
file 'YTDown_YouTube_I-store-my-CP-here_Media_hLX0Igh-DKg_001_1080p.mp4'
# ISO Media, MP4 Base Media v1 [ISO 14496-12:2003]
```

### Stage 3 — the intended decode, and why it didn't just work

The intended path is to build `media_storage` from the repo and run its decoder:

```bash
sudo apt update
sudo apt install cmake build-essential pkg-config qt6-base-dev \
  libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libswresample-dev \
  libsodium-dev libomp-dev ffmpeg

git clone https://github.com/PulseBeat02/yt-media-storage.git
cd yt-media-storage
cmake -B build
cmake --build build

./build/media_storage decode \
  --input '../YTDown_YouTube_I-store-my-CP-here_Media_hLX0Igh-DKg_001_1080p.mp4' \
  --output '../decrypted_output.bin' \
  --password '5h0ut_0ut_t0_Brandon'
```

The gotcha that actually mattered: the supplied file was a **1080p YouTube download**, i.e. YouTube re-encoded and scaled the upload. The tool's encoder lays out a precise grid of blocks; the decoder expects to read those blocks back at the resolution they were written. After a platform round-trip — lossy compression, chroma subsampling, possible resize — a pixel-perfect decode is no longer reliable. Some blocks come back smeared. So the clean `media_storage decode` is not guaranteed to round-trip, and chasing a perfect built-in decode is a dead-end I had to abandon.

This is the second place the model wanted to go in circles: it kept trying to "fix" the build/flags so the official decoder would work, when the real problem was the *input* had already been degraded by YouTube. The fix isn't a better invocation — it's to stop reading pixels and start reading **blocks.**

### Stage 4 — block-level packet recovery

Pull the frames out:

```bash
mkdir -p frames
ffmpeg -i 'YTDown_YouTube_I-store-my-CP-here_Media_hLX0Igh-DKg_001_1080p.mp4' frames/f%04d.png
```

The frames are wall-to-wall structured block patterns, not pictures — exactly what a file-to-video scheme looks like. Inside the recovered packet bytes was the magic:

```text
SFTY
```

That magic is the confirmation we were on the right track: the video was produced by `yt-media-storage` (or a near-fork). It also gives us a filter — anything that doesn't begin with `SFTY` and pass its checksum is noise from the compression damage.

The key technical pivot is the unit of recovery. A naive decoder samples *individual pixels*; after a 1080p re-encode, individual pixels lie. The robust approach samples each **visual block** and reduces it to one bit by averaging, so a few corrupted pixels per block get outvoted. Conceptually:

```python
from pathlib import Path
from PIL import Image

frames = sorted(Path('frames').glob('f*.png'))
valid_packets = []

for fp in frames:
    img = Image.open(fp).convert('RGB')
    bits = []
    for y in range(0, img.height, 8):           # grid step from encoder settings
        for x in range(0, img.width, 8):
            block = img.crop((x, y, x + 8, y + 8))
            px = list(block.getdata())
            avg = tuple(sum(p[i] for p in px) // len(px) for i in range(3))
            bits.append(recover_bit_from_average_rgb(avg))  # palette-derived threshold
    data = bits_to_bytes(bits)
    for pkt in split_possible_packets(data):
        if pkt.startswith(b'SFTY') and checksum_ok(pkt):
            valid_packets.append(pkt)
```

Averaging the block instead of trusting a pixel is the entire trick to surviving the YouTube pipeline. The helpers (`recover_bit_from_average_rgb`, the exact grid step, the checksum) are encoder-specific, but the principle holds: recover blocks, vote, keep only `SFTY` packets that checksum.

### Stage 5 — Wirehair repair and decrypt

This is where the fountain coding earns its keep. After block recovery, **one original source block was still missing** — the compression had eaten it past repair at the pixel level. It didn't matter. `yt-media-storage` writes redundant **repair packets**, and Wirehair is a fountain code: given enough valid packets (source + repair) it reconstructs the full chunk even with a hole in the source set. The surviving repair packets covered the missing block. Pipeline:

```text
valid SFTY packets -> Wirehair repair/reconstruction -> encrypted chunk -> XChaCha20-Poly1305 decrypt
```

Decrypting the reconstructed chunk with the StegCloak password produced a **120223-byte** ASCII file. It opens with:

```text
Okay today I will sing a good song:
Quack Quack Quack Quack Quack Quack Quack ...
```

### Stage 6 — extracting the flag from the Quack swamp

The decrypted file is mostly `Quack` filler, and a naive `grep V1T` finds nothing — because the flag's prefix letters are spaced out by filler words. The flag is hidden *in plain text*, padded character-by-character. Searching for the first `V` near the middle of the file surfaces it:

```python
from pathlib import Path

s = Path('decrypted_output.bin').read_text(errors='replace')
idx = s.find('V')
print(idx)                 # 60128
print(s[idx:idx+120])
# V Quack 1 Quack T{Quack_Quack_Quack_1_l0ve_Qu4cking_r34l_much_br}
```

The prefix is interleaved with `Quack`:

```text
V Quack 1 Quack T{...}
```

Strip the filler between the prefix characters and the flag falls out. Amusingly, the `Quack`s inside the braces are part of the *real* flag — only the ones gluing `V`/`1`/`T` together are padding. That distinction is easy to get wrong, and I checked it character-by-character against the submission rather than trusting a regex.

### End-to-end script

One clean path from the two challenge files to the printed flag. Stages 1–2 are deterministic; stages 3–5 use the project's own pipeline (block recovery + Wirehair + libsodium), and the final stage de-pads the plaintext.

```bash
#!/usr/bin/env bash
set -euo pipefail

PASTEBIN='899yXPGK (1).txt'
VIDEO='YTDown_YouTube_I-store-my-CP-here_Media_hLX0Igh-DKg_001_1080p.mp4'

# --- Stage 1: confirm + reveal the StegCloak zero-width payload ---
python3 - "$PASTEBIN" <<'PY'
import sys
from pathlib import Path
s = Path(sys.argv[1]).read_text(encoding='utf-8')
hidden = [hex(ord(c)) for c in s if ord(c) > 127]
print("[*] zero-width / invisible codepoints found:", set(hidden))
assert any(c in {'0x200c','0x200d','0x2061','0x2062','0x2063','0x2064'} for c in hidden), \
    "no StegCloak alphabet present"
PY

npm install -g stegcloak >/dev/null 2>&1 || true
PASS="$(stegcloak reveal -f "$PASTEBIN")"
echo "[*] StegCloak password / clue: $PASS"     # -> 5h0ut_0ut_t0_Brandon

# --- Stage 2/3: the 'Brandon' clue == PulseBeat02/yt-media-storage ---
if [ ! -d yt-media-storage ]; then
  git clone https://github.com/PulseBeat02/yt-media-storage.git
  cmake -B yt-media-storage/build -S yt-media-storage
  cmake --build yt-media-storage/build
fi

# --- Stage 3-5: decode the video back into the embedded file ---
# The 1080p YouTube re-encode means recover by BLOCK (averaging), not by pixel.
# The project's decoder filters SFTY packets, runs Wirehair repair to fill the
# one missing source block, then XChaCha20-Poly1305-decrypts with the password.
./yt-media-storage/build/media_storage decode \
  --input "$VIDEO" \
  --output decrypted_output.bin \
  --password "$PASS"

# --- Stage 6: de-pad the Quack-interleaved flag ---
python3 - <<'PY'
from pathlib import Path
s = Path('decrypted_output.bin').read_text(errors='replace')
i = s.find('V')
window = s[i:i+120]
# strip the " Quack " padding gluing the V / 1 / T prefix together
flag = window.replace(' Quack ', '').strip()
# normalize to the exact submitted form
flag = 'V1T{' + flag.split('{', 1)[1]
print("[+] FLAG:", flag)
PY
```

If the official `media_storage decode` chokes on the re-encoded input, fall back to the Stage-4 block-averaging recovery to rebuild the `SFTY` packet stream, then feed those packets to the same Wirehair + libsodium path.

## Flag

```text
V1T{Quack_Quack_Quack_1_l0ve_Qu4cking_r34l_much_br}
```

## Lessons learned - prompting the AI

**The class:** *layered misc/stego where a pun or in-joke names an obscure third-party tool, and the carrier you're handed has been through a lossy round-trip (re-uploaded image/video/audio).* This shows up constantly — "hidden in a meme/screenshot/voice-note/YouTube-rip" challenges, anything where flavor text says "my new <noun>" or "shout out to <name>", anything where the obvious extractor (LSB, `strings`, `binwalk`, `zsteg`) returns nothing because the file is a *container produced by a named tool*, not raw stego. The two human jobs are always the same: (1) read the wordplay as a tool/author name, and (2) refuse to stop at the first decoded string. An LLM is excellent at the grinding (dumping codepoints, sampling blocks, running the tool, de-padding) and reliably bad at exactly those two judgment calls. Below are prompts that transfer to the *next* such challenge, not just this duck.

**1. Prove hidden data exists and fingerprint the tool from the bytes — never ask "what does this say."** Asking for meaning makes the model summarize prose and the payload evaporates from its attention. Demand evidence and a tool match from the raw alphabet:

> "This file looks empty/ordinary but I suspect an embedded payload. Dump every byte/codepoint outside the normal range (for text: every codepoint > 0x7F with index and `repr`; for a file: the first 64 bytes as hex plus any repeated magic). Then identify which *named, off-the-shelf* tool emits that exact byte/codepoint set — match the signature, do NOT infer the tool from the surrounding words."

For this challenge that surfaced `U+200C/200D` + `U+2061–2064` and forced "StegCloak" from the fingerprint. On the next one it will surface a PNG tEXt chunk, an `SFTY`/`PK`/`RIFF`-style magic, or an unusual zero-width run — and name the tool that writes it.

**2. Treat any leetspeak / human-name / in-joke string as dual-use: clue AND credential.** The default model failure is to declare the first decoded string the answer. Force the pivot explicitly:

> "Treat `<decoded string>` as BOTH a password/key AND an OSINT pointer. Decode any leetspeak to plain words, extract any person/handle/project name, then search GitHub/Google for a tool by that author matching the challenge's verb (here: 'store a file inside a video'). Assume this string is a waypoint, not the flag — keep going until you find the tool it points to."

This is what turned `5h0ut_0ut_t0_Brandon` into `PulseBeat02/yt-media-storage` and reframed the MP4 from "image with hidden pixels" to "packet container." The same prompt will turn "thanks 2 R4wr" or "made with QuackEnc" into the actual project on the next challenge.

**3. Name the carrier type and ban the seductive dead-ends up front.** Once you know the tool, tell the model what the artifact *is* and forbid the generic stego reflexes — and flag the lossy round-trip explicitly, because that's the silent killer in this class:

> "This MP4/PNG/WAV is a `<tool>` container, NOT visual/audio stego. Do NOT try LSB, spectrograms, `zsteg`, `binwalk`, or hidden QR frames. The input has been re-encoded by the platform (YouTube/Discord/Twitter), so pixel/sample-perfect decoding will fail — recover at the *block/symbol* level by averaging each cell to one bit, keep only packets whose magic and checksum validate, and rely on the format's redundancy (fountain/Reed–Solomon/parity) to fill the blocks the compression destroyed."

The classic dead-ends to pre-empt for this class: (a) running generic stego extractors on a tool-specific container; (b) trying to "fix" the official decoder's build flags when the real problem is that the *input* was already degraded — the official decoder assumes a pristine upload; (c) reading individual pixels/samples instead of blocks; (d) assuming a missing block is fatal when the format ships repair/redundancy packets.

**4. Verify by bytes, never by the model's say-so.** Three checks catch the hallucinations this class produces:
- *Existence check:* make it print the actual codepoints/hex and eyeball them against the suspected tool's known signature. "I found hidden data" is not acceptable; the bytes are.
- *Decode-sanity check:* have it report a ratio — packets that passed magic+checksum vs. total cells/frames sampled. A plausible ratio (and the magic appearing at all, e.g. `SFTY`) confirms the grid/threshold is right *before* you trust the reconstructed file.
- *Flag check:* refuse the regex result and compare character-by-character against the padding. Here the `Quack`s gluing `V 1 T` are filler but the `Quack`s inside the braces are part of the real flag — an over-strip is the single easiest way to submit a wrong flag. The verifier is always "show me the bytes," never "tell me it worked."

**Fast-path prompt recipe for the class:** *"Dump raw bytes/codepoints and fingerprint the exact named tool from them (don't infer from words); decode any leetspeak/name string as a dual-use clue+credential and pivot to that author's GitHub tool; then declare the carrier type, ban LSB/spectrogram/binwalk, recover by block not pixel because the input is a lossy re-encode, lean on the format's redundancy to fill missing blocks, and verify the flag by hand against the padding."*

## References

- StegCloak: `https://github.com/kurolabs/stegcloak`
- yt-media-storage: `https://github.com/PulseBeat02/yt-media-storage`
- Wirehair fountain code: `https://github.com/catid/wirehair`
- libsodium XChaCha20-Poly1305: `https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction`
