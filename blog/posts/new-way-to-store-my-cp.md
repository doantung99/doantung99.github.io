---
title: "New Way to store my CP"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1T CTF 2026"
category: misc
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "A near-empty Pastebin hid a StegCloak password, and a YouTube video was actually a yt-media-storage container whose packets had to be block-reconstructed, Wirehair-repaired, and XChaCha20-decrypted to reveal the flag."
icon: "🦆"
---

## Summary
A Pastebin with an "empty" message hid invisible Unicode characters that StegCloak decoded into a password, and the linked YouTube video turned out to be a `yt-media-storage` file container that needed packet recovery, Wirehair fountain-code repair, and XChaCha20-Poly1305 decryption. My job was steering: I called the technique at each fork, fed artifacts to the model, and corrected it when a naive decode failed; the model did the reversing, scripting, and decoding grind.

## Solution

**Step 1 — the "new cloak" tell.** I gave the model the Pastebin text and the line `MY <looks empty> NEW CLOAK HEHEHE`. I recognized "new cloak" as the StegCloak signature and steered it that way rather than chasing visual stego. I had it dump every non-ASCII codepoint to confirm a hidden payload, and the output was full of zero-width characters (`⁡`, `⁢`, `⁣`, `⁤`, `‌`, `‍`). Then `stegcloak reveal -f '899yXPGK (1).txt'` gave the password/clue `5h0ut_0ut_t0_Brandon`.

**Step 2 — interpret the clue, then catch the wrong turn.** I asked the model to OSINT "Brandon" against "storing files in YouTube videos." It landed on Brandon Li / PulseBeat02 and the project `PulseBeat02/yt-media-storage` — a tool that packs arbitrary files into video frames as `SFTY`-magic packets with Wirehair redundancy and optional XChaCha20-Poly1305 encryption. The model's first instinct was a straight `media_storage decode` of the supplied MP4. I had it try, it was unreliable, and I made the call on why: the file was a 1080p YouTube re-encode, so pixel-perfect packet extraction was lost. I redirected it to reconstruct bits from visual blocks instead of single pixels.

**Step 3 — block-level recovery, repair, decrypt.** I had the model extract frames, sample each block back into bits, keep only packets matching the `SFTY` header/checksum, and feed them to Wirehair (one source block was missing but repair packets covered it). The recovered 120223-byte blob decrypted with the StegCloak password into `Quack`-filler text. I told it the flag prefix was likely split by filler, and a search around the middle confirmed it. End-to-end:

```python
from pathlib import Path
from PIL import Image
# pip install pillow ; npm install -g stegcloak
# yt-media-storage helpers (PulseBeat02): wirehair_repair, xchacha20_decrypt

# 1) StegCloak password (run separately, captured here):
#    stegcloak reveal -f '899yXPGK (1).txt'  ->  5h0ut_0ut_t0_Brandon
PASSWORD = "5h0ut_0ut_t0_Brandon"
VIDEO = "YTDown_YouTube_I-store-my-CP-here_Media_hLX0Igh-DKg_001_1080p.mp4"

# 2) extract frames:  ffmpeg -i $VIDEO frames/f%04d.png
# 3) block-level packet recovery (1080p re-encode => sample blocks, not pixels)
valid = []
for fp in sorted(Path("frames").glob("f*.png")):
    img = Image.open(fp).convert("RGB")
    bits = []
    for y in range(0, img.height, 8):
        for x in range(0, img.width, 8):
            block = list(img.crop((x, y, x + 8, y + 8)).getdata())
            avg = tuple(sum(p[i] for p in block) // len(block) for i in range(3))
            bits.append(recover_bit_from_average_rgb(avg))   # palette threshold
    data = bits_to_bytes(bits)
    for pkt in split_possible_packets(data):
        if pkt.startswith(b"SFTY") and checksum_ok(pkt):
            valid.append(pkt)

# 4) Wirehair repair -> encrypted chunk -> XChaCha20-Poly1305 decrypt
chunk = wirehair_repair(valid)                 # rebuilds the one missing block
plain = xchacha20_decrypt(chunk, PASSWORD)     # 120223 bytes of Quack filler
Path("decrypted_output.bin").write_bytes(plain)

# 5) flag prefix is split by "Quack" filler -> find the first 'V'
s = plain.decode(errors="replace")
i = s.find("V")
print(s[i:i + 120])   # V Quack 1 Quack T{Quack_Quack_Quack_1_l0ve_Qu4cking_r34l_much_br}
print("".join(s[i:i + 120].split(" Quack ")))   # collapse filler -> flag
```

The recovered region read `V Quack 1 Quack T{Quack_Quack_Quack_1_l0ve_Qu4cking_r34l_much_br}`; collapsing the `Quack` filler between the prefix letters yields the flag.

## Flag
```
V1T{Quack_Quack_Quack_1_l0ve_Qu4cking_r34l_much_br}
```
