---
title: "Polar Fragments"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: forensics
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, forensics, ai-assisted]
draft: false
summary: "A multi-source forensics challenge where each of five pcaps exfiltrates one flag fragment over a different protocol (HTTP/FTP/SMTP/chunked HTTP), and the fragments are low-contrast text hidden inside carried images and documents."
icon: "🐻‍❄️"
---

## Summary
The drop was a 10 GiB E01 disk image, a `locked.zip`, and five 224 MB pcapng captures. Each pcap smuggles exactly one flag fragment through a different protocol and file format, buried under decoy traffic; the disk image and zip are pure narrative. The core technique is per-protocol carrier identification, then reading low-contrast text out of the carried images/docs.

## Solution
I went in assuming "reconstruct what was hidden" meant the captures were the real target and the bulky disk image was a time sink, so I set that direction first and had the model confirm it by triaging the artifacts: it flagged `Bob/Desktop/flag.txt` (fake `V1t{th1s_1s_n0t...}`), a planted `v1t{`+garbage blob inside `Alice/Pictures/photo_48.jpg`, a steg-bait PNG, and an uncrackable OpenSSL-encrypted `secret.txt.enc` — all decoys. I told it to drop the E01 and `locked.zip` and focus on the pcaps.

Then I had it grind through the captures. My steering was: grep the raw pcap bytes for base64 file magics (`/9j/`, `iVBORw0`, `JVBER`) and force HTTP dissection on odd ports, then identify the carrier per pcap. It mapped four real fragments to four protocols (pcap5 is a decoy stream):

1. **HTTP** `POST /api/data` (UA `python-requests`) carrying a 400×200 PNG → `1c3_`
2. **FTP** `STOR secret_data.bin`, a base64 PDF with `(b34r_)Tj` in the content stream → `b34r_`
3. **SMTP** (tcp.stream 2653), base64 MIME `.docx` attachment with run `15_` → `15_`
4. **Chunked HTTP** `POST /api/chunk` (UA `ChunkSender/1.0`) reassembled to a JPEG → `cu73?}`

Pcap4 was the trap and where I had to correct the model's first pass: it tried to reassemble the first chunked stream it saw, but there are **9** chunked transfers to 9 `host:port` pairs and eight are high-entropy decoys. I told it to use entropy to separate them — the one real, low-entropy JPEG is the 7-chunk transfer to `172.20.0.50:7777`. After that it ordered chunks on `X-Chunk-Index` and the carried files all decoded cleanly. The fragment images are low-contrast text on white, so the last step is auto-contrast + upscale to read the characters; I verified each fragment by eye before concatenating.

```python
import base64
from PIL import Image, ImageOps

# --- pcap4: reassemble the real JPEG (7-chunk stream to 172.20.0.50:7777) ---
# chunk_bodies_in_index_order = base64 chunk bodies sorted by X-Chunk-Index
img = base64.b64decode(b''.join(chunk_bodies_in_index_order))
open('frag4.jpg', 'wb').write(img)

# --- read low-contrast fragment images (e.g. the PNG from pcap1) ---
def read_fragment(path, out):
    im = ImageOps.autocontrast(Image.open(path).convert('L')).resize((1600, 800))
    im.save(out)

read_fragment('frag1.png', 'frag1_big.png')   # -> v1t{1c3_
# frag2 (b34r_) from FTP PDF, frag3 (15_) from SMTP .docx, frag4 (cu73?}) from frag4.jpg

# --- assemble ---
flag = '1c3_' + 'b34r_' + '15_' + 'cu73?}'
print('v1t{' + flag)   # leading v1t{ is rendered in fragment 1's image
```

## Flag
```
v1t{1c3_b34r_15_cu73?}
```
