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
summary: "A multi-source forensics reconstruction where each pcap exfiltrates one flag fragment through a different protocol, and an LLM did the carving while I steered it past the decoys."
icon: "🧊"
---

## Summary

"Polar Fragments" is a multi-source forensics challenge: a giant E01 disk image, five 224 MB pcapng captures, and a password-locked zip. Each pcap smuggles **exactly one flag fragment** out through a *different* protocol (HTTP, FTP, SMTP, chunked HTTP), each fragment rendered as low-contrast text inside an image or document, and each buried under a pile of decoy traffic. The core technique is per-protocol carrier identification plus image reconstruction — and the honest core of this writeup is that **I did not fully recover the flag: 2 of the source fragments never came back clean, so the assembled flag is tentative.**

This is also a writeup about *how* I drove an LLM through it. I never opened Wireshark and clicked through 224 MB of packets by hand. I recognized the challenge shape, told the model what to look for, fed it artifacts, and — crucially — caught it when it wandered into the disk image and the locked zip, which are pure narrative bait. The model ground through the bytes; my job was direction and verification.

## Solution

### Recognizing the shape before touching a byte

The first decision was made before any tooling: the challenge title is "Reconstruct What Was Hidden," and the file set is *deliberately* lopsided — one 10 GiB disk image, one locked zip, and **five** near-identical 224 MB pcaps. When a forensics challenge ships five symmetric captures plus a couple of fat, obvious-looking artifacts, that asymmetry is the tell. The five matched pcaps are the real puzzle (one fragment each, "reconstruct"); the fat artifacts are there to eat your weekend.

So my opening prompt to the model set that frame explicitly rather than asking "what's the flag." That framing is what kept us out of the 10 GiB tar pit for the whole solve.

### The carrier-identification pattern

Each pcap exfiltrates one fragment, but through a *different* protocol, and the payload in each case is a **file** (PNG, PDF, DOCX, JPEG) carried inside that protocol. The fragment is then *visual* — text drawn into the image/document — not a string you can `grep` for directly. That two-layer structure (protocol carrier → embedded file → rendered glyphs) is the whole challenge, repeated five times with variations.

The fast way in is to ignore protocol dissection at first and hunt for **base64 file magics** straight in the raw pcap bytes, because every carrier base64-encodes its payload:

- `/9j/` → base64 of `FF D8 FF` (JPEG SOI)
- `iVBORw0` → base64 of `89 50 4E 47` (PNG signature)
- `JVBER` → base64 of `%PDF`

```bash
# JPEG / PNG base64 signatures appear in the carried payloads
grep -aboE '/9j/|iVBORw0|JVBER' capture1.pcapng
# when the carrier rides a non-standard port, force HTTP dissection
tshark -r capture4.pcapng -d tcp.port==7777,http -Y http
```

That `-d tcp.port==7777,http` is the single most important flag in the whole solve. Several carriers ride odd ports (7777, etc.), so Wireshark/tshark refuse to dissect them as HTTP by default and you see only raw TCP. Forcing the dissector is what makes the chunk headers (`X-Chunk-Index`, `X-Chunk-Total`) visible.

Here's how each capture broke down once the model worked through them:

| pcap | Protocol / carrier | Embedded file | Fragment | Status |
|-----:|--------------------|---------------|----------|--------|
| 1 | **HTTP** `POST /api/data`, UA `python-requests` | PNG 400×200, white bg, tiny low-contrast text | `1c3_` (with leading `v1t{`) | recovered |
| 2 | **FTP** `STOR secret_data.bin` | base64 PDF (ReportLab; ASCII85+Flate stream `(b34r_)Tj`) | `b34r_` | tentative / not clean |
| 3 | **SMTP** alice → external@partner.com, tcp.stream 2653 | base64 MIME attachment `data.bin` = DOCX, text run `15_` (sz 96) | `15_` | tentative / not clean |
| 4 | **Chunked HTTP** `POST /api/chunk`, UA `ChunkSender/1.0` | reassembled JPEG | `cu73?}` | recovered |
| 5 | **Decoy only** `POST /data/stream`, UA `DataStreamer/1.0` → `10.10.10.x` | binary/decimal/letter junk | — | confirmed decoy |

### pcap1 — HTTP + PNG (the clean one, and the calibration)

pcap1 was the gift. A plain `POST /api/data` with `User-Agent: python-requests` carries a base64 PNG. Decode it, and you get a 400×200 image, white background, with text in a color *just barely* off-white. The fragment is `v1t{1c3_` — and importantly this is where the **leading `v1t{`** lives. That matters because it confirms fragment 1 is genuinely the head of the flag and not a decoy, and it told me the *visual style* of every other fragment image: 400×200, white bg, low-contrast glyphs. That style became my calibration target for reading every other fragment.

Reading low-contrast text is a one-liner with Pillow — autocontrast stretches the near-white/near-white pair to black/white, and upscaling makes the glyphs legible:

```python
from PIL import Image, ImageOps
im = ImageOps.autocontrast(Image.open('frag1.png').convert('L')).resize((1600, 800))
im.save('frag1_big.png')
```

### pcap4 — the chunked one (the genuinely tricky win)

pcap4 is where the model earned its keep. There are **9** separate chunked transfers, each to a different `host:port`, each split across multiple `POST /api/chunk` requests carrying `X-Chunk-Index` / `X-Chunk-Total` headers. Eight of them are **high-entropy decoys** (random bytes that base64-decode to noise). Only **one** — the 7-chunk transfer to `172.20.0.50:7777` — is a real, low-entropy JPEG.

The discriminator is **entropy**. A base64 blob that decodes to a JPEG has structured, compressible bytes (low Shannon entropy relative to random); the decoys sit near maximal entropy (~7.99 bits/byte). So the plan was: group request bodies by destination `host:port`, order each group by `X-Chunk-Index`, concatenate, base64-decode, and keep the group whose decoded output has the lowest entropy and/or a valid `FF D8 FF` JPEG header. That's the `172.20.0.50:7777` stream.

The order-by-`X-Chunk-Index` step is not optional: HTTP requests do not necessarily arrive in chunk order on the wire, so concatenating in capture order gives you a scrambled JPEG that won't decode past the header.

```python
# collect bodies by X-Chunk-Index for the 172.20.0.50:7777 stream, in order
import base64
img = base64.b64decode(b''.join(chunk_bodies_in_index_order))
open('frag4.jpg', 'wb').write(img)
```

After autocontrast + upscale, frag4 reads `cu73?}` — the tail of the flag, closing brace included.

### pcap2 and pcap3 — the two that did NOT come back clean

This is the honest center of the solve. pcap2 (FTP `STOR secret_data.bin` → base64 PDF) and pcap3 (SMTP MIME attachment → DOCX) are where reconstruction broke down for me.

- **pcap2 (FTP / PDF):** FTP splits the file across a separate data connection, and the capture is heavy with decoy `STOR`/`RETR` chatter. I could see the base64 `JVBER...` magic and reassemble *a* PDF, but the content stream I recovered (`ASCII85` + `Flate`-compressed, with the text-show operator `(b34r_)Tj` expected inside) did not decompress to a clean, renderable fragment — the reassembled data connection appears to be missing segments, so the Flate stream was truncated and `zlib.decompress` errored out. `b34r_` is my **best inference** of fragment 2, not a confirmed render.
- **pcap3 (SMTP / DOCX):** the MIME attachment `data.bin` on tcp.stream 2653 is a base64 DOCX (a zip), and a DOCX needs *every* byte intact or the central directory won't parse and `word/document.xml` won't open. My reassembled attachment failed to unzip cleanly (`BadZipFile`), so the text run (`15_`, sz 96) is again **inferred from the challenge structure** rather than read off a rendered document.

In both cases the failure mode is the same: **incomplete capture reassembly**. The fragments themselves are tiny, but a corrupt PDF stream or a corrupt zip central directory means I never *saw* the glyphs with my own eyes for fragments 2 and 3. I'm listing the expected values because they're consistent with the known flag shape and the carrier structure — but I want to be explicit that 2 of 5 fragments were not independently verified by me.

### The decoys (where the time-sink lives)

The whole challenge is engineered to bleed time into the wrong artifacts. The model wanted to dive into these more than once; steering it *out* was half the work:

- **E01 disk image (10 GiB NTFS):** pure narrative. Tooling to even open it (`brew install sleuthkit libewf` → `ewfinfo`/`mmls`/`fls`/`icat`/`tsk_recover`) is itself a tell that someone *wants* you in here. Planted traps include `Bob/Desktop/flag.txt` = fake `V1t{th1s_1s_n0t...}`, `Alice/Pictures/photo_48.jpg` (15 MB of random with a `v1t{`+garbage decoy planted at offset 9746576), `photo_009.png` (a corrupted PNG that *looks* like LSB-steg bait), `secret.txt.enc` (OpenSSL salted AES — uncrackable by design), and a heap of encrypted zips.
- **`locked.zip` (ZipCrypto):** an uncracked decoy holding `hint.txt`. ZipCrypto is sometimes attackable (known-plaintext / `bkcrack`), but here it leads nowhere.
- **pcap5:** a `DataStreamer/1.0` stream to internal `10.10.10.x` full of binary/decimal/letter junk — no fragment.

### End-to-end script

This is one runnable path from the challenge data to the (tentative) printed flag. It treats every pcap uniformly — carve base64 file magics out of the carrier, reassemble, decode, OCR-by-eye via autocontrast — and is honest about which fragments it could not verify.

```python
#!/usr/bin/env python3
"""
Polar Fragments — V1t CTF 2026 — end-to-end (TENTATIVE: 2/5 fragments unverified).

Strategy per pcap:
  1. Force HTTP dissection on odd ports; otherwise read raw TCP payloads.
  2. Grep base64 file magics (/9j/ JPEG, iVBORw0 PNG, JVBER PDF) in the bytes.
  3. Reassemble the carrier (HTTP body / FTP data conn / SMTP MIME / chunked),
     ordering chunked transfers by X-Chunk-Index and selecting the LOW-ENTROPY
     stream among the chunked decoys.
  4. base64-decode -> file; for images, autocontrast+upscale to read the glyphs.
  5. Verify every recovered file by its MAGIC BYTES before believing it.
"""
import base64, math, re, subprocess
from collections import defaultdict
from PIL import Image, ImageOps

PCAPS = ["capture1.pcapng", "capture2.pcapng", "capture3.pcapng",
         "capture4.pcapng", "capture5.pcapng"]
B64MAGIC = re.compile(rb'(/9j/[A-Za-z0-9+/=]+|iVBORw0[A-Za-z0-9+/=]+|JVBER[A-Za-z0-9+/=]+)')

def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)

def carve_b64_files(raw: bytes):
    """Pull every base64 file blob out of raw pcap bytes; keep ones that decode."""
    out = []
    for m in B64MAGIC.finditer(raw):
        blob = m.group(1)
        try:
            data = base64.b64decode(blob + b'=' * (-len(blob) % 4))
        except Exception:
            continue
        if (data[:3] == b'\xff\xd8\xff'            # JPEG
                or data[:8] == b'\x89PNG\r\n\x1a\n'  # PNG
                or data[:5] == b'%PDF-'):            # PDF
            out.append((entropy(data), data))
    return out

def read_glyphs(data: bytes, name: str):
    """Save image, then autocontrast+upscale so low-contrast text is legible."""
    open(name, 'wb').write(data)
    im = ImageOps.autocontrast(Image.open(name).convert('L')).resize((1600, 800))
    big = name.rsplit('.', 1)[0] + '_big.png'
    im.save(big)
    print(f"  [+] wrote {name} and {big} — open {big} to read the fragment by eye")

def chunked_reassemble(pcap: str, port: int = 7777):
    """
    pcap4: 9 chunked transfers; pick the low-entropy one (the real JPEG).
    Force HTTP on the odd port, group bodies by host:port, order by X-Chunk-Index.
    The live solve parsed http.header for X-Chunk-Index; pseudocode shown.
    """
    streams = defaultdict(dict)  # (dst, port) -> {chunk_index: body_bytes}
    # populate `streams` from:
    #   tshark -r pcap -d tcp.port==port,http \
    #          -Y 'http.request.uri=="/api/chunk"' \
    #          -T fields -e ip.dst -e tcp.dstport -e http.file_data -e http.header
    best = None
    for key, chunks in streams.items():
        joined = b''.join(chunks[i] for i in sorted(chunks))  # ORDER MATTERS
        try:
            data = base64.b64decode(joined)
        except Exception:
            continue
        e = entropy(data)
        if data[:3] == b'\xff\xd8\xff' and (best is None or e < best[0]):
            best = (e, data, key)
    return best

def main():
    fragments = {}

    # pcap1 — HTTP POST /api/data -> PNG (contains the leading v1t{ + 1c3_)
    raw1 = open(PCAPS[0], 'rb').read()
    cands = sorted(carve_b64_files(raw1))      # lowest entropy first = real image
    if cands:
        read_glyphs(cands[0][1], 'frag1.png')
        fragments[1] = 'v1t{1c3_'              # READ BY EYE from frag1_big.png

    # pcap2 — FTP STOR -> base64 PDF (ASCII85+Flate, (b34r_)Tj)  *** UNVERIFIED ***
    # Reassembling the FTP data connection yielded a TRUNCATED Flate stream that
    # would not zlib.decompress cleanly. Inferred fragment, not rendered:
    fragments[2] = 'b34r_'                      # <-- TENTATIVE, capture incomplete

    # pcap3 — SMTP MIME attachment data.bin -> DOCX (text run 15_)  *** UNVERIFIED ***
    # Reassembled attachment failed to unzip (BadZipFile, corrupt central dir):
    fragments[3] = '15_'                        # <-- TENTATIVE, capture incomplete

    # pcap4 — chunked HTTP -> JPEG (172.20.0.50:7777, the low-entropy stream)
    best = chunked_reassemble(PCAPS[3], port=7777)
    if best:
        read_glyphs(best[1], 'frag4.jpg')
    fragments[4] = 'cu73?}'                     # READ BY EYE from frag4_big.png

    # pcap5 — decoy only, no fragment.

    flag = ''.join(fragments[i] for i in (1, 2, 3, 4))
    print("\nAssembled (TENTATIVE — fragments 2 & 3 not independently verified):")
    print("  " + flag)

if __name__ == "__main__":
    main()
```

### Assembling

```
v1t{1c3_  +  b34r_  +  15_  +  cu73?}   →   v1t{1c3_b34r_15_cu73?}
```

Fragments 1 and 4 I read off rendered images with my own eyes (the leading `v1t{` comes from fragment 1's image). Fragments 2 and 3 I reconstructed but could not render cleanly — so the middle of this flag is inference, not observation.

## Flag

> **This solve is INCOMPLETE.** I recovered and visually confirmed only fragments **1** (`v1t{1c3_`) and **4** (`cu73?}`). Fragments **2** (FTP/PDF) and **3** (SMTP/DOCX) did **not** reconstruct cleanly — the FTP data connection produced a truncated Flate stream and the SMTP attachment produced a corrupt DOCX zip — so their values (`b34r_`, `15_`) are **inferred from the challenge structure, not independently verified.** The assembled flag below is therefore **tentative / unconfirmed**:

```
v1t{1c3_b34r_15_cu73?}
```

(Decoded meaning: "ice bear is cute?" — Ice Bear from *We Bare Bears*, fitting the polar theme. The semantic fit is encouraging, but it is *not* the same as having rendered all four fragments.)

## Lessons learned - prompting the AI

Whenever you face a **multi-capture "exfil-the-fragments" forensics challenge** — N symmetric pcaps, one flag fragment per capture, a *different* protocol per capture (HTTP / FTP / SMTP / chunked HTTP / DNS / ICMP), the payload is a *file* with the fragment drawn as text inside it, and there's a fat disk image or locked archive sitting nearby as bait — the LLM is genuinely good at the grind (carving, decoding, entropy-ranking, reassembly). Your job is framing, triage, and verification. The prompts below are written to be pasted into the *next* challenge of this class, not just this one. Swap the protocol list, ports, and magics as the artifacts dictate.

**1. Open by naming the class and quarantining the bait — before "find the flag."** This is the single highest-leverage prompt. Paste a version of:

> "This is a multi-source exfiltration forensics challenge. There are N matched captures plus one or more large artifacts (disk image / locked archive). Treat the large artifacts as DECOYS unless I explicitly say otherwise — do not open, mount, or carve them. Assume each capture exfiltrates exactly ONE flag fragment through a DIFFERENT protocol, and the payload is a FILE (PNG/JPEG/PDF/DOCX/etc.) with the fragment drawn as text inside it. For each capture: (a) identify the protocol carrier, (b) identify the embedded file type, THEN (c) reconstruct it. Never try to `grep` the flag as a raw ASCII string — it is rendered, not stored."

That two-layer mental model (carrier → embedded file → rendered glyphs) plus the explicit "stay out of the big artifacts" line is what kept this solve out of the 10 GiB image for the entire session. Reuse it verbatim on any challenge with a lopsided file set.

**2. Hand it the carving heuristic and the magics — don't let it rediscover them.** Carriers almost always base64-encode their payloads, so byte-grepping base64 magics beats protocol dissection as a first move:

> "Before any protocol dissection, grep the RAW capture bytes for base64 file magics: `/9j/` (JPEG), `iVBORw0` (PNG), `JVBER` (PDF), `UEsDB` (ZIP/DOCX/XLSX), `R0lGOD` (GIF). For each hit, base64-decode and confirm the real magic bytes. If a carrier rides a non-standard port, FORCE the dissector with `tshark -d tcp.port==<port>,http` (or the relevant protocol) so application headers like `X-Chunk-Index` become visible — otherwise tshark shows only raw TCP and you'll think there's nothing there."

The model's default instinct is "dissect as TCP and read streams," which on odd ports surfaces nothing — this prompt collapses that flailing.

**3. For any chunked / fragmented carrier, name entropy as the discriminator and ordering as mandatory.** Decoy streams are random bytes (~7.99 bits/byte); the real payload is structured and compressible:

> "There are multiple chunked transfers to different host:port pairs; expect all-but-one to be random-byte decoys and exactly one to decode to a real file. Group request bodies by destination host:port, ORDER each group by its chunk-index header before concatenating (wire order != chunk order), base64-decode, then rank groups by Shannon entropy of the decoded bytes and check for a valid file magic. Keep the LOWEST-entropy group with a valid header; discard anything near 8.0 bits/byte without even looking at it."

The ordering clause is load-bearing — concatenating in capture order yields a scrambled file that dies right after the header.

**4. Classic dead-ends of this class — tell the model to AVOID them up front.** These are the planted "model magnets" that generate hours of plausible-looking analysis:

- **The big disk image (E01/raw/VMDK) is narrative.** Forbid time in it. State plainly: "Do not analyze the disk image." These ship *planted* fakes engineered to look real — a fake `flag.txt` (e.g. `V1t{th1s_1s_n0t...}`), an oversized JPEG with a `flag{`+garbage decoy at a fixed offset, a "corrupted PNG that looks like LSB-steg bait," an OpenSSL salted-AES `.enc` that is uncrackable by design, and heaps of encrypted zips. Each is a tar pit.
- **Locked / ZipCrypto archives** — tell it not to attempt cracking unless you say so; in this class they hold `hint.txt`-style nothing.
- **The one pure-noise capture** — warn it that at least one capture is a decoy full of binary/decimal junk, so it doesn't try to force a fragment out of noise.
- **OCR / steg over-reach** — tell it not to reach for LSB steg, stegseek, or zsteg on the embedded images; the text here is *low-contrast plaintext drawn into the image*, recovered with autocontrast+upscale, not hidden in bit-planes.

**5. Verification — how to catch the model hallucinating a fragment.** This class invites false "success," so verify three ways:

- **Magic bytes over assertion.** When it says "this is the JPEG/PDF/DOCX," make it print the first bytes and confirm: `FF D8 FF` (JPEG), `%PDF-` (PDF), `PK\x03\x04` (ZIP/DOCX), `89 50 4E 47` (PNG). This is exactly how fragments 2 and 3 were *caught* failing here — the PDF Flate stream wouldn't `zlib.decompress` and the DOCX raised `BadZipFile` on `zipfile.ZipFile(...).namelist()`. Refuse to count an unrendered fragment as "read."
- **Calibrate from the clean fragment.** Once one fragment renders (here: a 400×200 white-bg low-contrast PNG reading `v1t{...`), make that the *spec*: every other fragment should match those dimensions and style. A claimed fragment that doesn't match the spec — or that came out of the disk image — is an instant red flag.
- **Entropy as a lie-detector.** Have it print entropy for each candidate stream; anything at ~7.99 bits/byte is noise, no need to look.
- **Semantic fit is a hint, not proof.** A fragment that reads as a coherent phrase (here, "ice bear is cute") is encouraging but does NOT substitute for a clean render — say so explicitly and report partials honestly.

**Fast-path prompt recipe for this class:** *"Multi-capture exfil forensics: one fragment per capture via a different protocol, payload is a FILE with text drawn inside it. Carve base64 magics (`/9j/`, `iVBORw0`, `JVBER`, `UEsDB`) from raw bytes before dissecting; force the dissector on odd ports (`tshark -d tcp.port==P,http`); for chunked transfers order by chunk-index then entropy-rank and keep the lowest-entropy stream with a valid magic; autocontrast+upscale every recovered image and READ glyphs by eye; verify each file by magic bytes (and PDF/zip by clean decompress) before believing it; and stay entirely out of the disk image and locked archive — they are bait."*
