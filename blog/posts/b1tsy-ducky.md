---
title: "B1tsy Ducky"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: web
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, web, ai-assisted]
draft: false
summary: "A Bitsy browser game ships a Go WebAssembly module whose hidden duck routine derives an AES-GCM key from three page-sourced inputs; reconstructing the exact password string offline decrypts the flag."
icon: "🦆"
---

## Summary
This was a Bitsy-style HTML game backed by a Go WebAssembly module that hides a `duckWasmReveal` decrypt routine. The core technique was recognizing that the JavaScript wrapper leaks the three inputs (referrer, room-3 block, a 32-hex token) fed into an AES-GCM decryption, then rebuilding that exact password string offline to recover the flag.

## Solution
I clocked the shape of this one fast: a Bitsy game plus `wasm_exec.js` plus a raw wasm blob means Go-compiled WebAssembly, and the actual logic lives in the HTML wrapper and the wasm module, not in the runtime glue. I set that as the direction and told the model up front not to waste cycles reversing `wasm_exec.js`.

I had the model triage the three files. It confirmed the blob (`00a8bb72`) was a WASM MVP module, then I steered it to grep `game.html` for the call site. It surfaced the key line: the wrapper waits for `window.duckWasmReveal` to export, then calls it with exactly three args — `document.referrer`, a serialized `ROOM 3` block, and a `pick32()` token. That told us precisely what to reconstruct.

The model did the grinding from there. It read `pick32()` and traced the 32-hex value to the Cloudflare beacon `data-cf-beacon` token at the bottom of the page (`797084dac2504482bcfaec15adc048bb`), and pulled the AES-GCM constants out of the wasm with `strings`: the HMAC label `b1tsy-ducky-aesgcm`, the `nonce|` prefix, and the ciphertext hex. Its first local run failed — I caught that the empty local `document.referrer` was the culprit, since the wrapper passes whatever the browser reports. I had it pin the referrer to the original site value `https://b1tsy.v1t.site/`, and I verified the derivation matched the wasm flow: key = HMAC-SHA256(label, password), nonce = SHA256("nonce|" + password)[:12], password = `referrer|room3Block|picked32`. With those fixed, the decrypt produced the flag.

```python
#!/usr/bin/env python3
import re
import hmac
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

html = Path("game.html").read_text()

# Rebuild the serialized ROOM 3 block the wrapper feeds to the wasm
m = re.search(r"\nROOM 3\n(.*?)(?=\n\nTIL |\nROOM |\nTIL )", html, re.S)
if not m:
    raise SystemExit("ROOM 3 not found")
room3Block = "ROOM 3\n" + m.group(1).strip("\n")

# pick32(): the last 32-hex token on the page = the Cloudflare beacon token
tokens = re.findall(r"\b[a-f0-9]{32}\b", html, re.I)
picked32 = tokens[-1]

# document.referrer expected by the live site
referrer = "https://b1tsy.v1t.site/"

# Ciphertext pulled from the wasm via strings
ciphertext = bytes.fromhex(
    "9e8c2b395bbf6bd7434230ab998c6e86"
    "f3228c503324c8660715ccd0bc74deb7"
    "d6346dfcc4a9614e58cb"
)

password = f"{referrer}|{room3Block}|{picked32}".encode()
key = hmac.new(b"b1tsy-ducky-aesgcm", password, hashlib.sha256).digest()
nonce = hashlib.sha256(b"nonce|" + password).digest()[:12]

flag = AESGCM(key).decrypt(nonce, ciphertext, None)
print(flag.decode())
```

```bash
python3 solve.py
# v1t{b1tsy_t1psy_duck_w4sm}
```

## Flag
```
v1t{b1tsy_t1psy_duck_w4sm}
```
