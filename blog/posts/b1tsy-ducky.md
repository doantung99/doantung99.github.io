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
summary: "A Bitsy game ships a Go-WASM 'duck' that derives an AES-GCM key from three page-local inputs; reconstruct the exact password string offline and decrypt the flag."
icon: "🦆"
---

## Summary

We're handed a Bitsy-style HTML game, the standard Go `wasm_exec.js` runtime, and a WebAssembly binary that exports a single function, `duckWasmReveal`. The function derives an AES-GCM key and nonce from three values that the page itself supplies — `document.referrer`, the serialized `ROOM 3` block, and a 32-hex token scraped from a script tag — and uses them to decrypt a hardcoded ciphertext. The whole challenge is *key reconstruction*: get the password string byte-for-byte identical to what the live site would have produced, and AES-GCM hands you the flag.

This is the kind of challenge I now solve as a steering exercise. I recognized the shape immediately — "the secret isn't in the binary, the binary just rebuilds a key from page state" — and that recognition is the only hard part of the human's job. From there I let the model do the grinding: read the WASM strings, trace the JS wrapper, propose the KDF, and write the decrypt. My job was to point it at the right artifacts, kill the dead-ends it kept wandering into, and verify the GCM tag actually validated.

## Solution

### The mental model: don't reverse the binary, reverse the *contract*

The instinct with a WASM challenge is to disassemble. That instinct is mostly wrong here, and naming why is what makes the solve fast. `wasm_exec.js` is unmodified Go runtime glue — channels, the scheduler, syscall shims — and reversing it is a time sink with zero payoff. The Go WASM module is large and the actual crypto is a handful of stdlib calls buried in Go's allocator noise. Fully decompiling Go-from-WASM is genuinely painful.

The shortcut: a Go WASM export that takes inputs from JavaScript and returns a string is a *contract*. The HTML wrapper is the spec for that contract — it shows exactly what gets passed in and in what order. If I can read the three inputs off the page and find the small set of crypto constants in the binary, I never have to understand a single WASM opcode. The binary becomes a black box whose behavior I reproduce in Python.

So the plan is two-pronged:

1. From `game.html`: recover the three call arguments to `duckWasmReveal`.
2. From the WASM binary: recover the crypto constants (HMAC label, nonce prefix, ciphertext) and infer the KDF.

### Step 1 — confirm what we're holding

```bash
file 00a8bb72
# 00a8bb72: WebAssembly (wasm) binary module version 0x1 (MVP)
```

The odd filename `00a8bb72` is just the binary; the page fetches it as `main.wasm`. Confirming the magic up front matters only so we don't waste time treating it as a data blob.

### Step 2 — read the call site, because it is the entire spec

Grepping `game.html` for the interesting identifiers lands on the loader and the call:

```bash
grep -n "duckWasmReveal\|main.wasm\|referrer\|pick32\|room3Block" game.html
```

The wrapper instantiates the module, runs the Go program, and polls until Go has exported the function onto `window`:

```js
function loadDuckWasm() {
    return fetch("main.wasm")
        .then(r => r.arrayBuffer())
        .then(bytes => WebAssembly.instantiate(bytes, go.importObject))
        .then(result => {
            go.run(result.instance);
            return new Promise(resolve => {
                (function waitForExport() {
                    if (typeof window.duckWasmReveal === "function") return resolve(true);
                    setTimeout(waitForExport, 50);
                })();
            });
        });
}
```

That polling loop is a Go-WASM tell: Go's `main()` runs asynchronously, registers the JS callback via `js.Global().Set(...)`, and only *then* is the export live. Nothing secret here — but it confirms the export name we'll hunt for in the binary.

The payoff is the call site:

```js
var room3Block = serializeRoomBlock("3");
var referrer   = document.referrer || "";
var picked32   = pick32();

var flag_decrypt = window.duckWasmReveal(referrer, room3Block, picked32);
```

Three arguments, fixed order. That single line is the contract:

```text
arg0 = document.referrer
arg1 = serialized ROOM 3 block
arg2 = picked32 token
```

Everything else in the solve is reproducing those three strings exactly, then figuring out how the binary stitches them into a key. The "exactly" is where the challenge hides its difficulty — any byte-level mismatch (a stray newline, the wrong referrer, the wrong token) makes AES-GCM authentication fail with no hint as to which input was off.

### Step 3 — recover `arg2` (picked32): a deliberate misdirection

`pick32()` walks the page's `<script>` tags *backwards* and returns the first 32-hex string it finds in any attribute value:

```js
function pick32() {
    var re = /\b[a-f0-9]{32}\b/i;
    for (var i = document.scripts.length - 1; i >= 0; i--) {
        var script = document.scripts[i];
        for (var j = 0; j < script.attributes.length; j++) {
            var m = script.attributes[j].value.match(re);
            if (m) return m[0];
        }
    }
    return "";
}
```

The backward scan is the gotcha. It's designed so the token comes from the *last* script with a matching attribute — the Cloudflare insights beacon at the very bottom of the page, whose `data-cf-beacon` JSON carries a `token` field:

```html
<script defer src="https://static.cloudflareinsights.com/beacon.min.js/..."
        data-cf-beacon='{"version":"2024.11.0","token":"797084dac2504482bcfaec15adc048bb",...}'>
</script>
```

A Cloudflare beacon token looks like boilerplate analytics cruft you'd skip right past — that's the misdirection. It's load-bearing:

```text
picked32 = 797084dac2504482bcfaec15adc048bb
```

The faithful way to reproduce `pick32()` offline is "last 32-hex token in the file," which is what the solve script does with `findall(...)[-1]`. (Naively grabbing the *first* 32-hex match would pick the wrong one if any earlier script attribute matched — the backward scan exists precisely to flip that ordering, so honoring it matters.)

### Step 4 — recover `arg0` (referrer): the input you can't see locally

`document.referrer` is the value of the page that linked to the game. Played from the real site, the navigation chain produces:

```text
referrer = https://b1tsy.v1t.site/
```

This is the single nastiest part of the challenge for offline solving, because **opening `game.html` from `file://` or a local server gives an empty referrer**, and an empty `arg0` silently changes the password string, so the decrypt fails its GCM tag with no diagnostic. The challenge weaponizes an environment value that doesn't exist off the live host. The fix is simply to hardcode the expected origin-with-trailing-slash. The trailing slash is not optional — `https://b1tsy.v1t.site/` and `https://b1tsy.v1t.site` are different bytes and produce different keys.

### Step 5 — recover `arg1` (room3Block): match the serializer's format

`serializeRoomBlock("3")` emits room 3 in Bitsy's on-disk game-data format:

```text
ROOM 3
<16 tilemap rows>
NAME ...
EXT ...
PAL ...
TUNE ...
```

The convenient fact in this challenge is that the raw `ROOM 3` section already embedded in `game.html` matches the serialized form closely enough to lift directly with a regex — we don't need to re-implement Bitsy's serializer. The thing to be careful about is the boundary: the block runs from the `ROOM 3` header up to (but not including) the next top-level `ROOM `/`TIL ` section, and trailing/leading newlines have to be normalized the same way the serializer does, or `arg1` is off by a `\n` and, again, the tag fails.

### Step 6 — recover the crypto constants from the WASM

I never disassemble. `strings` on the binary surfaces everything the KDF needs, because Go bakes string literals into the data section in the clear:

```bash
strings -a 00a8bb72 | grep -E "duckWasmReveal|b1tsy|aesgcm|nonce|9e8c"
```

```text
duckWasmReveal
b1tsy-ducky-aesgcm
nonce|
9e8c2b395bbf6bd7434230ab998c6e86f3228c503324c8660715ccd0bc74deb7d6346dfcc4a9614e58cb
```

Four artifacts, and each one tells you its role:

- `duckWasmReveal` — confirms this is the export, matching the JS.
- `b1tsy-ducky-aesgcm` — an HMAC key/label. A standalone ASCII label sitting next to AES-GCM code is almost always the HMAC key in an HMAC-as-KDF.
- `nonce|` — a literal prefix. A short prefix string ending in `|` next to a hash is the domain-separation tag for deriving the nonce from the same password (`SHA256("nonce|" + password)`).
- The long hex blob — 42 bytes. This is the AES-GCM ciphertext: the flag plaintext plus the 16-byte GCM tag appended. The 42-byte length is consistent with a `v1t{...}` flag plus one tag, which is a sanity check that we found the right blob and not some unrelated constant.

From those four pieces the KDF reconstructs cleanly. The `|` separators in `nonce|` and the obvious need to combine three inputs imply pipe-joined concatenation:

```text
password = referrer + "|" + room3Block + "|" + picked32
key      = HMAC-SHA256(key="b1tsy-ducky-aesgcm", msg=password)   # 32-byte AES-256 key
nonce    = SHA256("nonce|" + password)[:12]                       # 96-bit GCM nonce
flag     = AES-GCM-Decrypt(key, nonce, ciphertext, aad=None)
```

Why this is the right shape and not a guess: HMAC-SHA256 yields exactly 32 bytes (AES-256 key size), `SHA256(...)[:12]` yields exactly the 96-bit nonce AES-GCM wants, and the AAD is empty because the JS call passes no fourth argument. Everything lines up dimensionally. And critically — **if any of these were wrong, GCM's tag check would reject the ciphertext.** AES-GCM is authenticated; a successful decrypt is itself proof that all three inputs and the whole KDF are byte-perfect. That property is what makes this challenge verifiable without ever touching the live site.

### Step 7 — end-to-end solve

```python
#!/usr/bin/env python3
import re
import hmac
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

html = Path("game.html").read_text()

# arg1: lift the ROOM 3 block from the embedded game data, matching the
# serializer's boundaries (up to the next top-level ROOM/TIL section).
m = re.search(r"\nROOM 3\n(.*?)(?=\n\nTIL |\nROOM |\nTIL )", html, re.S)
if not m:
    raise SystemExit("ROOM 3 not found")
room3Block = "ROOM 3\n" + m.group(1).strip("\n")

# arg2: pick32() scans scripts backwards -> effectively the LAST 32-hex
# token in the file (the Cloudflare beacon token).
picked32 = re.findall(r"\b[a-f0-9]{32}\b", html, re.I)[-1]

# arg0: document.referrer on the live site. Empty locally -> hardcode it.
# The trailing slash is significant.
referrer = "https://b1tsy.v1t.site/"

# Ciphertext (incl. 16-byte GCM tag) lifted from the wasm strings.
ciphertext = bytes.fromhex(
    "9e8c2b395bbf6bd7434230ab998c6e86"
    "f3228c503324c8660715ccd0bc74deb7"
    "d6346dfcc4a9614e58cb"
)

# Reconstruct the exact password and derive key + nonce the way the wasm does.
password = f"{referrer}|{room3Block}|{picked32}".encode()
key   = hmac.new(b"b1tsy-ducky-aesgcm", password, hashlib.sha256).digest()
nonce = hashlib.sha256(b"nonce|" + password).digest()[:12]

# A successful AES-GCM decrypt authenticates every input at once.
flag = AESGCM(key).decrypt(nonce, ciphertext, None)
print(flag.decode())
```

```bash
python3 solve.py
# v1t{b1tsy_t1psy_duck_w4sm}
```

The GCM tag validated on the first run where all three inputs were correct — which is the only confirmation needed.

## Flag

```text
v1t{b1tsy_t1psy_duck_w4sm}
```

## Lessons learned - prompting the AI

This challenge is the *perfect* shape for an LLM-driven solve, and recognizing the shape is the whole human contribution. The pattern: **a binary that doesn't hold a secret, it rebuilds a key from observable page state.** Once you name that, you don't reverse-engineer anything — you point the model at the artifacts and have it reconstruct the contract. Here's how I steered it.

**Open by forbidding the obvious time-sink.** The model's default reflex on a `.wasm` file is "let's disassemble." For Go-WASM that's a swamp. My first prompt set the altitude:

> "This is a Go WebAssembly challenge. Do NOT try to disassemble the wasm or analyze `wasm_exec.js` — that's unmodified Go runtime glue. Instead: read `game.html`, find where it calls the wasm export, and tell me the exact list of arguments passed to that export, in order. Then run `strings` on the wasm binary and list every literal that looks like a crypto constant (labels, prefixes, long hex blobs)."

That one prompt did the structural work: it produced the three-argument contract and the four constants, and it kept the model out of the disassembly swamp entirely.

**Make it justify the KDF dimensionally, not by vibes.** When the model proposed the key derivation, I didn't take it on faith — I made it defend the shapes:

> "You said key = HMAC-SHA256(label, password) and nonce = SHA256('nonce|'+password)[:12]. Justify each output length against AES-256-GCM's required key and nonce sizes, and tell me how you'll know if any input is wrong."

The answer I wanted — and got — was "32 bytes = AES-256 key, 12 bytes = 96-bit GCM nonce, and the GCM tag will reject if anything's off." That last clause is the verification strategy baked into the crypto, and forcing the model to state it meant I trusted a clean decrypt as proof.

**Where the model went wrong, and how I caught it.** Two real dead-ends:

1. *It grabbed the wrong 32-hex token.* The model's first pass took the *first* 32-hex match in the file. I caught it by re-reading `pick32()` myself and noticing the loop runs `document.scripts.length - 1` down to `0` — a *backward* scan. I corrected it: "pick32 iterates scripts in reverse, so it's the LAST matching token, not the first — that's the Cloudflare beacon token at the bottom of the page." Lesson: when the model transcribes a scraper, have it explain the *iteration direction*, because that's exactly the kind of subtle inversion challenge authors plant.

2. *It left the referrer empty.* The model initially set `referrer = ""` (because `document.referrer` is empty when you open the file locally) and the decrypt failed its tag. The failure mode was useless — just "InvalidTag" — so the real skill was *diagnosing which of three inputs was wrong* rather than thrashing. I told it: "GCM failing means one input's bytes are wrong. The referrer is the only input that depends on the live environment — hardcode `https://b1tsy.v1t.site/` *with the trailing slash* and try again." It worked. Lesson: enumerate which inputs are environment-derived vs. page-derived, and suspect the environment-derived ones first when authentication fails.

**Verification was free because of AES-GCM.** I didn't have to eyeball anything. A passing tag is a cryptographic proof that all three reconstructed inputs and the entire KDF are byte-perfect. So my verification instruction was simply: "Don't print the flag until `AESGCM.decrypt` returns without raising — if it raises, stop and tell me which input you suspect, don't guess-and-spray." That keeps the model from fabricating a flag or silently mangling inputs.

**Fast-path prompt recipe for next time:**
> "Treat this WASM/binary as a black box that rebuilds a key from page state. Forbid disassembly. (1) Read the HTML/JS and give me the exact ordered argument list to the export. (2) `strings` the binary and list crypto-looking literals. (3) Propose key+nonce derivation and justify each length against the cipher's required sizes. (4) Reproduce every input byte-for-byte — flag environment-derived inputs (referrer, cookies, location) as failure suspects and honor scraper iteration order exactly. (5) Trust nothing until the AES-GCM tag validates; on failure, name the suspect input instead of guessing."
