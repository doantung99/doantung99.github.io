---
title: "Classless"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A stripped x86-64 'object VM' runs base64(zlib(JSON)) programs through a triple type-confusion vault; the flag is XOR-0x37-decoded straight out of .rodata."
icon: "🧬"
---

## Summary
`objectvm` is a stripped Linux x86-64 ELF implementing a tiny "classless" object system whose `.bbl` programs are `base64(zlib(JSON))`. The target sample falls into a three-stage "vault" of type checks, but the flag turns out to be a 37-byte `.rodata` blob that the success path simply XORs with `0x37` and prints — so we extract it directly without satisfying the vault.

## Solution
I pegged this as a custom-VM reversing job from the prompt ("forget what a class is"), so I set the direction and let the model grind the disassembly. First I had it decode a sample with `base64 -> zlib -> JSON` and triage the structure; it surfaced that each object carries three competing type notions (`declared_class`, `runtime_class`, and a `__class__` field) plus a 16-slot `vtable`, and that `04_denied.bbl` has no `__task__`, so `main` falls through to a vault running `dispatcher -> resolver -> verifier` and dies at the verifier — the intended `trilingual_vtable_babel` type confusion across CPP/JAVA/PY dialects.

The model's first instinct was to forge a `.bbl` that passes all three stages. I steered it off that rabbit hole: I asked it to check the imports first, and it confirmed there are no `exec`/`getenv`/file-read paths beyond the input `ifstream` — meaning the flag is baked into the binary, not loaded at runtime. I then had it locate and read the success routine at `0x10ca5`. It found a tight loop that walks `.rodata:0x134a0..0x134c5` (37 bytes), XORs each byte with `0x37`, and prints the result through the same `cout` code as the deny messages. I verified by decoding the blob; the neighboring `.rodata` blobs decode to gibberish (those are the vault's comparison data under a different key), confirming `0x134a0` is the real flag.

```python
# Extract the flag straight from objectvm — no vault needed.
data = open("objectvm", "rb").read()
blob = data[0x134a0:0x134c5]              # 37 bytes
print(bytes(b ^ 0x37 for b in blob).decode())
# -> v1t{trilingual_vtable_babel_6f01a2c9}
```

## Flag
```
v1t{trilingual_vtable_babel_6f01a2c9}
```
