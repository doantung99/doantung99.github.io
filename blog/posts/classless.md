---
title: "Classless"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: misc
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "A stripped C++ object-VM whose success path XOR-decodes the flag from .rodata, so we skip the trilingual type-confusion vault and pull the flag straight out of the binary."
icon: "🧩"
---

## Summary

`Classless` ships a stripped x86-64 ELF (`objectvm`) that interprets a toy "classless" object system, where each program is `base64(zlib(JSON))` and every object carries three competing notions of type. The intended path is a three-stage type-confusion "vault" across CPP/JAVA/PY dialects, but the real shortcut is that the flag is XOR-`0x37`-encoded inside `.rodata` and printed by the success path — so once you find that loop, you decode 37 bytes and you're done. I drove this almost entirely by prompting an LLM through the recon, decompilation, and the final extraction; my job was recognizing it was a "flag baked into the binary" rev problem and steering the model away from the rabbit hole the challenge wanted me in.

## Solution

### Reading the artifacts before touching disassembly

The download is `objectvm` plus five sample programs `00_hello.bbl` through `04_denied.bbl`. The prompt — *"Ever learnt OOP? If yes? Good, now forget what a class is xD"* — plus the `.bbl` extension screams "custom bytecode/serialization format," so the first move is to understand the data format, not the binary. The `.bbl` files are not text; running them through the obvious container transforms reveals the layering:

```python
import base64, zlib, json
raw = open("samples/00_hello.bbl", "rb").read()
obj = json.loads(zlib.decompress(base64.b64decode(raw)))
print(json.dumps(obj, indent=2))
```

That is the key early insight: **`.bbl` = `base64(zlib(JSON))`**. Decoding any sample shows the object model the VM operates on:

```json
{
  "classes": [{
    "name": "Almost", "dialect": "JAVA", "parents": [], "interfaces": [],
    "final": false,
    "methods": [
      {"name":"pad","slot":0,"visibility":"public","body":"noop"},
      {"name":"open","slot":7,"visibility":"public","body":"allow"}
    ]
  }],
  "objects": [{
    "id": 1, "declared_class": "Almost", "runtime_class": "Almost",
    "fields": {"__class__": "TrustedPlugin"},
    "vtable": ["Almost.pad", "...", "Almost.open", "..."]
  }],
  "entry": 1
}
```

Three things matter here, and they are the whole conceptual trick of the challenge:

1. **Each object carries three different "types."** `declared_class` (what it was declared as), `runtime_class` (what it claims to be at runtime), and a `fields.__class__` string. In a sane language these agree; here they are allowed to disagree. That disagreement is the attack surface.
2. **There is a 16-entry `vtable`.** Dispatch goes by *slot number*, not by name — `slot 7 -> Almost.open -> body "allow"`. This is the "classless" part: methods resolve positionally, the way a real C++ vtable does, independent of the nominal class.
3. **The `classes[].dialect` field is one of `CPP`, `JAVA`, `PY`.** Different dialects apply different resolution rules. That is the "trilingual" in the flag.

The five samples form a tutorial that maps one-to-one onto VM features. Decoding each and reading its `fields.__task__` makes the structure obvious:

| sample | `__task__` | observed output |
|--------|-----------|-----------------|
| `00_hello` | `hello` | `hello from objectvm` |
| `01_interface` | `interface` | `interface Greeter: yes` |
| `02_mro` | `mro` | `resolved class: Cat` |
| `03_dispatch` | `dispatch` | `dispatch slot 7: allow` |
| `04_denied` | *(absent)* | **`Vault denied: verifier`** |

`04_denied` is the target. It is the only sample with **no `__task__`**, which means `main` does not branch into one of the tutorial handlers — instead it falls through into the **Vault**. The Vault runs three sequential gates and prints exactly which one rejected you. On the stock sample it prints `Vault denied: verifier`, so we know stages 1 and 2 (dispatcher, resolver) already pass and only the third (verifier) fails.

### Reversing main and the vault

The binary is stripped, so symbol names are gone. I used `radare2` for disassembly and a headless Ghidra pass (`blacktop/ghidra` container, Java post-script) for decompilation. `fcn.00010190` is `main`: it reads the input `.bbl` with `ifstream`, runs base64 → zlib → JSON, then inspects `fields.__task__`. When `__task__` is absent it jumps to the vault body around `0x10a38`. The three gates are three calls with branch-on-result:

```
verifier   : call 0xcc00          -> jne pass ; else print "Vault denied: verifier"
resolver   : call 0x51d0 / 0x10f50 ; test bl   -> branch
dispatcher : call 0x9910          ; test bl   -> branch
all pass   -> 0x10ca5             ; success path
```

Conceptually the three gates each judge the object's type *through a different lens*:

- the **dispatcher** checks it via positional **vtable** dispatch (slot 7 must resolve to an `allow` body),
- the **resolver** checks it via **MRO / runtime-class** resolution,
- the **verifier** checks the **declared** identity.

`04_denied` deliberately sets `fields.__class__ = "TrustedPlugin"` while `declared_class` and `runtime_class` are both `Almost`. Because the CPP/JAVA/PY dialects disagree about which of those three notions is authoritative, an object can look like a `TrustedPlugin` to one gate and an `Almost` to another. That is the intended *"forget what a class is"* type confusion, and it is literally the flag text: `trilingual` (three dialects) + `vtable_babel` (a tower-of-Babel of class systems that can't agree).

### The shortcut: the flag is not gated, it is baked in

The decisive observation — and the thing that turns a multi-hour rev grind into a five-minute decode — is about **imports**. I had the model enumerate the binary's symbol/relocation table and the only I/O-relevant import is `std::ifstream` for reading the input `.bbl`. There is **no `open`/`read` of any other file, no `exec`, no `getenv`, no socket**. So the flag is not fetched from disk or the environment at runtime. It must already be in the binary, and it must be emitted by the success path using the same `cout` machinery as the deny messages.

Disassembling the success target `0x10ca5` shows a tight single-byte XOR loop:

```asm
mov   esi, 0x25            ; 0x25 = 37 -> output length / byte count
lea   rbp, [0x000134a0]    ; pointer to encoded blob in .rodata
loop:
  movzx r15d, byte [rbp]
  xor   r15d, 0x37         ; single-byte XOR with key 0x37
  ...                      ; store decoded byte into the std::string
  add   rbp, 1
  cmp   rbp, 0x000134c5    ; end pointer (exclusive); 0x134c5 - 0x134a0 = 0x25 = 37
  jne   loop
```

So the success path reads 37 bytes from `.rodata:0x134a0`, XORs each with `0x37`, builds a `std::string`, and prints it. Crucially, **the encoded bytes and the key are constants in the file** — passing the vault only controls *whether* the loop runs, not *what* it produces. We can run the loop ourselves against the raw file and recover the flag without satisfying a single gate.

The one gotcha worth recording: the neighbouring `.rodata` blobs (you'll see fragments like `;665-` if you eyeball the section) decode to gibberish under `0x37`. Those are the obfuscated comparison constants for the three vault gates, XORed with a *different* key. It's easy to waste time trying to brute-force them into "the real flag." They aren't it — the flag is specifically the 37-byte run `[0x134a0, 0x134c5)` keyed with `0x37`, which is the exact range and key the success path itself uses. Trust the loop the binary actually executes on success; ignore the decoy constants the gates consume.

### End-to-end script

This is the complete path from the challenge file to the printed flag. It reads `objectvm`, slices the exact `.rodata` window the success loop walks, applies the same `xor 0x37`, and prints the result. (It also decodes the samples for context, which is how you'd confirm the format and find `04_denied` in the first place.)

```python
#!/usr/bin/env python3
"""Classless - V1t CTF 2026. Recover the flag straight from the binary."""
import base64, zlib, json, sys

BIN = "objectvm"

# --- (optional) confirm the .bbl format and locate the target sample ---
def decode_bbl(path):
    raw = open(path, "rb").read()
    return json.loads(zlib.decompress(base64.b64decode(raw)))

def show_samples():
    for n in ("00_hello", "01_interface", "02_mro", "03_dispatch", "04_denied"):
        try:
            obj = decode_bbl(f"samples/{n}.bbl")
        except FileNotFoundError:
            continue
        task = obj["objects"][0]["fields"].get("__task__", "(none)")
        print(f"{n:14s} __task__={task}")

# --- the actual solve: replay the success-path XOR loop ---
def extract_flag():
    data = open(BIN, "rb").read()
    START, END, KEY = 0x134a0, 0x134c5, 0x37   # range + key taken from 0x10ca5
    blob = data[START:END]                      # 37 = 0x25 bytes
    assert len(blob) == 0x25, f"expected 37 bytes, got {len(blob)}"
    return bytes(b ^ KEY for b in blob).decode()

if __name__ == "__main__":
    if "--samples" in sys.argv:
        show_samples()
    print(extract_flag())
```

Running it:

```
$ python solve.py
v1t{trilingual_vtable_babel_6f01a2c9}
```

The flag's three parts decode the joke: `trilingual` = the CPP/JAVA/PY dialects, `vtable_babel` = the irreconcilable class systems, `6f01a2c9` = the unique tag. A "proper" solve would hand-craft a `.bbl` whose object simultaneously satisfies the vtable dispatcher, the MRO resolver, and the declared verifier so the binary prints the flag live — but the deterministic XOR extraction is the ground truth and is far faster.

## Flag

```
v1t{trilingual_vtable_babel_6f01a2c9}
```

## Lessons learned - prompting the AI

**The class of challenge.** Whenever you face a *custom-VM / interpreter / "parse this serialized program" rev binary that ends by printing a flag* — a bytecode loader, a serialized-object machine, a toy scripting engine, a "submit a config and it validates you" checker — the single highest-leverage question is **"is the flag computed from my input, or is it a constant the success branch reveals?"** In the overwhelming majority of these, the flag is *embedded* and the elaborate validation logic only decides *whether* the reveal runs. The intended puzzle (here: three type-confusion gates across CPP/JAVA/PY dialects) is bait. Your job as the human is to recognize the genre and aim the model at the reveal, not the gauntlet. Everything below is written so it transfers to the *next* binary of this shape, not just `objectvm`.

**Step 1 — nail the input format before any disassembly.** These challenges almost always wrap their program in a standard container chain. Don't ask the model an open-ended "what format is this?"; hand it the suspected chain so it writes a decoder instead of guessing:

> "Here's a file with a `.bbl` extension that this binary reads — it's not text. Try the standard container chain in order: base64-decode, then decompress (try zlib, then gzip, then zstd), then parse as JSON (fall back to msgpack/pickle/protobuf if JSON fails). Write the decoder, print the parsed structure, and tell me every field each object carries."

The transferable trick is *enumerate the chain explicitly* (base64 → compression → structured format) and *ask for the field inventory*, because the field names (`declared_class`, `runtime_class`, `fields.__class__`, `dialect`) are what hand you the conceptual trap for free.

**Step 2 — force an import/IO audit BEFORE reversing any logic.** This is the prompt that turns hours into minutes for this whole class:

> "This is a stripped C++/ELF interpreter. Before reversing any validation logic, enumerate every imported/PLT function and every syscall it can reach. I specifically need yes/no answers: does it open or read any file other than the input? does it call exec/system, read env vars, or open a socket? If all of those are NO, the flag is embedded — so find the success branch and the string/XOR/RC4/decode loop it runs, and dump the constants from there."

If the answer is "only the input file is read" (here: just `std::ifstream`), you are *guaranteed* the flag is a baked-in constant and the gates are irrelevant. This import-audit-first move is the reusable backbone for any "VM that prints a flag."

**Step 3 — pull the decode constants verbatim off the success branch.** Once the audit proves embedding, anchor the model to the *winning* branch, not the failure messages, and make it lift the literals out of the disassembly rather than eyeballing the section:

> "Go to the success/accept branch (the target of the all-gates-pass jump). Read the exact decode loop there and give me, copied verbatim from the instructions: the source pointer, the end pointer or length immediate, and the XOR/decrypt key. Then decode ONLY that byte range with ONLY that key — do not scan the rest of `.rodata`."

**Where to point the model, and the classic dead-ends to forbid up front.** Tell it to focus on: (a) the IO/import surface first; (b) the *success* branch, never the deny/error strings; (c) constants lifted literally from the disassembly. Tell it to AVOID, explicitly, the dead-ends that this class is built to lure you into: do **not** emulate or hand-craft an input that defeats the validation gates (the type-confusion vault here is pure rabbit hole); do **not** brute-force XOR/crypt keys across the whole `.rodata`/`.data` section — these challenges plant **decoy constants** (here the gates' comparison values under a *different* key) that look flag-adjacent and burn hours; and do **not** trust a "flag-shaped" string until its length and pointer math check out.

**How to verify the model's output for this class (catch the hallucination).** The decode is only trustworthy when *independent numbers agree*. Here three did: the loop's length immediate `mov esi, 0x25` (37), the pointer arithmetic `0x134c5 - 0x134a0 = 0x25` (37), and the decoded byte count (37) all matched — and the result fit `v1t{...}`. Make the model show this triangulation:

> "Prove this is the real loop, not a coincidence: show that the length immediate, the end-minus-start pointer math, and the decoded byte count all agree, and that the result matches the flag format. If any of the three disagree, you grabbed the wrong region."

A model will happily emit a clean-looking `v1t{...}` from the *wrong* `.rodata` run; format alone is not proof. The length/pointer/count agreement is what separates the genuine success-path constant from a decoy.

**Fast-path prompt recipe for the next one:** *"Custom-VM/interpreter binary that prints a flag — (1) decode the input via the base64→decompress→structured chain, (2) audit imports/IO to prove the flag is embedded, (3) lift pointer+length+key straight off the success branch's decode loop and decode only that window, (4) ignore the gates and any decoy `.rodata` constants, (5) confirm length-immediate = pointer-math = byte-count before trusting the string."*
