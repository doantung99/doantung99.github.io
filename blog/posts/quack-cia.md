---
title: "Quack CIA"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: osint
difficulty: easy
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, osint, ai-assisted]
draft: false
summary: "An OSINT trail from a video to a GitHub repo, ending in a Vim undo file whose Base64-encoded flag survived being deleted from the working copy."
icon: "🦆"
---

## Summary

Quack CIA is an OSINT chain: a video points to a GitHub account, the commit history of the repo `tommypony326532/cia` hides a file that was added and then effectively scrubbed, and the real prize is a stray Vim persistent-undo file (`flag.txt.un_`). That undo file is a binary blob with the `Vim\x9fUnDo\xe5` magic header, and it still carries an old buffer state containing the flag Base64-encoded — recover it and you win. My role was steering: I recognized the artifact type at each hop, told the model exactly what to look for, and verified the chain. The model did the grinding (parsing commits, carving strings, decoding candidates).

## Solution

This challenge is two problems stitched together: a *navigation* problem (find the file) and a *forensics* problem (read the file). I'll treat them in that order, because the second one is where the interesting structure lives.

### Hop 1 — the video to a handle

The entry point is a video. Watching it, there's on-screen text that surfaces a GitHub identity. The trick of this stage is not technical at all — it's resisting the urge to overthink. OSINT intro challenges almost always hand you the pivot directly; the failure mode is treating the video like a steganography puzzle when the answer is plainly written on a frame. The text resolves to the account `tommypony326532` and the repository:

```
https://github.com/tommypony326532/cia
```

The flag itself (`v1t{t0mmy_scr1pt_k1dd13_1n1t}`) is a wink at this: "tommy", "script kiddie", "init" — the author is role-playing a careless operator, and carelessness is exactly what we are going to exploit.

### Hop 2 — the commit history, not the file tree

If you only look at the *current* state of the repo (the file tree on the default branch), you find nothing useful. That is the whole point. The interesting artifact was added in a specific commit and is not what you would notice browsing normally:

```
commit 178b58ed916506407b5221c81beb3f81a3264964
```

The file added in that commit is named `flag.txt.un_`. The key insight at this hop is that **Git remembers everything**, including files that look uninteresting or are later overwritten. You can reach the exact blob without trusting the working tree by fetching it from the commit. Two reliable ways:

```bash
# Option A: clone, then extract the file as it existed at that commit
git clone https://github.com/tommypony326532/cia
cd cia
git show 178b58ed916506407b5221c81beb3f81a3264964:flag.txt.un_ > flag.txt.un_

# Option B: raw download straight from GitHub at that commit SHA
curl -L -o flag.txt.un_ \
  https://raw.githubusercontent.com/tommypony326532/cia/178b58ed916506407b5221c81beb3f81a3264964/flag.txt.un_
```

The naming convention is the giveaway for the forensics stage. A file called `flag.txt.un_` is not a flag — it is the *undo history* for a file called `flag.txt`. Vim, with persistent undo enabled, writes undo files alongside the buffer; depending on platform and `&undodir`, the path is mangled into a flat filename ending in `.un~` / `.un_`. The committer edited `flag.txt`, deleted the visible flag, and left the persistent undo file lying around — and that file still contains the deleted text.

### Hop 3 — reading the Vim undo file

This is the part worth slowing down on, because "just run `strings`" undersells *why* it works.

First, confirm what we are holding. The file is binary and the first bytes are diagnostic:

```bash
file flag.txt.un_
od -An -tx1 -N16 flag.txt.un_
```

```
56 69 6d 9f 55 6e 44 6f e5
```

Interpreting the printable bytes: `Vim\x9fUnDo\xe5`. That is the magic header of a Vim persistent-undo file. The format is Vim's own binary serialization of the *undo tree* — not a flat diff, but a tree of buffer states. Each node ("uhp" — undo header) records the lines that changed between states, and crucially **the format stores the actual text of changed lines as length-prefixed byte runs.** That is why deleted text is still physically present: undo has to be able to *restore* it, so it keeps a verbatim copy of the line you removed.

You do not need to write a full parser for the undo-tree format to win. The flag text was a line in the buffer at some point, so it exists as a contiguous run of printable bytes somewhere in the blob. Carving strings is enough:

```bash
strings -a flag.txt.un_
```

Among the noise, one run stands out:

```
(djF0e3QwbW15X3NjcjFwdF9rMWRkMTNfMW4xdH0=5
```

Here is the gotcha that actually mattered, and the dead-end I had to steer the model away from: **the surrounding bytes are not part of the payload.** The leading `(` and the trailing `5` are structural bytes from the undo format (length/marker bytes that happen to render as printable ASCII), *not* part of the encoded data. If you feed the whole run into a Base64 decoder it will either error on alignment or produce garbage. You have to isolate the clean token:

```
djF0e3QwbW15X3NjcjFwdF9rMWRkMTNfMW4xdH0=
```

Two signals confirm this is the real payload and not a coincidence:

1. It begins with `djF0`. Base64 encodes 3 input bytes into 4 output characters, and the first three bytes `v` `1` `t` (`0x76 0x31 0x74`) encode to exactly `djF0`. So any Base64 string starting with `djF0` decodes to text starting with `v1t` — precisely our flag prefix.
2. It ends with a single `=`, meaning the decoded length is `≡ 2 (mod 3)`. The flag `v1t{t0mmy_scr1pt_k1dd13_1n1t}` is 29 bytes, and `29 mod 3 == 2`, so exactly one `=` of padding is expected. The arithmetic checks out.

Decode it:

```bash
echo 'djF0e3QwbW15X3NjcjFwdF9rMWRkMTNfMW4xdH0=' | base64 -d
```

```
v1t{t0mmy_scr1pt_k1dd13_1n1t}
```

### End-to-end script

The robust, hands-off version doesn't eyeball strings or hand-trim framing bytes. It carves *every* Base64-looking token out of the raw binary, tries to decode each one, and keeps only candidates that actually match the flag format. This is what defeats the framing-byte trap automatically — the Base64 token regex (`[A-Za-z0-9+/]+={0,2}`) naturally stops at `(` and at any non-Base64 byte, and the `validate=True` plus format check throws out everything that is not the flag.

```python
#!/usr/bin/env python3
"""
Quack CIA -- recover the flag from a Vim persistent-undo file.

Usage:
    python solve.py            # expects flag.txt.un_ in cwd
    python solve.py path/to/flag.txt.un_

If the file isn't present locally, fetch it first:
    curl -L -o flag.txt.un_ \
      https://raw.githubusercontent.com/tommypony326532/cia/178b58ed916506407b5221c81beb3f81a3264964/flag.txt.un_
"""
import base64
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "flag.txt.un_"

with open(path, "rb") as f:
    data = f.read()

# Sanity check: is this actually a Vim undo file?
if not data.startswith(b"Vim\x9fUnDo"):
    print(f"[!] {path} is not a Vim undo file (header={data[:9]!r}); continuing anyway")

# Carve every Base64-looking token directly out of the raw bytes.
# This stops at framing bytes like '(' and trailing non-b64 bytes on its own,
# so we never have to hand-trim the run that 'strings' shows.
candidates = re.findall(rb"[A-Za-z0-9+/]{12,}={0,2}", data)

seen = set()
for token in candidates:
    if token in seen:
        continue
    seen.add(token)
    try:
        decoded = base64.b64decode(token, validate=True)
    except Exception:
        continue
    if re.search(rb"v1t\{[^}]*\}", decoded, re.IGNORECASE):
        print(decoded.decode(errors="replace"))
        break
```

Running it prints the flag:

```
v1t{t0mmy_scr1pt_k1dd13_1n1t}
```

Why this is the right approach rather than just `strings | grep`: by operating on the raw bytes and validating decodes, it is immune to the two things that bit me when going manual — (a) the structural framing bytes glued to the token, and (b) any other printable runs in the undo tree that look Base64-ish but are not. Let the format check (`v1t{...}`) be the filter, not your eyes.

## Flag

```
v1t{t0mmy_scr1pt_k1dd13_1n1t}
```

## Lessons learned - prompting the AI

This is the section I actually care about, because Quack CIA is a clean case study in *division of labor*: the LLM is excellent at the mechanical carving-and-decoding, but it will happily walk off a cliff at the two ambiguous joints — the navigation pivot and the framing-byte trap. My job was to recognize the artifact types and keep it on the rails.

**1. Name the artifact type up front so the model stops guessing.** The single highest-leverage prompt was telling it *what the file is* the moment I saw the header, instead of letting it free-associate about "suspicious binary." When the hex started with `Vim\x9fUnDo`:

> "This is a Vim persistent-undo file (`.un_` / `.un~`), the undo history for `flag.txt`. Vim stores the verbatim text of deleted lines so it can restore them, so the deleted flag is still physically in this blob as a contiguous run of printable bytes. Do NOT write a full undo-tree parser — just carve printable strings and Base64 tokens out of the raw bytes."

That one instruction collapsed the whole forensics stage. Left to itself the model wanted to reverse-engineer the undo-tree node format, which is real but completely unnecessary here.

**2. Pre-empt the framing-byte dead-end explicitly.** The model's first decode attempt failed because it grabbed the whole `strings` run, including the leading `(` and trailing `5`. The correcting prompt:

> "The `(` before and the `5` after are undo-file framing bytes, not data. Don't trim by hand — change the approach: regex the raw bytes for `[A-Za-z0-9+/]{12,}={0,2}`, decode each candidate with `validate=True`, and only keep ones matching `v1t\{...\}`. Make the format check the filter, not visual inspection."

Telling it the *failure mode* and the *fix* in one breath is far faster than letting it retry blindly.

**3. For the OSINT navigation, tell it the answer is plain, not hidden.** Models over-engineer intro OSINT. I steered with: "The video text directly names a GitHub handle — read it literally, don't run stego on the frames. Then: don't browse the file tree, walk the *commit history*; the file was added in one commit and is meant to be missed." Giving it the meta-strategy ("Git remembers deleted things") is what made it look at commit `178b58e...` instead of the default branch.

**How I caught the mistakes / verified:** I didn't trust the decode on sight — I sanity-checked the math. `djF0` *must* decode to a `v1t`-prefixed string (bytes `v` `1` `t` → `djF0`), and the single `=` implies `len ≡ 2 (mod 3)`, which matches the 29-byte flag. Both checks passing before I even ran the decoder told me we had the real token and not a lookalike. I also re-confirmed the source by its header (`startswith(b"Vim\x9fUnDo")`) so I knew I'd pulled the right blob from the right commit.

**Dead-ends to tell the model to AVOID for this challenge class:**
- Don't parse the Vim undo-tree format node-by-node — string carving is enough.
- Don't decode the whole `strings` run; structural bytes will be glued to the token.
- Don't treat the video as stego; read the on-screen text literally.
- Don't inspect only the current file tree on a GitHub OSINT challenge — the payload lives in history.

**Fast-path prompt recipe for next time:** *"This is a [Vim undo / Git-history / encoded] artifact. Carve raw printable + Base64 tokens from the bytes, decode each with strict validation, and filter by the flag regex `v1t\{...\}` — make the format check the filter, not my eyes; and on a GitHub OSINT trail, search commit history, not the working tree."*
