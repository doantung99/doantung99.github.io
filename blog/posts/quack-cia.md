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

**Class of challenge: GitHub-OSINT-trail-ending-in-a-deleted-artifact-recovered-from-a-binary-editor-sidecar.** Whenever a challenge sends you to a person's GitHub (or GitLab/Bitbucket) account and the visible repo "has nothing in it," you are almost always looking at this class: the secret was committed once and scrubbed, and/or it survives inside an editor's metadata sidecar — a Vim `.un~`/`.un_` undo file, a `.swp`/`.swo` swap file, an Emacs `#file#` autosave or `file~` backup, a `.orig`/`.bak`, or the packfile of a deleted branch. The lessons below are written so they transfer to the *next* one of these, not just to Quack CIA. The recurring shape: **a navigation half (find the scrubbed thing in history) and a forensics half (carve the verbatim text out of a binary editor format that keeps deleted lines).** The AI is great at both halves mechanically but reliably faceplants at two joints — the "it's hidden, not deleted" pivot and the "framing bytes are glued to the token" trap.

**1. Reusable prompts for the navigation half (find what was scrubbed from history).** Don't let the model browse the file tree and conclude "empty repo." Tell it the meta-strategy: history is the database.

> "This is a GitHub OSINT trail. Treat the working tree as a decoy. Enumerate the FULL history instead: `git log --all --oneline`, `git log --all --diff-filter=D --name-only` for deleted files, `git log -p --all -S '<keyword like flag/secret/key>'` (pickaxe) for added-then-removed content, and `git rev-list --all --objects | git cat-file --batch-check` to find dangling/large blobs. List every commit SHA and every path that ever existed, then fetch suspicious blobs by `git show <sha>:<path>` or the raw URL `raw.githubusercontent.com/<user>/<repo>/<sha>/<path>`."

> "Before any technical step on the entry artifact (video / image / profile / README): extract the literal on-screen / EXIF / bio text first and treat it as the answer. Do NOT run stego, do NOT brute-force — intro OSINT pivots are written in plain sight. Give me the handle/URL you read, verbatim, and your confidence."

**2. Reusable prompts for the forensics half (carve verbatim text out of the editor sidecar).** The instant you see a sidecar header, name the format and forbid over-engineering:

> "This is a Vim persistent-undo file (header `Vim\x9fUnDo`). [For other instances substitute: a Vim swap file header `b0VIM`, an Emacs autosave/backup, etc.] These formats store the VERBATIM text of changed/deleted lines so they can be restored, so the scrubbed secret is physically present as a contiguous run of bytes. Do NOT write a parser for the undo-tree / swap format — that is a time sink. Just carve printable strings and Base64/hex-looking tokens straight out of the raw bytes."

> "Carve candidates with a regex over the raw bytes — `[A-Za-z0-9+/]{12,}={0,2}` for Base64 (and `[0-9a-fA-F]{16,}` for hex) — decode each with strict validation (`base64.b64decode(token, validate=True)`), and keep ONLY decodes matching the flag regex `v1t\{...\}`. Make the format check the filter, not visual inspection of `strings` output."

**3. What to tell it to focus on, and the classic dead-ends of THIS class to forbid up front.** Lead with the focus, then list the traps in the same breath so it never wanders into them:
- Focus on: history enumeration (pickaxe + deleted-file filter), identifying the sidecar by its magic header, and carving-then-validating tokens from raw bytes.
- Avoid (state these proactively): (a) **Don't parse the binary editor format node-by-node** — string carving wins; (b) **Don't decode the whole `strings` run** — sidecar length/marker bytes (the leading `(`, trailing `5` here) render as ASCII and get glued to the token; carve with a regex that stops at non-alphabet bytes; (c) **Don't treat the entry video/image as stego** — read the literal text; (d) **Don't inspect only the default-branch file tree** — the payload lives in commits, deleted files, or dangling blobs; (e) **Don't trust the first Base64-ish run** — multiple printable runs in the blob look encodeable but aren't, so let `validate=True` + the flag regex reject them.

**4. How to verify the output for this class (so you catch hallucinations).** The model will sometimes "find" a flag that is a hallucinated lookalike. Force it to prove the decode arithmetically and prove the provenance:
- **Prefix arithmetic:** a Base64 string for a `v1t{...}` flag MUST start with `djF0` (since `v` `1` `t` = `0x76 0x31 0x74` → `djF0`). If the candidate doesn't start with `djF0`, it does not decode to our prefix — reject it. (For hex, the flag's first bytes must be `76 31 74`.)
- **Padding arithmetic:** count the `=`. Exactly one `=` means `len ≡ 2 (mod 3)`; two means `≡ 1`; none means `≡ 0`. Cross-check against the decoded length (the 29-byte flag here → one `=`). A mismatch means you trimmed wrong.
- **Provenance:** re-confirm the source blob by its magic header (`data.startswith(b"Vim\x9fUnDo")`) and the exact commit SHA, so you know you pulled the right object from history and not a coincidental hit elsewhere in the repo.
- Make the model show these three checks BEFORE it runs the decoder; if it can't, the candidate is suspect.

**Fast-path prompt recipe for the class:** *"GitHub OSINT trail — treat the working tree as a decoy: enumerate full history with `git log --all`, the `--diff-filter=D` deleted-file list, and `-S` pickaxe, then fetch the scrubbed blob by SHA. It's an editor sidecar (Vim undo/swap, Emacs backup) that stores deleted text verbatim — don't parse the format, carve `[A-Za-z0-9+/]{12,}={0,2}` from raw bytes, `b64decode(validate=True)`, keep only `v1t\{...\}` matches, and verify it starts with `djF0` with padding consistent with the decoded length before trusting it."*
