---
title: "Quack CIA"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: osint
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, osint, ai-assisted]
draft: false
summary: "An OSINT trail from a video to a GitHub repo, then recovering the flag from a deleted Vim undo file (flag.txt.un_) committed to the repo's history."
icon: "🕵️"
---

## Summary
A multi-step OSINT chase: a clue in a video leads to a GitHub account, a specific commit drops a `flag.txt.un_` file, and that file turns out to be a Vim persistent-undo blob hiding a Base64-encoded flag. My job was steering the AI through the pivot points; the model did the grinding once I pointed it at each artifact.

## Solution
I treated this as a pure OSINT pivot exercise and kept the model on a tight leash, one lead at a time.

1. **Video to identity.** I watched the provided video and pulled the on-screen text by hand, then handed those strings to the model and asked it to enumerate likely usernames and search GitHub for matches. It surfaced the account `tommypony326532` and its repo at `https://github.com/tommypony326532/cia`. I confirmed the repo actually matched the video's theme before moving on.

2. **Commits to artifact.** I asked the model to triage the repo's commit history rather than just the current tree, since CTF flags love to hide in deleted files. It flagged commit `178b58ed916506407b5221c81beb3f81a3264964`, which *added* a file named `flag.txt.un_`. The model's first instinct was to `cat` it as text and report garbage; I caught that and redirected it to treat the file as binary and identify the format instead.

3. **Format recognition.** Once it dumped the header, the first bytes (`56 69 6d 9f 55 6e 44 6f e5`, i.e. `Vim\x9fUnDo\xe5`) gave it away as a Vim persistent-undo file. I recognized this immediately and prompted the model to scrape printable strings out of the binary, since undo blobs retain old text the editor user thought they'd deleted. Among the strings was a Base64-looking chunk starting `djF0` — which decodes to `v1t`, the flag prefix. I had it decode that candidate and verified the result.

Here is the one clean path from the downloaded file to the flag:

```bash
# 1. Grab the file the OSINT trail pointed us to
git clone https://github.com/tommypony326532/cia
cd cia
git checkout 178b58ed916506407b5221c81beb3f81a3264964 -- flag.txt.un_

# 2. Confirm it's a Vim undo file (magic: "Vim\x9fUnDo\xe5")
od -An -tx1 -N16 flag.txt.un_

# 3. Pull the Base64 fragment out of the binary and decode it
strings -a flag.txt.un_ | grep -oE '[A-Za-z0-9+/]{12,}={0,2}' | while read c; do
  echo "$c" | base64 -d 2>/dev/null | grep -a 'v1t{' && break
done
```

Output:

```text
v1t{t0mmy_scr1pt_k1dd13_1n1t}
```

## Flag
```
v1t{t0mmy_scr1pt_k1dd13_1n1t}
```
