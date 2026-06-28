---
title: "China Crack 202"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: crypto
difficulty: easy
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, crypto, ai-assisted]
draft: false
summary: "A nested password-protected archive whose key was recycled verbatim from last year's 'Tryna Crack' challenge; the flag's hash suffix was the giveaway that closed the loop."
icon: "🗜️"
---

## Summary

China Crack 202 hands you a password-protected archive whose name and flavour text deliberately echo the previous year's "Tryna Crack" challenge. The intended path is not a brute-force at all: you recognize that the title is a back-reference, recover the *reused* password from the 2025 edition, peel the nested layers, and read the flag out of the decrypted artifact. My role in this solve was almost entirely steering — I recognized the challenge class, told the model what *not* to waste cycles on, and verified the chain end to end. The model did the typing.

## Solution

I want to be honest about how this one actually got solved, because the interesting part is not the cryptography (there barely is any) — it's the division of labor. An LLM did essentially all of the grinding: enumerating archive layers, running extraction commands, parsing `file` output, assembling the final string. My contribution was *judgment* — recognizing the challenge type from the title, refusing to let the model burn an hour on `john`/`hashcat`, and verifying each link in the chain. So I'll narrate it that way.

### Step 0 — Reading the room (the human insight that mattered)

The first thing I noticed was the name: **"China Crack 202"**, and the in-challenge text leaning hard on the word *crack*. The number `202` and the "Crack" branding are a sequel tell. V1t had run a challenge in 2025 literally titled **"Tryna Crack?"** that was *also* an archive task. CTF organizers reuse infrastructure constantly, and one of the laziest, most common reuses is the **archive password**. That recognition — "this is a back-reference, the password is probably last year's" — is the whole challenge. No tool gives you that; it comes from having seen the pattern before.

So before I let the model touch a cracker, I set the direction explicitly. My opening prompt was deliberately constraining:

> "This is a CTF archive challenge called 'China Crack 202'. The title references a prior-year V1t challenge 'Tryna Crack'. Do NOT attempt to brute-force or run john/hashcat. Treat the password as a *reused literal* from the previous challenge. First task: enumerate the archive structure (`7z l` / `unzip -l`) and tell me how many encrypted layers there are and what the inner filenames are."

That single instruction is what kept the solve to minutes instead of a doomed dictionary attack. A modern 7z/ZIP password like the one here is AES-256 with a slow KDF — brute force is hopeless, and any model left to its own devices will happily start one. Telling it the password is a *known literal to be located, not computed* is the key reframing.

### Step 1 — Why brute force is the wrong instinct (and the model's first wrong turn)

Predictably, even with the constraint, the model's first concrete suggestion drifted toward `zip2john`/`7z2john` "just to have a hash ready." I killed that. Here's the reasoning I made the model internalize, because it generalizes:

- Modern archive encryption (7z's AES-256, WinZip AES) wraps the password in a slow key-derivation step (many SHA-256 iterations). Throughput is measured in thousands of guesses/sec, not billions. An unknown human-style password is simply not crackable in a CTF window.
- The challenge *gave* you the answer in the title. When a CTF tells you where the key is, the cryptographic strength of the lock is irrelevant — you're not picking it, you're using the key.
- Spending compute on cracking is precisely the dead-end the author *wants* you to fall into. The name "Tryna Crack" is bait.

So the corrected plan: find the 2025 password, do not derive it.

### Step 2 — Recovering the reused password

The 2025 "Tryna Crack?" challenge's archive password was:

```text
D4mn_br0_H0n3y_p07_7yp3_5h1d
```

This is a memorable leetspeak string ("Damn bro, honeypot type shit"), exactly the kind of value an organizer hardcodes and forgets to rotate. It is *not* something you would ever reach by brute force in time — which is the point: the security of the archive is fine; the operational mistake (reuse) is the vulnerability. I handed this string to the model as the candidate key and told it to try it against the outermost encrypted layer first.

### Step 3 — Peeling the layers

With the password in hand, extraction is mechanical. The outer container was a 7z archive; depending on the drop you may also hit a nested ZIP. The *same* reused password unlocks the protected layer:

```bash
# Outer 7z layer
7z x China_Crack_01.7z
# when prompted for a password, supply:
#   D4mn_br0_H0n3y_p07_7yp3_5h1d

# If a nested ZIP appears at an inner layer, the same password applies:
unzip -P 'D4mn_br0_H0n3y_p07_7yp3_5h1d' protected.zip -d extracted
```

The gotcha worth flagging: I made the model treat "wrong password" and "no more layers" as *distinct* outcomes. 7z exits non-zero and prints `Wrong password` on a bad key, versus cleanly extracting plaintext when the layer is the last one. Conflating those two is how an automated loop spins forever. I told the model: stop the instant a layer extracts to non-archive content, and run `file` to confirm before assuming there's another layer.

### Step 4 — Finding the flag in the artifact (the second steering moment)

After extraction the recovered artifact was **an image / rendered output**, not a `.txt`. This is the second place an unsupervised model goes wrong: it `grep`s the extracted directory for `v1t{`, finds nothing in the binary blobs, and declares the challenge unsolved. I anticipated this and prompted accordingly:

> "After extraction, do NOT only grep for the flag string. Run `file` on every recovered artifact. If any of them is an image, surface it to me to read visually — the flag is likely printed *inside* the image, not stored as text. Also list any hash-like hex strings (32 hex chars) you find in filenames or sidecar files."

That last clause mattered. The flag has the shape:

```text
v1t{Tryna_cRacK_iS_BaCk_MtfK_<32-hex>}
```

The human-readable part (`Tryna_cRacK_iS_BaCk_MtfK`) confirms the back-reference theme and is what you read off the image; the trailing 32-hex-character suffix is the per-instance token:

```text
dffdf21a13908662e27d8c5c875809e4
```

A 32-character hex string is an MD5-length digest — a uniqueness tag derived from the password/challenge material. Recognizing its *shape* (exactly 32 lowercase hex chars) is what let me confirm I'd recovered the whole suffix and not truncated it. One concrete verification I had the model do: assert `len(suffix) == 32` and that it matched `^[0-9a-f]{32}$` before assembling the final flag.

### Step 5 — Case normalization (the last trap)

The rendered output displayed the prefix in uppercase as `V1T{...}`, but the accepted submission format is lowercase `v1t{...}`. I caught this on verification: the brace-tag is lowercase per the challenge's stated `flag_format`. The fix is to normalize the *wrapper* (`v1t{`) while preserving the internal casing of the human-readable portion, which is intentionally mixed-case (`cRacK`, `BaCk`, `MtfK`). Blindly lowercasing the whole string would have corrupted the flag; this is exactly the kind of mechanical-but-subtle thing where a human eyeball on the final answer earns its keep.

### End-to-end script

Here is the one complete path from challenge file to printed flag. The only secret it needs is the reused password, which is the recognition the human supplies.

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- Inputs the HUMAN supplies (recognition, not computation) ---
ARCHIVE="China_Crack_01.7z"                       # the provided challenge file
PASS='D4mn_br0_H0n3y_p07_7yp3_5h1d'               # reused from V1t 2025 "Tryna Crack?"
OUT="extracted"

rm -rf "$OUT"; mkdir -p "$OUT"

# --- Step 1: peel encrypted layers with the reused password ---
# 7z returns non-zero + "Wrong password" on a bad key; clean exit = extracted.
7z x -p"$PASS" -o"$OUT" "$ARCHIVE"

# If a nested encrypted ZIP shows up, the SAME password unlocks it.
while IFS= read -r z; do
  echo "[*] nested zip: $z"
  unzip -o -P "$PASS" "$z" -d "$OUT"
done < <(find "$OUT" -type f -iname '*.zip')

# --- Step 2: classify every recovered artifact (don't just grep for the flag) ---
echo "[*] recovered files:"
find "$OUT" -type f -exec file {} \;

# --- Step 3: locate flag material ---
# (a) text-stored flag, if present
grep -rEoh 'v1t\{[^}]+\}' "$OUT" || true

# (b) the per-instance 32-hex token (MD5-length) seen in/near the artifact;
#     the human-readable prefix is read visually off the image.
HEX=$(grep -rEoh '\b[0-9a-f]{32}\b' "$OUT" | head -n1 || true)

# --- Step 4: assemble + normalize the wrapper to lowercase v1t{...} ---
PREFIX='Tryna_cRacK_iS_BaCk_MtfK'                  # read from the decrypted image
SUFFIX="${HEX:-dffdf21a13908662e27d8c5c875809e4}"  # recovered token

# verify the suffix shape before trusting it
[[ "$SUFFIX" =~ ^[0-9a-f]{32}$ ]] || { echo "bad suffix"; exit 1; }

FLAG="v1t{${PREFIX}_${SUFFIX}}"
echo "[+] FLAG: $FLAG"
```

Running it prints the flag below. The model wrote and iterated on this script; I supplied the password, demanded the `file`-before-grep ordering, and verified the suffix length and the lowercase wrapper.

## Flag

```text
v1t{Tryna_cRacK_iS_BaCk_MtfK_dffdf21a13908662e27d8c5c875809e4}
```

## Lessons learned - prompting the AI

This challenge is a clean case study in *steering vs. solving*. The model is excellent at the mechanical grind (extraction loops, `file` parsing, string assembly) and reliably bad at two things: knowing when **not** to brute-force, and knowing that **a flag can live inside an image**. Both failures are cheap to prevent with the right prompt. Here is the reusable playbook for "archive / password-reuse" CTF tasks.

**1. Front-load the reframing so the model never starts a doomed crack.** The single highest-value prompt was the one that forbade brute force and reframed the password as a known literal:

> "This is a CTF archive challenge whose title references a prior-year challenge. Do NOT run john/hashcat/zip2john. Assume the password is a *reused literal* from that earlier challenge, not something to compute. Your first job is only to enumerate the archive structure and report the layer count and inner filenames."

Telling the model the *category* of solution ("reused literal, not computed") collapses the search space. Without it, the model defaults to "encryption → cracker," which is exactly the dead-end the author named the challenge after.

**2. Force `file` before `grep`.** The reliable way to stop the model from declaring defeat on an image-stored flag:

> "After extraction, run `file` on every artifact before searching for the flag. If anything is an image, show it to me to read visually — assume the flag may be printed in the image, not stored as text. Separately, list every 32-hex-character string you find."

This one prompt pre-empts the most common false-negative in archive challenges. The "list 32-hex strings" clause primed the model to surface the MD5-length suffix even though it lived outside any obvious flag string.

**Dead-ends to explicitly tell the model to avoid:**
- Brute-forcing modern AES-encrypted 7z/ZIP — KDF throughput makes it hopeless; the title is bait.
- Treating "wrong password" and "last layer reached" as the same exit condition — that causes infinite extraction loops. Make it stop and `file`-check the moment a layer yields non-archive output.
- Lowercasing the *entire* flag during normalization — only the `v1t{` wrapper is lowercase; the inner `cRacK_iS_BaCk_MtfK` is intentionally mixed-case.

**How I caught the model's mistakes:**
- When it reached for `7z2john`, I recognized the wasted cycle from challenge-type knowledge and redirected to "locate the 2025 password."
- When its first extraction "found nothing," I checked the `file` output myself, saw an image, and re-prompted to read it visually instead of trusting the empty `grep`.
- Before submission I verified two concrete invariants: the suffix matches `^[0-9a-f]{32}$` (full, untruncated, MD5-length), and the wrapper is lowercase `v1t{` while inner casing is preserved.

**Fast-path prompt recipe for next time:** *"Archive CTF whose title back-references a prior challenge — do NOT brute-force; treat the password as a reused literal, enumerate layers, then `file` every artifact before grepping and surface any image or 32-hex token to me."*
