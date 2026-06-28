---
title: "HVL"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: web
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, web, ai-assisted]
draft: false
summary: "A troll web challenge that hides its real flag in a substitution-cipher font, where emoji codepoints are mapped to flag characters and rendered on screen."
icon: "🦆"
---

## Summary

`hvl.v1t.site` is a deliberately trolly "MCK Vamp Visualizer" page that buries its flag under two layers of steganography: a decoy made of invisible Unicode variation selectors, and the real channel — a **substitution-cipher font** masquerading as `NotoSans-Regular.ttf` whose `cmap` maps emoji codepoints to flag characters. The solve is mostly artifact extraction and font-table parsing; my job was recognizing the challenge type, steering the LLM past the decoy, and verifying the cipher mapping byte by byte.

## Solution

I want to be honest about how this one actually went down: the LLM did the grinding — pulling apart Unicode, parsing the font's binary tables, writing the decoder — and my contribution was *direction and skepticism*. I recognized the shape of the problem early, told the model where to dig, and crucially caught it celebrating the wrong answer. This writeup is structured around that division of labor.

### Recon: where does the page even come from

The target serves a single animated page titled **"MCK Vamp Visualizer"** — a lyric visualizer for the Vietnamese rapper MCK's song *Ghét Xong Lại Thích / Vamp*. The audio and animation are pure theater. The whole point of a "troll" challenge is to make you stare at the spectacle.

First obstacle: the site sits behind **Cloudflare's "managed challenge"** — the *"Just a moment…"* JS interstitial. This matters for tooling. Every dynamic request from a datacenter IP returns `403`; a residential browser with a real JS engine passes straight through. So my instinct to throw `curl` at it was a dead-end, and I told the model as much rather than letting it burn turns retrying `requests.get()`.

Two endpoints leak the origin because Cloudflare auto-allowlists them:

- `GET /favicon.ico` and `/robots.txt` reach the origin directly. The favicon comes back as GitHub's **"Page not found · GitHub Pages"** body — a dead giveaway that the site is hosted on **GitHub Pages**.
- GitHub Pages is served from a *public* repo, and github.com is not behind this Cloudflare config. A repo search for `hvl v1t` lands on **[`tommytheduck/hvl`](https://github.com/tommytheduck/hvl)** ("v1t ctf 2026"). Inside: `CNAME`, `index.html`, `GhetXogLaiThik-MCK.mp3`, and the file that turns out to be the whole challenge — **`NotoSans-Regular.ttf`**.

The naming is itself thematic foreshadowing. `v1t` = *vịt* = "duck" (the CTF mascot); `hvl` echoes **haivl**, the infamous Vietnamese troll-meme site. The challenge is *telling you* it's going to waste your time. Recognizing that framing is what kept me suspicious of the first thing I found.

### Layer 1: the decoy — invisible variation selectors

`index.html` embeds an SRT subtitle string as a JS constant (`const embeddedSrt = "..."`). Scanning the cues, one stands out — cue #33:

```
ĐÉO CẦN PHẢI GIẢI THÍCH 🔥<invisible chars>
```

After the 🔥 emoji there is a run of **invisible Unicode characters**. This is the classic [Paul Butler emoji-smuggling scheme](https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/): arbitrary bytes are encoded as Unicode *variation selectors*, which render as nothing but ride along attached to the preceding character.

The encoding is a direct byte-to-codepoint map:

- bytes `0–15`  → `U+FE00 .. U+FE0F` (Variation Selectors block)
- bytes `16–255` → `U+E0100 .. U+E01EF` (Variation Selectors Supplement)

Decoding the run after the 🔥:

```
0xE0158 0xE0155 0xE015C 0xE015C 0xE015F 0xE0110 0xE0163 0xE0159 0xE0162
   h       e       l       l       o      (sp)    s       i       r
```

→ **`hello sir`**.

This is *exactly* the trap. It looks like a flag channel — it's hidden, it's clever, it decodes to clean ASCII. The LLM, when I first handed it the SRT, decoded this and announced victory. This was the first wrong turn I had to catch: `hello sir` is not in `v1t{...}` format. The format mismatch is the tell. I pushed back with "that's not flag-shaped, this is a troll challenge, what else in the repo is anomalous" — which redirected attention to the font.

### Layer 2: the real bug — a cipher font

The decisive artifact is `NotoSans-Regular.ttf`. A font file shipped alongside a visualizer is easy to ignore as a styling asset. But its internal `name` table immediately gives it away — it is **not** Noto Sans:

```
nameID 1: Emoji To AZ
nameID 3: Emoji To AZ Regular
```

"Emoji To AZ" is the entire spoiler. This is a **substitution-cipher font**: its `cmap` table (the codepoint → glyph mapping) is rigged so that *emoji codepoints* map to *letter/digit/brace glyphs*. The visualizer renders the lyric captions in this font. So when the SRT spills a burst of emojis at the end (cues #34–#38), the browser doesn't draw emojis — it draws the glyphs the font says those codepoints map to, which spell the flag **on screen**.

The "intended aha" is purely visual: watch the visualizer to the end *with the custom font loaded* and the emoji lines literally render as `v1t{...}`. But you don't need a browser — the mapping lives in the font's binary `cmap`, and `fontTools` reads it directly.

Parsing the `cmap`, each emoji used in the SRT resolves to a glyph:

| codepoint | emoji | glyph name | char |
|-----------|-------|------------|------|
| U+1F600 | 😀 | `v` | `v` |
| U+1F603 | 😃 | `one` | `1` |
| U+1F604 | 😄 | `t` | `t` |
| U+1F601 | 😁 | `braceleft` | `{` |
| U+1F606 | 😆 | `g` | `g` |
| U+1F605 | 😅 | `zero` | `0` |
| U+1F602 | 😂 | `four` | `4` |
| U+1F923 | 🤣 | `t` | `t` |
| U+1F972 | 🥲 | `underscore` | `_` |
| U+1F60A | 😊 | `m` | `m` |
| U+1F607 | 😇 | `c` | `c` |
| U+1F642 | 🙂 | `k` | `k` |
| U+1F972 | 🥲 | `underscore` | `_` |
| U+1F643 | 🙃 | `h` | `h` |
| U+1F609 | 😉 | `v` | `v` |
| U+1F60C | 😌 | `l` | `l` |
| U+1F60D | 😍 | `braceright` | `}` |

Reading the `char` column top to bottom: `v1t{g04t_mck_hvl}`.

Two gotchas mattered here, and both were places the LLM stumbled until corrected:

1. **Glyph names are not characters.** `fontTools` returns glyph *names* like `braceleft`, `underscore`, `zero`, `four` — not `{`, `_`, `0`, `4`. The model's first decoder printed `v one t braceleft g zero four t...` and started to conclude the font was broken. It wasn't; it just needed a glyph-name → character translation table for the *named* glyphs (digits, braces, underscore). Single-letter glyph names (`v`, `t`, `m`) already *are* the character, so the table only needs to cover the named ones — that's why `names.get(g, g)` falls back to the glyph name itself.

2. **Filter to emoji codepoints only.** The SRT contains plenty of ordinary text and the `hello sir` decoy. If you naively run every character through the cipher `cmap` you get garbage from the Latin text (or `KeyError`s on codepoints the font doesn't define). The clean filter is: only process codepoints `>= 0x1F000` that exist in the `cmap`. That isolates the emoji payload and preserves SRT order, which is what makes the flag come out in sequence rather than scrambled.

### End-to-end script

This goes from the two repo artifacts (`index.html`, `NotoSans-Regular.ttf`) straight to the printed flag:

```python
from fontTools.ttLib import TTFont
import re

# 1. Load the cipher font and pull its codepoint -> glyph-name map.
font = TTFont("NotoSans-Regular.ttf")
cmap = font.getBestCmap()                      # {codepoint: glyph_name}

# 2. Translate the NAMED glyphs (digits/braces/underscore) to characters.
#    Single-letter glyph names already equal their character, so fall back to g.
names = {
    'braceleft': '{', 'braceright': '}', 'underscore': '_',
    'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
    'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9',
}
def glyph_to_char(g):
    return names.get(g, g)

# 3. Extract the SRT string from index.html and un-escape its \uXXXX sequences.
html = open("index.html", encoding="utf-8").read()
srt = re.search(r'const embeddedSrt = "(.*?)";', html, re.S).group(1)
srt = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), srt)

# 4. Run ONLY the emoji codepoints (>= 0x1F000) that the cipher cmap defines,
#    preserving SRT order. Latin text and the variation-selector decoy fall away.
flag = ''.join(
    glyph_to_char(cmap[ord(c)])
    for c in srt
    if ord(c) >= 0x1F000 and ord(c) in cmap
)
print(flag)        # v1t{g04t_mck_hvl}
```

The flag reads cleanly on theme: `g04t` = GOAT, `mck` = the artist, `hvl` = the challenge / haivl.

## Flag

```
v1t{g04t_mck_hvl}
```

## Lessons learned - prompting the AI

This challenge is a great case study in *why human steering still matters even when the model writes all the code*. The technical work — Unicode decoding, `fontTools` `cmap` parsing — is squarely in the model's wheelhouse. The two places it failed were both **judgment failures**, not capability failures, and judgment is exactly what I supplied.

**Prompt 1 — frame the genre before handing over artifacts.** I opened with:

> "This is a 'troll' web CTF (the name `hvl` references haivl, a meme site). Expect decoys. Here's `index.html` and a font file from the repo. List every *anomalous* asset and tell me which one is most likely the real flag channel versus a deliberate distraction — don't commit to the first hidden thing you find."

Telling the model upfront that decoys are expected is what made it skeptical of its own findings later. Without that priming, models love to declare victory on the first hidden payload.

**Prompt 2 — kill the decoy explicitly.** When it decoded the variation selectors to `hello sir` and got excited, I corrected:

> "`hello sir` is not in `v1t{...}` format, so it's the decoy, not the flag. Stop working the variation selectors. Pivot to the font: dump its `name` table and `cmap` with `fontTools` and tell me what the emoji codepoints map to."

The format check (`v1t{...}`) is the single most powerful disambiguator in a multi-layer stego challenge — I gave the model the acceptance criterion so it could self-reject wrong answers instead of looking to me for a thumbs-up.

**Prompt 3 — anticipate the glyph-name gotcha.** Before it could conclude the font was broken:

> "`fontTools` returns glyph *names*, not characters — `braceleft` means `{`, `four` means `4`, `underscore` means `_`. Build a glyph-name→char map for the named glyphs only, leave single-letter names as-is, and filter to codepoints >= 0x1F000 so the Latin text and decoy don't pollute the output."

**What to tell the model to focus on:** the `name` table of any unexpected font (it spoils cipher fonts instantly — here "Emoji To AZ"), the `cmap` as a *substitution table*, and SRT/source order preservation so characters come out in sequence.

**Dead-ends to tell it to AVOID:** don't `curl`/`requests` the live site (Cloudflare managed challenge → 403 from datacenter IPs; go to the public GitHub Pages repo instead); don't treat the variation-selector payload as the flag (it's `hello sir`, a decoy); don't feed all SRT characters through the cipher (filter to emoji codepoints); don't assume `fontTools` returns characters (it returns glyph names, so digits/braces/underscore need translation).

**How I verified / caught mistakes:** I checked every candidate against the `v1t{...}` format — that immediately exposed `hello sir` as a decoy. For the final answer, I cross-checked the script's output against the *intended* visual: the font is designed so the emojis render as the flag on screen, so "does it read as a sensible, on-theme flag" (`g04t`/`mck`/`hvl`) was a second independent confirmation. When the model produced glyph-name soup, the giveaway was that the output contained recognizable *names* of characters (`braceleft`, `four`) — a clear sign of a name-vs-character bug, not a corrupt font.

**Fast-path prompt recipe for next time:** *"Troll/stego web chal — expect decoys, don't commit to the first hidden payload. Validate every candidate against the flag format and reject non-conforming ones as decoys. Inspect unexpected fonts via `fontTools` name + cmap tables (cipher fonts), remember cmap returns glyph names not chars, and filter payload codepoints by range while preserving source order."*
