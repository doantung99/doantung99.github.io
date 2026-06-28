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
icon: "🦆"
draft: false
summary: "A 'troll' GitHub Pages site hides the flag behind two stego layers; the real one is a substitution-cipher font that renders emoji lyrics as flag text."
---

## Summary
`hvl.v1t.site` is an MCK lyric visualizer that smuggles data two ways: invisible Unicode variation selectors (a decoy reading `hello sir`) and a custom `cmap` font that maps emoji codepoints to flag characters. The real solve is parsing that font's `cmap` to translate the emoji burst at the end of the subtitles.

## Solution
This was very much a "me steering, model grinding" solve. I recognized the duck/`haivl` naming as a troll signal and told the model to assume nothing on screen was the channel and to hunt for a hidden one.

1. **Recon, model-driven.** I had the model triage the site behind Cloudflare's managed challenge. It noticed `favicon.ico` returns GitHub's "Page not found · GitHub Pages" page, so I pointed it at GitHub: the source lives in the public repo `tommytheduck/hvl`, exposing `index.html`, the MP3, and a suspicious `NotoSans-Regular.ttf`.
2. **Catching the decoy.** The model first locked onto invisible variation selectors after the 🔥 in SRT cue #33 and proudly decoded `hello sir`. I flagged that as the troll and redirected it: that font is named "Emoji To AZ" internally, not Noto — so it's a substitution cipher, and the emoji captions are being *drawn* as letters.
3. **Verify via the font.** I asked it to script the `cmap` extraction with `fontTools`, map glyph names like `braceleft`/`one`/`underscore` to characters, and apply it to the emojis in the embedded SRT in order. I confirmed the output matched the on-theme flag (`g04t` = GOAT, `mck` = the artist, `hvl` = haivl).

```python
from fontTools.ttLib import TTFont
import re

font = TTFont("NotoSans-Regular.ttf")
cmap = font.getBestCmap()  # codepoint -> glyph name

names = {'braceleft': '{', 'braceright': '}', 'underscore': '_',
         'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
         'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9'}

def g2c(g):
    return names.get(g, g)

# emojis from the embedded SRT, in order
html = open("index.html", encoding="utf-8").read()
srt = re.search(r'const embeddedSrt = "(.*?)";', html, re.S).group(1)
srt = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), srt)

flag = ''.join(g2c(cmap[ord(c)]) for c in srt
               if ord(c) >= 0x1F000 and ord(c) in cmap)
print(flag)  # v1t{g04t_mck_hvl}
```

The intended "aha": load the page to the end with the custom font and the emoji lines literally render the flag on screen.

## Flag
```
v1t{g04t_mck_hvl}
```
