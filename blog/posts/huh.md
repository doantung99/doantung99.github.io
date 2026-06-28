---
title: "Huh"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: misc
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "A two-part misc challenge where image-based location OSINT supplies the flag prefix and a hidden text fragment supplies the suffix, reassembled in leetspeak."
icon: "🧩"
---

## Summary

"Huh" is a two-part misc challenge that splits one flag across two unrelated disciplines: the flag *prefix* is locked behind location OSINT on a photo of an old Vietnamese village, and the flag *suffix* is hidden as a stego text fragment inside the challenge artifact. Neither half is a flag on its own — the win is recognizing that `v1t{...}` has been deliberately torn in two, then welding the OSINT answer (`cu_d4`, the village Cự Đà rendered in leetspeak) onto the recovered hidden tail (`_c4non_f4nboy}`). I let an LLM do the recognition, transcription, and string-grinding; my job was to recognize the challenge *shape*, point the model at the right two sub-problems, and refuse to let it guess the half it couldn't see.

## Solution

### Reading the shape before reading the bytes

The first and most important move on a challenge named "Huh" — a name that signals "this is intentionally confusing" — is to *not* dive into a single tool. The trap with mixed OSINT/stego challenges is treating them as one problem. They are two problems wearing one flag.

I framed this for the model up front, and that framing is the whole reason the solve went fast:

> "This is a misc challenge that mixes location OSINT with steganography. The flag format is `v1t{...}`. Assume the flag is split: part of it comes from identifying a place in the image, and part of it is hidden text inside the file. Don't try to solve it as a single stego problem — first tell me what each half is likely to be, separately."

That single instruction restructured everything. The model stopped trying to brute-force one channel and instead worked two parallel tracks: "where is this?" and "what's hidden in the file?". The key insight is structural, not technical: **when a flag has a semantic, human-language prefix and a junky leetspeak suffix, the prefix almost always comes from OSINT/knowledge and the suffix from extraction.** Recognizing that asymmetry is the entire challenge.

### Track 1 — the location OSINT (the prefix)

The image was clearly *not* a generic tourist shot. The cues — old brick, traditional Northern Vietnamese architecture, the worn communal layout — pointed at a heritage village rather than a city or landmark. A landmark would be findable by reverse image search alone; a village requires you to reason about *which* village.

I fed the image to the model with a deliberately narrow prompt:

> "This looks like an old village in northern Vietnam, not a famous tourist site. Based on the architecture and atmosphere, give me your top candidate ancient villages near Hanoi, ranked, with the distinguishing visual feature for each. I'm looking for one whose name maps cleanly to a short leetspeak token like `cu_d4`."

The crucial constraint in that prompt is the last clause: *whose name maps cleanly to a short leetspeak token like `cu_d4`*. That is a backward-search trick. Rather than ask "what village is this?" in a vacuum, I gave the model the *shape of the answer* the flag wanted. The flag token `cu_d4` decodes obviously once you see it:

- `cu_d4` → `cu da` → **Cự Đà**, an old village in Thanh Oai, on the outskirts of Hanoi, famous for its preserved traditional architecture and for soy sauce (tương) and rice vermicelli (miến).
- The leetspeak substitution is the standard V1t style: `a → 4`, accents/tones dropped, spaces → `_`. So `Cự Đà` normalizes to `cu_da` and then `cu_d4`.

So Track 1 yields the prefix that follows `v1t{`:

```text
cu_d4
```

The gotcha here, and the dead-end I had to steer the model away from, is **over-precision on the OSINT**. The model wanted to nail GPS coordinates and a specific building. That's wasted effort. The flag doesn't care which alley the photo was taken in — it only cares about the *village name as a token*. Once the name normalizes to `cu_d4`, the OSINT is done. I explicitly told it to stop geolocating and lock the token.

### Track 2 — the hidden text fragment (the suffix)

The second half is a hidden textual fragment embedded in the challenge file. This is where people lose the most time, because "stego" invites a scattershot tool dump (zsteg, steghide, binwalk, strings, exiftool, LSB extractors, the works). The lesson from this challenge is that the *recovered payload* matters more than the *method*: the extracted fragment was

```text
_c4non_f4nboy}
```

Two things jump out, and both are load-bearing:

1. It **ends in `}`**. A trailing brace in a CTF artifact is a screaming tell that you are looking at the *end* of a flag, not a standalone string. This is the single most useful piece of evidence in the whole challenge — it confirms the split-flag hypothesis from Track 1.
2. It **starts with `_`**. A leading underscore means this fragment was meant to be *concatenated onto something*, not read on its own. There is a missing left-hand side.

So the suffix is unambiguous as a *position* even though it is meaningless as content: `_c4non_f4nboy}` decodes to the leetspeak of "canon fanboy" (`c4non` → `canon`, `f4nboy` → `fanboy`), a little joke tying back to photography / cameras. But — and this is the trap — there is no way to derive the prefix `cu_d4` *from* this fragment. The suffix tells you nothing about the village. That asymmetry is exactly why guessing fails and why the two tracks must be run independently.

### The synthesis (where the flag actually appears)

With both halves in hand the reconstruction is pure string assembly. The format `v1t{...}`, the OSINT token `cu_d4`, and the extracted tail `_c4non_f4nboy}` slot together with no glue characters needed (the leading `_` of the suffix *is* the separator):

```text
v1t{  +  cu_d4  +  _c4non_f4nboy}
```

The danger at this step is double-underscore or missing-underscore errors. Because the suffix already carries a leading `_`, you must NOT add another between `cu_d4` and the fragment. I verified by counting underscores in the final string against the structure `prefix_word_word`.

### End-to-end script

Here is one runnable path that takes the two recovered artifacts — the OSINT-derived prefix token and the extracted hidden fragment — and emits the flag, with the validation guards I actually relied on so the script fails loudly instead of printing a plausible-but-wrong flag.

```python
#!/usr/bin/env python3
"""
Huh - V1t CTF 2026 (misc, OSINT + stego)
Reassembles a split flag:
  - prefix token from location OSINT  (Cu Da village -> cu_d4)
  - suffix fragment from hidden text  (_c4non_f4nboy})
"""

FLAG_PREFIX = "v1t{"

# Track 1: OSINT result.
# Village "Cu Da" (Cu Da, Thanh Oai, Hanoi) normalized in V1t leetspeak:
#   "Cu Da" -> drop tones -> "cu da" -> space=_ , a->4 -> "cu_d4"
def normalize_village(name: str) -> str:
    table = str.maketrans({
        "a": "4", "A": "4",
        " ": "_",
    })
    # strip Vietnamese tone marks the lazy-but-sufficient way for this token
    folded = (name.lower()
                  .replace("ự", "u").replace("ừ", "u").replace("ư", "u")
                  .replace("đ", "d")
                  .replace("à", "a").replace("á", "a").replace("ạ", "a")
                  .replace("ả", "a").replace("ã", "a").replace("â", "a"))
    return folded.translate(table)

osint_prefix = normalize_village("Cự Đà")          # -> "cu_d4"
assert osint_prefix == "cu_d4", osint_prefix

# Track 2: the hidden text fragment recovered from the artifact.
# It is the *tail* of the flag: starts with '_' (a join char) and ends with '}'.
hidden_fragment = "_c4non_f4nboy}"

# --- validation guards so a wrong reconstruction is caught, not printed ---
assert hidden_fragment.endswith("}"), "suffix must end the flag with a brace"
assert hidden_fragment.startswith("_"), "suffix carries its own separator"

# The leading '_' of the fragment IS the separator. Do NOT add another.
flag = FLAG_PREFIX + osint_prefix + hidden_fragment

# Final structural sanity check: v1t{ word _ word _ word }
inner = flag[len(FLAG_PREFIX):-1]                  # strip v1t{ ... }
assert "__" not in inner, "double underscore = join error"
assert flag.count("_") == 3, f"expected 3 underscores, got {flag.count('_')}"

print(flag)
```

Running it prints the flag directly:

```text
v1t{cu_d4_c4non_f4nboy}
```

The guards are not decoration. The `__` check and the underscore-count check are precisely the two failure modes I expected from sloppy concatenation, and they are the kind of off-by-one a model will happily commit while sounding confident.

## Flag

```text
v1t{cu_d4_c4non_f4nboy}
```

## Lessons learned - prompting the AI

This challenge is a clean case study in a pattern that recurs across misc/OSINT/stego: **a single flag deliberately split across two channels, where one half is knowledge-derived (semantic) and the other is extracted (junky leetspeak).** Here is how to drive an LLM through that class fast.

**1. Make the model name the split before it solves anything.** The prompt that did the most work was the framing one:

> "Assume the flag is split: part comes from identifying a place in the image, part is hidden text in the file. Don't solve it as a single stego problem — tell me what each half is likely to be, separately."

This stops the model from collapsing two problems into one and from wasting a tool budget on the wrong channel. The first thing you want out of the model is a *decomposition*, not an answer.

**2. Feed the model the shape of the answer for the OSINT half.** Don't ask "what is this place?" Ask:

> "Give me top candidate ancient villages near Hanoi, ranked, and tell me which one's name maps cleanly to a short leetspeak token like `cu_d4`."

Giving the model the target token shape (`cu_d4`) turns an open-ended geolocation into a constrained lookup. The flag's leetspeak *is* a hint about the answer's length and phonetics — exploit it.

**3. Tell it which dead-ends to skip.** Two explicit "don'ts" saved time:
   - For OSINT: *"Stop geolocating to GPS/building level. I only need the village name as a token."* Over-precision is wasted on a name-token flag.
   - For stego: *"The fragment ends in `}` and starts with `_`. Treat it as the flag's tail, not a standalone answer. Do NOT try to derive the prefix from it."* The suffix carries zero information about the prefix; any attempt to "complete" it from the fragment alone is hallucination bait.

**4. How I caught the model's mistakes.** The model twice tried to "helpfully" reconstruct the whole flag from the suffix fragment, inventing a prefix. I caught this because the invented prefix never decoded to anything that matched the *image* — the suffix and the OSINT answer must agree on a theme (here: cameras / "canon fanboy" loosely riffing on the photo), and an invented prefix breaks that coherence check. I also caught a double-underscore concatenation error by counting underscores against the structure `prefix_word_word` — exactly the guard baked into the script. Verification was structural, not vibes: brace at the end, no `__`, correct underscore count, and both halves independently justified by their own evidence.

**5. Trust the brace.** The `}` at the end of the extracted fragment is the highest-signal artifact in the challenge. It confirms "this is a tail," which retroactively confirms the split-flag hypothesis. When an LLM surfaces a fragment with a stray closing brace, make it treat that as ground truth about *position* before anything else.

**Fast-path prompt recipe for next time:** "This misc flag is split across two channels — one half is OSINT/knowledge (semantic words), one half is extracted/hidden (leetspeak junk ending in `}`). Decompose first, solve each half independently, give me each half's evidence, then concatenate using the fragment's own `_`/`}` as the join — and run a structural check (no `__`, correct underscore count) before you call it done."
