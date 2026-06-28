---
title: "Huh"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: osint
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, osint, ai-assisted]
draft: false
summary: "An OSINT/stego challenge that is NOT fully solved. Image recon nailed the location — Làng Đường Lâm (Đường Lâm ancient village, Sơn Tây, Hà Nội) — but the part 1 flag was never recovered. Writeup is partial/unsolved."
icon: "🧩"
---

## Summary

"Huh" is a two-part OSINT/stego challenge, and this is an honest **partial** writeup: it is **not solved**. The recon got far enough to confidently identify the location in the image — **Làng Đường Lâm** (Đường Lâm ancient village, Sơn Tây, Hà Nội) — using the architecture, the laterite (ong-stone) walls, and the village-gate / banyan-tree cues. But identifying the place is only the *first half* of the problem. The **part 1 flag was never recovered**: the step that turns the location finding into the actual `v1t{...}` token (the decode / extraction that produces the flag) did not work out, and there is a hidden-text / stego component that I also could not crack. I used an LLM heavily for the geolocation reasoning, and it did well on the "where" — but "where" is not a flag, and the writeup stops where the real solve does: short of the flag.

## Solution

### What the challenge is

The artifact is a photo of an old Northern Vietnamese village plus a `v1t{...}` flag format. As with most V1t misc/OSINT challenges, the flag is expected to be split or encoded: a location-derived piece plus a hidden/encoded piece. The name "Huh" is itself a signal that the path is deliberately confusing.

### Track 1 — the location recon (this part worked)

The image was clearly not a generic tourist shot. The visual cues were strong and consistent with one specific heritage site:

- **Laterite (ong-stone) walls** — the distinctive porous, rust-colored stone blocks. This is the signature building material of one village in particular near Hà Nội.
- **Traditional Northern Vietnamese village layout** — narrow brick lanes, low tiled-roof houses, an old communal/gate structure.
- **Village-gate and banyan-tree atmosphere** — the classic "cổng làng + cây đa" composition that heritage photographers shoot at this site.

Feeding these cues to the model and asking it to rank candidate ancient villages near Hà Nội by *distinguishing visual feature* pointed strongly and repeatedly at one answer:

```text
Làng Đường Lâm  (Đường Lâm ancient village, Sơn Tây, Hà Nội)
```

Đường Lâm is the textbook match: it is *the* laterite-wall ancient village near Hà Nội, a nationally recognized heritage site, and the ong-stone walls plus the village gate are exactly what the photo shows. The location identification is the part I am confident in.

### Track 2 — turning location into the flag (this part did NOT work)

Identifying Đường Lâm is necessary but not sufficient. The flag is `v1t{...}`, and a place name is not a flag. The missing step is the **decode / extraction**: how the location name (or some attribute of it) maps into the flag token, and/or how a hidden text fragment is pulled out of the artifact to complete it.

What I tried and what remains open:

- Normalizing the location name into V1t-style leetspeak (drop tones, `a→4`, spaces→`_`) — but it is unclear *which* string is meant (the village name? a sub-hamlet? an attribute like the stone or a person/figure associated with the site?), so this did not converge on an accepted flag.
- Stego / hidden-text extraction on the artifact — I did not recover a clean, brace-terminated fragment, so the suffix half (if there is one) is still missing.

So Track 1 (the "where") is solved; Track 2 (the "what is the flag") is not. **Part 1 flag: not recovered.**

### Honest status

This is a partial solve. The location is **Làng Đường Lâm**. The flag is **not** obtained. Anyone picking this up next should start from the confirmed location and focus entirely on the decode/extraction step that I could not complete.

## Flag

**Not recovered — the challenge is unsolved.**

The location was identified as **Làng Đường Lâm** (Đường Lâm ancient village, Sơn Tây, Hà Nội), but the part 1 flag was never extracted and no valid `v1t{...}` was produced.

> Unverified guess (do NOT treat as the answer): `v1t{cu_d4_c4non_f4nboy}` was floated during the attempt but was **never obtained from the challenge and the grader did not accept it**. It is recorded here only so the next person does not waste time re-trying it.

## Lessons learned - prompting the AI

**Whenever you face an OSINT geolocation challenge — "where was this photo taken?" on an image with no EXIF, especially a regional/heritage site rather than a world landmark — and the location then has to be turned into a flag,** the model is excellent at the *recognition* step and dangerous at the *flag-derivation* step. This challenge is the cautionary version: the AI nailed "this is Đường Lâm" and then I (and it) failed to convert that into the actual flag. Treat geolocation and flag-derivation as two separate skills and verify them differently.

**1. For the geolocation, force ranked candidates with distinguishing features — never accept a single confident guess.** The prompt that actually worked here:

> "This is an old village in northern Vietnam, no EXIF, not a world-famous landmark. Identify it from physical cues only. Give me your top 5 candidate sites near Hà Nội, ranked, and for EACH one name the single most distinguishing visual feature and whether this image shows it. Call out the building material, the gate/architecture style, and any vegetation. Do not commit to one answer until you've compared the discriminating feature across all five."

Asking for the *discriminating feature per candidate* is what surfaced the laterite (ong-stone) walls as the decider and led to Đường Lâm. A second reusable probe for any geolocation:

> "What in this image is region-specific versus generic? List the cues that could ONLY occur at a small number of places, and the cues that occur everywhere — then geolocate using only the region-specific ones."

**2. Tell it what to focus on, and name the classic geolocation dead-ends up front so it skips them.** Focus prompt plus the don'ts:

> "Focus on building material, roof style, signage/language, vegetation, terrain, and any text on walls or shopfronts. Avoid these dead-ends: do NOT claim EXIF/GPS you can't see; do NOT pick a famous landmark just because it's famous (this is deliberately an obscure site); do NOT hallucinate street names or coordinates; do NOT confuse visually-similar heritage villages — distinguish them by their UNIQUE material/feature, not vibes."

For the stego/decode half (the part that beat me), pre-empt its worst habit:

> "There is likely a second, hidden/encoded half to the flag. Do NOT invent or 'complete' a flag from the location alone. If you cannot extract a real fragment from the artifact, say so explicitly and stop — a place name is not a flag."

**3. How to verify the model's output for this class — so you catch hallucinations.** Geolocation answers are easy to bluff, so verify before you trust:
   - **Reverse-image / cross-check the named site independently.** Pull up reference photos of the model's #1 candidate and confirm the *same* distinguishing feature (here: the ong-stone laterite walls) appears in both the challenge image and the references. If the discriminating cue doesn't match, the ID is wrong no matter how confident the prose was.
   - **Demand the per-candidate feature table** and reject any answer that can't say *why not* for the runners-up. A real ID can articulate what rules out the alternatives.
   - **Hard-separate "location identified" from "flag obtained."** This is the exact failure here: confidence in the location got mistaken for progress on the flag. Never report a flag unless it was extracted/decoded from the artifact AND accepted by the grader. An unverified leet rendering of a place name (like the `cu_d4_...` guess above) is a hypothesis, not an answer — mark it as such.
   - **Treat any model-generated flag with suspicion if it was reasoned out rather than extracted.** If the model "derives" the flag from the location instead of pulling it from the file/encoding, assume it's hallucinated until the grader says otherwise.

**4. Fast-path prompt recipe for the class.** "Geolocate this photo from physical cues only (no EXIF, obscure site): give top-5 ranked candidates near <region>, the single discriminating feature per candidate, and confirm which feature THIS image shows — then independently cross-check the winner against reference photos; and remember a place name is NOT a flag, so do not invent one — if the encode/extract step that turns the location into the flag isn't recoverable from the artifact, say 'location found, flag not recovered' and stop."
