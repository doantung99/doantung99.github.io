---
title: "Huh"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: misc
difficulty: easy
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, misc, ai-assisted]
draft: false
summary: "A mixed OSINT/stego challenge where a Vietnamese village photo gives the flag prefix and a hidden text fragment gives the suffix."
icon: "🕵️"
---

## Summary
A hybrid OSINT/stego puzzle: one image points to an old Vietnamese village (Cự Đà), and a hidden text fragment inside the artifact supplies the tail of the flag. The win is reconstructing the full `v1t{...}` by pairing the location-derived prefix with the recovered suffix.

## Solution
I pegged this early as an OSINT-plus-stego combo and set that as the direction for the model: treat the picture and the hidden data as two halves of one flag, not two separate puzzles. That framing mattered, because the suffix alone looks like a complete flag and it's tempting to just submit it.

1. I handed the image to the model and prompted it to geolocate by architectural and cultural cues rather than generic landmarks, steering it toward "old Vietnamese village" instead of a tourist spot. It converged on **Cự Đà village**, which normalizes to the leetspeak prefix `cu_d4`.
2. Separately, I had the model extract the hidden text fragment from the artifact. It pulled out `_c4non_f4nboy}` — clearly a flag suffix, not a whole flag. I caught the trap here: I told it not to submit the fragment standalone and to instead splice it onto the OSINT prefix.
3. I verified the join by hand. The model did the grinding (geolocation reasoning, stego extraction, normalization); my job was the prompting and the judgment call that the two pieces were one flag.

```python
# Two recovered halves, assembled into one flag.
osint_prefix = "cu_d4"          # Cự Đà village, leetspeak-normalized (from the image)
stego_suffix = "_c4non_f4nboy}" # hidden text fragment recovered from the artifact

flag = "v1t{" + osint_prefix + stego_suffix
print(flag)  # -> v1t{cu_d4_c4non_f4nboy}
```

## Flag
```
v1t{cu_d4_c4non_f4nboy}
```
