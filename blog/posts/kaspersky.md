---
title: "Kaspersky"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: osint
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, osint, ai-assisted]
draft: false
summary: "A 5-question Kaspersky / Kaspersky Academy OSINT quiz at kaspersky.v1t.site, industrialized by scripting the grader's API — and the final question only accepted the course title in its native Cyrillic, not any romanization."
icon: "🛰️"
---

## Summary
`kaspersky.v1t.site` is a linear 5-question OSINT quiz on Kaspersky / Kaspersky Academy — file metadata, course curricula, an archived social repost, and a Foursquare check-in badge. Validation is server-side but scriptable, so I had the model build a replay harness to batch-test answers; the last question only accepted the course's **native Cyrillic** title, `Кибергигиена`.

## Solution
I split this into two problems and let the model do the legwork on both: turn the grader into a cheap oracle, then grind five OSINT sub-puzzles against it. My job was reading each question's *real* intent (metadata vs. page text, on-domain vs. off-domain, English vs. Cyrillic) and killing wrong hypotheses fast.

### Step 1 — Make the grader scriptable
I had the model reverse the SPA's inline script and it surfaced a clean API: `POST /api/start` → `{token, question}`, `POST /api/answer {token, answer}` → `Correct.` + next token (Q1–Q4) or `Completed.` + `flag` (Q5). The base64 token carries a wrong-counter, but in practice the only limiter was a burst rate limit (HTTP 429) — so I told the model to build a replay harness with a ~250 ms delay + retry-on-429, which lets us re-mint a Q5 token by replaying Q1–Q4 and batch-test candidates.

### Step 2 — The five answers (and how I steered each)
- **Q1 — "modified date of the Advanced Membership file":** I flagged "*of the file*" as a metadata steer, not the page's publish date. Had the model check the `Last-Modified` header / PDF `ModDate` on the Kaspersky Academy Alliance Program doc → **`10/04/2025`**.
- **Q2 — who led "Malware Reverse Engineering":** the live SPA only credits Victor Chebyshev; I had the model pull the curriculum PDF + Wayback capture, which adds Boris Larin → **`VictorChebyshev_BorisLarin`**. (This also fingerprinted "instructor data lives in curriculum docs" — a fact I had to *not* over-trust in Q5.)
- **Q3 — Aug 3 2017 reposted album → registration link:** I insisted the link was off-domain (the format hint `example.com/abcxyz` was literal). Wayback of the Academy Twitter timeline → the event's **`surveymonkey.com/r/Z8M9C2D`** (every kaspersky.com / Starmus / JunctionX guess was rejected — JunctionX didn't even exist until 2018).
- **Q4 — man who visited the fitness room 50+ times:** "50+ times" = a Foursquare/Swarm badge. The model found the **Kaspersky Lab Gym** venue, hit Foursquare's auth wall, so I logged in (passwordless email code) and read the Tips — only **`DimmChern`** carries "Been here 50+ times".
- **Q5 — the course with 5 instructors (3M/2F):** see below.

### Step 3 — Q5: answer in the source's native script
The model identified the course almost immediately: on the **Russian-locale** API (`domainType=1`) exactly one course returns 5 speakers, 3 male / 2 female — `cyberhygiene` / **`Кибергигиена`** (the English page shows 8, which doesn't match). The trap was the *spelling*: ~200 English/transliterated forms (`Cyberhygiene`, `Kibergigiena`, `Kaspersky_Cyber_Hygiene`, …) were all rejected, and I briefly over-generalized Q2's "data lives in PDFs" insight into a long, useless Wayback/SOCKS5 PDF hunt. The fix was simple once I trusted the live API: the grader stores the **literal Cyrillic title** from the Russian page. The format hint `(Kaspersky_Next_EDR_Optimum)` only meant "underscore-join multiple words" — a one-word Cyrillic title needs neither.

```js
// Replay harness: mint a fresh token, answer Q1-Q4, then submit each Q5 candidate.
// Run on the kaspersky.v1t.site origin (browser console / Playwright evaluate).
const KNOWN = ["10/04/2025", "VictorChebyshev_BorisLarin",
               "surveymonkey.com/r/Z8M9C2D", "DimmChern"];
const Q5 = ["Кибергигиена",            // <- native Cyrillic title (the winner)
            "CyberHygiene", "cyber_hygiene", "Kiberhigiena", "Kaspersky_Cyberhygiene"];
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function post(path, body) {
  for (;;) {                                   // retry on 429 rate limit
    const r = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json"},
                                 body: JSON.stringify(body)});
    if (r.status === 429) { await sleep(800); continue; }
    return r.json();
  }
}
for (const cand of Q5) {
  let { token } = await post("/api/start", {});
  for (const a of KNOWN) {                      // replay Q1-Q4 to reach Q5
    const res = await post("/api/answer", {token, answer: a}); token = res.token; await sleep(250);
  }
  const res = await post("/api/answer", {token, answer: cand});
  await sleep(250);
  if (res.flag) { console.log("FLAG via", cand, "->", res.flag); break; }
}
```

`Кибергигиена` returned `{"message":"Completed.","flag":"v1t{kaspersky_pls_collabbb}"}` on the first try — 5/5.

## Flag
```
v1t{kaspersky_pls_collabbb}
```
