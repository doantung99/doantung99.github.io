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
summary: "A 5-question Kaspersky OSINT quiz solved by an LLM grinding artifacts while I steered the search, killed a costly false trail, and forced the final answer into native Cyrillic."
icon: "🕵️"
---

## Summary

`kaspersky.v1t.site` is a linear 5-question OSINT quiz about Kaspersky / Kaspersky Academy: each correct answer unlocks the next, and the fifth returns the flag. The interesting part is the collaboration — an LLM did almost all the grinding (enumerating Wayback slugs, scraping speaker panels, parsing PDFs, batch-testing answers against a scriptable grader), while my job was to recognize each question's *real* OSINT primitive (file metadata, archived curriculum, a Foursquare badge, a native-locale API), to kill a multi-hour dead-end the model talked itself into, and to make the final call that the grader wanted the course title in **Cyrillic**, not English. That last judgment is what turned `Кибергигиена` into `v1t{kaspersky_pls_collabbb}`.

## Solution

### The machine: a scriptable, server-side grader

Before any OSINT, I had the model reverse-engineer the SPA's inline script so we'd have a programmatic loop instead of clicking through a UI. The API is small and clean:

- `POST /api/start` → `{ token, question, max_wrong_attempts }`
- `POST /api/answer` with `{ token, answer }` → `{ message, token?, question?, flag? }`
  - Intermediate correct (Q1–Q4): `{ message: "Correct.", token, question }` — a **fresh token** plus the **next** question.
  - Final correct (Q5): `{ message: "Completed.", flag: "v1t{…}" }` — note the *different* message string.
  - Wrong: `{ message: "Wrong answer. Try again.", flag: null }`.

The token is a base64 payload `{"i":<questionIndex>,"w":<wrongCount>,"exp":<ts>}`. The model's first read of this was: `w` plus `max_wrong_attempts = 3` means a 3-strikes lockout, so be careful. That inference was *wrong in practice*, and this is the first place I had to correct it. Empirically the lockout never fired — a wrong answer left the token usable — so we could hammer candidates back-to-back. The only real limiter was a burst **rate limit (HTTP 429)**, which we handled with a ~200–250 ms delay and a retry-on-429 loop.

Why this matters: because validation is **server-side**, you cannot read answers from the page. But you *can* replay the four known answers to re-mint a fresh Q5 token and then brute-test hypotheses cheaply. That replay harness is what eventually cracked Q5 after ~200 string variants. Establishing it early, before we knew any answers, is the single highest-leverage thing we did — it turned "guess and despair" into "enumerate and verify."

### Q1 — Modified date of the "Advanced Membership" file → `10/04/2025`

> What is the modified date of the *Advanced Membership* file in the Kaspersky Academy **Alliance Program**? Format `(DD/MM/YYYY)`.

The trap here is treating "modified date" as a search-engine question. It is not — it is a **document-metadata** question, and the phrasing "*modified date of the file*" is a deliberate steer away from the publish/upload date shown on the page. The Kaspersky Academy Alliance Program (the partner/university section of academy.kaspersky.com) publishes downloadable membership documents, including an "Advanced Membership" brochure PDF.

The "modified date" is a file property, recoverable three ways, in order of reliability:

1. The HTTP `Last-Modified` response header when fetching the file directly.
2. The PDF's internal document-info / XMP `ModDate` field (`exiftool`, `pdfinfo`, or any PDF properties dialog).
3. The "last modified" timestamp in the hosting/listing UI.

All three converge on **10 April 2025** → `10/04/2025`. My steer to the model was simply "don't Google this; fetch the file and read its metadata" — the kind of redirect a human gives once and the machine then executes flawlessly.

### Q2 — Who led "Malware Reverse Engineering" → `VictorChebyshev_BorisLarin`

> Who led the *Malware Reverse Engineering* training course on academy.kaspersky.com? Format `(BillGates_LinusTorvalds)`.

This is the **Rosetta Stone** of the whole challenge, and getting it right shaped (and later mis-shaped) the rest. The live academy.kaspersky.com is a JS SPA, and the "Our Experts" section on the Malware Reverse Engineering page credits only **Victor Chebyshev**. The second lead, **Boris Larin**, is *absent from the live DOM* — the string "Larin" simply isn't on the rendered page.

Where the model found him:

1. The course's linked **"detailed course program" / curriculum document**, which credits both leads.
2. **Wayback Machine** snapshots of the pre-SPA course page.

Both are well-known Kaspersky GReAT researchers, which corroborates the pairing → `VictorChebyshev_BorisLarin`.

The lasting lesson — and the seed of a later trap — is that the author's instructor data sometimes lives in **curriculum PDFs / archived pages, not the live SPA**. I noted that as a *hypothesis to test per-question*, not a law. The model wanted to promote it to a law. Hold that thought; it costs us hours in Q5.

### Q3 — The Aug 3, 2017 re-posted album → `surveymonkey.com/r/Z8M9C2D`

> On August 3, 2017, Kaspersky Academy re-posted a photo album from an event — send the registration link. Format `(example.com/abcxyz)`.

This is **temporal social-media OSINT**: pin what Kaspersky Academy shared on a precise date, identify the event, then find that event's registration URL. The key facts:

- The repost was Kaspersky Academy **sharing another page's album** (their own Flickr only holds 2013 content), so the artifact lived on **Twitter**, recoverable via a **Wayback capture** of the Academy timeline near 3 Aug 2017.
- The registration page for that event is an **off-domain SurveyMonkey form**: `surveymonkey.com/r/Z8M9C2D`.

The reason this took real iteration is a pile of plausible-but-wrong guesses the model generated, all of which I let it fire at the grader to *prove* dead rather than argue:

- `academy.kaspersky.com/cyberday2017`
- `www.kaspersky.vn/ransomware-workshop-2017/`
- `academy.kaspersky.com/talentlab`
- `bit.ly/junctionxhanoi-registration`, `bit.ly/JunctionXAsia` — **temporally impossible**: Kaspersky's worldwide JunctionX program only began in **2018**, so it can't be an Aug-2017 repost. (I caught this one by date arithmetic, not by submitting it.)
- `academy.kaspersky.com/subprojects/kaspersky-faculty-days.html`
- `starmus.com` / `starmus2017.starmus.com` — seductive because Kaspersky title-sponsored Starmus IV that summer. Wrong.
- various `academy.kaspersky.com/news` / "nextgen" / "Hot Event" pages.

The unifying insight: the format hint `(example.com/abcxyz)` was **literal** — a third-party host with a short path. The registration link is **off the organiser's domain**. Every kaspersky.com / Starmus / JunctionX guess failed because of an unstated assumption that the sign-up page lived on Kaspersky's own site. Once I told the model to stop privileging kaspersky.com and treat the hint as "third-party short link," the SurveyMonkey form fell out.

### Q4 — The man who visited the fitness room 50+ times → `DimmChern`

> Kaspersky has a fitness room for employees, and there's a man who visited it more than 50 times. What is his name? Format `(ChrisMartin)`.

"Visited more than 50 times" is not prose — it is a **literal check-in counter** on a location-based social network. An *indoor* "fitness room" rules out GPS/Strava segments and points squarely at **Foursquare / Swarm**. The chain:

1. **Locate HQ:** Kaspersky HQ = *39A/3 Leningradskoe Shosse, Moscow* (BC «Olympia Park», Voykovsky district).
2. **Find the venue:** → **"Kaspersky Lab Gym"** on Foursquare: `foursquare.com/v/kaspersky-lab-gym/51f7c6f6498ea22aecbef517`.
3. **Hit the auth wall** (this is the whole puzzle): every Foursquare venue/tip URL **302-redirects to login** for anonymous users; search-index snippets held only boilerplate (rating 7.6, hours, 2 tips); Wayback / archive.today had no usable snapshot; and spoofing Googlebot returned `503 "fake google bot reject"` because Foursquare verifies real Googlebot by reverse-DNS. Conclusion: **the visit data is only visible while authenticated.**
4. **Authenticate:** Foursquare uses passwordless **email-code** login. A valid `oauth_token` session in the browser made the venue page render.
5. **Read the Tips section**, where each user carries a check-in-frequency badge:
   - *Evgeny Ablesov* — "Been here **10+** times"
   - **Dimm Chern — "Been here 50+ times"** — tip: *"Вышел с работы и на треню :)"* ("Left work and off to training").

The only "Been here 50+ times" badge belongs to **Dimm Chern** → `DimmChern`. The model's instinct was to keep trying to scrape the page anonymously; my contribution was recognizing the 302→login pattern as "auth-gated, stop scraping, log in" rather than "try another proxy." That same auth-gating instinct, ironically, is what the model over-applied in Q5.

### Q5 — The course with 5 instructors (3M/2F) → `Кибергигиена`

> I learned from **five exceptional instructors — three male and two female experts**. Which course was it? Example format `(Kaspersky_Next_EDR_Optimum)`.

This question consumed more time than the other four combined, and almost none of that time was spent *finding* the answer — it was spent un-learning a false trail and then beating a string-format trap. Both failures are instructive, so here they are in full.

**The data was found almost immediately, and was correct.** Scanning the modern academy.kaspersky.com course API across locales (`domainType` 0/1/2), exactly one course reaches a five-person panel, and it is **locale-dependent**:

| Locale | Panel |
|---|---|
| Russian (`domainType=1`) | **5 speakers (3M/2F)** — matches the clue |
| English | **8 speakers** — does *not* match 3M/2F |

The Russian-locale panel, exactly as the API returns it:

| # | Speaker (RU) | Latin | Gender |
|---|---|---|---|
| 1 | Иван Лауре | Ivan Laure | M |
| 2 | Максим Королёв | Maxim Korolev | M |
| 3 | Георгий Лавриненко | Georgy Lavrinenko | M |
| 4 | Елена Сивенкова | Elena Sivenkova | F |
| 5 | Ксения Ипполитова | Ksenia Ippolitova | F |

3 male + 2 female = 5. The course is **Кибергигиена** ("Cyberhygiene"). So why didn't we win in five minutes?

**Trap #1 — the string-format trap.** Every natural way of spelling it for the grader was submitted and rejected:

```
Cyberhygiene        Cyber_Hygiene        CyberHygiene        cyber_hygiene
Kibergigiena        Kiberhigiena         Kiberhigiyena
Kaspersky_Cyberhygiene   Kaspersky_Cyber_Hygiene
```

…plus ~200 other candidate course names (live + retired courses, in `A_B_C`, `Title_Case`, `lowercase`, and `Kaspersky_`-prefixed forms). All wrong. The grader keys on the **exact Cyrillic title** the Russian page displays.

**Trap #2 — the over-generalized fingerprint (the expensive one).** Because every English / transliterated spelling failed, the model concluded the modern API's "Cyberhygiene = 5" must be a **locale-dependent decoy**, and that the real answer lived elsewhere. It reached for Q2's lesson — *"instructor data sometimes lives in curriculum PDFs, not the live page"* — and promoted that one-question observation into a law:

> "The real course is some retired old-site `academy.kaspersky.com/courses/<slug>/` whose curriculum cover lists 5 lecturers (3M/2F), and the modern API is a red herring."

That hypothesis was wrong, and chasing it was costly:

- **88 retired old-site slugs** enumerated via the Wayback **CDX** API.
- "Our Experts" sections scraped for ~35 of ~43 old courses — they top out at 1–4 named experts; none cleanly give 3M/2F = 5 on the page.
- Bigger panels were assumed to hide in **curriculum PDFs**, which were network-blocked from our box (`web.archive.org` hard-blocked; PDFs wouldn't load via jina / allorigins / translate.goog). A whole sub-project stood up **public SOCKS5 proxies** (from `TheSpeedX/PROXY-List`) just to reach `web.archive.org` and pull PDFs with `pdftotext`.
- **xtraining.kaspersky.com** expert-training PDFs (LLM, Ghidra, YARA, Suricata…) were downloaded and read — each credits only 1–3 leads.
- A stray 8-name panel (*Youssef, Losyukova, Kotthoff, Shikova, Koval, Gavenko, Burdova, Ivanov*) surfaced and was chased as a possible 5-person sub-listing — another dead end.

All of that was the price of *distrusting the modern API*. The API had been right the entire time.

**The breakthrough.** I made the model go back to first principles: re-query the Russian domain (`domainType=1`) directly and *read the raw `name` field* instead of inventing how to spell it. It returned, unambiguously:

```json
{
  "domain": 1,
  "groupName": "cyberhygiene",
  "name": "Кибергигиена",
  "count": 5,
  "speakers": ["Елена Сивенкова","Иван Лауре","Ксения Ипполитова","Максим Королёв","Георгий Лавриненко"]
}
```

The realization: the grader stores the answer as the **literal title string from the source it used — the Russian-locale page — which is Cyrillic.** The example `(Kaspersky_Next_EDR_Optimum)` only signals "join multi-word titles with underscores"; a single-word Cyrillic title needs neither transliteration nor underscores. The candidate to try was simply the value of the API's `name` field, character-for-character: **`Кибергигиена`**.

### End-to-end script (challenge data → printed flag)

This is the complete replay-and-submit harness, run on the `kaspersky.v1t.site` origin (e.g. via a browser `evaluate` / devtools console so cookies and CORS are satisfied). It mints a fresh token, replays the four confirmed answers to re-reach Q5, then submits Q5 candidates with the native Cyrillic title first. It handles the only real constraint — HTTP 429 — and prints the flag the instant it sees `"Completed."`.

```js
// Run on https://kaspersky.v1t.site (browser console / evaluate harness).
const SLEEP = ms => new Promise(r => setTimeout(r, ms));

// POST helper with retry-on-429 (the only real limiter; the "3-wrong lockout" never fires).
async function post(path, body) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.status === 429) { await SLEEP(400 + attempt * 200); continue; }
    return res.json();
  }
  throw new Error('rate-limited too long: ' + path);
}

// Confirmed Q1–Q4 answers, in order. Replaying these re-mints a fresh Q5 token.
const KNOWN = [
  '10/04/2025',                  // Q1: file ModDate / Last-Modified
  'VictorChebyshev_BorisLarin',  // Q2: leads (Larin only in curriculum doc / Wayback)
  'surveymonkey.com/r/Z8M9C2D',  // Q3: off-domain SurveyMonkey registration link
  'DimmChern',                   // Q4: Foursquare "Been here 50+ times" badge
];

// Q5 candidates — native Cyrillic FIRST; the rest are the failed forms, kept for the record.
const Q5 = [
  'Кибергигиена',                // ← native Cyrillic title (the winner)
  'CyberHygiene', 'cyber_hygiene', 'Kiberhigiena', 'Kiberhigiyena',
  'Kaspersky_Cyberhygiene', 'Kaspersky_Cyber_Hygiene',
];

async function attempt(q5cand) {
  let { token } = await post('/api/start', {});      // fresh session
  for (const ans of KNOWN) {                          // replay Q1–Q4
    const r = await post('/api/answer', { token, answer: ans });
    await SLEEP(250);
    if (r.message !== 'Correct.') {
      return { cand: q5cand, msg: 'replay failed at: ' + ans, raw: r };
    }
    token = r.token;                                  // advance to next question
  }
  const r = await post('/api/answer', { token, answer: q5cand }); // submit Q5
  await SLEEP(250);
  return { cand: q5cand, msg: r.message, flag: r.flag, raw: r };
}

(async () => {
  for (const cand of Q5) {
    const out = await attempt(cand);
    console.log(JSON.stringify({ cand: out.cand, msg: out.msg, flag: out.flag }));
    if (out.msg === 'Completed.' && out.flag) {
      console.log('FLAG =', out.flag);                // <-- printed flag
      return;
    }
  }
  console.log('no candidate completed the quiz');
})();
```

The very first candidate hit:

```json
[ { "cand": "Кибергигиена", "msg": "Completed.", "flag": "v1t{kaspersky_pls_collabbb}" } ]
```

`"Completed."` (not the intermediate `"Correct."`) plus a non-null `flag` is the unambiguous "you're done, 5/5" signal.

## Flag

```
v1t{kaspersky_pls_collabbb}
```

## Lessons learned - prompting the AI

Whenever you face a **multi-question OSINT quiz with a server-side grader** — the kind where each clue is a riddle, every answer is checked against an exact string, and a wrong guess just costs you a request — the LLM is an extraordinary grinder (enumerate 88 Wayback slugs, parse dozens of PDFs, batch-submit 200 strings, reverse a SPA's `fetch` calls) and a reliable failure on exactly two things: it over-generalizes one question's quirk into a "law" for the others, and it infers the answer's *language/encoding* from a *format* hint. The prompts below are written to repeat on the next quiz of this class, not just this one.

**1. Reusable prompts — make the model name the OSINT primitive before it searches.** The single most valuable move on this class is forcing the riddle into the concrete platform/artifact it denotes *before* a single search. These four prompts transfer directly:

> "For each question, before searching, tell me the *OSINT primitive* the wording denotes: is this file metadata, an archived/curriculum doc, a check-in/badge counter, a geolocated venue, a native-locale API field, or a literal search? Pick one and justify it from the exact phrasing."

> "A 'modified date of the FILE' / 'created' / 'uploaded' phrasing is a **metadata** question, not a search question. Fetch the artifact directly and report the HTTP `Last-Modified` header, the PDF `ModDate`/XMP fields (exiftool/pdfinfo), and any 'last modified' UI timestamp — all three — and flag any disagreement."

> "A countable verb in the clue ('visited N+ times', 'checked in', 'reviewed') is a **literal counter on a social platform**, not prose. Indoor venue → Foursquare/Swarm check-in badge; outdoor route → Strava; reviews → Google/Yelp. Identify the venue/object, then read the exact badge text. If the page 302-redirects to login, STOP scraping — it is auth-gated; we log in and read it authenticated."

> "When the live site is a JS SPA and a name/number is missing from the rendered DOM, do not conclude it doesn't exist. Re-check (a) the linked curriculum/program PDF, (b) the underlying JSON/API the SPA calls, and (c) Wayback snapshots of the pre-SPA page — *for this one question*, and report which source had it."

**2. What to focus on, and the classic dead-ends of this class to forbid up front.** Tell the model these before it starts, because they are predictable for *every* quiz of this type:

- **Focus:** "Treat the format hint as literal. `(example.com/abcxyz)` means a **third-party** host with a short path — the answer is probably *off* the obvious org's domain. `(Title_Case_With_Underscores)` describes punctuation, not language. `(DD/MM/YYYY)` means zero-pad and match the order exactly."
- **Dead-end — domain bias:** "Do NOT keep generating paths on the org's own domain when the format hint points to a third party (short links, SurveyMonkey/Typeform, bit.ly). List off-domain hosts first."
- **Dead-end — temporal impossibility:** "Before submitting any event/program answer, do the date arithmetic. If a program/brand didn't exist yet on the clue's date (here: JunctionX started 2018, the repost is Aug 2017), discard it without spending a request."
- **Dead-end — promoting one question's quirk to a law:** "If question N's answer lived in a curriculum PDF / archived page, that is a hypothesis for question N only. For every *other* question, re-test the cheap live source FIRST before committing to a Wayback/proxy/PDF hunt. State 'cheapest disproof' before any infrastructure work."
- **Dead-end — anonymous-scrape tunnel vision:** "A repeated 302→login or 503 means auth-gated, not 'try another proxy/user-agent.' Switch to logging in, not to a new evasion."

**3. How to verify the model's output for this class — catch the two hallucinations it always makes.** Graded-string OSINT has a built-in oracle (the grader), so exploit it and never trust derived text:

- **Build the replay harness first, and read the success string literally.** Prompt: "Reverse the grader endpoints, then write a loop: `POST /start`, replay all confirmed prior answers to re-mint the final token, then batch-submit candidates. Confirm the *exact* success message (here `Completed.`, distinct from the intermediate `Correct.`) and a non-null flag — don't assume any wrong-attempt lockout fires until you've observed it; add a delay and retry only on the rate-limit status you actually see (429)." This converts "I think it's X" into a one-line `Wrong answer` and kills argument.
- **Submit the source's raw field byte-for-byte; never the model's transliteration.** Prompt: "Do not spell or romanize the answer yourself. Print the raw `name`/`title` field from the authoritative source (here `domainType=1` API → `Кибергигиена`) and submit that verbatim, native script and all. Put it first in the batch." The grader keying on Cyrillic is the canonical instance of a general rule: when the source is non-English, the answer is usually in the source's own encoding.
- **Demand the cheapest disproof before any proxy/PDF marathon.** Prompt: "What is the laziest possible way to disprove this hypothesis? Do that before standing up SOCKS5/CDX/PDF tooling." The hours lost here were entirely the cost of skipping this check once.

**Fast-path prompt recipe for this class:** *"For each clue, name the OSINT primitive (metadata / archived doc / check-in badge / geolocated venue / native-locale API) and treat the format hint as literal; script the grader and replay known answers to batch-test candidates cheaply, watching for the exact success string; submit the authoritative source's raw field verbatim in its native script — never your transliteration; and before any proxy/Wayback/PDF hunt, state and run the cheapest live-site disproof first."*
