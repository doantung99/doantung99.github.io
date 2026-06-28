---
title: "Slop Anti or Anti Slop"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: crypto
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, crypto, ai-assisted]
draft: false
summary: "A deliberately misleading crypto challenge where the real target is an AES-GCM ciphertext whose key is reconstructed from a Decimal-polynomial leak, Lagrange interpolation, and 70M rounds of modular squaring."
icon: "☕"
---

## Summary
The challenge ships `challenge.py` + `output.txt` stuffed with RSA/PoW/OTP-flavored decoys, but the only thing that matters is one AES-GCM ciphertext `c`. Its key derives from three secrets — `coffee` (a degree-8 integer polynomial recovered from high-precision Decimal leaks), `cream` (Lagrange interpolation over five points), and `sugar` (`r` put through 70M rounds of modular squaring).

## Solution

I went in assuming the title was the hint: "slop" meant the file was padded with intentionally misleading crypto vocabulary. So my first move was to steer the model away from the noise — I had it triage `challenge.py` and asked it to ignore the RSA/NoHash/PoW/OTP strings and the `main()` printout (`coffee = 11:27:...`, `sugar = a6c4...`), and instead trace what actually encrypts the flag. It landed on `E()`, confirming the ciphertext is `base64(nonce || AESGCM(K).encrypt(nonce, flag, A))` with `A = b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"`. That fixed the goal: recover `coffee`, `cream`, `sugar`, build the key, decrypt.

The model wanted to interpolate `coffee` directly from the five leaked points, which I caught — five points can't pin a degree-8 polynomial in plain algebra. I redirected it: the Decimal leaks carry huge precision and the coefficients are bounded integers, so this is an LLL / hidden-number style approximate reconstruction. With that framing it ground out the nine coefficients. For `cream`, I had it combine the two direct points from `v` with the three extra points produced by `M(coffee, v, m)` (now that `coffee` was known) and feed all five into the provided `I()` Lagrange routine. For `sugar` I made it resist the obvious trap of using `r` as-is — the source defines `R(sugar, z, n)`, plain repeated squaring, so `sugar = R(r, 70_000_000, n)`. I verified by running the final decrypt end to end.

```python
#!/usr/bin/env python3
import base64
import hashlib
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

A = b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"


def H(x):
    return hashlib.sha256(x).digest()


def K(coffee, cream, sugar):
    x = ",".join(map(str, coffee)).encode()
    return hashlib.sha256(
        b"coffee" + H(x) +
        b"cream" + H(str(cream).encode()) +
        b"sugar" + H(str(sugar).encode())
    ).digest()


def R(sugar, z, n):
    for _ in range(z):
        sugar = (sugar * sugar) % n
    return sugar


# Recovered offline: degree-8 polynomial from the Decimal leaks
coffee = [
    -794776879491038202558712248,
     231978547017104987636113337,
    -1236111155741405863929313341,
    -703614985251603931111397881,
    -914058253825396366167362727,
     1012081845277004387528301932,
      28127542803535647396748015,
     338456460421344523263806475,
    -1220995114101159313257217147,
]
# Recovered via Lagrange interpolation I() over 5 points
cream = 384647880619861103603355431

z = open("output.txt", encoding="utf-8").read()
q = lambda k: re.search(rf"^{k} = (.+)$", z, re.M).group(1).strip()

ct = base64.b64decode(q("c"))
nonce, payload = ct[:12], ct[12:]

r = int(q("r"))
rounds = int(q("z"))   # 70000000
n = int(q("n"))

sugar = R(r, rounds, n)  # repeated modular squaring
flag = AESGCM(K(coffee, cream, sugar)).decrypt(nonce, payload, A)
print(flag.decode())
```

## Flag
```
v1t{1_w0nd3r1ng_w1th0ut_41_c4n_y0u_st1ll_s0lv3_1t_4nyw4y_h0p3_y0u_h4v3_fun_w1th_th4t}
```
