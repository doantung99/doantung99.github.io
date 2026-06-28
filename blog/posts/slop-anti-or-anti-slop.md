---
title: "Slop Anti or Anti Slop"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: crypto
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, crypto, ai-assisted]
draft: false
summary: "A deliberately noisy crypto challenge where the printed values are decoys; the real AES-GCM key is rebuilt from a Decimal polynomial, a modular affine map plus Lagrange interpolation, and a 70-million-round repeated-squaring chain."
icon: "🍵"
---

## Summary

`challenge.py` is a wall of crypto-flavored noise — RSA, "NoHash", PoW and OTP all name-dropped in the associated data — but the flag is just an AES-GCM ciphertext `c` sitting in `output.txt`. The whole game is reconstructing the three secret ingredients the key is derived from: `coffee` (a degree-8 integer polynomial leaked through five high-precision `Decimal` evaluations), `cream` (recovered via a modular affine map plus Lagrange interpolation over a small prime field), and `sugar` (the result of 70,000,000 modular squarings of `r`). Get all three and the key falls out of one SHA-256.

I solved this as a steering exercise: I recognized the obfuscation pattern, told an LLM exactly which functions were real and which were slop, and let it grind the polynomial recovery and the squaring loop while I checked its math at each junction.

## Solution

### Step 0: separating signal from slop

The title — "Slop Anti or Anti Slop" — is the hint, and it's honest. `challenge.py` is written to waste your time. Running it prints two lines:

```text
coffee = 11:27:5:113:89
sugar = a6c474d9e2014567397094be60a5ea64
```

Both are decoys. The printed `coffee` is a colon-joined list of small ints; the printed `sugar` is a hex digest. Neither feeds the AES key. They exist purely so that a solver who pattern-matches on `print()` statements wastes an afternoon on the wrong values.

The first real job is to ignore `main()` entirely and read the encryption routine bottom-up. The function that actually touches the flag is `E()`:

```python
def K(coffee, cream, sugar):
    x = ",".join(map(str, coffee)).encode()
    return hashlib.sha256(
        b"coffee" + H(x)
        + b"cream" + H(str(cream).encode())
        + b"sugar" + H(str(sugar).encode())
    ).digest()

def E(f, coffee, cream, sugar):
    x = ",".join(map(str, coffee)).encode()
    y = hashlib.sha256(b"drip" + H(x) + b"cream" + H(str(cream).encode())).digest()[:12]
    return base64.b64encode(y + AESGCM(K(coffee, cream, sugar)).encrypt(y, f, A)).decode()
```

This tells you the exact shape of the target. The base64 blob `c` decodes to:

```text
c = base64( nonce(12) || AESGCM_ciphertext_with_tag )
```

and both the **key** and the **nonce** are pure functions of `coffee`, `cream`, `sugar`:

```text
key   = SHA256( "coffee" || H(coffee_csv) || "cream" || H(str(cream)) || "sugar" || H(str(sugar)) )
nonce = SHA256( "drip"   || H(coffee_csv) || "cream" || H(str(cream)) )[:12]
ad    = b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"
```

The crucial realization, and what makes the whole thing tractable, is that **the nonce is prepended to the ciphertext**. So we don't have to recompute the nonce from `coffee`/`cream` to decrypt — we just slice the first 12 bytes off the decoded blob. That removes one entire dependency from the critical path; we only strictly need the *key*, which means we only need the *exact string forms* of `coffee`, `cream`, and `sugar` (they go into SHA-256 as text), nothing more.

Why does the string form matter so much? Because `H(",".join(map(str, coffee)))` hashes the **decimal representation** of each coefficient, including the leading minus sign. A coefficient that's off by one, or recovered with the wrong sign, produces a totally different SHA-256 and AES-GCM fails its tag check loudly. There is zero tolerance: the polynomial recovery has to be bit-exact. That property is also a gift — GCM's authentication tag is a free oracle telling you the instant any of the three ingredients is wrong.

So the three sub-problems are independent reconstructions, and AES-GCM's tag is the single pass/fail at the end.

### Step 1: recovering `coffee` from Decimal leaks

`coffee` is the coefficient list of a polynomial evaluated by `P()`:

```python
def P(x, coffee):
    s = Decimal(0)
    t = Decimal(1)
    for v in coffee:
        s += Decimal(v) * t
        t *= x
    return s
```

`output.txt` gives `d = 8` (degree) and `l = 5` (number of leaked points), plus five `(x, y)` pairs `o0..o4` printed at very high `Decimal` precision. Degree 8 means **9** unknown integer coefficients.

Here is the trap, and the dead-end I explicitly steered the model away from: five points cannot interpolate a degree-8 polynomial. In ordinary algebra you'd need 9 points and the system is hopelessly underdetermined. A naive solver (human or LLM) reaches for Lagrange, finds it impossible, and gives up or guesses.

The insight is that the leaks are not exact algebraic samples — they're **high-precision Decimal values**, and the coefficients are **bounded integers**. That converts an underdetermined algebra problem into a *lattice* problem: you're looking for small integer coefficients consistent with the truncated decimal evaluations, exactly the hidden-number / `Decimal`-polynomial pattern that LLL handles well. Each leaked `(x, y)` gives a linear relation `sum(coeff_i * x^i) ≈ y` where the approximation error is bounded by the truncation, so you build a lattice whose short vectors encode the true integer coefficients and reduce it. With enough fractional precision per point, five relations over nine unknowns is plenty because the integers are small relative to the precision.

The reconstructed coefficients (this is the load-bearing artifact — the exact integers and signs are what get hashed):

```python
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
```

The full proof that this is right doesn't come until the end (the GCM tag), but there's a cheap intermediate check: plug these integers back into `P(x, coffee)` for each leaked `x` and confirm the result rounds to the leaked `y` at full precision. I had the model do exactly that before trusting the vector — see Lessons.

### Step 2: recovering `cream` via the affine map + Lagrange

`cream` is hidden behind two layers. First, the `v` array from `output.txt`:

```text
v = 11,196063417363387642597346826,27,120384749444008048520026890,44,58,73,6,1,7,
    482948303402462271535984297,6508987245398838175194216,
    96179654543215792434642574,271196288682360083095841201
```

The first four entries are two ready-made points on the `cream` polynomial: `(v[0], v[1])` and `(v[2], v[3])`. Two points aren't enough on their own — we need more, and that's what `M()` produces:

```python
def M(coffee, v, m):
    a   = v[10]
    xs  = v[4:7]
    ids = v[7:10]
    bs  = v[11:14]
    return [(x, (a * coffee[i] + y) % m) for x, i, y in zip(xs, ids, bs)]
```

This is the elegant bit: `M()` doesn't hand you points directly, it hands you points **scrambled through the already-recovered `coffee`**. Each new `y`-value is `(a * coffee[ids[k]] + bs[k]) mod m`, an affine function of a specific `coffee` coefficient selected by `ids`. That's why Step 1 must finish first — `M()` is literally a consumer of the polynomial you just reconstructed. The dependency runs `coffee -> cream`, not the other way around.

The chosen indices `ids = [6, 1, 7]` pull `coffee[6]`, `coffee[1]`, `coffee[7]`, multiply each by `a = v[10]`, add the corresponding `bs` value, reduce mod `m` (the small prime in `output.txt`), and emit three fresh points at abscissae `xs = [44, 58, 73]`. Combine those three with the two direct points and you have five points on the `cream` polynomial over GF(m), which is exactly enough for the provided Lagrange routine `I()`:

```python
points = [(v[0], v[1]), (v[2], v[3])] + M(coffee, v, m)
cream  = I(points, m)
```

Recovered:

```python
cream = 384647880619861103603355431
```

The gotcha here is index discipline. It is very easy to mis-slice `v` — an off-by-one on `xs`, `ids`, or `bs`, or feeding the wrong `coffee` index — and Lagrange will happily return *a* number that is simply wrong. There's no local check on `cream` either; it also only proves out at the final GCM tag. So the safe move is to transcribe `M()` verbatim from the source rather than paraphrasing the slices — precisely the kind of mechanical fidelity an LLM is good at, if you tell it not to "clean up" the indexing. Note the deliberate word-collision with Step 1: the same word "Lagrange" is *wrong* there and *right* here.

### Step 3: recovering `sugar` via 70 million modular squarings

`sugar` is the last decoy trap. The instinct is to read `r` from `output.txt` and use it directly. Wrong. The source defines:

```python
def R(sugar, z, n):
    for _ in range(z):
        sugar = (sugar * sugar) % n
    return sugar
```

and `output.txt` supplies the real inputs:

```text
r = 3448266514036296117494138663621749045542248311040284894137711815584606161278...
z = 70000000
n = 30846394261521820240880213655817161620137997327411663830906890383159321837336...
```

So `sugar = R(r, z, n)` — seventy million sequential modular squarings of a ~512-bit number mod a ~3072-bit `n`. This is a *time-lock-puzzle*-style construction (repeated squaring with no known factorization shortcut). Each step depends on the previous one, so it cannot be parallelized; you genuinely have to crank the loop.

There is no clever shortcut here unless you know `phi(n)` — which we don't, because `n` isn't factored. If you knew the factorization you could reduce the exponent `2^z mod phi(n)` and do a single `pow`. We don't, so we square 70M times. In pure CPython that's a few minutes; the integers are big but each squaring is a single Python-level multiply-and-mod, and 70M of them is bounded. The thing to NOT do is try to be clever (it's the time-lock; there's no fast path), and the thing to watch is letting the loop actually finish — a partial run gives a wrong `sugar` and, again, the GCM tag will reject it.

This is the part where the human's only job is patience and the model's only job is writing a tight loop. I told it to keep the loop trivial — `sugar = sugar * sugar % n`, no per-iteration allocations, no logging inside the loop — and just let it run.

### Step 4: assemble the key and decrypt

With all three ingredients in their exact forms, the key is one SHA-256, the nonce is sliced from the blob, and AES-GCM verifies-and-decrypts in one call. The complete, runnable end-to-end script (challenge data to printed flag):

```python
#!/usr/bin/env python3
import base64
import hashlib
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Associated data is fixed in challenge.py (and is itself part of the slop theme).
A = b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"


def H(x):
    return hashlib.sha256(x).digest()


def K(coffee, cream, sugar):
    # Key = SHA256 over the *string* forms of the three ingredients.
    x = ",".join(map(str, coffee)).encode()
    return hashlib.sha256(
        b"coffee" + H(x) +
        b"cream" + H(str(cream).encode()) +
        b"sugar" + H(str(sugar).encode())
    ).digest()


def R(sugar, z, n):
    # Time-lock: z sequential modular squarings. No shortcut without phi(n).
    for _ in range(z):
        sugar = (sugar * sugar) % n
    return sugar


# --- Step 1 output: degree-8 integer polynomial recovered from Decimal leaks (LLL).
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

# --- Step 2 output: recovered from M() affine points + Lagrange interpolation.
cream = 384647880619861103603355431

# --- Read everything else straight out of output.txt.
z = open("output.txt", encoding="utf-8").read()
q = lambda k: re.search(rf"^{k} = (.+)$", z, re.M).group(1).strip()

blob = base64.b64decode(q("c"))
nonce, payload = blob[:12], blob[12:]   # nonce is prepended -> no need to recompute it

r = int(q("r"))
rounds = int(q("z"))   # 70_000_000
n = int(q("n"))

# --- Step 3: grind the time-lock.
sugar = R(r, rounds, n)

# --- Step 4: derive key, then GCM verify+decrypt (tag check is our correctness oracle).
flag = AESGCM(K(coffee, cream, sugar)).decrypt(nonce, payload, A)
print(flag.decode())
```

The moment this prints without throwing `InvalidTag`, every one of the three reconstructions is simultaneously confirmed correct — the polynomial, the interpolation, and all 70M squarings.

## Flag

```text
v1t{1_w0nd3r1ng_w1th0ut_41_c4n_y0u_st1ll_s0lv3_1t_4nyw4y_h0p3_y0u_h4v3_fun_w1th_th4t}
```

The flag is its own punchline: "I wondering without AI can you still solve it anyway, hope you have fun with that." Cute, given how I solved it.

## Lessons learned - prompting the AI

**This class: obfuscated-source crypto where the printed values are decoys and the real key is derived from a few hidden sub-secrets.** Whenever you face an "anti-AI" / slop crypto challenge — one short Python (or Sage) file, a pile of genuine-looking helper functions, a `main()` that prints red-herring values, and a single ciphertext you actually have to decrypt — the work is *not* arithmetic, it's triage. Your job is to tell the model which functions are load-bearing, name the right technique for each sub-secret, pre-empt the genre's standard dead-ends, and use the AEAD tag as a correctness oracle. The prompts below are written to transfer to the *next* challenge of this shape, not just this one. This instance happened to factor into "underdetermined Decimal-polynomial (LLL)" + "affine-scrambled points then Lagrange over GF(p)" + "repeated-squaring time-lock," and I'll use those as the concrete examples — but swap in whatever sub-primitives the next file uses.

### 1. Force a backwards trace + real-vs-decoy classification before any solving

The single highest-leverage move for this class is to make the model map the file before it touches math. Decoys live in `main()`/`print()`; the truth lives in whatever function feeds the cipher. Copy-paste:

> "Here is challenge.py and output.txt. Do NOT solve anything yet. Find the function that produces the ciphertext / calls AESGCM/encrypt/seal. Starting from that call, trace **backwards**: list every function whose output flows into the key, nonce, or AAD, and every value that is *only* printed in main() and never reaches the cipher. Output a two-column table: REAL (reaches the key) vs DECOY (printed only). Tell me exactly which string/byte forms get hashed into the key, because formatting matters."

That last sentence matters for the whole class: keys in these challenges are almost always `SHA256(str(secret))`, so a sign or an off-by-one changes everything. The classification pass is what surfaced here that `main()`'s printed `coffee`/`sugar` are bait and that `K()`/`E()` are the only targets — and the same pass works on any file in this genre.

### 2. Name the technique per sub-secret — and warn that the same word can be right in one step and wrong in another

The model's default failure in this class is reaching for the obvious tool. For an under-determined polynomial it tries exact Lagrange, finds it "impossible," and stalls. Steer it explicitly, and tell it where the *correct* use of that same tool is:

> "There are N independent secrets feeding the key; solve each with the right tool, and don't assume one tool fits all. If a secret is a small-bounded-integer polynomial leaked through high-precision Decimal/float evaluations with FEWER points than coefficients, that is NOT exact interpolation — set it up as an LLL/lattice (hidden-number) reconstruction of the integer coefficients. If a secret has a FULL set of exact points over a prime field, that IS classic Lagrange interpolation mod p. If a secret is `x` squared a huge fixed number of times mod n, that is a time-lock — run the loop as written. State which technique you're using for which secret before coding."

The deliberate trap in this genre is word-collision: "Lagrange" is the *wrong* answer for the leaked-polynomial step and the *right* answer for the recovered-points step. Tell the model which step gets which tool; don't name a technique once and let it generalize.

### 3. List the genre's classic dead-ends up front, by name

These traps recur across nearly every challenge of this class, so seed them in the prompt instead of letting the model rediscover them on the clock:

> "Avoid these known traps: (a) do NOT use any value that only appears in a print() in main() — they are decoys; (b) do NOT feed a raw seed straight into the key if a transform function exists — apply the transform (e.g. run R(seed, z, n), don't use the seed directly); (c) for repeated-squaring `2^z mod n`, do NOT try to factor n or reduce the exponent via phi(n) — assume n is unfactorable and it's an intentional time-lock, just iterate; (d) when reconstructing integer coefficients, track the SIGN — a wrong sign hashes to a different key even though the magnitude looks right."

Each of (a)–(d) is exactly where an unsupervised model burns an hour on this kind of challenge.

### 4. Reuse the challenge's own helpers verbatim — forbid "tidying"

When a secret is recovered by an in-file function with fiddly slicing/index selection (here `M()` with `v[4:7]`, `v[7:10]`, `v[11:14]` and `ids` indexing into the previously-recovered list), the model's instinct to "clean up" the indices silently corrupts the result, and there's usually no local check. Demand fidelity:

> "Do not rewrite or simplify the challenge's helper functions. Copy M()/I()/R() (or their equivalents) **character-for-character**, including the exact slice bounds and index variables, then call them with the inputs the source uses. If a recovered secret feeds a later function, pass it in exactly as the source does — same indices, same order. No paraphrasing of index arithmetic."

This generalizes to the whole class: any time one sub-secret is consumed by another step (the `coffee -> cream` dependency here), preserve the source's wiring rather than re-deriving it.

### 5. Verify cheaply before paying for the expensive step — and let the AEAD tag be the final judge

This class hands you a free correctness oracle: the ciphertext is almost always AES-GCM (or another AEAD), so `decrypt()` either returns plaintext or throws `InvalidTag` — a binary verdict on *all* sub-secrets at once. But you don't want to discover a sign error only after a multi-minute time-lock run, so verify the cheap reconstructions first:

> "Before running the expensive time-lock loop, validate the cheap secrets locally: re-evaluate the recovered polynomial P(x, coeffs) at every leaked x and confirm it rounds to the leaked y; confirm every field-element secret is in range [0, m); re-derive, don't guess, if anything is off. Only after those pass, run the time-lock once and call decrypt(). Treat an InvalidTag as proof that an upstream secret is wrong — re-derive it, never brute-force around the tag."

**How to catch the model's hallucinations in this class:** (1) make it show the lattice/interpolation *check* (re-evaluate at the leaked points; mod-range check on field elements) rather than just asserting numbers — recovered constants are the most common silent fabrication; (2) confirm it actually iterated the full squaring count `z` and didn't substitute a `pow`-based "optimization" that assumes a factorization it doesn't have; (3) require it to print intermediate hashes/lengths (e.g. the 12-byte nonce slice) so a formatting mismatch surfaces before the tag does; (4) the final guard is the AEAD tag — if it claims success, the decrypt either ran clean or it's lying, so make it paste the real plaintext.

**Fast-path prompt recipe for this class:** *"Obfuscated 'anti-AI' crypto source — first trace BACKWARDS from the AEAD/encrypt call and label every function REAL-vs-DECOY, ignoring anything only printed in main(); for each hidden secret name the right tool explicitly (LLL for under-determined Decimal/float-polynomial leaks, Lagrange mod p for full point sets, iterate-as-written for repeated-squaring time-locks), watch signs and exact string forms since the key is SHA256(str(secret)); copy the challenge's own helpers verbatim with original slices; verify the cheap reconstructions locally before running the time-lock, then let the AES-GCM tag be the single yes/no."*
