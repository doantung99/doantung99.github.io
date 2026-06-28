---
title: "Ducks Ping-Pong"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A user-mode EXE that ping-pongs IOCTLs with a kernel driver; recover the driver's response buffer and apply the user-mode final transform offline to print the flag."
icon: "🦆"
---

## Summary
Two binaries shipped together: `Ducks_Ping-Pong.exe` and a kernel driver `DucksKD.sys`. The EXE opens `\\.\DucksKD`, exchanges data via `DeviceIoControl`, and feeds the driver's response into a local 32-byte decoding routine to print the flag. The solve is to reconstruct the driver's output buffer and the user-mode transform statically, then run them offline.

## Solution
The moment I saw a `.exe` paired with a `.sys`, I called the shape: a user-mode/kernel "ping-pong" where the flag is split across the IOCTL boundary. My job here was steering an LLM through the reversing and catching the one place it would predictably trip.

First I had the model triage both PEs. It confirmed `Ducks_Ping-Pong.exe` is an x86-64 console app and `DucksKD.sys` is a native driver, and pulled the strings that nail down the protocol: `\\.\DucksKD`, `CreateFileA`, `DeviceIoControl`, `[+] Kernel link established. The pond is open.`. I told it not to chase the driver as a black box — it's small enough to read statically — and to map the IOCTL path from `DriverEntry` through the dispatch routine to the branch that fills the output buffer. That output is *not* the flag; it's an intermediate buffer the EXE consumes.

Then I pointed the model at the EXE's final decoding function. This is where it first went wrong: the routine has several local buffers at similar offsets, and the model grabbed `[rbp - 0x70]` as the XOR/mixing source. That produced a plausible-but-garbage prefix. I recognized the failure mode, told it the stack source had to be reconsidered, and verified the corrected pick — `[rsp + 0x40]` — gave clean ASCII. With the right source isolated, I had it emulate the driver's IOCTL output and replay the transform over the 32-byte encrypted buffer offline.

```python
# Offline solve: reproduce the driver IOCTL output + the EXE's final transform.
# kernel_buffer  = bytes the DucksKD IOCTL handler writes to its output buffer
# enc            = the 32-byte encrypted buffer baked into Ducks_Ping-Pong.exe
# final_mix      = the per-index XOR/arithmetic from the EXE's final routine,
#                  using the CORRECT stack source [rsp + 0x40] (not [rbp - 0x70])

kernel_buffer = emulate_driver_ioctl()        # reconstructed from DucksKD.sys
enc           = extract_user_mode_encrypted_buffer()  # 32 bytes from the EXE

def final_mix(c, k, i):
    return (c ^ k ^ i) & 0xFF                  # transform recovered from the EXE

out = bytearray()
for i in range(len(enc)):
    k = kernel_buffer[i % len(kernel_buffer)]
    out.append(final_mix(enc[i], k, i))

print(out.decode())                            # -> v1t{kn0w_h0w_to_p1ngp0ng_ducks!}
```

The load-bearing insight is the data dependency, not the exact arithmetic: the final decode needs the driver-produced buffer *and* the correct user-mode stack source. Get the `[rsp + 0x40]` source right and the 32 bytes resolve to clean ASCII.

## Flag
```
v1t{kn0w_h0w_to_p1ngp0ng_ducks!}
```
