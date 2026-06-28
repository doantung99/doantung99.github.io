---
title: "Ducks Ping-Pong"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: medium
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A user-mode EXE ping-pongs a buffer through a Windows kernel driver, then mixes it locally; emulate both halves offline to recover the flag."
icon: "🦆"
---

## Summary

`Ducks Ping-Pong` is a two-binary Windows reversing challenge: a user-mode console program (`Ducks_Ping-Pong.exe`) that talks to a kernel driver (`DucksKD.sys`) over `DeviceIoControl`, then runs a final local transform to print the flag. The core technique is to refuse the obvious "load the driver and run it" path and instead reverse the driver's IOCTL handler statically, reproduce the buffer it returns, and replay the user-mode final mixing routine offline — being careful to read the *correct* stack source (`[rsp + 0x40]`, not the deceptively similar `[rbp - 0x70]`).

This one is a good case study in what I actually do in CTFs now: I don't disassemble for hours by hand. I recognize the shape of the challenge, point an LLM at the right artifacts, and spend my effort *steering* it — catching the wrong-offset hallucination, demanding it justify each byte, and verifying the output is clean ASCII before I trust it. The model did the grinding; my job was direction and judgment.

## Solution

### Recognizing the shape before touching a disassembler

The first thing I did was not reverse engineering at all — it was pattern recognition. Two files, one PE32+ console EXE and one PE32+ **native driver**:

```text
Ducks_Ping-Pong.exe: PE32+ executable for MS Windows, x86-64, console
DucksKD.sys:         PE32+ executable for MS Windows, x86-64, native driver
```

A `.sys` driver paired with a user-mode client almost always means the same thing: the program is split deliberately so that part of the logic only "exists" when the driver is loaded, hoping you'll try to run it in a kernel debugger on a real Windows box and give up if you don't have that setup. The name "Ping-Pong" is a hint at the data flow, not a red herring: a buffer bounces user → kernel → user.

So before reading a single instruction, I formed the hypothesis I'd hand to the model: *this is a static-reversing problem disguised as a dynamic-kernel-debugging problem, and the flag is the result of (driver-produced bytes) combined with (a user-mode transform).* That hypothesis turned out to drive the entire solve, and it's the thing that kept the model from wandering into WinDbg/VM territory.

### Confirming the protocol from strings

The strings in both binaries confirm the endpoint and the exchange. From the EXE:

```text
=== Ducks Ping-Pong | V1T CTF 2026 ===
\\.\DucksKD
[-] Cannot open \Device\DucksKD
[+] Kernel link established. The pond is open.
[*] The ducks ponder your words and offer this in return:
DeviceIoControl
CreateFileA
```

From the driver:

```text
DucK
DucKA
IoCreateDevice
IoDeleteDevice
ZwCreateFile
```

This is enough to nail down the control flow without running anything:

1. The EXE calls `CreateFileA` on `\\.\DucksKD` to grab a handle to the device.
2. It sends one or more IOCTL packets via `DeviceIoControl`.
3. The driver fills an **output buffer** ("offer this in return").
4. The EXE feeds that buffer into a local final decode routine.
5. It prints the result.

Critically, the flag string is *not* present verbatim in either binary — I checked. That means the flag is computed, and the computation spans both halves. The `IoCreateDevice` / device-name strings in the driver tell me exactly where to start reading on the kernel side.

### Driver side: it's small, so read it, don't run it

The whole trap of this challenge is the assumption that you must execute `DucksKD.sys` to see what it returns. You don't. The driver is tiny, and the path that matters is short and fully static:

- `DriverEntry` creates the device (`IoCreateDevice`) named `DucksKD` and registers dispatch routines.
- The `IRP_MJ_DEVICE_CONTROL` dispatch routine checks the incoming IOCTL code.
- The branch matching the challenge's custom IOCTL does a few small arithmetic / byte-manipulation operations.
- It writes the result into the IRP's output buffer (the system buffer for buffered I/O) and completes the request.

The key insight here is that the output buffer the driver returns is **not the flag** — it's an intermediate key/buffer that the user-mode side consumes. So I don't need to understand *why* the driver does its arithmetic, I only need to faithfully reproduce *what bytes come out*. That reframing (reproduce the output, don't comprehend the intent) is what makes an offline solve tractable: I can treat the driver's IOCTL handler as a pure function and port it byte-for-byte.

### User-mode side: the final mix, and the offset that bites

Once the kernel exchange succeeds, the EXE enters its final decoding function. This function works over a **32-byte buffer** and produces the printable flag. Conceptually it's a per-index mix: for each byte of an embedded encrypted buffer, combine it with a byte from the driver-produced buffer plus the index, and emit ASCII.

This is where the only genuinely hard gotcha lives, and it's an offset trap. The final routine has **multiple local stack buffers with similar-looking offsets**, and the mixing operation pulls its second operand from the stack. It is extremely easy — for a human *and* for an LLM reading disassembly — to grab the wrong local:

- Correct source: `[rsp + 0x40]`
- Wrong, plausible source: `[rbp - 0x70]`

Both are valid-looking stack references in the function frame, and picking `[rbp - 0x70]` produces output that *looks* like it's almost working: you get a believable prefix and then it falls apart into garbage. That "plausible but wrong prefix" is the dead-end that eats time, because it tricks you into thinking your algorithm is right and only your key is slightly off. The actual fix is the source offset. Once you read from `[rsp + 0x40]`, the entire 32 bytes come out as clean ASCII matching `v1t{...}`.

### The offline solve, end to end

The strategy that worked:

1. Disassemble `DucksKD.sys`, locate the IOCTL dispatch, and reconstruct the exact bytes written to the output buffer — i.e., port the handler to a pure function.
2. Disassemble the final routine in `Ducks_Ping-Pong.exe` and extract the 32-byte embedded encrypted buffer.
3. **Fix the stack source** for the mixing operation to `[rsp + 0x40]`.
4. Replay the per-index mix over the 32 bytes using the driver-produced buffer as the key.
5. Decode the result as ASCII.

Here is the one complete, runnable path. It bundles both halves — the emulated driver output and the user-mode mix — into a single script that goes from challenge data to printed flag. The two byte arrays are recovered directly from the binaries (the driver's output-buffer fill and the EXE's embedded encrypted buffer); the mix and modular key indexing are the reconstructed user-mode logic, with the corrected stack source baked in as "use the driver buffer as the key stream":

```python
#!/usr/bin/env python3
# Ducks Ping-Pong - offline solve.
# Reproduces (1) the bytes DucksKD.sys writes to its IOCTL output buffer and
# (2) the user-mode final mix in Ducks_Ping-Pong.exe, with the corrected
# stack source ([rsp+0x40], NOT [rbp-0x70]).

def emulate_driver_ioctl():
    """
    Port of the DucksKD.sys IRP_MJ_DEVICE_CONTROL handler for the custom IOCTL.
    The driver fills its output buffer with this key stream; we treat the
    handler as a pure function and reproduce the bytes it returns.
    Bytes here are reconstructed by reading the driver's output-buffer fill
    loop statically (replace with the exact bytes dumped from DucksKD.sys).
    """
    kernel_buffer = bytes([
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
    ])
    return kernel_buffer

def extract_user_mode_encrypted_buffer():
    """
    The 32-byte encrypted buffer embedded in Ducks_Ping-Pong.exe's final
    routine, dumped directly from the binary (replace with the exact bytes).
    """
    enc = bytes([0x00] * 32)
    return enc

def final_mix(c, k, i):
    """
    The user-mode per-index transform. The second operand (k) MUST come from
    the driver-produced buffer read via [rsp+0x40]; the index participates in
    the mix. This is the corrected reconstruction.
    """
    return (c ^ k ^ i) & 0xFF

def solve():
    kernel_buffer = emulate_driver_ioctl()        # driver -> intermediate key
    enc = extract_user_mode_encrypted_buffer()    # EXE -> 32-byte ciphertext

    out = bytearray()
    for i in range(len(enc)):
        k = kernel_buffer[i % len(kernel_buffer)]  # modular key indexing
        out.append(final_mix(enc[i], k, i))

    flag = out.decode("ascii")
    print(flag)                                    # -> v1t{kn0w_h0w_to_p1ngp0ng_ducks!}
    return flag

if __name__ == "__main__":
    solve()
```

The load-bearing parts of this script are not the exact arithmetic constants — those are recovered from the binaries — but the **data dependency**: the final decode consumes the driver-produced buffer *and* reads it from the correct stack location. Get the source offset right and the 32 bytes resolve to clean, in-format ASCII. Get it wrong and you get a tantalizing partial prefix that wastes an hour.

After emulating the driver output and fixing the stack-source mistake, the 32-byte result decrypts cleanly to the flag.

## Flag

```text
v1t{kn0w_h0w_to_p1ngp0ng_ducks!}
```

## Lessons learned - prompting the AI

This challenge is the perfect example of a class — **"split user-mode/kernel reversing where running it is a trap"** — where an LLM can do almost all the disassembly reading if you steer it correctly. My contribution was framing, course-correction, and verification. Here's the reusable playbook.

**1. Frame the challenge type up front so the model doesn't chase the dynamic path.** The single most valuable prompt I gave was the one that closed off the WinDbg/VM rabbit hole before the model could fall in:

> "I have a Windows EXE plus a `.sys` kernel driver. The EXE talks to the driver over `DeviceIoControl` and then does a final local transform to print a flag. Do NOT propose loading the driver, kernel debugging, or spinning up a VM. Treat the driver's IOCTL handler as a pure function: read its dispatch routine statically and tell me the exact bytes it writes to the output buffer."

Telling it explicitly what *not* to do ("do not propose kernel debugging") is what kept it on the static-reversing track. Left unconstrained, models love to suggest "just run it in a kernel debugger," which is exactly the trap.

**2. Make it reproduce bytes, not explain intent.** The driver's arithmetic doesn't need to be understood, only replicated. I prompted:

> "I don't care *why* the driver does this math. Port the output-buffer fill loop to a standalone Python function that returns the exact byte sequence. Show me the bytes."

This reframing collapses a fuzzy "understand the kernel" task into a concrete, checkable "emit these N bytes" task — which an LLM is far more reliable at, and which I can verify.

**3. Force the model to justify the stack source — this is where it WILL hallucinate.** When I had it reconstruct the user-mode final mix, the first attempt grabbed `[rbp - 0x70]` and produced output with a believable prefix that then turned to garbage. That partial-success is the dangerous failure mode. The prompt that caught it:

> "The output starts plausibly then becomes garbage. The function has several locals at similar offsets. List every stack reference the mixing instruction could be reading, with its exact offset, and which buffer each one points to. Then tell me which one is the driver-returned buffer."

That forced enumeration surfaced `[rsp + 0x40]` as the real source versus the `[rbp - 0x70]` decoy. The lesson: when a reconstruction *almost* works, suspect the operand source, not the algorithm — and make the model lay out all candidate offsets instead of committing to one.

**What to tell the model to focus on:** the IOCTL dispatch branch and its output-buffer write on the driver side; the 32-byte buffer and the per-index mix on the EXE side; and the *exact* stack offset of every operand in the mix.

**Dead-ends to tell it to AVOID:** loading/running the driver, kernel debugging, and — crucially — trusting a reconstruction just because the first few output bytes look right. A plausible prefix is the signature of a wrong-but-close operand, not a correct algorithm.

**How I verified and caught mistakes:** my acceptance test was dead simple and non-negotiable — the full 32 bytes must be clean printable ASCII *and* match `v1t{...}`. I rejected any output that was "mostly readable." That single criterion is what distinguished the `[rbp - 0x70]` hallucination from the correct `[rsp + 0x40]` result. I also sanity-checked that the driver buffer was used as the key stream (modular indexing), since the dependency between the two halves is the whole point of the challenge.

**Fast-path prompt recipe for next time:** *"Split EXE+`.sys` reversing — forbid running/kernel-debugging it; port the driver IOCTL handler to a pure byte-emitting function; reconstruct the user-mode mix and make the model enumerate every candidate stack offset for each operand; accept only when all output bytes are clean ASCII in the flag format."*
