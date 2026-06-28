---
title: "Ducks Ping-Pong Revenge"
date: "2026-06-28"
author: "tungdlm99"
ctf: "V1t CTF 2026"
category: rev
difficulty: hard
points: 0
flag_format: "v1t{...}"
tags: [ctf, v1t-ctf-2026, rev, ai-assisted]
draft: false
summary: "A user-mode EXE and a kernel driver play a multi-stage IOCTL ping-pong; recover the driver-validated stage state offline, then run the final transform to decrypt the flag."
icon: "🦆"
---

## Summary
A user-mode binary (`DucksPingPongV2.exe`) talks to a kernel driver (`DucksKDv2.sys`) over a multi-stage IOCTL "ping-pong" protocol — the flag only decrypts after every stage commitment passes. The core technique was reconstructing the driver-validated stage state offline (including two VM-blob-generated answers), then running the final ARX/XOR transform over the encrypted buffer.

## Solution
I clocked the shape immediately: two PE64 files, one console EXE plus one native driver, means the flag is gated behind a client-to-kernel handshake rather than sitting in plaintext. So I set the direction up front — don't try to shortcut the driver, model the protocol.

I fed both binaries to the model and had it triage them first (`file` confirmed `DucksPingPongV2.exe` is x86-64 console, `DucksKDv2.sys` is a native driver), then asked it to pull the strings that reveal the flow: the device path `\\.\DucksKDv2` on the client side and the `stage-commit` keyword on the driver side. That told us the flag path needs both halves.

The model's first instinct was the obvious shortcut — grab the 0x25-byte encrypted blob near the final routine and XOR it with the visible constant. I let it try, it spat out a malformed `v1g...` prefix, and I caught that as the tell: the final buffer is still missing the driver-produced state. I corrected course — reconstruct the stage state first, *then* transform.

From there the model did the grinding: it lifted the per-stage check (a keyed commitment of the form `KDF(0x50 + stage, answer || salt || "stage-commit") == expected_digest`, answers constrained to roughly 8–16 bytes), reproduced the two VM-like stage generators in Python, and validated each answer against the extracted digests offline so we never had to load the test-signed driver. I verified by watching the recovered prefix flip from `v1g` to a clean `v1t{`.

```python
# Offline reconstruction of the driver's stage commitments, then final decrypt.
# Digests/salts/blobs are lifted from DucksKDv2.sys + DucksPingPongV2.exe.

# Two stage answers come from bytecode-like VM blobs embedded in the binaries.
VM_BLOBS = {
    1: bytes.fromhex("d76f83d50038ea79e041ab35"),
    3: bytes.fromhex("eff9982c8954a707e0b9e4841c"),
}

def recover_stage_answer(stage):
    # Stages 1 and 3 decode from VM output; the rest come from the lifted
    # per-stage transform. Returns the 8..16 byte answer for the commitment.
    return run_stage_generator(stage, VM_BLOBS.get(stage))

state = b""
for stage in range(5):
    answer = recover_stage_answer(stage)
    digest = kdf(0x50 + stage, answer + salt[stage] + b"stage-commit")

    assert 8 <= len(answer) <= 16            # length window enforced by driver
    assert digest == expected[stage]          # commitment must match

    state = update_stage_state(state, stage, answer)

# Final IOCTL path returns a success block; combine with state, then run the
# ARX/XOR transform over the 0x25-byte (37-char) encrypted flag buffer.
flag = final_transform(encrypted_flag_blob, state)   # len == 0x25
print(flag.decode())                                  # v1t{...}
```

## Flag
```
v1t{th3_duck_n3v3r_h4nds_y0u_th3_k3y}
```
