# 4.45 MACHINE DAY — THE HIJACK CONFIRMED IN SILICON ON THE CONSUMER CARD

**The date: 2026-09-25 (the same night, after the 4.51 day). 6 boots
(r0 + the r1 sweep), zero Xid GPU. The rollback = proven twice.**

## r0 — THE TRANCHING EXPERIMENT: SUCCESS

The v445 payload (the benign fill + the inert spine 0x100aec, the ctx
zero = INERT, the TT-D class — ZERO memory writes) written into the
signature memdesc by the driver drop-in (the exact anchor: after the
portMemCopy of _kgspCreateSignatureMemdesc). The boot:

```
NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: GSP failed to halt with
      GFW_BOOT: (progress 0xff)
NVRM: GPU0 kgspWaitForGfwBootOk_TU102: failed to wait for GFW boot
      complete: 0x65 (NV_ERR_TIMEOUT)
```

**NO "Booter failed" line — NO 0x1d.** The boot ROM never reported a
verification failure: **THE COPY + THE OVERFLOW RAN BEFORE THE VERIFY**,
the hijacked flow entered the inert spine, and the ROM spun — **the
exact final state the paper (Zenodo 20916112) predicted for a successful
hijack, reproduced in silicon on a consumer GA104.** The founder's
observable: the wallpaper = late (the driver waiting out the GSP boot
timeout). The 4.44-machine 0x1d = the REPLACED memdesc (the verify read
the corrupted signature); THE OVERFLOW = the alive lane.

## r1 — the distance map: the spin is UNIFORM

| fill_len | fill_value | mode |
|---|---|---|
| 64 | 0 | SPIN (GFW_BOOT progress 0xff) |
| 96 | 0 | SPIN |
| 112 | 0 | SPIN |
| 64 | 0x4a7 (the cmpunlocker canary-killer) | SPIN |

The spin = uniform across the fill_len AND the fill_value. The
interpretation: the copy's return address lands in the **0xFF tail
region BEYOND the ctx block** (the word > 145 = 0x488/8 — unreachable by
the chain as the v445 builder lays it out; the ctx = fixed at 0x488).
The corrupted RA = the garbage (the 0xFFFFFFFF...) = the trap loop =
the spin. The canary value = not the variable (the booter = compiled
without the stack-protector per 4.45a — the uniformity argument stands).

## THE NEXT LEVER — the ctx relocation (the offline design work)

The builder v446 = the fully relocatable layout: the ctx block (the
slot0/capacity/dest = the chain's variables) = placeable ANYWHERE in the
4096 B; the chain = extendable across the words 145-511 (the 0xFF region
= where the RA lives). The r2-probe = the CARPET mode: {the spine entry,
the terminal} repeated across the post-ctx region — whatever word = the
RA, the return falls into the carpet (the paper's try-pattern method —
the closed ROM = not derivable by bytes). The pass 4.53 = the control
lane (the builder v446 + the carpet probe + the MMIO O5 scatter chain +
the emulator extension + the runbook-453).

## The arsenal (committed, tools/booter-patch/)

- v445_memdesc_patch.c: the drop-in (the embedded 4 KB payload over the
  signature memdesc after the portMemCopy);
- v445_payload.h: the generated r0 payload (the builder byte-exact);
- patch445.py: the exact-anchor patcher (the include + the call);
- r1point.sh: the sweep-point script (the builder param → the header →
  the dkms --force → the UKI).

## The rollback

Proven twice in the day (~2 commands from ~/dmem-451/ stocks + dkms
--force + limine-mkinitcpio): 0 v445 strings in the stock module, the
firmware sha = c0156954 = untouched.
