# 4.44-machine — the TL444 inert boot: the memdesc lane FALSIFIED in vivo
# (booter error 0x1d), the full rollback ritual proven

Date: 2026-09-24, ~02h. Author: the machine-side session (Cheurteen +
ZCode). Zero payload reached the GSP (dest=0 = INERT, the TT-D guard) —
the failure = the memdesc replacement itself.

## The experiment

The 4.44 payload (byte-exact vs v444_transfer_list_build.py, sha
85d77114 — verified by compiling a userland twin of the exact kernel
function and diffing) was written over the signature memdesc in
_kgspCreateSignatureMemdesc (the drop-in between the portMemCopy and
the memdescUnmapInternal, kernel_gsp.c). dest=0 → the TT-D guard = the
transfer loop INERT — no writes anywhere. The boot = the pure pipeline
proof: does the booter accept a patched signature memdesc?

## The verdict

    NVRM: GPU0 s_executeBooterUcode_TU102: Booter failed with non-zero error code: 0x1d
    NVRM: GPU0 kgspExecuteBooterLoad_TU102: failed to execute Booter Load: 0xffff
    NVRM: GPU0 _kgspBootGspRm: unexpected WPR2 already up, cannot proceed with booting GSP
    NVRM: GPU0 RmInitAdapter: Cannot initialize GSP firmware RM

**0x1d (≠ the 0xb of the rm.elf-patch rejection). The booter failed
DURING the Booter Load, on the memdesc itself.**

## The falsification

**The signature memdesc = the booter's VERIFICATION INPUT, not a free
config buffer.** The 4.42-4.44 design assumed the memdesc carries the
transfer-list config the booter's logger consumes; the emulator proved
the loop MECHANICS (11/11+9/9 — the loop is real code) but the SURFACE
SEMANTICS = wrong: the booter reads the memdesc as the signature of the
GSP-RM binary (or parses its structure strictly) — 0xFF+our payload =
the verify/parse fails → 0x1d → the WPR2 bad state. The memdesc lane =
DEAD as designed.

## What survives

- The transfer-list loop = REAL (the emulator proof stands); the
  logger = the booter's own stage logger.
- The {value, target} tables + the formula + the f18/base routes =
  all stand (4.43/4.44 static work untouched).
- The remaining lanes:
  1. **The ROP runtime (the phase III, the paper's canary defeat —
     PROVEN in silicium on THIS card, the spin 0x4a7)**: the booter
     DMAs the memdesc ONTO ITS OWN STACK (the unbounded DMA) → our
     payload = the overflow → the canary defeated by uniformity → the
     ROP chain (the 4.40 gadget inventory: 84 rets, 24 chainable, the
     write primitive 0x100b3e/0x100b48) → the booter control → the
     runtime write. **The memdesc = the VEHICLE via the OVERFLOW, not
     via the replacement.** The verify never runs — the ROP owns the
     booter first.
  2. The driver-side patch of the RM image in RAM (the 4.38 Lane V/H)
     — to re-examine with this lesson: any surface the booter
     VERIFIES = dead; any surface the GSP consumes AFTER the verify =
     alive.

## The tooling lessons (banked by the failed boot)

1. **The mkinitcpio `kms` hook embeds nvidia.ko into the initramfs
   INSIDE the UKI** — after ANY module change the ritual = dkms
   build/install **+ limine-mkinitcpio** (the UKI rebuild + the
   limine.conf refresh). Skipping it = the boot loads the OLD module
   (the 01h44 boot = the July UKI = the patch never loaded, the silent
   false negative).
2. **/proc/cmdline = the effective cmdline truth** — the UKI freezes
   the cmdline at build time; /etc/kernel/cmdline = the NEXT build.
3. The nv_printf RM prints (kernel_gsp.c) = reach dmesg (the v10
   proof) — a missing print = check the loaded module FIRST (the
   build-id, the strings in the .ko), then the gating.
4. The patch anchor = the EXACT source text — a replace that eats a
   parameter list = the build = the judge.
5. The full rollback cycle = ~10 minutes and PROVEN: cp the .stock +
   dkms build/install + limine-mkinitcpio → the machine healthy
   (250 W, zero Xid, zero booter failures at 02h10).

Machine state: healthy, stock, 250 W. The cmdline = cleaned (the
RpcDump param removed — /etc/kernel/cmdline.bak-444 = the backup).
