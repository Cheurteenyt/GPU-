# 4.56 MACHINE DAY — the trajectory captured: the hijack characterized to the register

**The date: 2026-09-26. The PGC6 probe (the zero-patch live read) + the
carpet boot with the AUTOMATIC trajectory service (36 snapshots x 5 s
over the entire hang window). Zero Xid. The rollback = clean.**

## T0 — the PGC6 probe: the pair is HOST-READABLE

The live-system read of {0x00118128 (the PLM), 0x00118234 (the
GFW_BOOT progress)} — the zero-patch, the PROT_READ mmap (the v454b
pattern): **both registers = readable from the host** (the PLM
0x00008b8f = no lock on these). The stock boot = progress field
0xff = COMPLETED (the sanity: the normal boot = the terminal marker).

## THE TRAJECTORY — 0xff CONSTANT over 180 s (36 snapshots)

The carpet boot (the v446 payload resident in the signature memdesc):
**the progress field = 0xff from the first snapshot to the last, across
the ENTIRE hang window.** The causal chain, measured:

1. **the GFW boot COMPLETES with our payload resident** in the
   signature memdesc — the signature verification = bypassed or neutral
   (the GSP boots normally);
2. **the hang = the falcon handoff phase** — the falcon never halts
   AFTER a successful boot — the spin = post-completion (the paper's
   exact predicted state, now REGISTER-VERIFIED);
3. **the payload = confirmed inert in flight** (the boot = not degraded
   by its presence — the TT-D class validated on the machine).

## THE STRUCTURAL NEGATIVE — closed honestly

The return address of the ROM's copy routine = NOT controllable by the
memdesc content: **6 payload variants (the fills 64/96/112, the canary
0x4a7, the libos spine, the libos carpet, the ROM-gadget carpet) = ALL
the same spin.** The candidates: the ROM frame > 4 KB, or the handoff =
register-context (not stack). This negative = the most expensive of the
campaign — it saves dozens of future boots.

## THE METHOD ARTIFACT (banked)

**nm on a function name = the inline erases it** — the REAL module
check = the data symbol (the payload array) + the od byte pattern.
The false "0"s = the 3rd/4th occurrences of the verification law.

## THE 280 W ROUTES REMAINING

1. **ROUTE W**: the FB/WPR2 read probe (the 4.54 T4 design — the read
   first, always);
2. **the O5 via the 20 power leads** (the dumps = ~/dmem-451/, the
   agent 4.56 = the map);
3. **the falcon-handoff** = the NEW design target (the pass 4.57: what
   is the falcon waiting for, post-completion?).

## The tools

- pgc6_probe.py (tools/edpp/): the PGC6 pair probe (the zero-patch
  live read);
- pgc6-traj.service: the automatic trajectory systemd unit (60 x 5 s,
  the JSON per snapshot) — the machine reads the hijacked booter in
  time, no human in the window.
