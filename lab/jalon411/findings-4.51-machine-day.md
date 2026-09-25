# 4.51 MACHINE DAY — the DMEM verdict day, executed (4 boots, zero Xid GPU)

**The date: 2026-09-25 (night). The founder executed all 4 boots. The
machine rolled back clean (0 NVRM-451 strings in the stock module, the
firmware sha = c0156954 = the .stock, untouched all day).**

## The instrument: PROVEN IN FLIGHT (the two-sided design)

The v1 monolith FAILED the DKMS build at the pre-flight — **the RM TU
(kernel_gsp.c) = OS-abstracted: NO linux headers** (linux/workqueue.h
unresolvable). The v2 = the two-sided instrument:
- the RM side (gsp_dmem_dump.c, included by kernel_gsp.c): the read-only
  capture of the S1-S8 surfaces (osReadRegistryDword gate, the
  pointer/size copies, the sysmem-heap phys capture) into the non-static
  state struct;
- the nv.c side (kernel-open, patch_nv_451.py, the v9-scanner anchor
  pattern): the delayed work (8 s) publishes the blobs via
  debugfs_create_blob + the dmesg printk ledger.

12-13 surfaces published per boot, 4 boots end-to-end, the module
verified at nm (the gc-sections law: the unreferenced globals = stripped
— the late capture = passed by the FUNCTION POINTER in the shared state,
the modpost caught the first attempt).

## VERDICT 1 — THE LIBOS SYSMEM HEAP DOES NOT EXIST ON THIS CONFIG

`args.bin` (= GSP_ARGUMENTS_CACHED, the layout from gsp_init_args.h)
decoded: **sysmemHeapArgs = {pa: 0, size: 0}**. The layout = confirmed
exact by the rmStateMonitorBufferArgs pair {0xC7FE0000, 4096} matching
the published statemonitor.bin (4096 B). The GSP desktop lives in its
FB/WPR2 heap. **S5 = the named negative for this card — ROUTE H
(the host-writable heap poke) = CLOSED.** (The heap = alive on the other
configs — the v452 tooling = the shelf.)

## VERDICT 2 — the timing records are NOT in any host-reachable surface

The v451a scan on the boot-B blobs (args, libosinit, statemonitor,
wpr2meta, logs0-7): the SPECIFIC patterns (raw76 verbatim, the (rc,rfc)
pairs, the 4.48 vectors) = MISS everywhere. The raw_any65_table_shadow =
the generic noise (hit every blob). The remaining homes: **the FB/WPR2
heap (ROUTE W — the next instrument: the read probe) or the falcon-
internal DMEM (the named negative, unreachable while running)**. The
statemonitor = present WITHOUT its key (4 KB — a summary export).

## VERDICT 3 (TÂCHE C) — the ways knob = NO-EFFECT

pillarB-sysmem x2 per state (the 4.47 doctrine):
- ways=0 (boot C): warm 23.0/22.2, cold 24.0/22.9 → ratio 0.96/0.97
- default=7 (boot D): warm 20.4/20.7, cold 21.3/21.8 → ratio 0.96/0.95

The sysmem reads = NEVER L2-served in either state (the coherent with
the l2bench law: the streamed reads do not allocate). The criterion (a)
(a delta beyond noise) FAILS → **NO-EFFECT, closed honestly**.

## The traps of the day (all banked)

1. the RM TU = OS-abstracted (the build = the judge, caught pre-reboot);
2. the multi-key RegistryDwords = the SEMICOLON (the space = never
   parsed — the 4.26 lesson re-proven: the space conf = the capture OFF);
3. the gc-sections strips the unreferenced globals (the modpost catches)
   → the function-pointer-in-shared-state pattern;
4. the RM NV_PRINTF = level-gated — ONLY the nv.c printk = the ledger;
5. dkms = "already built, skip" → --force MANDATORY (the UKI lesson);
6. /tmp = wiped by the reboot (the stocks = to ~/dmem-451/);
7. grep -c = 0 matches = exit 1 (the pipefail trap);
8. THE VERIFICATION LAW: nm the final module, never the conf nor the
   mixed &&/; command chains (the false-ready generator, caught).

## The next lane

**ROUTE W: the FB/WPR2 read probe** (the v452 T4 design: B1 the BAR1
read with ReBAR standing / MD the memdesc-over-phys with the in-tree
anchors). The 4.52 pass = merged with the caveats (the route-H tooling =
the shelf; gsp_hpoke.c = the two-sided conversion TODO).
