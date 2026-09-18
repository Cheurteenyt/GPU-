# findings-gx40 — the dial stack verdict: REFUTED by the machine

Date: 2026-09-18. Subject: the 5-dial stack (RmSramVminCheckIgnore,
RmVFPointCheckIgnore, RMDisablePerfIntersect, RmPerfLimitsOverride,
RmBootGspRmWithBoostClocks — all =1, one reboot, official Time Spy run).

## The result

| Run | Graphics | CPU | Total | Conditions |
|---|---|---|---|---|
| 14/09 (1) | 12,557 | 9,241 | 11,915 | stock |
| 14/09 (2) | 12,472 | 11,388 | 12,296 | stock, quiet CPU test |
| 18/09 | 11,957 | 9,701 | 11,553 | stock, busy desktop |
| **18/09 + dials** | **11,874** | 9,128 | 11,361 | **the 5-dial stack** |

Graphics 11,874 vs the comparable 11,957 (busy-desktop stock): **−0.7 % =
noise**. The dials changed nothing measurable.

## The verdict

1. **The "code that punishes" hypothesis via registry dials is REFUTED**
   for this card: the checks the dials bypass (VF validation, perf
   intersection, VMIN) do not bind at stock — the 1890 MHz wall is
   silicon/voltage, not a software limit the registry reaches.
2. The dials are loaded cleanly (no dmesg errors) and change nothing —
   they are no-ops on this card. **Stack removed** (config cleared,
   initramfs regenerated — stock restored).
3. The consumer sites (ring 38-40) are real code — the RM reads the dials
   — but the gated behaviors are not on the binding path at stock clocks.

## What remains (the honest levers)

1. **The 280 W flash** (the kit is ready): for power-saturated workloads —
   NOT Genshin (voltage-limited, vague 1), but render/other games.
2. **The memory timing mod** (ring 33-34): the FBPA grammar decode, then
   the tightened-timing design — the bandwidth lever.
3. **Phase O**: the core offset (+75/+150) — the voltage-limited lever
   that LACT already reaches; A/B in a real game.
