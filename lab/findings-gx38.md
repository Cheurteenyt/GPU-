# findings-gx38 — THE MONSTROUS LEVER: the VMIN checks are the power-efficiency governors

Date: 2026-09-18. Subject: the deep lever the founder demanded — found in
the RM code, on OUR firmware version, with the consumer sites pinned.

## The engineering insight

The card is voltage-limited at 1890 MHz (vague 1). But the power budget
(250 W) buys EITHER voltage OR frequency. The VMIN checks (VMIN_NVVDD =
the core rail, VMIN_SRAM, VMIN_LOGIC, VMIN_IODVDD — the rail names are in
the RM's own tables) enforce a **minimum voltage** per operating point —
conservatively binned for all silicon. A VMIN floor higher than the silicon
needs = watts spent on voltage instead of frequency = the clock ceiling
under the power cap.

**Ignoring the VMIN checks = the VF curve floor extends lower = at the
same 250 W, more MHz.** The undervolt-by-firmware, done at the Resource
Manager level.

## Proven (this session, on OUR rm.elf 610.57.04)

1. **`RmSramVminCheckIgnore` is a registry dial** (the sibling of
   RmVFPointCheckIgnore from vague 4.5) and it is **read by our firmware**:
   2 code consumer sites pinned at 0x6b98c4 and 0x6ba30c (auipc+addi
   references to the name string, VA 0x1e871b0).
2. The consumer window disassembles to a **capability-bitmask test +
   7-entry dispatch table** (bltu a4=7 → jump table; lui/and/bnez bit
   tests on a shifted flags register) — the VMIN check gating structure.
3. The full VMIN rail inventory is in the RM's own tables: VMIN_NVVDD(0/1),
   VMIN_MSVDD(0/1), VMIN_LOGIC, VMIN_SRAM, VMIN_IODVDD.
4. Instrument adaptation: `xref_dials.py` re-targeted to our build
   (paths + the VMIN dials added); our own auipc+addi scanner cross-
   confirms the sites (capstone unavailable, pure-Python scanner used).

## The test protocol (Phase D-volt, via the dial gate)

1. `RmSramVminCheckIgnore=1` + `RmVFPointCheckIgnore=1` (the two
   validation bypasses) — ONE reboot, via campagne-dial-gate.sh.
2. Genshin uncapped + MangoHud: the decision metrics are
   **the voltage at 1890 MHz** (drops below 987 mV = the floor moved) and
   **the sustained clocks** (rise past 1890 if the freed watts convert).
3. Instability/crash = the VMIN was real for this silicon → remove the
   dials, reboot, done (volatile RAM, zero persistence, zero flash).
4. If the voltage floor moves AND clocks hold stable → the gains stack
   with the core offset (Phase O) — the monstrous combination.

## Honesty

The consumer semantics are partially decoded (the gating structure is
clear; the exact bit-to-rail mapping inside the dispatch continues).
VMIN exists for silicon safety — the ignore dial trades the conservative
margin for headroom, and the crash test IS the stability test. The dials
are volatile: a crash costs a reboot, never the card.
