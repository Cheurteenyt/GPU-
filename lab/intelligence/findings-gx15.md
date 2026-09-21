# findings-gx15 — the fifteenth ring: the vP-state, decoded — the machine's own clocks in the file

Scope: the day-0 live dump plus the three verified acquisitions, one
instrument (`gx15-vpstate.py`), the vP-state v0x20 grammar imported from
the community tool JadeRover/Nvidia-vBIOS-Clock-Power-Tweaker
(`imports/CPR_calculator.py` — the founder's GitHub hunch, third strike).
Selftest green (0 failures).

## What is measured

**The vP-state v0x20 (Ampere) grammar.** Header `20 15 01` (21 bytes +
the 0x0F denominator byte), 65-byte profiles, clocks as fixed-point
/2^15, profile list opened by ID 0x07, coherence-checked by decoding the
first clock to 100–2000 MHz. Applied to the corpus, the profiles read:

| vP-state ID | graphics limit | mem_clock_short | reading |
|---|---|---|---|
| 0xF | 2100 MHz | **7001 MHz** | stock P0 memory |
| 0xD | 2100 MHz | **6801 MHz** | **the founder's live memory clock** |
| 0xC | 2100 MHz | 5001 MHz | mid-state |
| 0xA | 2100 MHz | 810 MHz | idle memory |
| 0x7 | 420 MHz | 405 MHz | deep idle |

**The live cross is total**: the live memory clock (6801) is itself one
of the profiles; the live graphics clock (1890) sits under the 2100
cap; the idle clocks (405/810) match what a downclocked 3070 reports.
The table is the card's clock ladder at the vP-state level — the
written state (6801) is not just a runtime number, it is a named
profile the card selects.

**The header grew at the LHR seam — the profiles did not.** The
launch-era build carries the Turing-length header (19 B — the tool
classifies it "Turing") with identical profiles (7001/6801/5001/810/
405, limit 2100). Ring 4's "hlen 19 vs 21" measurement now has its
meaning: the Ampere header growth happened without touching a single
profile value. And the primary acquisition carries **two identical VP
tables** (the tool's own note: never more than two) — a redundant copy
whose purpose is not named by any source.

**The window law holds**: the day-0 sysfs dump reports no VP table —
the vP-state lives in the tail, beyond the legacy image, exactly where
rings 4–8 had registered it.

## Consequences

1. The last big unknown falls: the vP-state v0x20 — "unknown" since
   ring 4 — is decoded, gated, and cross-validated against the machine.
   The only remaining unnamed object of the entire ROM is now the PERF
   table v0x60 (7 records × 5 B) and the misc small tables.
2. The optimization reading is direct: the 2100 MHz graphics cap and
   the 7001/6801 MHz memory profiles are the card's own performance
   envelope, in the file, in fixed-point, at named offsets.

## Honesty ledger

- Proven: the header grammar (imported), the profile decode, the live
  cross (6801 ∈ profiles), the LHR header growth with identical
  profiles, the dual-table copy on the primary.
- Inferred: the tool's "Turing" label for the launch-era hlen-19 header
  (a classification by header length, not silicon); the ID semantics of
  the profiles (0xF/0xD/0xC/0xA/0x7 as vP-state indices).
- Unknown: the purpose of the dual-table copy; the exact meaning of
  first/second/third limits inside a profile; the PERF v0x60 records.
