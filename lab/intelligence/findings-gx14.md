# findings-gx14 — the fourteenth ring: the fan curves, decoded end to end

Scope: the three verified GA104 specimens, one instrument
(`gx14-fanpolicy.py`), the fan-policy grammar imported verbatim from the
community parser `shengyuewangshuai-del/NVIDIA-VBIOS-Info-Reader`
(`imports/vbios_fan_policy.py` — the founder's GitHub hunch, second
strike). Selftest green (0 failures).

## What is measured

**The fan policy table (P+0x5C, v0x20, 8 records × 51 B) decodes into
three-point fan curves** — per record: three duty percents @+14, three
temperatures (u16/32, °C) @+18/+22/+26, three target RPMs @+20/+24/+28.
All 8 records are plausible on all three specimens, and the cap anchor
re-derives through this instrument (240 000/250 000 mW Trio, 220 000/
220 000 Ventus — the ring-3 cross holds).

**The founder's board (Gaming Trio Plus), the actual curves:**

| Record | Duties | Temps | Target RPM | Reading |
|---|---|---|---|---|
| 0–1 | 17 / 45 / 100 % | 55 / 75 / 80 °C | 1000 / 2100 / 3250 | the operating curve |
| 2 | 17 / 45 / 100 % | **95 / 100 / 103 °C** | 1000 / 2100 / 3250 | the emergency curve |
| 3 | 20 / 20 / 76 % | **133 / 136 / 139 °C** | 1000 / 1000 / 3750 | the hardware-panic curve |
| 4–7 | 30 / 42 / 85 % | 42 / 75.7 / 95 °C | 1100 / 1627 / 4200 | the alternate curve set |

**The board law becomes a curve law.** The Ventus's operating curve is
different everywhere: 20 / 60 / 100 % at 60 / 75 / 84 °C, 1000 / 2300 /
3450 RPM — consistent with its 20 % duty floor (ring 6). The launch-era
Gaming X Trio's curves are identical to the primary's (17 % floor, same
points) — the fan behavior is a board-family marker, and its bytes live
at named offsets: every value in that table is a candidate lever,
localized and gated.

**The emergency and panic curves** (95–103 °C and 133–139 °C) are the
firmware's own protection ladder — now readable, meaning any future
fan-curve question ("what does the card do at 90 °C") is answered from
the file, not guessed.

## Consequences

1. The cooling-optimization surface is complete: duty floor (ring 6),
   PWM frequency (ring 6), the three-point curves with temperatures and
   target RPMs (this ring), the RPM candidates of the cooler records,
   and the power budget they serve (ring 3) — all named, all gated.
2. The community grammar cross-validates the sibling lab's doctrine:
   the offsets the parser uses match our independently-measured table
   pointers exactly (0x2C / 0x58 / 0x5C).

## Honesty ledger

- Proven: 8/8 plausible records per specimen, the curve values, the cap
  re-derivation, selftest 0 failures.
- Inferred: the semantic roles of record groups (operating/emergency/
  panic/alternate — the temperature ladders make the reading strong but
  the names are ours); the record-selection mechanism (which of the 8
  curves runs when — presumably per strap/mode, unproven).
- Unknown: which curve is active on the founder's card right now (needs
  the runtime strap/mode); the /32 temperature scaling is the parser's
  convention, consistent with plausible °C values.
