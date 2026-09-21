# findings-gx36 — the voltage hunt: the vP-state chained structure

Date: 2026-09-18. Subject: where is the per-point voltage that holds the
1890 MHz wall? (the monstrous-lever hunt, ring 36 first pass)

## Established this pass

1. The vP-state table (CPR offset 563,764, header 22 B, 7 profiles × 65 B
   @ 563,786) is a **chained structure**: profile records contain internal
   address references (profile 0's address 0x89a4a appears inside later
   profiles) — NOT flat independent 65-byte records. The CPR parser's
   field offsets (first_limit @ [2100, 563686] etc.) are the reliable
   anchors; naive re-parses misalign.
2. **Voltage candidates found**: u16 `990` appears twice in profile 4
   (+0x11, +0x3a) and once in profile 5 (+0x22) — a plausible GDDR6 mV
   value in the heavier profiles. The 2100 MHz profiles (0-2) show no
   clean mV u16 — the top-profile voltage is either packed differently or
   lives in a referenced block.
3. The CPR parser (JadeRover grammar) decodes clocks but not voltage —
   the voltage field of the Ampere vP-state grammar is the decode target.

## Why this matters (the lever)

Genshin is voltage-limited at 1890 MHz (vague 1). The VBIOS vP-state
table is unsigned (ring 26) and flashable (the kit). Raising the
per-point voltage of the high VF states in the table → the wall moves
→ 1980-2100 MHz sustained in voltage-limited games. This is the
deep-lever candidate the founder asked for.

## Next (ring 37)

- Decode the chained-reference grammar (the CPR parser's walk, extended
  to the voltage fields — anchor: the 990 candidates and the profile
  chain pointers).
- Alternative anchor: the live machine's voltage under load (MangoHud
  gpu_voltage — Phase V) vs the table values → the encoding falls out of
  a known-plaintext pairing.
- Then: the voltage-raise mod design (which bytes, how much), the flash
  kit unchanged.
