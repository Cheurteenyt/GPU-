# findings-gx6 — the sixth ring: the fan coolers, named by the kernel itself

Scope: the three verified GA104 specimens, one instrument (`gx6-fan.py`),
grammar imported from torvalds/linux nouveau `nvkm/subdev/bios/fan.c`
(fetched to `imports/nouveau/fan.c`), pointer offsets anchored on the
ring-3 register. Selftest green (0 failures).

## What is measured

**The FAN COOLERS decode, with named fields.** nouveau's
`nvbios_fan_parse` reads exactly our table (bit_P + 0x58, version 0x10):
type u8@0x00, min_duty u8@0x02, max_duty u8@0x03, pwm_freq u32@0x0b &
0xffffff. Applied to the corpus:

| Specimen | Coolers | Type | Min duty | Max duty | PWM freq |
|---|---|---|---|---|---|
| Gaming Trio Plus (primary) | 2 | PWM | **17 %** | 100 % | 27000 |
| Ventus 3X OC | 2 | PWM | **20 %** | 100 % | 27000 |
| Gaming X Trio (launch) | 2 | PWM | 17 % | 100 % | 27000 |

**The minimum duty is a board marker**: the Trio boards let the fans
idle at 17 %, the Ventus floor is 20 % — same silicon, same build date
for the two LHR boards. A real, firmware-level cooling-behavior delta
between boards, measured to the byte (it lives at record offset 0x02).

**The two coolers of each board** differ in exactly two raw bytes
(per-cooler identity/config), and the board tails differ by two more
bytes (0x0cb2 vs 0x0d7a in the 16–17 span — RPM-class candidates).

**POWER TOPOLOGY** (P+0x3c): v0x20, **32 records × 22 B** — the per-rail
map, measured and registered raw (no open grammar; the power-budget
cross — 20 entries, cap 240/250 W — is the ring-3 anchor it should map
onto). **POWER FAN_MGMT** (P+0x5c): 8 × 51 B, RPM-class u16 candidates
(100, 1760, 1000, 2400, 2100, 2560, 3250, 1440, 1760…), honest unknown.

**The version wall, confirmed by source.** nouveau's perf.c handles up
to v0x40; our PERFORMANCE table is v0x60 — beyond every open parser,
consumed by the closed GSP-RM. The vP-state v0x20 and the FAN_MGMT
shape share that status. The open-source frontier is exactly here, and
now it is documented by citation, not by assumption.

## Consequences

1. The fan-optimization surface has its first fully-named object: two
   PWM coolers, 27 kHz, duty floor 17 % (this board), ceiling 100 %.
   Any "can my fans idle lower" question now starts from the exact byte.
2. The board-marker law gains a cooling axis (min duty), completing the
   set: budget (240/250 vs 220/220), memory records, fan floor.
3. The remaining RAW objects (PERF v0x60, vP-state v0x20, topology
   32×22, fan_mgmt 8×51) are precisely the territory where the open
   ecosystem ends — mapped, gated, and waiting for the full-SPI live
   read or a GSP-RM-side grammar hunt.

## Honesty ledger

- Proven: fan decode 3/3 against the kernel grammar; the 17/20 % board
  law; topology/fan_mgmt geometry; selftest 0 failures.
- Inferred: the RPM-class reading of the fan_mgmt candidates; the
  per-cooler byte as identity/config.
- Unknown: PERF v0x60 and vP-state v0x20 structures; the topology
  record semantics; the units of the fan_mgmt speeds.
