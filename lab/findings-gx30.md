# findings-gx30 — the 881 dials: the RM's own switches, no flash required

Date: 2026-09-17. Subject: the founder's intuition — "there is code that
punishes the user" — is structurally true, and part of it is toggleable.

## The discovery

`rm.elf` (the GSP Resource Manager, 17.2 MB, plaintext RISC-V) contains
**881 registry parameter names** — the Resource Manager's own tunable
space. These are the keys NVIDIA's driver accepts through
`NVreg_RegistryDwords` (modprobe module option), applied at module load,
reversible by removing the config line. No flash. No firmware write.

The perf-relevant shortlist extracted from the strings census:

| Parameter | Reading |
|---|---|
| `RmPerfLimitsOverride` | override the performance-limit logic — the "punishing" limits |
| `RMDisablePerfIntersect` | disable the perf-limit intersection (power×thermal×voltage) |
| `RmBootGspRmWithBoostClocks` | boot the GSP RM with boost clocks enabled |
| `RMEnableOverclockingAllPstates` / `DisableOverclockedPstates` | overclocked P-state gating |
| `RMClkVfOverride` / `RmPerfCfOverride` + controllers/policy overrides | voltage-frequency and controller overrides |
| `RmPerfRatedTdpLimit`, `RMPowerSupplyCapacity` | TDP and PSU-capacity accounting |
| `RMPriorityBoost`, `RMForceLockedClocksMode` | boost priority, locked-clock mode |
| `RmOverrideIdleSlowdownSettings`, `RMClkSlowDown`, `EnableMClkSlowdown` | the slowdown behaviours |
| `RmFan2XOverride` | fan doubling override |
| ~150 `RMLpwr*` idle thresholds | the entire low-power machinery |

## The mechanism

`/etc/modprobe.d/hwtruth-dials.conf`:
```
options nvidia NVreg_RegistryDwords=RmPerfLimitsOverride=1
```
Applied at module load (reboot). Removed = back to stock. Protocol:
ONE dial per reboot, verified with nvidia-smi limits/clocks and a real
MangoHud session; a dial that changes nothing or destabilizes is removed.

## Caveats, stated honestly

- Value semantics are not documented; the community reference is the
  excerpted `nvrm_registry.h` (denji's gist) and forum lore. A wrong value
  can degrade or destabilize — one dial per reboot bounds the blast radius.
- Several `RMBug*` strings are workarounds, not features — leave them.
- The Reddit "NVIDIA may be artificially reducing your performance" PSA
  is laptop-oriented (Optimus power balancing); on a desktop 3070 the
  relevant dials are the perf-limit ones above.
- Sources: NVIDIA forums (RegistryDwords mechanism, DGX Spark boost-clock
  workaround), denji's RegistryDwords gist, the rm.elf string census in
  `tools/gsp-extract/rm-strings.txt`.

## Status

This is the accessible "deep" layer: the dials live in the driver+RM path
we can actually reach, unlike the encrypted bindata. Ring 31: build the
test matrix and run the first reboots with one dial each, measured in a
real game.

## Addendum: where the dial strings live in rm.elf (consumer analysis)

- The dial-name strings sit at file 0xe27b80-0xe8e4f8 (VA 0x1e27b80+).
- auipc+addi scan found direct code references for three dials:
  RmPerfLimitsOverride @ 0xbad5c0, RMClkVfOverride @ 0xecee0,
  RMPriorityBoost @ 0xd66c. Window disassembly of the first shows a
  **debug/log-name registration table** (repeated `li a1, <line-id>` +
  call, ids 0x99-0xb7): the RM registers these names in its trace system.
- Interpretation: the RM knows the keys (its trace table names them), the
  VALUES arrive from the host driver through the registry channel
  (NVreg_RegistryDwords → host registry → GSP RPC). Mechanism confirmed
  functional by NVIDIA forum usage; value semantics remain host-side.
- Pointer-table search (8-byte VAs of the strings): zero hits — the
  registry lookup is by name at runtime.

## The safe test matrix (ring 31, one dial per reboot)

1. `RmBootGspRmWithBoostClocks=1` — first: documented working usage on
   NVIDIA's own forum (DGX Spark clock-pinning workaround).
2. `RMDisablePerfIntersect=1` — second: may relax the limit intersection.
3. `RmPerfLimitsOverride=1` — third: the named "punishing" limits.
Each: verify with nvidia-smi (limits/clocks) + a real MangoHud session;
keep what measurably wins, remove what does nothing or destabilizes.

## Ring 31 result: the first real-game telemetry (Genshin, uncapped 180 fps, dial 2 active)

Source: `day0/genshin-session-dial2.csv` (3,193 samples, ~5.3 min of
MangoHud auto-logging, 100 ms interval — the founder played normally).

- **GPU load: 98 % median** — the card was genuinely working.
- **Power: 214 W median, 235 W max, ≥200 W for 72.5 % of the session** —
  Genshin uncapped is NOT a light load; the card rides the upper power
  region. (The 180 fps unlock changed the workload class completely.)
- **Core clock: 1890 MHz median/max, with 1st-percentile dips to
  1770 MHz** — occasional one-power-state droops under the heaviest
  moments. This is exactly the behaviour the 280 W power-budget mod would
  remove (more headroom → fewer state drops).
- Temps 61/64 °C median/max — the founder's LACT fan curve holds it well.
- **Dial 2 verdict: UNMEASURABLE this session** — max power 235 W never
  touched the 250 W cap, and `RMDisablePerfIntersect` only matters when
  limits intersect. The A/B (same session without the dial) decides it;
  the expected effect size is small (the p1 clock dip, 1770→1890).
- MangoHud auto-logging (autostart_log) works: the measurement pipeline
  is now repeatable without any user input beyond playing.
