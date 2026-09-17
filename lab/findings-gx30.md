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
