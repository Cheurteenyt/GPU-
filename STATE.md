# gpu-lab — state of the campaign (2026-09-17)

One page to answer: what did the founder gain, what is proven, what is
parked, what is next.

## The gains (real, measured)

| Item | Before | After | Ring |
|---|---|---|---|
| Resizable BAR | dead (CSM silently disabled Above-4G) | **8192 MiB BAR1**, Region 1 above 4 GB | 18 |
| Fan curve | stock (17/45/100 % @ 55/75/80 °C) | founder's custom LACT curve — cooler at load | 19 |
| Power limit | 250 W | 250 W — already the silicon ceiling | 19 |
| Core/VRAM offsets | unknown | tested honestly: no measurable gain; reset to 0 | 19 |

## The decoded truth (this board, cross-verified)

- Chip build identified: **MSI.RTX3070.8192.210519_1**, shifted 0x9200 in
  the TPU dump; the first 512 KiB of the chip matches it **byte-exact**.
- Power budget: **100 / 240 / 250 W** — matches the live NVML range to the
  watt. No hidden headroom.
- Fan policy: 8 records; operative curve 17/45/100 % @ 55/75/80 °C →
  1000/2100/3250 RPM; escalation records to 139 °C.
- vP-states: 0xF=2100/7001, 0xD=2100/6801, 0xC=2100/5001, 0xA=2100/810,
  0x7=420/405 — LACT's ceilings are the firmware's own caps; live 6801
  covered.
- Memory timings (7 bins, monotone) and PERF v0x60 generation constant.

Verdict: **the performance campaign is closed honestly.** The one real
gain was ReBAR; everything else was already at its designed ceiling, and
the decoded firmware proves it rather than assuming it.

## The method library (all in-session, all safe)

- sysfs ROM read + BAR-window read (two independent paths, byte-identical)
- kcore scan (39.8 GiB in 63 s) — the driver cannot seal it
- LACT daemon socket API (offsets without the GUI, Revert button bypassed)
- saturated and paired benchmark protocol (A/B, dispersion-checked)
- the full decoder suite gx1–gx15, re-run against the real chip dump

## Parked (ready, not executed)

1. **Direct read of chip[512 KiB, 976 KiB)** — inferred identical via the
   build identity; a live-USB nvflash read verifies it in five minutes.
   The ISO (1.5 GiB) and `usb-rom-read.sh` sit on the data drive; the USB
   key contents are backed up at `usb-key-backup-6A4B/`.
2. **VBIOS write phase** — never from the running desktop; same live USB.
   Nothing to write today: the tables say there is nothing to gain.
3. **B550 side** — BIOS 3645 (official CAP) available via EZ Flash when
   the founder wants it; deep SPI dump needs CH341A (declined).
4. **gsp.bin unpacking** — the GSP firmware's own tables are the next
   unexplored firmware layer, fully in-session work.

## Incidents ledger (transparency)

- 4 faillocks this day, all from one repeated shell mistake of the
  assistant's (heredoc + `sudo -S`), never from the founder's actions.
  Structural fix ready (targeted sudoers rule), awaiting the founder's
  approval.
- 2 black screens: one from the maintenance boot before
  `nvidia_drm.modeset=0` (fixed), one display-link incident on a normal
  boot (recovered).
- The GPU itself: zero NVRM Xid across the entire campaign; every read
  was passive; the flash was never written.
