# findings-gx19 — software OC measured, ROM read route unlocked

Date: 2026-09-17. Subject: the performance campaign on the RTX 3070, and the
foundation step for firmware-level work.

## What was asked

The founder's thesis: with both BIOSes decoded and AI in the loop, performance
headroom should be extractable. This ring measured the software headroom and
prepared the firmware route.

## Proven (measured on this board)

1. **LACT offsets can be driven without the GUI.** The daemon's unix socket at
   `/run/lactd.sock` accepts the same request grammar as its client
   (v0.10.1, confirmed against the tagged source): `batch_set_clocks_value`
   + `confirm_pending_config`. Used to zero offsets exactly (the GUI's
   Revert button does not work for the founder). Driver readback verified
   per P-state before/after every change.
2. **The +200 LACT VRAM offset IS applied under load**: memory clock reads
   6801 → 6901 MHz in all three A/B pairs, always P2. Note the scale: LACT
   "+200" = +100 MHz in the NVIDIA readout.
3. **No demonstrated gain from that offset.** Paired terrain runs
   (1920x1080 offscreen, 8 s warmup + 20 s measured): A=1163/1130/1104 FPS,
   B=1162/1103/1041. The zero-offset baseline itself drifted −5.1 % across
   the session, so the apparent B deficit is not attributable. Honest
   verdict: setting works, benefit not established, no overclock kept.
4. **LACT's `vbios_dump` is AMD-only** — daemon answers "Not supported on
   Nvidia". Route closed, one sentence of work, documented.
5. **Power limit already at ceiling**: 250 W is the top of the configurable
   range (100–250 W). No software headroom there at all.

## Built (reversible, verified)

6. **Limine `nomodeset` maintenance entry** appended to `/boot/limine.conf`
   (backup: `/boot/limine.conf.bak-gx19`): same omarchy UKI, same cmdline
   minus resume/quiet/splash, plus `nomodeset loglevel=7`. The kernel
   cmdline IS honored for these UKIs — the snapper snapshot entries boot the
   same UKI files with different cmdlines into different roots, which
   proves the override path. Menu timeout set to 5 s (was commented out).
   Default entry and entry numbering untouched (appended last).
7. **`tools/gpu-rom-dump-tty.sh` (v1)** — READ-ONLY full-ROM dump for the
   maintenance boot: refuses to run unless nomodeset is on the cmdline and
   no nvidia module is loaded; two independent reads (sysfs expansion-ROM +
   nvflash 5.867, now extracted from the zip and smoke-tested); sha256
   cross-check over the common prefix; mismatch = stop. Doctrine enforced:
   never flash to read.

## Inferred

- glmark2 saturation runs are workload-limited (GPU util ~92 %, ~150 W of
  250 W), so even a real memory-clock gain may be invisible to them. The
  no-gain verdict is about this test family, not about gaming.

## Unknown / next

- The maintenance boot itself (founder executes when ready). After a
  verified read: diff the on-chip ROM against the known
  `vbios-94.04.46.00.EB.rom`, then the actual firmware lever — the vP-state
  and power-table records decoded in gx15 — becomes writable via a
  controlled nvflash write, with the MSI dual-BIOS switch as the safety net.
- Real-game measurement (MangoHud, capped frame rate) if the founder wants
  gaming numbers instead of synthetic ones.
- ASUS 3645 update via EZ Flash remains available (official CAP URL already
  extracted in the sibling lab) — founder's call, done from BIOS setup.
