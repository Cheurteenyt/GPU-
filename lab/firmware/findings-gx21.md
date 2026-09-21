# findings-gx21 — the chip's geometry, measured; the tail is real and mapped

Date: 2026-09-17. Subject: decoding the founder's own chip dump against the
reference corpus, and finding out where the performance tables actually live.

## Proven (measured)

1. **The legacy half of the chip matches the reference build.** Full decoder
   suite re-run on `day0/rom-read-20260917/vbios-sysfs.rom` vs
   `vbios-94.04.46.00.EB.rom`: BIT structure identical (signature @432,
   v1.0), PERF table identical field-for-field, identity identical
   (94.04.46.00.EB, GA104). Only header-level deltas: x86 checksum 0 vs 31,
   data-range image_start ±5 B, and the reference is 2560 B short of the
   legacy image end (62,464 vs 65,024). Verdict: same build, differently
   packaged and truncated — the chip dump is the authority.
2. **The vP-state instrument scans only the legacy window — by design it
   found nothing in EITHER file.** The tables live in the tail.
3. **Pointer resolution cross-checked against the full TPU corpus**
   (`acquisitions/MSI.RTX3070.8192.210519_1.rom`, 999,424 B): the P-token
   pointers (power_budget 0x6ff48, fan_cooler 0x70a2d, fan_policy 0x70a67)
   resolve to real tables with the expected headers — fan_policy
   `20 04 33 08` (8×51 B), fan_cooler `10 06 1a 02`, power budget 20 entries
   — and a `20 15 01` vP-state header at 0x89a1e. On our chip those
   addresses land at ~551-563 KiB.
4. **The chip image is ~976 KiB; the host-visible ROM window is 512 KiB.**
   The kernel sizes the expansion-ROM resource of 0000:07:00.0 at exactly
   512 KiB (0xFC000000-0xFC07FFFF, audio function right behind at
   0xFC080000 — a 1 MiB read would cross into it; the conflict guard caught
   this). The corrected `read-rom-bar.py` v3.1 read the window through
   /dev/mem at the firmware-assigned address: 524,288 B, ff_share 1.4 %,
   **byte-identical prefix with the independent sysfs read** — two paths,
   one truth. BAR restored to 0 afterwards.
5. **Ring-13's old `rom-bar-window.bin` was 1 MiB of pure 0xFF** — the v1
   tool guessed an address outside the bridges' decode ranges and saved the
   garbage without a plausibility gate. Lessons kept in the tool: never
   guess an address (use the firmware-assigned one, probe-classified), and
   never save an all-FF read as if it were data.
6. **Scratch-hole assignment master-aborts**: re-assigning the ROM BAR to
   free-looking holes (0xfdf00000, 0xfe000000, 0xe8000000) reads all-FF —
   only windows inside the upstream bridges' decode ranges work. The
   kernel does not assign one on `echo 1 > rom`; it only arms the enable
   bit.

## Consequence

The performance tables (power budget, fan cooler, fan policy, vP-states)
are provably at 551-563 KiB on this chip — unreachable through the 512 KiB
BAR window, absent from the truncated reference. The only remaining
in-PC route is nvflash (which pages the SPI beyond the window) on the
nomodeset boot with the driver unloaded. Built for that:
`tools/gpu-rom-full-tty.sh` (v4) — a detached systemd-run flow that stops
the desktop, unloads the driver (possible because the console sits on
simpledrm), saves the full image to /root, verifies it, then reloads
everything and restarts the login screen. The screen goes black ~2 min;
that is the design, not a crash.

## Unknown / next (gx22)

- Execute the v4 flow on the maintenance boot; then decode the tail:
  power budget vs the live 250 W cap, fan policy vs the founder's LACT
  curve, vP-states vs the live 6801 MHz — the ring-15 cross, now on the
  real chip.
