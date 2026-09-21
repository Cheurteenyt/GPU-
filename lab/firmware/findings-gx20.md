# findings-gx20 — the chip speaks: full ROM read, in-session, driver loaded

Date: 2026-09-17. Subject: the full-SPI/ROM read that ring 13 declared
in-session-exhausted, closed without unloading anything.

## Proven (measured on this board)

1. **`nomodeset` did not prevent driver load.** The omarchy initramfs
   early-loads the nvidia modules before the cmdline matters; the maintenance
   boot came up as a full desktop on simpledrm with the driver re-attached
   (375 references: Hyprland, quickshell, Xwayland, mpvpaper, megasync,
   lact, coolercontrold, zcode). The maintenance entry's real win is that
   the **console sits on simpledrm**, so `nvidia_drm` is no longer the
   pinned console KMS driver that blocked ring 13 — but the desktop stack
   re-holding the driver still rules out an in-session `modprobe -r`.
2. **None of that matters for a READ.** The kernel PCI core serves
   `/sys/bus/pci/devices/0000:07:00.0/rom` independently of the NVIDIA
   driver. Double read: 157,696 bytes, byte-identical both times
   (sha256 `135b2153…`), valid `55 aa` header, "NVIDIA VIDEO" strings,
   version `94.04.46.00.EB`, PCIR device 2488.
3. **The chip's own structures certify completeness**: image 0 (x86, 65,024 B)
   + image 1 (EFI, 92,672 B, indicator 0x80) = 157,696 B = file size. A
   self-consistent PCI ROM chain, read twice identically, with the GPU
   serving the live desktop the whole time (no NVRM Xid).
4. **The downloaded reference was not the board's build.** The 62,464-byte
   `vbios-94.04.46.00.EB.rom` used for decodes differs from the chip over
   its entire prefix despite the same version string. It was partial and
   foreign. Every decode derived from it inherits an asterisk; the real
   decode baseline is now `day0/rom-read-20260917/vbios-sysfs.rom`.

## Built

5. `tools/gpu-rom-dump-tty.sh` v2 — kept for the future WRITE phase: nvflash
   (now also at `/usr/local/bin/nvflash`, sha256-verified copy) refuses to
   run with the driver loaded, so a write still needs the detached
   stop-session → unload → flash → reload → restart-session sequence. The
   sysfs read made that unnecessary today; the write will want it.
6. Limine maintenance entry fixed (`//` → `/`: top-level entries take one
   slash; the double-slash form was silently ignored at top level).

## Inferred

- Reading the chip needed no privileged hardware and no downtime — the
  barrier was never the ROM BAR, it was assuming nvflash was the only door.

## Unknown / next (gx21)

- Re-run the decode suite (BIT walk, INIT grammar, PERF v0x60, vP-states,
  fan policy) against the REAL chip dump and diff every table against the
  reference-derived numbers; every discrepancy is a place the foreign
  image lied to us.
- The write phase (power table / vP-state mod, nvflash under the detached
  maintenance boot, dual-BIOS switch as safety) is now unblocked end-to-end.
