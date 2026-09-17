# CHANGELOG

All measured work, ring by ring. Registers are frozen once scored; the
findings files carry the honesty ledgers.

## Unreleased — the eight rings of the first session (2026-09-15)

- **ring 0** — the lab founded: `day0/` protocol, the runtime snapshot
  (power limit written to 250 W vs the 240 W factory default — a written
  state), the acquisition kit.
- **ring 1** — the anatomy: NVGI @0x0/0x2000, legacy @0x9200, EFI @0x19000,
  the dense tail (never slack), board id strings, TPU's truncated versions.
- **ring 2** — BIT + memory grammar; the LHR seam (memory record 14→22 B);
  the from-memory decoder lesson (code 9 = GDDR6, source-verbatim now).
- **ring 3** — the 'P' table: 58 pointers, the spec pointer rule, the tail
  owned; PowerCapping decoded (100/240/250 W, byte-exact vs the machine);
  **the budget is a board marker** (Ventus 220/220 W).
- **ring 4** — the memory ladder (7 bins, live 6801 MHz covered); the
  Ampere header growth; the timing table geometry; vP-state v0x20 raw.
- **ring 5** — the timing layer decoded (18 fields × 28 records); the
  census (40 FF pairs, **1 stock zero-record landmine**); 4 Hynix records
  tightened at the LHR seam.
- **ring 6** — the fan coolers named (nouveau grammar): **min duty 17 %
  (Trio) vs 20 % (Ventus)**; the 32-rail topology; the version wall
  documented (GSP-RM territory).
- **ring 7** — identity: chip 0x9404 = GA104; **the OEM version byte is
  the version suffix**; the self-consistent checksum; 10 factory-spare
  timing records; the live window precisely bounded.
- **ring 8** — 58/58 pointers named (ImHex pattern, community source);
  PowerCapping's RM name; the memory-clock header decoded; the Falcon
  ucode inventory; **the PMU grew at the LHR seam**.
- **day-0** — the live dump: sibling-not-twin verdict, byte-stable second
  read, the BAR investigation closed by measurement (the full-SPI path is
  the live USB + `iomem=relaxed`).

## Unreleased — ring 9 (2026-09-15, post-publication)

- **ring 9** — recon of the last territory: `gsp_ga10x.bin` (84 MB,
  ELF64 RISC-V container) wraps 14 per-family firmware images
  (`kernel_ga10x.elf`…); the libos 3.1.0 microkernel layer is plaintext
  (source paths, assertions, task machinery); the RM payload — where the
  VBIOS table parsers live — is packed (zero plaintext table names);
  no public extractor exists. The unpacking project is registered with
  its groundwork: container layout, embedded-ELF map, libos layer
  identified. See `lab/findings-gx9.md`.

## Unreleased — ring 10 (2026-09-15, late)

- **ring 10** — the devinit scripts decoded with nouveau's INIT grammar
  (self-validating walk to `init_done`): **317 scripts live** (the memory
  -training program: NV_REG ×294, SUB_DIRECT ×402, writes concentrated in
  the 0x4061c*/0x6061c* training registers); **the day-0 differ resolved
  at last** — the acquisition lost 59+ devinit scripts (66 live-only, all
  in the zeroed region): the TechPowerUp file is an incomplete capture,
  the card's ROM is whole. The ring-1 "3s2bwb vocabulary" resolved: INIT
  opcode streams matched mid-instruction. See `lab/findings-gx10.md`.

## Unreleased — ring 11 (2026-09-15, night)

- **ring 11** — every BIT token owned (17/17 with a named grammar): the
  Sign-On message signs the board design (`PG142 SKU 12` vs `SKU 10` —
  a finer board marker than the subsystem ID) and the copyright year;
  display flags production-clean; VBE PCLK NULL (the legacy list is
  gone); the UEFI token a vestige. The identity chain is closed
  end-to-end inside the file. See `lab/findings-gx11.md`.

## Unreleased — ring 12 (2026-09-15, night II)

- **ring 12** — the devinit program has a shape: 259 roots calling 58
  subroutines by 216 direct calls, depth 2, hot routines 0x6951 (48×) /
  0x675f (47×); index-calls zero (the raw count was an overlap artifact);
  **both TPU acquisitions share the same amputation** (259 scripts, same
  subroutine offsets, same hot callees) — the capture loss is a pipeline
  property; the memory-clock script lists are a third lost instance
  (dense live, zeroed in the acquisitions; pointer domain unresolved).
  See `lab/findings-gx12.md`.

## Unreleased — ring 13 (2026-09-16, the wall)

- **ring 13** — five in-session attempts, five layers peeled
  (coolercontrold, lactd, the signal pass, the watchdog), and the final
  wall measured: `lsof` empty against 371/54/13/8 kernel refcounts —
  the console pins the display driver. The in-session full-SPI route is
  exhausted with the wall named; the remaining path is the live USB (or
  a hardware clip). The script suite (v2→v2.6, watchdog-armed) is
  committed as the attempt's durable output. See
  `lab/findings-gx13.md`.

## Unreleased — rings 14 (2026-09-16)

- **ring 14** — the fan curves decoded end to end (grammar imported from
  the community parser NVIDIA-VBIOS-Info-Reader): three-point curves
  (duty/°C/RPM) for all 8 records × 3 specimens; the founder's board
  runs 17%→55°C→1000 RPM / 45%→75°C→2100 / 100%→80°C→3250, with an
  emergency curve (95–103°C) and a hardware-panic curve (133–139°C);
  the Ventus curve differs everywhere (20/60/100% @ 60/75/84°C) — the
  fan behavior is a board-family marker at named offsets. See
  `lab/findings-gx14.md`.

## Unreleased — ring 15 (2026-09-16)

- **ring 15** — the vP-state v0x20 decoded (grammar imported from the
  community tool JadeRover/Nvidia-vBIOS-Clock-Power-Tweaker): 65-byte
  profiles with fixed-point clocks, IDs 0xF/0xD/0xC/0xA/0x7 carrying
  **7001 / 6801 / 5001 / 810 / 405 MHz** memory and a 2100 MHz graphics
  cap — **the founder's live 6801 MHz is itself a named profile**; the
  launch-era build keeps identical profiles under the Turing-length
  header (the LHR header growth touched no profile value); the primary
  carries two identical VP tables. The last big unknown falls; only the
  PERF v0x60 records remain unnamed. See `lab/findings-gx15.md`.

## Unreleased — ring 16 (2026-09-16)

- **ring 16** — the triple cross: the community tweaker's signature
  search independently finds the power budget at the ring-3 offsets
  (240000/250000 mW, slider enabled) — three grammars, same bytes. The
  PERF v0x60 encoding identified: its records carry clocks in the same
  /2^15 fixed-point as the vP-state (420/600/405 — the deep-idle
  profile's values — plus 842/810/900/1050/1200 MHz windows); the field
  layout remains the last open question. See `lab/findings-gx16.md`.

## Unreleased — ring 17 (2026-09-17)

- **ring 17** — the PERF table (P+0x00, v0x60, 7×5B) is a GENERATION
  CONSTANT: all 35 record bytes identical on all three boards (launch
  2020 at its own address 0x85CD5, LHR 2021 at 0x8984D); records carry
  the vP-state values (420/600/405) — the RTX 3070-class clock envelope
  is shared in-file across the generation. The public grammar hunt is
  exhausted: zero GitHub implementations of the modern perf tables, no
  doc, the gsp plaintext layer names the runtime vocabulary
  (PERF_CF_CONTROLLER_*, JPAC_PSTATE, DEEP_IDLE) behind which the
  parser stays packed. The founder's fresh vendor CAP (3644, re-packaged
  vs ring 44) stored as the day-0 reference. See `lab/findings-gx17.md`.

## Unreleased — the B550 SPI campaign (2026-09-17, night)

- **the in-system SPI bypass, exhausted to the last layer**: flashprog
  probes the chip (W25Q256JW, RDID allowed) but data reads are globally
  gated (opcode 0x13 → the sticky IllegalAccess bit); the CNTRL0 and
  RESTRICTED_CMD1/2 writes are SMU-ignored; the protect ranges read
  zero; EzFlash on this board has no save function; spi_amd does not
  bind the desktop FCH.
- **the UEFI-shell kit is prepared on the founder's key**: shellx64.efi
  (pbatard/edk2 build) as EFI/BOOT/BOOTX64.EFI + AMI AfuEfix64.efi
  (Aptio 4) and AfuEfiV.efi (Aptio V), mirrored from the
  Slimbook-Team/fwupd archive — the SMM flash service route, which the
  SMU lock cannot stop by construction. The dump gesture is the
  founder's: boot the key, run `AfuEfix64.efi NW3644.ROM /O`.

## Unreleased — the B550 software ladder, fully measured (2026-09-17)

- the generic AMI AFU (2017 v3.09 AND 2023 v5.16 from the official
  package) runs in the UEFI shell but hangs on the ASUS OFBD layer —
  the board demands Aptio 5 and still blocks;
- ASUS ships no DOS package for this board (the support API lists CAP
  files only);
- the founder's flash-a-CAP suggestion was refused: it writes factory
  state over the chip (destroying the written ReBAR evidence) with
  brick risk and zero information gain;
- verdict: the B550 chip dump requires the CH341A + SOIC8 clip route
  (~10-15 EUR, flashrom ch341a_spi, read offline). Eight software
  methods measured and closed; the machine-half day-0 finding (ReBAR
  not engaged) stands.

## Unreleased — the founding complaint, SOLVED (2026-09-17, night)

- **ring 18** — the founder's founding question is closed: ReBAR was
  silently dead because CSM disabled Above-4G at boot (the board's own
  help note names it; the sibling lab's rings 49-50 predicted it from
  the IFR grammar). Fix = one BIOS toggle. Measured before/after:
  BAR1 256 MiB → **8192 MiB**, Region 1 relocated above 4 GB at the
  full 8 GB window. The GPU's VBIOS supported ReBAR all along — no
  firmware update ever needed. See `lab/findings-gx18.md`.

- **ring 19** — the performance campaign, measured honestly: the LACT VRAM
  offset is provably applied (6801 → 6901 MHz under load; LACT "+200" =
  NVIDIA "+100 MHz") but shows **no demonstrated gain** in paired runs, and
  the power limit already sits at its 250 W ceiling — software OC is closed
  with no invented numbers. The GUI's broken Revert button bypassed via the
  daemon's socket API. The firmware route is now unlocked 100 % on the PC:
  a Limine `nomodeset` maintenance boot entry (reversible, backup kept) plus
  a read-only double-read ROM dump script with sha256 cross-check. Next:
  one maintenance reboot → full ROM read → diff against the known image →
  the decoded vP-state/power tables become writable. See
  `lab/findings-gx19.md`.
