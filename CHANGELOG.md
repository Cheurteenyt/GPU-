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

- **ring 20** — the chip speaks. The full ROM read that ring 13 called
  in-session-exhausted is done **with the driver loaded and the desktop
  live**: the kernel PCI core serves the sysfs ROM attribute on its own.
  Double read byte-identical (157,696 B, sha256 `135b2153…`), PCI chain
  self-certified complete (x86 65,024 B + EFI 92,672 B, end bit set),
  version `94.04.46.00.EB`, device 2488. Two lessons kept: `nomodeset`
  doesn't stop initramfs module load (it moves the console to simpledrm),
  and the downloaded reference image was partial **and not the board's
  build** — all decodes move to the chip dump. Write phase stays behind
  nvflash + the maintenance boot. See `lab/findings-gx20.md`.

- **ring 21** — the chip's geometry, measured. The legacy half matches the
  reference build (BIT/PERF/identity identical; only header-level deltas),
  but the performance tables provably live at ~551-563 KiB of a ~976 KiB
  image, while the host-visible ROM window is 512 KiB — the BAR read (now
  conflict-guarded, probe-classified, BAR restored) confirms the sysfs dump
  byte-for-byte and ring-13's all-FF artifact is explained (v1 guessed an
  address outside the bridges' decode ranges). Scratch-hole assignment
  master-aborts; only the firmware-assigned window decodes. Next: nvflash
  beyond the window on the nomodeset boot, detached (v4 script built).
  See `lab/findings-gx21.md`.

- **ring 22** — the no-reboot hunt, closed with receipts: sysfs is
  chain-capped by design, the ROM window is 512 KiB of hardware, the chip's
  upper half is unique (no SPI aliasing), BAR1 and System RAM are sealed
  while the driver is bound (EIO/EPERM, STRICT_DEVMEM beats iomem=relaxed
  for RAM), nvflash refuses and nvflashk is Windows/certificates only, and
  the RM SDK exposes no image-read control. The proprietary driver ignores
  `nomodeset` (fbdev held the console — the ring-13 wall reproduced); the
  maintenance entry now forces `nvidia_drm.modeset=0 nvidia_drm.fbdev=0`,
  which unblocks the detached full-read. One maintenance reboot delivers
  the image and re-trains the display from POST. See `lab/findings-gx22.md`.

- **ring 23** — the in-session full read, delivered by identity: /proc/kcore
  (immune to the /dev/mem seals) reveals the driver caches only the ROM
  chain, and the 512 KiB BAR window is **byte-exact** the
  MSI.RTX3070.8192.210519_1 build shifted by 0x9200 — so the chip's full
  976 KiB content already sits on disk in the acquisitions. The board's
  real tables decode immediately: power budget 100/240/250 W (matches the
  live NVML range to the watt), fan curve 17/45/100 % @ 55/75/80 °C →
  1000/2100/3250 RPM, vP-states 2100/7001 caps covering the live 6801,
  memory bins and PERF constants. The firmware confirms the measurements:
  **no hidden headroom — the performance campaign is closed honestly.**
  ReBAR +8 GiB stands as the one real gain. See `lab/findings-gx23.md`.

- **ring 24** — gsp.bin peeled: the 84 MB firmware is an ELF wrapping a
  .fwimage whose anatomy is now mapped — RISC-V bootloader + signed section
  directory (13 entries: seven per-chip GSP kernels, debug/init/vgpu/mnoc,
  rm.elf at 17.2 MB, and a 64.5 MB rm.bindata.bin at entropy 8.00 compressed
  by the bootloader's proprietary LZ). The SES/SPI engine code the nvflash
  hint pointed to lives inside that bindata — reaching it is ring 25's
  bounded target. See `lab/findings-gx24.md`.

- **ring 25** — the fan-curve/boost experiment, closed honestly: the new
  mid-range curve measured +30 MHz (1440p) and −15 MHz (4K) — both inside
  noise, because glmark2 tops out at 109 W of the 250 W ceiling and the GPU
  never reaches the temperature region where fan behavior matters. The
  automated keep/restore rule put the stock curve back. The decisive
  measurement is a real game with MangoHud (founder-side). Also: the
  3644→3645 BIOS diff verdict — one replaced module + cert rollover, stay
  on 3644. See `lab/findings-gx25.md`.

- **ring 26** — the pivot: RE becomes modification. `vbios-power-mod.py`
  builds a verified 280 W power-budget VBIOS offline (six bytes, cap entry
  re-derived from scratch, sanity ceilings, independent re-decode as
  verification) — the GPU untouched; flash stays behind the live-USB +
  real-chip-read + dual-BIOS procedure. The full power table anatomy is
  mapped (20 entries: the cap, the board-total sense point, per-rail
  budgets). GSP bindata recon: the compressed stream starts page-aligned
  at 0x12d1000 behind a 3.5 KiB uncompressed table; llvm-objdump (RISC-V)
  is the tool for the bootloader LZ in ring 27. See
  `lab/findings-gx26.md`.

- **ring 27** — the GSP bootloader is readable: minimal-ELF wrapper recipe
  (e_flags must carry the RVC bit or llvm-objdump renders every compressed
  instruction unknown), 5,370 instructions decoded, the directory parser
  entry confirmed (a4 = 0x16d000), the width-dispatch table located, and
  the bindata framing confirmed coded-only (no plaintext header). The LZ
  format walk is ring 28. See `lab/findings-gx27.md`.

- **ring 28** — the fwimage memory map is complete: ~20 KB of bootloader
  code + 408 KB of zeros + directory + 12 ELFs + the 64 MB bindata stream
  (page-aligned at 0x12d1000). Negatives proven: not raw LZ4-block, not
  deflate, no plaintext. Prime suspect isolated: the 4 KiB code blob at VA
  0x120000 — ~1,024 instructions, reversible in one focused session. See
  `lab/findings-gx28.md`.
- **ring 29 conclusion** — the bindata is encrypted, proven by statistics
  (perfect entropy/uniformity/zero autocorrelation) — the LZ hypothesis is
  closed; the anti-tamper boundary is documented and deliberately not
  crossed. Pivot: rm.elf (17.2 MB plaintext RISC-V) is the new deep target
  — the RM's power heuristics are readable. See `lab/findings-gx28.md`.

- **ring 30** — the founder's intuition proven: the RM exposes 881
  registry dials (census in `tools/gsp-extract/rm-strings.txt`), and the
  perf-limit family (`RmPerfLimitsOverride`, `RMDisablePerfIntersect`,
  `RmBootGspRmWithBoostClocks`, …) is settable through
  `NVreg_RegistryDwords` — no flash, one dial per reboot, reversible. The
  test matrix is the next deliverable. See `lab/findings-gx30.md`.

- **ring 31 completion** — benchmarks stopped per the founder's call, the
  concrete advance delivered: the Arch live USB is flashed and
  sha256-verified onto the backed-up key, and
  `tools/usb-flash-session.sh` chains the entire mod session with hard
  gates (chip read → identity check against build 210519_1 over 512 KiB →
  verify → protectoff → flash the 280 W image → re-verify → rollback
  instructions). One USB boot runs the whole thing.

- **ring 32** — the in-session flash attempt (detached, auto-restore) hit
  two new seals and is documented: `resource_resize` is EPERM on this
  kernel (BAR shrink unavailable at runtime) and the driver pin survives
  the runtime console release. The live-USB route stays the flash path —
  now with the ReBAR/BAR1 shrink step and `iomem=relaxed` baked into the
  USB boot entries (the Arch ISO kernel lacked it — the real root cause
  of nvflash's "system restart" error, warm or cold). The founder's
  3DMark-on-Linux tooling (official UL-validated Time Spy under Proton)
  is archived in `tools/3dmark-linux/` with its run ledger — the
  validation instrument for every future change. BIOS- lane: the
  founder's write-layout map committed (protected-head vs readable-body).

## Unreleased — the cloud RM campaign (2026-09-18): five vagues from the strings to the VF-point bit

Cloud-side (no GPU access), mining the full `rm.elf` — the 16,912,384-byte
RISC-V plaintext behind `win.elf`, extracted from the official NVIDIA
package — plus the 881-dial census of ring 30. The ring-30 promise ("the
dials are settable") becomes readable code. Deliverables in
`campagne-rtx3070/` (French, one doc per vague), instruments in
`tools/gsp-extract/`; the v42/v44 JSON caches are reproducible from the
instruments + `win.elf` and are deliberately not committed.

- **vague 1 (Task 61)** — the real-game verdict re-derived: Genshin
  (3 193 samples) is VOLTAGE-limited, not power-limited — 1890 MHz pinned
  with ~15 W of margin under the cap, 19 °C at throttle onset; the 280 W
  flash buys Genshin nothing, the core offset is lever #1. The full lever
  map re-qualified from the 31 rings, with machine-side directives.
- **vague 2 (Task 62)** — the punitions mapped + the omarchy bridge: the
  881 dials are settable host-side via `NVreg_RegistryDwords` under
  nvidia-open-dkms (GSP mandatory, the mkinitcpio early-load trap), and
  the LHR verdict lands by proof of absence — zero ethash strings in the
  whole RM, the limiter lives in the closed host driver.
- **vague 3 (Task 63)** — the safety doctrine: a broken dial is volatile
  host RAM (zero NVRAM/flash/SPI), classes A/B/C/D, the rescue ladder
  verified against omarchy's own files, the kill-switch
  (`module_blacklist=nvidia,nvidia_drm`), the Xid radar (79, 119/120).
  `campagne-dial-gate.sh` is the gate (`--status`/`--rollback`, ledger at
  `/root/DIAL-ROLLBACK.txt`).
- **vague 4 (Task 64)** — the wall crossed: the rm.elf extracted, indexed
  and disassembled cloud-side (v42 build_index/query/tables/extract;
  clusters, xrefs, tables JSON); the first calculations decoded; the
  encrypted-rodata boundary mapped.
- **vague 4.2 (Task 65)** — the RM's arithmetic: internal limit tables,
  encoding formats and the power tree, read directly in the RISC-V bytes.
- **vague 4.3 (Task 66)** — the branches unrolled: every mode of the
  limit dispatcher followed instruction-exact to its machine effect
  (P-state flags, voltage rails, conversion tables), the 16
  `RmPerfLimitsOverride` combinations, the generic 0x400 P-state
  invalidation poke.
- **vague 4.4 (Task 67)** — the `RmVFPointCheckIgnore` milestone, sold:
  dial → generic parser (0x1631010) → instanciation → 5 text vtables →
  setter 0x1630c48 (`requestCapabilityChange`: +0x324 effective, +0x328
  pending, +0x350 recal callback) → commit bit 0 → engine 0x1634a38 →
  request type 0xc. The first partial breach of the encrypted-rodata
  wall: the vtables sit IN the text.
- **vague 4.5 (Task 69, cloud GLM 5.3 Flash)** — the capability-bit map:
  the whole X-R segment linearly disassembled (5 342 005 instructions,
  capstone, 7 s) and the setter's callers counted PROPERLY — the wave-4.4
  "zero references" was a jal-only artifact: 42 direct auipc+jalr callers
  cover bits 0-11. Bit 8 is NAMED: `RmPerfChangeSeqOverride` (branch
  0x1631394 → 0x1631824, value & 1), armed symmetrically by the ClkAdc
  module (SET-if-absent / CLEAR-on-teardown), read by the engine as the
  second-check skip. The other six CheckIgnore dials consume by NAME
  (generic lookup 0x10432d4 at the check site), never through the
  capability word — the wave-4.4 "same state object?" hypothesis is
  refuted with proof of absence. The VFPoint handler is a full
  re-sequencer: mode 4, callback 0x169455c, request 0x1456c7c, SET bit 1,
  8 VF entries invalidated, SET bit 0.
- **vague 4.6 (Task 70, cloud GLM 5.3 Flash)** — the grand perf parser and
  the request enum. The parser proven to be ONE function
  (0x1631300-0x1632790, epilogue-anchored); its four dials pinned
  instruction-exact — RMDisablePStates 0x1631e02 / AllowMaxPerf 0x1631e28
  (shared block: the 0x13 type written in-state at [s1+0x8A9A0], a
  0x3000-byte stride-0x18 table wipe, the VF parser 0x1631010 re-called),
  RMDisablePerfIntersect 0x16322c6 (object search BY dial value, the
  '3b1w1d4b' DRAM timing under the ==0xd carveout test), PerfPmaControlReg
  0x1632714 (value==1 → in-state callback [s1+0x288]; otherwise request
  type 0xf via the ctor's sibling 0x14561b8). Bit 9 CORRECTED: not a dial
  — the exit state of the P-state revalidation loop (mask s4 |= 1<<idx,
  the 0x400 poke, then SET bit 9). The request enum closed on the
  constructor 0x1456c7c: 52 direct callers, 52 distinct ENCRYPTED format
  tables, 17 type values resolved over 28 sites — v42's "normal" types
  0x10/0x13/0x1d land exactly where predicted, 0xf is alive, and the two
  type levels (prep format vs engine dispatch) set the vague-4.7 jalon.
- **vague 4.7 (Task 71, cloud GLM 5.3 Flash)** — the reconciliation, closed
  as a PROOF OF SEPARATION. The finder 0x1457440 finally called: four
  auipc+jalr sites from the engine dispatcher 0x1634a38 (0x1634b5c/0x1634ba4/
  0x1634bd6/0x1634bfc, a1 = 0x10/0x13/0xc/0x1d, a0 = [s2+0x3CD0]) — the
  constructor's 17 N values are TABLE FORMATS, not request types. The 0xc
  request is gated by capability bit 0 (lw 0x324; andi 1 at 0x1634bc2).
  Bit 8 gains its engine arm: idempotent sync at 0x16355be-0x1635662 —
  read (sraiw 8; andi 1), compare to request field +0x18, setter only on
  delta (SET 0x1635662 / CLEAR 0x16355d6) — a poke of the bit itself would
  be corrected back. The PerfPmaControlReg callback mechanics closed: two
  exits to the fallback path (dial absent OR value != 1), callback
  [s1+0x288](dispatch, rm, 1) with NO null guard (field guaranteed
  initialized), fallback type 0xf via 0x14571b8 (address corrected from
  0x14561b8 by script). The "P-state pass" 0x1b3c4f0 (address corrected
  from 0x1b3c4f4) is GENERIC REVALIDATION: 52 auipc+jalr callers census;
  the bit-9 loop is an internal block of the grand parser, entered by the
  mode-7 path (ctor N=7 → pass a1=16 ×2 → pass 0x40 → pass 8 → SET bit 9).
  The capability object self-registers: [state+0x88130] is a full BOARDOBJ
  carrying mode byte (+0), the capability word (+0x324) and callbacks
  (+0x460 = 0x169455c written by the small parser itself at 0x16312b0);
  the PMA callback (+0x288) travels by field-by-field clone — nominative
  attribution honestly unresolved, reported to vague 4.8. Bit 11 from the
  dispatcher demoted (context-window artifact). Zero machine-side changes:
  levers 1-3 unchanged, all consolidated.
- **vague 4.8 (Task 72, cloud GLM 5.3 Flash)** — the plaintext haul. The
  0x20-0x4F whitelist bitmap READ FROM THE FILE: auipc a4, 0x84e; ld a4,
  0x72e(a4) resolves to VA 0x1e83d38 (file offset 0xe83d38, first LOAD,
  unencrypted) = 0x0001000100210001 → exactly FOUR allowed sequence IDs
  0x20/0x30/0x35/0x40 (a fifth bit, 0x50, is set but unreachable through
  the bltu 0x30 gate); bit clear → log (format 0x202c74f0, volatile rodata)
  + return 0x56, bit set → sequence handler [s7+0x348](s6, s2, s7,
  &req+0x314) with the ≤9 count guard and [req+0x31c] = -1. SAFETY ANSWER:
  the whitelist does NOT bound the RmPerfChangeSeqOverride dial — the dial
  path carries no request, beqz skips the whole policy. Bit 8 REVERSED: the
  dispatcher FORCES it at sequence-request entry (0x1635516/0x1635522: cap
  object absent OR bit clear → 0x1635656, hardcoded a3=1 → setter, then
  main path) — bit 8 is the "sequence change in progress" state; the 4.7
  sync is ONE site (0x16355d6, a3 = request value +0x18, both directions);
  the 0x1635662 site is the entry force, not a sync arm (correction
  recorded). 0x1b3c4f0 renamed AGAIN — a GENERIC KEY-FINDER: list at
  [root+0x1100], count [list+0x170] (byte), accessor [list+0x38], item key
  [item+0x28], out-index, return 0/0xFFFF; the 52 callers' keys census
  (0x10 ×11, 0x8 ×5, 0x1 ×4, 0x40 ×3, 0x2, 0xff, 13 register-derived);
  the "P-state passes" are key-0x40 then key-8 SEARCHES: found item's
  [item+0x60] callback invoked (s2, s6, item), s4 |= 1<<found_index — the
  4.6 accumulation decoded. The 0x1b3c4f0-0x1b3ca10 cluster mapped (five
  utilities) and TWO CODE MAPPERS DECODED from file-backed rodata jump
  tables — 0x1DEB210 (27 entries: 0→0x11, 1→0, 2..16→i−1, 20→0x1e, 21→0x1f,
  invalid→0x1c logged) and 0x1DEB280 (i→i+1, 9 entries) — 5-bit
  packed-field decoders (bits [8:4], [20:16]) in the memory-timing module
  0x1bd9xxx. The "+0x288 cloners" are SELF-POINTER CONSTRUCTORS
  ([obj+0x288] = obj+0x3b8 — the 4.7 clone hypothesis corrected; those
  sites cannot feed a jalr); the perf-state destructor found (0x164b7be:
  destroy + null of [s2+0x88130] and [s2+0x8F188], crossing the 4.6
  +0x8F180 config — the capability object dies with its carrier); the
  grand parser bulk-inits ~160 0x14-byte records at state+0x881A0 with
  +0x88000 back-pointers. The +0x288 code-pointer writer honestly still
  open: four scan families exhausted (constants, self-pointers, fused
  lui-0x88, vtable-slot loads), bulk-init hypothesis. Machine levers
  unchanged; the whitelist is new defensive knowledge (0x56 in an RM log
  = "sequence not on the list").
- **vague 4.9 (Task 73, cloud GLM 5.3 Flash)** — the constructor proven
  ABSENT, the lists named by their roots, the packed word traced to
  hardware. The +0x288 writer question (open since 4.7) closed by PROVEN
  ABSENCE: all 261 sd/sw stores to +0x288 in X-R classified by value
  origin — ZERO carry an auipc-resolved code address; every pointer
  transits memory/registers (third structural negative: +0x88130 (4.8),
  +0x1100, +0x288 — the RM's BOARDOBJ wiring is installed transitively,
  never by nominative stores). The 4.7 "dominant families" REVERSED:
  0x1915574/0x193cc44 are not vtable-construction regions but TINY NO-OP
  STUBS (six-instruction functions, confirmed at file; no static template
  holds their pointers — 0 matching qwords in both LOAD segments) — 18/17
  object families receive no-op default callbacks at +0x288, giving
  PerfPmaControlReg=1 "observation only" its mechanical explanation. The
  destructor's carrier function anatomized (0x164b388-0x164c7c8, 1585
  insns, pointer-dispatched — zero direct callers, zero address-taken
  refs): it searches type 0xf (the PMA fallback type) AND type 0x16 via
  the finder 0x1457440 with root [state+0x3CD0] — DOUBLE PROOF with the
  4.7 fallback path: +0x3CD0 is the PMA-fallback list holder; it also
  calls 0x1630b60(root) (unnamed, setter region) and the destroy utility
  0x18e8ae0 repeatedly. The grand parser's TRUE entry is 0x1631010 (4.6
  anchored mid-function at 0x1631300); signature (a0→dispatch, a1→rm
  state) matches the PMA callback convention, and the mode==0 entry path
  calls the capability setter 0x1630c48 immediately (0x1631310). The
  key-finder pinned instruction-exact with two 4.8 corrections: miss
  return is 0x10000 (not 0xFFFF; empty list returns 0, out-index
  unwritten on miss), the key is a 32-BIT read at [item+0x28], and the
  list is RELOADED from [root+0x1100] EVERY iteration (mutation
  tolerant). The 52 callers' roots classified: the grand parser searches
  key 0x10 with a frame handle (s0-0x90, fed by a prior call result);
  the 0x17677xx block is a KEY→INDEX TABLE BUILDER (root [s4+0x1ED0],
  ≤0xa guard, writes [s3+0x64+idx*2]); zero stores to +0x1100 — the list
  catalogue is runtime-dynamic and NOT statically enumerable (the honest
  verdict). THE STRAP→CODE CHAIN CLOSED BOTH ENDS: the two mappers live
  in the 0x1b3c cluster (0x1b3c5ec bound-27, 0x1b3c708 bound-8 — 4.8's
  module attribution corrected; 0x1bd9xxx holds the CONSUMERS); JT1 read
  from file case by case (adds 24..26→0x1c store-only, exact bltu bounds,
  EBREAK-guarded error path), JT2 k→k+1 confirmed; the consumer
  0x1bd979c sources the packed word from a VTABLE CALL that receives
  HARDWARE REGISTER OFFSETS — 0x68A00C + (index<<10) then 0x68A01C +
  (index<<10) (page 0x68Axxx, 0x400 domain stride); bit 31 split out to
  [out+0xc], fields [1:0]/[8:4]/[11:10]/[20:16]/[23:22] mapped to
  [out+0x24]/JT1→[out+0x2c]/[out+0x28]/JT1→[out+0x38]/[out+0x34]; the
  single caller wrapper 0x12b5c88 gates a3!=0 and shifts args. JUNCTION
  with the founder's rings 38-39 (VMIN hunt, pushed during the mining):
  the 0x68Axxx page is the machine-side reading target; the JT1 case
  bodies (0x1b3c684-0x1b3c6c6) are the field grammar — 28 identities,
  two logged unknowns, three extension values 0x1e/0x1f. Machine levers
  unchanged, rank 3 consolidated with a mechanism.

- **vague 4.10 (Task 74, cloud GLM 5.3 Flash)** — the domain-classes built
  at runtime, the SIX sibling registers, the domain namespace. The wrapper
  0x12b5c88 fully disassembled (74 insns — never done before): it is NOT a
  plain arg translator; after the consumer call it chains FOUR more vtable
  reads on the same [holder+0x50] object with UNSEEN sibling registers:
  +0x008 (bit 3 → [out+0x44]), +0x030 (bit 16 → [out+0xb5]), +0x368
  (16-bit halfword SWAP → [out+0xe8]), +0x36C (raw 16 bits → [out+0xec]);
  the pre-wrapper adds a fifth extraction (+0x030 bits 17+ → [out+0xb0]).
  The 0x68Axxx page holds SIX exploited registers per domain, not two.
  The pre-wrapper's true entry is a TRAMPOLINE at 0x12c7a1c (c.beqz a3,
  +0x58 short-circuit; guarded by ld 0(zero)+c.ebreak anti-exec barrier;
  4.9 address corrected). SIX reference mechanisms proved NEGATIVE across
  (pre-wrapper, wrapper, consumer): 0 static pointers, 0 auipc+addi
  formations, 0 lui+addi, 0 rodata base+off jump-table hits (full scans),
  no ELF relocations (EXEC, 3 phdrs) — the SEVENTH mechanism is POSITIVE
  and exact: the mega-constructor (0x192xxxx, >8000 insns, site
  0x1922358/0x191f2a4) stores 0x12c7a1c into a FLAT RUNTIME VTABLE at
  [obj+0x928] (row -0x6e0..-0x6a8: methods 0x12c79bc — same trampoline
  motif, 0x1914594, 0x127d2f4, 0x19145ac, 0x128e5a8); v50_window maps 351
  address formations to 30+ module functions posed by SEVEN
  mega-constructors (0x1928b44/0x1949cb4/0x1964a90/0x1973924/0x19751c0/
  0x197a2ac/0x1980e94) — the 0x12b5xxx-0x12c7xxx module is an LTO class
  family, instantiated at runtime. THE DOMAIN NAMESPACE found in-file:
  0x1e05fc0-0x1e05ff0 = DRAMCLK, LTCCLK, XBARCLK, HUBCLK, SYSCLK, AWP,
  RRRB (SEVEN domains, indexed 0..6 by the timing engine 0x136ecb4 — the
  only function citing them; builds the runtime name table, calls slot
  +0x400, computes picosecond conversions via const 999448120832 ≈ 1e12,
  ring-39-style integrity canary). The VMIN/rail lexicon mapped in the
  0x1e78xxx zone: VMIN_LOGIC/SRAM/NVVDD_0-1/MSVDD_0-1, OVERVOLTAGE_*,
  RELIABILITY_*, THERM_POLICY_*, PMU_DOM_GRP_*, UNLOAD_DRIVER_VOLTAGE_
  RAIL_0-3, PWR_RAIL_MISMATCH, PERF_CF_CONTROLLER_{DRAM,GPC,NVD}_{MIN,
  MAX}+XBAR_MAX — the junction vocabulary for the founder's rings 38-39.
  The 28 JT1 identities stay the closed per-domain state grammar;
  individual naming goes to the live-reading protocol (deliverable §4).
  Reader implementation (+0x28) honestly still unnamed (generic BOARDOBJ
  slot, 3090 call sites); the holder writer [+0x3AF0] unfound (0 stores
  in 0x19xxxxx). Deliverable §4 poses jalon 4.11: the holder constructor,
  the +0x400 timing consumer, JT1 identities vs PERF_CF controllers.

Instruments: `tools/gsp-extract/` gains `wave2_dial_names.txt` (the 881
names), `wave2_strings_taxonomy.py`, `xref_dials.py`, `v42_*` (4),
`v43_*` (3), `v44_*` (3), `v45_*` (8), `v46_*` (6: dials, window, ctor,
check, enum, enum2), `v47_*` (5: explore, explore2, resolve, hunt,
registr), `v48_*` (10: bitmap, policy, pass, find, clone, ctor, ctor2,
ctor3, ctor4, vtbl288 — the ctor/ctor2/ctor3 iterations kept for the
audit trail of the same chantier), `v49_*` (11: ctor, ctor2-ctor6 (the
five scan families of the +0x288 hunt, kept for the audit trail),
lists, lists2, straps, straps2, straps3), `v50_*` (12: wrapper, domain,
reader, ptr, ptr2, window, slot28, holder, holder2, jtscan, micro,
semantics).

- **ring 34** — the timing record grammar, first decode: the 76-byte
  records are 19 packed 32-bit FBPA timing registers (one bank per
  frequency bin); scaling classification across the 7 bins maps the
  cycle-count fields vs constants; the FBPA bit-layout decode (envytools
  grammar import) is the next session. rm.elf patching formally closed
  (bootloader signature chain). See `lab/findings-gx34.md`.

- **ring 38** — THE MONSTROUS LEVER: the VMIN checks (VMIN_NVVDD/SRAM/LOGIC
  — the power-efficiency governors) are dial-ignore-able
  (`RmSramVminCheckIgnore`), read by OUR firmware (2 consumer sites pinned
  in our rm.elf 610.57.04). Ignoring them lowers the VF curve floor = at
  the 250 W cap, more MHz — the undervolt-by-firmware. Test protocol
  defined (paired dials + Genshin + voltage/clock metrics, volatile,
  crash-recoverable). See `lab/findings-gx38.md`.

- **ring 40 verdict** — the 5-dial stack tested by official Time Spy:
  graphics 11,874 vs 11,957 comparable stock = noise. **The dial-lever
  hypothesis is refuted** — the checks the dials bypass don't bind at
  stock; the wall is silicon/voltage. Stack removed, stock restored. The
  honest levers: the 280 W flash (power-saturated loads) and the timing
  mod (bandwidth). See `lab/findings-gx40.md`.

- **ring 35** — THE SCALING LAW: the 19 FBPA timing registers hold
  **constant-ns timings as per-bin cycle counts** (value/frequency =
  constant µs — proven exact across all 7 bins, e.g. register 9-hi =
  4.67 µs at every bin). ns = cycles/frequency names every field against
  the JEDEC GDDR6 spec — the timing mod design path is open. See
  `lab/findings-gx35.md`.

- **ring 41 result** — THE MONSTROUS LEVER DELIVERED: the VF-curve
  construction reversed empirically (4 offset dumps diffed — LACT as the
  oracle): the core offset shifts the whole curve up — at the founder's
  own Genshin voltage (987 mV), the card now runs 1995 MHz instead of
  1890 (+5.6 % clocks at equal voltage — the undervolt-and-boost
  simultaneously). Offset +225 applied live; MangoHud auto-log armed;
  the crash-test is the game itself; rollback = one line. The curves are
  saved in `tools/gsp-extract/vf-curve-offsets.json`.

- **ring 41 resolution** — the bindata mystery SOLVED from the open
  source: it is NVIDIA's documented bin-archive system (g_bindata*.c, MIT)
  containing the boot-stage components (RM boot ucode, SEC2 ucode,
  certificates), compressed with the proprietary LZ (~20 % ratio). NOT the
  performance path — the power policy lives in plaintext rm.elf where the
  cloud campaign mines it. The lane closes on VALUE, not difficulty. See
  `lab/findings-gx28.md` resolution.

- **ring 42** — THE UNLOCK ROM: the clock caps (vP-state 2100 → **2200 MHz**,
  first+second+third limits, u16×4 encoding cracked) AND the power budget
  (250 → **280 W** peak) in one image — every patch gate-checked against
  the decoded values, re-verified by the CPR parser and the power decode.
  The flash kit re-targeted. The combined unlock: caps + power + the RM
  dials if they ever bind. See `tools/vbios-unlock-mod.py`.

- **ring 41 architecture** — PROVEN BY ABSENCE: "BIT\0" appears zero times
  in rm.elf — the host driver parses the VBIOS and passes the parsed data
  to the GSP via the init RPC. The timing table's consumption semantics
  live host-side (closed); the VBIOS EDITS still propagate (the host
  parses the edited table). The mods remain valid without the consumer
  decode. See `lab/findings-gx41.md`.
