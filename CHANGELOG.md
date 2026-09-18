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

Instruments: `tools/gsp-extract/` gains `wave2_dial_names.txt` (the 881
names), `wave2_strings_taxonomy.py`, `xref_dials.py`, `v42_*` (4),
`v43_*` (3), `v44_*` (3), `v45_*` (8), `v46_*` (6: dials, window, ctor,
check, enum, enum2) — 26 files.

- **ring 34** — the timing record grammar, first decode: the 76-byte
  records are 19 packed 32-bit FBPA timing registers (one bank per
  frequency bin); scaling classification across the 7 bins maps the
  cycle-count fields vs constants; the FBPA bit-layout decode (envytools
  grammar import) is the next session. rm.elf patching formally closed
  (bootloader signature chain). See `lab/findings-gx34.md`.
