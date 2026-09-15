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
