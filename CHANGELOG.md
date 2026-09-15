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
