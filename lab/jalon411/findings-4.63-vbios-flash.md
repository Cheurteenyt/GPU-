# findings-4.63 — VBIOS FLASH: le chemin matériel (the stock-ROM route, the ID-gate autopsy, the 280 W confirmation design)

Scope: the research pass the founder ordered (T1 the TechPowerUp census, T2
the patched nvflash, T3 the power-table offsets, T4 the runbook). Zero GPU
writes this pass; the flash day itself = runbook-463 §2 (the gated VM day).
Everything below is either the campaign's own banked bytes (cited) or
curl-verifiable vendor/community sources (the method noted per claim).

## §1 T1 — the census: what exists, and the 280 W verdict

**The TechPowerUp VBIOS Database, MSI / RTX 3070: 39 entries** (the
filtered listing `?architecture=NVIDIA&manufacturer=MSI&model=RTX+3070`,
fetched by curl with a browser UA — the LISTING pages are reachable, the
details/download pages are behind the JS bot check: PoW + fingerprint +
playwright-detection, 113 KB obfuscated; the headless-browser route is
hard-403 from this environment, TLS-level). The full parsed table =
`vbios-463/msi_3070_list.json` (the pass's working copy, out-of-repo; the
repo carries the verdict table below).

The Gaming family (our board's cousins), by version/build:

| board | versions (TPU) | boost | power consumption (MSI official) | budget verdict |
|---|---|---|---|---|
| GAMING TRIO | 94.04.3A.40.91 (210309) | 1770 | — | (not decoded this pass) |
| **Gaming Trio Plus (OURS)** | **94.04.46.00.EB** (210519) | 1770 | — | **{100 W, 240 W, 250 W}** ring-3 byte-exact |
| GAMING X TRIO (launch) | 94.04.25.40.82/.C5, 94.04.25.80.6C (2009-10) | 1830 | 240 W | {100, 240, 250} ring-3 (the .C5 specimen) |
| GAMING X TRIO (LHR-era) | 94.04.3A.00.D8, 94.04.3A.40.90 (201117/29) | 1830 | 240 W | board-marker law ⇒ 240/250 |
| GAMING Z TRIO | 94.04.46.00.EA (210518) | 1845 | **240 W** (spec page) | board-marker law ⇒ 240/250 |
| SUPRIM | 94.04.3A.40.7F/.80, 94.04.46.00.E6/.E7 | 1830 | — | (not decoded this pass) |
| **SUPRIM X** | 94.04.25.C0.19/.1E (201108/09), 94.04.3A.00.D6/.D7 (201117), **94.04.46.00.E4/.E5 (210519)** | **1905** | **280 W, 2×8-pin** (spec page) | **the target family** |

- **MSI official spec pages** (read via the page-extraction service; the
  plain SPA pages are curl-empty): SUPRIM X RTX 3070 = **Power consumption
  280 W**, 8-pin × 2, Extreme Performance 1920 MHz; GAMING Z TRIO = 240 W,
  8-pin × 2. **The Suprim X family = the only MSI RTX 3070 at 270-280 W.**
- **The budget is a BOARD marker, not a generation marker** (the ring-3
  law, already byte-proven inside our own family: the same-build-date
  Ventus 3X OC reads 220000/220000 while the Trio Plus reads
  240000/250000). Therefore non-LHR vs LHR within a board does NOT move
  the budget — the LHR seam moved the table FORMAT (rlen 67 → 71), never
  the watts. The mission's "non-LHR ET LHR" comparison resolves to: the
  same budget per board across the seam; the 280 W = the Suprim X alone.
- **The recommended target = MSI.RTX3070.8192.210519.rom (Suprim X,
  94.04.46.00.E5, TPU id 277875)** — LHR-era, OUR OWN 46.00 family, same
  build DATE as our card's EB (210519). The pre-LHR alternatives
  (25.C0.19/.1E, 3A.00.D6/.D7) stay named for completeness.
- **The community precedent** (r/overclocking kuiwbg, fetched read-only):
  "MSI 3070 Gaming X Trio VBIOS flash results (flashed to MSI 3070 Suprim,
  280 watts)" — the SAME cross-flash on the SAME board family: stock
  250 W → the 280 W Suprim vBIOS, daily driver, +150 core / +1000 mem,
  ~280 W drawn in full synthetic, #1 FS Ultra ranking for the 3700X/3070
  class. And the switch question answered: **"No dual bios switch"** on
  this board family — the rollback = the re-flash (see §4).

## §2 T2 — the patched nvflash, named to the byte

**The tool is already in-repo, and the patch is now NAMED**: 
`tools/flash/nvflash-5.867/x64/nvflash-patched` differs from the stock
`nvflash-5.867/x64/nvflash` (both ELF x86-64, NVIDIA Firmware Update
Utility 5.867.0) by **exactly two bytes**:

```
@0x18460B: 0x75 0x18  →  0x90 0x90      (JNE +0x18  →  NOP; NOP)
```

The stock binary's ID-gate reaches its error path through a conditional
jump (`75 18`); the patch NOPs the jump, so a subsystem/board-ID mismatch
prints its WARNING and proceeds instead of refusing. That is the classic
RTX-30 community bypass, byte-identified for our repo. runbook-463 §0
admits the binary ONLY if `cmp -l` reports exactly those two byte
positions — any other binary = refused.

- **The "certificat" nuance, honestly scoped**: a GENUINE vendor ROM
  carries NVIDIA's valid signature — nvflash's integrity/signature checks
  pass unmodified. The certificate wall bites only MODIFIED images. Our
  previous failure (§3) died BEFORE any signature question, on the ID
  gate. The 4.63 route flashes an UNMODIFIED vendor ROM ⇒ zero exposure
  to the certificate wall; the 2-byte patch covers only the
  subsystem/board mismatch.
- **The alternatives, for the record**: nvflashk (TechPowerUp, 2023 —
  the "safe board ID" bypass, flash-anything-signed tool), Modified
  NVFlash v5.667 (the winraid classic, DeviceID/SubsystemID overrides).
  Neither is needed while the in-repo 2-byte patch verifies.

## §3 The autopsy the day-0 record hands us (why 4.63 exists)

The ~35 `day0/vfio-flash-20260919-*` sessions tell one story: the staged
`unlock.rom` (999,424 B, the self-modded image) carried a **ZEROED PCI
head** — every session's nvflash verdict:

```
WARNING: Firmware image PCI Vendor ID (0000) does not match adapter (10DE).
WARNING: Firmware image PCI Device ID (0000) … Adapter PCI Device ID: 2488
WARNING: Firmware image PCI Subsystem ID (0000.0000) vs adapter (1462.3904).
WARNING: None of the firmware image compatible Board ID's match (adapter 02DA).
ERROR: GPU PCI Device ID mismatch.  Nothing changed!  VM FLASH FAILED
```

The transport is thereby PROVEN fail-safe (35 sessions, no write ever
fired unwantingly, the chip-read gate + the watchdog held), and the cause
of the stock 250 W state is NAMED: not the transport, the IMAGE. The
4.63 fix = a genuine vendor ROM (intact IDs) + the 2-byte-patched binary
(the subsystem/board delta IS real: ours 1462:3904 / board 02DA vs the
Suprim X's own values — v463a names the target's at §0).

## §4 T3 — the power table: the offsets where 250000 lives

The grammar is the campaign's ring-3 byte-exact decode (findings-gx3,
`gx3-perf-register.json`, envytools `nvbios/power.c` nameplate, the
NVIDIA BIOS Information Table spec pointer rule) — now re-derived
per-ROM by **`tools/flash/v463a_vbios_decode.py`** (selftest 20/20,
host-only):

```
0x55AA chain → PCIR (image_length ×512, code_type, last-indicator)
BIT table    → magic ff b8 'B' 'I' 'T' 00; hlen @+8, rlen @+9, count @+10
token 'P'    → BIT+hlen+i·rlen; pointer u16 @+4  (the performance table v2)
pointer rule → raw > legacy_len → + UEFI image length (the tail = the table farm)
P-table ptr #11 (rel 44) = POWER BUDGET → table v0x30, hlen, rlen, count
cap index    @table+0xA (which entry is THE cap)
entry k      = table + hlen + k·rlen
min u32 mW   @entry+2     avg u32 mW @entry+6     peak u32 mW @entry+10
```

On the verified sibling specimen (`MSI.RTX3070.8192.210519_1.rom`,
sha256_16 `41a0860f8abfcfa7`, our own version 94.04.46.00.EB):
budget @0x8FB48 (v0x30, hlen 44, rlen 71, 20 entries, cap entry 2) —
**min 100000 mW @0x8FC04 · avg 240000 mW @0x8FC08 · peak 250000 mW
@0x8FC0C**. THE 250000 LIVES AT 0x8FC0C (u32 LE). The live machine
(default 240 W / max 250 W / current 250 W) closes the
VBIOS→driver→runtime chain at the byte level (ring-3, re-cited).

**The 280 W confirmation design**: the Suprim X target ROM is decoded by
the SAME grammar (never the hardcoded 0x8FC0C — the rlen moved at the LHR
seam once already; v463a re-derives and names the new offsets), and the
runbook §0 REFUSES the day unless the decoded peak == 280000 mW. The
whole-image u32 mW census (the 4.38 pair-scanner law: {220000, 240000,
250000, 265000, 280000, 300000, …}) names every candidate offset as the
cross-check. THE T3 GATE IS IN CODE.

## §5 T4 — runbook-463 (the day, in code)

`tools/edpp/runbook-463.sh` (bash -n clean, the ACK refusal tested):

- **§0 the guards** (host-only): the ACK; the device; **the GSP firmware
  sha guard** (the stock file never touched — the VBIOS day is not a
  firmware-file day); the instruments; **the T2 byte-law** (cmp the two
  nvflash binaries == exactly the 2 named bytes); **the admission gate**
  (T463_ROM + T463_MD5/T463_SHA1 = the TPU-published values, the
  ring-12/14 protocol — the founder's browser fetches, we verify);
  **the identity gate** (vendor 10DE / device 2488 / non-zero subsystem —
  the 0000 trap of the 35 sessions, refused in code); **the T3 gate**
  (decoded peak == 280000 mW or the day stops).
- **§1 the decode comparison**: the target vs our stock (the chip dump
  when CHIP_REF= is given) — the T1 table materialized on the day.
- **§2 the VM day**: the day-0 VFIO machinery called with the ADMITTED
  ROM and the BYTE-VERIFIED patched binary; the session V-steps: stage →
  version → **chip read ×2 + cmp (the backup gate)** → protectoff +
  flash + verify → chip read-back ×2 + cmp → verdict. The screen-black
  discipline, the 6-min watchdog, the self-reboot — banked, not
  reinvented. RUNBOOK_463_FLASH_ACK=1 arms it.
- **§3 the verification**: v463a decodes the chip-after dump (identity +
  280000); the live `nvidia-smi -q -d POWER` = 280000 mW; zero-Xid check.
- **§4 the rollback = the re-flash of chip-before.rom** (the same
  instrument reversed; the stock binary suffices — the backup's IDs are
  ours). The dual-BIOS honesty is in code: NO switch on this board
  family — the safety = the byte-identical backup + the proven-never-
  write-alone transport.
- **§5 the contingencies**: the ID refusals parsed by class; the verify
  failure = no second write on the same boot; the Xid path = the
  rollback becomes plan A; the false-zero law (the cmp before nvidia-smi).

## §6 The negative results and the refusals (named, as always)

- **UNFETCHED-BYTES**: the target ROM bytes are NOT in this environment —
  TPU's details/download pages are bot-checked (PoW + fingerprint, the
  headless browser hard-403, archive.org unreachable from here). The
  admission therefore REQUIRES the founder's browser fetch (the ring-12/14
  method re-run: in-app page-context fetch, hashes read off the TPU page,
  verified by v463a before anything boots). The 18 bot-check HTML pages
  saved by curl = the documented negative, not data.
- **REFUSED**: any modified image (the 0000 trap verdict); any binary
  whose diff against the stock nvflash is not exactly the 2 named bytes;
  any target whose decoded peak ≠ 280000 mW; any admission without the
  founder-provided hashes; the GSP firmware file (the sha guard, all day).
- **INDECIDABLE-BY-BYTES here, DECIDED ON THE MACHINE**: the target's own
  subsystem/board IDs and budget offsets (v463a names them in §0, from
  the ROM itself); the post-flash live state (§3).

## §7 The queue (what the day decides)

1. **the J-463 day** (runbook-463): the founder fetches + hashes the
   target → §0-§1 host-only → the VM day (FLASH_ACK) → §3 the 280 W
   verdict → the VRAM A/B battery (the 600 GB/s question inherits a
   280 W envelope: the v451a/v452 lane finally has thermal headroom).
2. If the flash holds: the f18 lane (4.61, the PERSISTENT class) and the
   route-W read lane (4.62) become CORROBORATION instruments, not load
   paths — the budget's peak lives in the VBIOS now.
3. If the day fails at the ID gate with the ADMITTED ROM: the nvflashk
   alternative (§2's named fallback) = the next transport trial, one
   variable per transition.
4. The rollback stays one §4 away, byte-identical, stock-first.
