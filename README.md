# GPU- — the RTX 3070 unlock research lab

> **From read-only VBIOS intelligence to the CERT20 break.** The sibling of
> [BIOS-](https://github.com/Cheurteenyt/BIOS-): the same doctrine — work
> from evidence, registers before verdicts — applied to a live
> **MSI RTX 3070 Gaming Trio Plus LHR (GA104, VBIOS 94.04.46.00.EB)**.
> The lab began as read-only firmware intelligence (the eight rings),
> built the factory-limit unlock ROM, hit NVIDIA's CERT20 write
> enforcement, mapped it end-to-end, and adopted the community-published
> break that walks around it at runtime.

## The three phases

| Phase | What happened | Where |
|---|---|---|
| **I. Read-only intelligence** (rings 0-42) | the VBIOS decoded table by table: power budget, memory ladder, timings, fans, vP-states, the Falcon ucode inventory — and the **unlock ROM built** (caps 2200 MHz + 280 W, gate-checked) | `lab/findings-gx*.md`, `CHANGELOG.md`, `tools/vbios-unlock-mod.py` |
| **II. The write campaign** (15 VM flash runs) | the full EEPROM write path walked inside a QEMU/VFIO VM; every failure named and fixed; **the CERT20 wall proven**: Falcon VV (`SIG_INVALID`) + PMU EWR (`OK_TO_FLASH_CHECK_FAILED`) refuse any modified image | `day0/vfio-flash-*/`, `tools/vfio-flash-session.sh`, the `CHANGELOG` CERT20 entry |
| **III. The published break** (now) | the community exploit (the unbounded signature DMA in the SEC2 booter → the canary defeated by uniformity → the PC hijack → the PLM opening → the runtime register writes) — **validated end-to-end in emulation on OUR firmware**; the GA104 discovery campaign (the mailbox oracle) is designed | `tools/cert20-plm-feat-test.py`, `lab/findings-cert20-e2e-pass.md`, the cmp170hx wiki (cloned sibling) |

## The current phase: the GA104 discovery campaign

The exploit is validated mechanically on our firmware (the emulator: 16
BAR0 writes, 0 deviations). What remains is die-specific discovery:

1. **The baseline fire** — the uniform fill V=0x4a7 (the GA100 value) on
   our GA104; the CSB MAILBOX0 read-back tells which code path ran
   (MB0=0x47 = the canary abort; silence = the hijack).
2. **The V sweep** — candidate addresses, one driver cycle each, the
   mailbox oracle mapping the booter's code paths without ever reading
   the encrypted image.
3. **The chain** — write_addr/write_value at the discovered slots → the
   PLM opens → the power-limit register (250 → 280 W) hunt in the
   FEAT_OVR space.

Everything is volatile (lost at power cycle, reapplied per run) — the
worst case is a failed module load and a clean reboot. The dual-BIOS
switch (pos 2) is the last-resort net; it has never been needed.

## The data catalog

**[lab/DATA-INDEX.md](lab/DATA-INDEX.md)** — the master index (in
reconstruction): the decoded structures, the artifacts, the instruments.
The lab findings: **`lab/findings-gx1.md` → `gx41.md`** (the read-only
era) and `lab/findings-cert20-e2e-pass.md` (the break validation). The
authoritative campaign state: **[STATE.md](STATE.md)**.

## The doctrine (how the rules evolved)

- **Phase I (read-only)**: the card is never written; every acquisition
  is a read; an invented conclusion is a defect. All of it stands for the
  intelligence work — the eight rings and their selftests below.
- **Phase II/III (the write campaigns)**: writes happen only through
  documented, staged protocols — every write target named in advance,
  every run logged to the data drive, every failure analyzed before the
  next, the stock state restorable in one step (the .bak / the offset-0
  rollback / the dual-BIOS switch). No experiment without its rollback.

## The eight rings (the intelligence foundation)

| Ring | Instrument | What it measured |
|---|---|---|
| 1 | `lab/gx1-anatomy.py` | the ROM skeleton: NVGI head, legacy x86 image @0x9200, EFI image @0x19000, the dense tail (never slack), the board's signature strings, TPU's truncated versions |
| 2 | `lab/gx2-bit.py` | the BIT table (17 tokens, checksum zero), the memory grammar (14 straps → 8 GDDR6 profiles: Samsung/Micron/Hynix), the LHR seam (record 14→22 B) |
| 3 | `lab/gx3-perf.py` | the 'P' performance table: 58 pointers, the spec pointer rule, **the power budget decoded (100/240/250 W — byte-exact vs the live machine)** |
| 4 | `lab/gx4-clocks.py` | the memory clock ladder (7 bins, live 6801 MHz covered), the timing table geometry (65×76 B), vP-state v0x20 registered raw |
| 5 | `lab/gx5-timings.py` | the timing layer decoded: 18 named fields × 28 records, the coverage census (40 FF pairs, **1 stock zero-record landmine**), 4 Hynix records tightened at the LHR seam |
| 6 | `lab/gx6-fan.py` | the fan coolers named by nouveau's own grammar, **min duty 17 % (Trio) vs 20 % (Ventus) — a board marker**, the 32-rail power topology |
| 7 | `lab/gx7-identity.py` | the ROM names itself: chip 0x9404 = GA104, **the OEM version byte is the version suffix** (0xEB→EB), self-consistent checksum, 10 real factory-spare timing records |
| 8 | `lab/gx8-named.py` | 58/58 pointers named (PerfCf*, Nne*, FanArbiter…), the memory-clock header decoded (FBVDDSettleTime 64 µs, script lists), the Falcon ucode inventory, **the PMU grew at the LHR seam** |

Rings 9-42 and the CERT20 campaign: **[CHANGELOG.md](CHANGELOG.md)**.

## Quick start

```bash
# the intelligence selftests (phase I)
python3 lab/gx1-anatomy.py selftest     # → 0 failures
python3 lab/gx8-named.py selftest

# the CERT20 staged test (phase III — from a TTY, the display manager
# is stopped and restarted by the tool; volatile, auto-restored)
sudo python3 tools/cert20-plm-feat-test.py
```

## Sources & provenance

| Source | Role |
|---|---|
| [NVIDIA open-gpu-kernel-modules](https://github.com/NVIDIA/open-gpu-kernel-modules) | the GSP boot flow (fwsec parsing, the booter load), the bindata archive system, the swref register headers |
| [d3dx9/cmpunlocker](https://github.com/d3dx9/cmpunlocker) | the published Falcon-BootROM exploitation (GPL-2) — the ROP chain, the PLM registers, the FEAT_OVR writes; technique from Jon's paper |
| [Consensus-Protocol/cmp170hx](https://github.com/Consensus-Protocol/cmp170hx) | the 278k-word wiki: the vulnerability documented to the instruction level (cloned at `../cmp170hx-wiki/`) |
| [NVIDIA BIOS Information Table spec](https://github.com/NVIDIA/open-gpu-doc) | the spec-fresh grammar anchor (BIT, pointer rule, BIOSDATA, Data Range Table) |
| [nvidia-bios-reader](https://github.com/fmuniztriana/nvidia-bios-reader) | the memory/timing grammar, imported file-by-file |
| [envytools](https://github.com/envytools/envytools) | the 2012 grammar that still decodes 2020 silicon; the Falcon ISA; built for this lab |
| [nouveau](https://github.com/torvalds/linux) (`nvkm/subdev/bios/`) | the maintained kernel grammar (fan coolers); vendored in `imports/nouveau/` |
| the kepler-ada ImHex pattern (TPU forums, `imports/`) | the modern RM nameplate (58/58), the memory-clock header, the Falcon ucode grammar |

The reference machine is a Ryzen 9 5900X on an ASUS TUF GAMING B550-PLUS
WIFI II running [Omarchy](https://github.com/basecamp/omarchy); the board
and the card are read at run time, never hardcoded.

## License

MIT — see [LICENSE](LICENSE). The vendored `imports/` keep their original
licenses (kernel sources: GPL-2.0; the ImHex pattern: provenance stated
in its header comment). The nvflash binaries are NVIDIA's freeware tool,
hash-documented per the repo convention.
