# GPU- — the RTX 3070 unlock research lab

> **From read-only VBIOS intelligence to the CERT20 break.** The sibling of
> [BIOS-](https://github.com/Cheurteenyt/BIOS-): the same doctrine — work
> from evidence, registers before verdicts — applied to a live
> **MSI RTX 3070 Gaming Trio Plus LHR (GA104, VBIOS 94.04.46.00.EB)**.
> The lab began as read-only firmware intelligence (the eight rings),
> built the factory-limit unlock ROM, hit NVIDIA's CERT20 write
> enforcement, mapped it end-to-end, and adopted the community-published
> break that walks around it at runtime.

## The four phases

| Phase | What happened | Where |
|---|---|---|
| **I. Read-only intelligence** (rings 0-42) | the VBIOS decoded table by table: power budget, memory ladder, timings, fans, vP-states, the Falcon ucode inventory — and the **unlock ROM built** (caps 2200 MHz + 280 W, gate-checked) | `lab/findings-gx*.md`, `CHANGELOG.md`, `tools/vbios-unlock-mod.py` |
| **II. The write campaign** (15 VM flash runs) | the full EEPROM write path walked inside a QEMU/VFIO VM; every failure named and fixed; **the CERT20 wall proven**: Falcon VV (`SIG_INVALID`) + PMU EWR (`OK_TO_FLASH_CHECK_FAILED`) refuse any modified image | `day0/vfio-flash-*/`, `tools/vfio-flash-session.sh`, the `CHANGELOG` CERT20 entry |
| **III. The published break** | the community exploit (the unbounded signature DMA in the SEC2 booter → the canary defeated by uniformity → the PC hijack → the PLM opening) — **validated in emulation on OUR firmware, then proven executing on the real GA104**: the hardware runs show the SEC2 Falcon spinning at V=0x4a7, the IMEM self-loop gadget — the canary defeat and the PC hijack confirmed in silicon | `tools/cert20-plm-feat-test.py`, `lab/findings-cert20-e2e-pass.md`, `day0/cert20-plm-feat-test.log`, the cmp170hx wiki |
| **IV. The GSP-RM cartography** (now) | the rm.elf reverse-engineered at scale: 66 % of the image boundary-verified (recursive descent), 221,201 verified indirect transfers, the state-pointer derivation graph measured end to end — and the honest revision: **the power limit is the EDPp runtime policy of the GSP-RM, not a fuse shadow** — the FEAT_OVR lane does not reach it; the next lane = the static RPC-table anchors (ID→handler) inside the runtime-bound dispatch graph | `lab/jalon411/findings-4.14→4.19.md`, `tools/analysis/gsp-extract/` |
| **V. The transport & the falsification wave** (the passes 4.20→4.34) | the RPC dispatch table found (1156 entries, ID→handler named); the transport instrumented end to end (the send + the recv small/large); **the falsifications banked**: the power limit value NEVER travels fn=76 (the 250000s captured = the LACT clock offsets — the issuer = NVML userspace, proven), the 1616-B request = rejected unread, the seven rm.elf 250000 constants = the TIME hysteresis (µs), NOT power; the closed x86 RM acquired (19 MB + 121 MB, provenance) and the plaintext booter emulated (the risk-free patch validation) | `lab/jalon411/findings-4.20→4.34.md`, `lab/jalon411/INDEX.md`, `tools/edpp/`, `tools/gsp-lz/`, `tools/gsp-container/`, `tools/analysis/x86-rm/`, `tools/booter-patch/` |
| **V+. The transfer-list & the booter bypass** (the passes 4.35→4.42) | the SAFE LANE proven (the 864 RM regkeys, 251 with xrefs); the ROP gadget hunt in OUR bootloader (the write-primitive found); **the transfer-list BUILT and PROVEN end-to-end** (the C patch, the emulator 11/11); the patched gsp.bin **booted WITHOUT signature rejection** — the rm.elf modification accepted by the silicon; the x86 closed core acquired (19 MB + 121 MB) with provenance | `tools/booter-patch/`, `tools/edpp/`, `tools/gsp-lz/`, `tools/gsp-container/`, `tools/analysis/x86-rm/`, `lab/jalon411/findings-4.35→4.42.md` |

## The current phase: THE HIJACK CONFIRMED IN SILICON — the control lane (the ctx relocation, the carpet probe, the MMIO scatter) is the deliverable

The wave 4.20→4.34 closed every transport lane to the power limit:

1. **The RPC dispatch table = found** (1156 entries, ID→handler named —
   pass 4.20), and the transport instrumented end to end (the send +
   the recv small/large paths, the sequence-tagged dumps).
2. **The power limit value NEVER travels it.** Every "250000" captured
   was falsified in turn: the LACT clock offsets (the issuer = NVML
   userspace, proven against both x86 cores), an unconsumed rejected
   request (the handler returns INVALID_STATE — confirmed live by the
   surgical rewrite), and in the firmware itself the seven 250000
   constants = the TIME hysteresis in µs ([250000, 500000]), not power.
3. **The enforcement = the GSP-RM's EDPp policy object**, fed by a
   mechanism still unobserved — the recv large-path hook (the pass
   4.26-ready) and the force-get = the armed observation instruments.
4. **The anti-tamper lock** stands (the pass III lesson): one fire per
   power cycle, the restoration = the full cycle.

The active gains on the machine: the core offset +225 → 2325 MHz, the
undervolt 1995 @ 987 mV, 250 W stock, the memory OC +500 validated
(+6 % Solar Bay official, +25 % the 1 % low in Q2RTX).

## The data catalog

**[lab/jalon411/INDEX.md](lab/jalon411/INDEX.md)** — the master index
of the wave 4.14→4.34: each pass, its findings, its verdict, its
instruments. The tool domains: **tools/edpp/** (the power-limit
instruments, the runbook), **tools/gsp-lz/** + **tools/gsp-container/**
(the verified gsp.bin rebuild pipeline), **tools/analysis/x86-rm/**
(the closed x86 cores with provenance), **tools/booter-patch/** (the
plaintext-booter patch tooling), **tools/analysis/gsp-extract/** (the
rm.elf disassembly and the extraction). The authoritative campaign
state: **[STATE.md](STATE.md)**.

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
