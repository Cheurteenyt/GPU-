# GPU- — the video-BIOS lab

> **Read-only video-BIOS intelligence, ring by ring.** The sibling of
> [BIOS-](https://github.com/Cheurteenyt/BIOS-): the same doctrine — work
> from evidence, registers before verdicts, zero writes to the hardware —
> applied to a live **MSI RTX 3070 Gaming Trio Plus LHR (GA104,
> VBIOS 94.04.46.00.EB)** and to the vendor-verified corpus around it.

## The founding rule (+0 octet, GPU edition)

The card is **never written**. Every acquisition is a read: a sysfs dump
performed by the human, a vendor CDN download verified against published
hashes, a passive BAR-window read. Every instrument is stdlib-only Python
and refuses loudly when its anchors drift. "Undetermined" is an honest
verdict; an invented conclusion is a defect.

## The eight rings

| Ring | Instrument | What it measured |
|---|---|---|
| 1 | `lab/gx1-anatomy.py` | the ROM skeleton: NVGI head, legacy x86 image @0x9200, EFI image @0x19000, the dense tail (never slack), the board's signature strings, TPU's truncated versions |
| 2 | `lab/gx2-bit.py` | the BIT table (17 tokens, checksum zero), the memory grammar (14 straps → 8 GDDR6 profiles: Samsung/Micron/Hynix), the LHR seam (record 14→22 B) |
| 3 | `lab/gx3-perf.py` | the 'P' performance table: 58 pointers, the spec pointer rule, the tail owned, **the power budget decoded (100/240/250 W — byte-exact vs the live machine)** |
| 4 | `lab/gx4-clocks.py` | the memory clock ladder (7 bins, live 6801 MHz covered), the timing table geometry (65×76 B), vP-state v0x20 registered raw |
| 5 | `lab/gx5-timings.py` | the timing layer decoded: 18 named fields × 28 records, the coverage census (40 FF pairs, **1 stock zero-record landmine**), 4 Hynix records tightened at the LHR seam |
| 6 | `lab/gx6-fan.py` | the fan coolers named by nouveau's own grammar (2× PWM, 27 kHz), **min duty 17 % (Trio) vs 20 % (Ventus) — a board marker**, the 32-rail power topology |
| 7 | `lab/gx7-identity.py` | the ROM names itself: chip 0x9404 = GA104, **the OEM version byte is the version suffix** (0xEB→EB), self-consistent checksum, 10 real factory-spare timing records |
| 8 | `lab/gx8-named.py` | 58/58 pointers named (PerfCf*, Nne*, FanArbiter…), the memory-clock header decoded (FBVDDSettleTime 64 µs, script lists), the Falcon ucode inventory, **the PMU grew at the LHR seam** |

Every ring has its `findings-gxN.md` (with an honesty ledger: proven /
inferred / unknown) and its JSON register; every instrument has a
two-tier selftest (`python3 lab/gxN-*.py selftest`) that re-derives its
anchors live and exits 2 on any drift.

## Day-0: the live card vs the acquisition

The human's read-only sysfs dump of the actual card was confronted to the
vendor-verified TechPowerUp acquisition of the "same" version:

**Verdict: sibling, not twin.** Same version string, same board string
(`MSINV390MH.670`), byte-equal BIT and memory layers, ~30 KiB identical
code core — different bytes (head, 23 patch bytes, a 30 KiB dense-vs-zero
region). The version-string trap measured to its final form: even version
+ subsystem + board string + a byte-equal grammar layer do not certify
image identity. See `day0/findings-day0.md`.

## The acquisitions protocol

* vendor CDN / TechPowerUp downloads, admitted **only** when the
  published MD5+SHA1 match the fetched bytes (`acquisitions/REGISTER.json`),
* the browser page-context fetch is the working capture path (curl hits
  the JS bot wall — the ring-12 WAF playbook of the sibling lab does
  *not* transfer),
* the live dump protocol and its measured window properties:
  `day0/ACQUISITION.md`.

ROM images are **not** committed to this repository (the registers carry
sha256 + provenance instead — the repo tracks knowledge, not scratch).
The reference specimens are re-downloadable from the URLs in the register.

## What this lab does NOT claim

The power/timing/fan tables are **read and named**, never edited. The
two remaining true unknowns — the PERF table v0x60 records and the
vP-state v0x20 entries — sit beyond every open parser (nouveau stops at
v0x40; `open-gpu-kernel-modules` parses no VBIOS at all; GSP-RM, which
consumes them, is closed). They are mapped, gated and registered raw.
The full-SPI read (the complete 1 MiB flash, beyond the 62 KiB sysfs
window) is documented and requires a live-USB gesture: `day0/ACQUISITION.md`.

## Quick start

```bash
python3 lab/gx1-anatomy.py selftest     # → 0 failures
python3 lab/gx2-bit.py selftest
python3 lab/gx3-perf.py selftest
python3 lab/gx4-clocks.py selftest
python3 lab/gx5-timings.py selftest
python3 lab/gx6-fan.py selftest
python3 lab/gx7-identity.py selftest
python3 lab/gx8-named.py selftest
```

Selftests marked "tier-I" re-read the corpus live; without the ROM files
they degrade loudly, never silently.

## Sources & provenance

| Source | Role |
|---|---|
| [NVIDIA BIOS Information Table spec](https://github.com/NVIDIA/open-gpu-doc) | the spec-fresh grammar anchor (BIT, pointer rule, BIOSDATA, Data Range Table) |
| [nvidia-bios-reader](https://github.com/fmuniztriana/nvidia-bios-reader) | the memory/timing grammar, imported file-by-file |
| [envytools nvbios](https://github.com/envytools/envytools) | the 2012 grammar that still decodes 2020 silicon; the P2 nameplate (39/58) |
| [nouveau](https://github.com/torvalds/linux) (`nvkm/subdev/bios/`) | the maintained kernel grammar (fan coolers); vendored in `imports/nouveau/` |
| the kepler-ada ImHex pattern (TPU forums, `imports/`) | the modern RM nameplate (58/58), the memory-clock header, the Falcon ucode grammar |
| [cmp170hx](https://github.com/Consensus-Protocol/cmp170hx) | the synthesis/methodology model; GSP-RM as the GA10x deep layer |

The reference machine is a Ryzen 9 5900X on an ASUS TUF GAMING B550-PLUS
WIFI II running [Omarchy](https://github.com/basecamp/omarchy); the board
and the card are read at run time, never hardcoded.

## License

MIT — see [LICENSE](LICENSE). The vendored `imports/` keep their original
licenses (kernel sources: GPL-2.0; the ImHex pattern: provenance stated
in its header comment).
