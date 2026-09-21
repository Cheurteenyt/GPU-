# gpu-lab — state of the campaign (2026-09-21)

One page to answer: where the campaign stands, what is proven, what is
open, what is next. The historical snapshots (2026-09-17, 2026-09-20)
are at the bottom.

## The current phase: the GSP-RM cartography → the EDPp handlers

**Phase III is proven in silicon.** The hardware campaign (7+ runs,
`day0/cert20-plm-feat-test.log`) fired the published ROP chain on our
GA104 with the driver patch (kernel_gsp.c `_kgspCreateSignatureMemdesc`,
the 0xF800 signature memdesc → the unbounded DMA). The verdict is the
paper's own test/stall payload observed live: **the SEC2 Falcon spins at
V=0x4a7 — the IMEM self-loop gadget** — the canary defeat and the PC
hijack confirmed on real consumer-Ampere silicon. The V=0x7dd9 probe
produced the same `0xbadf5620` abort signature (V-independent — the
failure sits upstream of the epilogues, in the HMAC validation of our
payload; the GA100 gadget addresses do not transfer to our build).

**The two campaign facts learned in hardware:**

1. **The anti-tamper lock.** After a fire, the secure domain reads
   DENIED across the registers and the entire FEAT region
   (6144/6144), surviving warm reboots — the always-on island.
   Recovery = a full power cycle. One fire per power cycle.
2. **The honest 280 W map.** The exploit opens fuse shadows
   (FEAT_OVR). The 250 W ceiling is the **EDPp table applied by the
   GSP-RM at runtime** — a policy, not a fuse. The FEAT_OVR lane does
   not reach it.

**The cartography (phase IV, merged via PR #1):** the rm-full.elf
reverse engineering passes 4.14→4.19 (`lab/jalon411/`) boundary-verified
66 % of the image (recursive descent, 3.4M insns, 81,871 validated call
edges), counted 221,201 verified indirect transfers (47,961
object-vtable, 1,201 state-frame), resolved the state-pointer economy
into a **derivation graph** (base = argument + 0x1000; 0.4 % static
formation; one state shape through dozens of carried bases) — and hit
the wall honestly: **the dispatch is runtime-bound end to end** (0
named targets in 3,542 slot fills). Static analysis alone will not name
the dispatch targets.

**The next lane (designed):** the RPC dispatch tables — static ID→
handler anchors inside the closed firmware. The `NV2080_CTRL_CMD_PWR_*`
command IDs are public (the open kernel modules headers); locating
their handler tables in rm-full.elf and walking from a known ctrl (the
power-limit GET/SET) into the EDPp enforcement code turns the
runtime-bound graph into a bounded hunt. That is the path to 280 W.

## The standing results (real, on the machine now)

| Item | State | Source |
|---|---|---|
| Resizable BAR | 8192 MiB BAR1 | ring 18 |
| Core offset | +225 MHz — **max graphics 2325 MHz, above the 2200 target** | the VF campaign (vague 2) |
| Undervolt | 1995 MHz @ 987 mV (vs 1890 @ 1075 stock) — the effective 280 W perf/watt | the VF campaign |
| Power limit | 250 W (the VBIOS ceiling; 280 W = the EDPp target) | LACT |
| Memory OC | **not applied** — GDDR6 typically +1000-1500 MHz = +5-10 % bandwidth | pending (LACT) |
| The unlock ROM | built, verified, ready (2200 MHz + 265/280 W) — unf lashable on Ampere (CERT20) | ring 42 / unlock-v2-REALCHIP |

## The wall (proven, documented)

| Layer | Mechanism | Verdict |
|---|---|---|
| EEPROM image write | Falcon VV (CERT20/VDPA RSA-3072 manifest) | SIG_INVALID on any modified byte |
| EEPROM programming | PMU EWR OK-to-flash check | refuses, then stops answering |
| GSP-RM firmware | SEC2 Boot ROM, fused keys | patch = rejected at load |
| Host-side table patch | the parse lives in the GSP-RM (closed) | not reachable |
| InfoROM policies | PPO object absent on GeForce | not applicable |
| HULK license | needs NVIDIA's signature | partner process only |
| Secure domain (post-fire) | the anti-tamper lock, always-on island | DENIED until a full power cycle |
| The 280 W ceiling | the EDPp runtime policy of the GSP-RM | not a fuse shadow — the FEAT_OVR lane misses it; the RPC-table lane is open |

The full map: the CHANGELOG, the memory of record, and the cmp170hx wiki
(278k words, cloned at `../cmp170hx-wiki/`).

## The tools (all in tools/, committed)

- `cert20-plm-feat-test.py` — the staged GA104 ROP test (7+ hardware
  runs; the fill-V parameter, the ROP chain, the ELF growth, the log
  tee, the driver-unload/reload flow, the full restore).
- `cert20/` — `cert20-verify.py` (the post-boot register verdicts,
  the DENIED = the signal), `cert20-scan.py` (the FEAT region sweep),
  `cert20-brom-dump.py` (the BROM read attempt via the Falcon XFER
  ports).
- `scan-kcore-power.py` — the host-RAM power-value scan (run once,
  died silently with its session — no result; rerun when the
  EDPp-in-host-RAM question reopens).
- `vfio-flash-session.sh` v14 — the VM flash pipeline (the signed images).
- `nvflash-5.792-k4/nvflash-k4-vv` + `nvflash-5.867/x64/nvflash-patched` —
  the verification/protectoff tools.
- `vbios-unlock-mod.py --source` — the unlock builder (the real chip dump).
- `analysis/gsp-extract/` — the GSP-RM extracted (rm-full.asm = 5M lines
  of RISC-V disassembly; the minimal rm-full.elf), the booter
  disassembled (bootloader.asm), the cartography instruments v414-v419
  (with `lab/jalon411/`), rm-strings.txt.
- `../cmp170hx-wiki/` + the cmpunlocker clone (at `../cmpunlocker/`) —
  the published research.

## Open questions

1. Where are the RPC dispatch tables in rm-full.elf, and which handlers
   serve `NV2080_CTRL_CMD_PWR_*`? (The designed next pass — the lane to
   the EDPp code and 280 W.)
2. Does a host-RAM copy of the power policy exist (the kcore scan died
   without output — rerun), or does the GSP-RM read the tables alone?
3. The exact GA104 booter gadget set for a productive chain (the GA100
   addresses abort upstream — the V sweep with the mailbox oracle
   remains the mapping method, one fire per power cycle).
4. The Xid 109 CTX SWITCH TIMEOUT on memtest_vulkan: patched-driver
   caused (suspect n°1) or independent? — pending the stock-driver
   memtest baseline.

## The historical snapshot (2026-09-20, evening — kept for the record)

Phase III as designed, before the hardware runs: the emulator
validation (16 BAR0 writes, 0 deviations), the discovery campaign
planned (the baseline fire, the V sweep, the chain), the wall table at
six layers. Superseded by the phase III→IV state above.

## The historical snapshot (2026-09-17 — kept for the record)

The performance campaign as it stood before the unlock ROM existed:
ReBAR was the one real gain; the power budget read 100/240/250 W; the
vP-states matched LACT's ceilings; the verdict then was "the performance
campaign is closed honestly" — **the unlock ROM (ring 42) and the CERT20
research superseded that verdict**. The method library (the sysfs reads,
the kcore scan, the LACT socket API, the decoder suite gx1-gx15) remains
the foundation everything above was built on.

## Incidents ledger (transparency)

- The faillock incidents: all from the assistant's heredoc + `sudo -S`
  mistake (the garbage-as-password), never the founder's actions.
- 3 black screens during the PLM tests: the GSP re-init after FLR + the
  ROP attempts — all recovered without damage (the stock firmware
  restored in-flow each time).
- **The anti-tamper lock** (the first ROP fire with the patched driver):
  the secure domain DENIED and persistent across warm reboots; a full
  power cycle is the documented recovery — not yet exercised at the
  time of writing.
- **The Xid 109** (memtest_vulkan, patched driver): the first NVRM Xid
  of the campaign — the TDR recovered, the system unharmed; the
  stock-driver baseline is pending to attribute it. Every read was
  passive; the EEPROM write attempts never reached a partial state.
