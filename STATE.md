# gpu-lab — state of the campaign (2026-09-20, evening)

One page to answer: where the campaign stands, what is proven, what is
open, what is next. The historical snapshot (2026-09-17) is at the bottom.

## The current phase: the CERT20 break via the published technique

The byte-mod VBIOS path is **cryptographically closed on Ampere** (the
CERT20/VDPA enforcement: the Falcon VV + the PMU EWR both refuse any
modified image — 15 VM runs, the TPU 312631 scope confirmation). The
**published community break** (the cmpunlocker technique, documented to
the instruction level in the cmp170hx wiki) walks around the EEPROM
entirely: the unbounded signature DMA in the SEC2 booter overwrites the
canary and every return address with a uniform value V — the PC lands on
V — and the booter's own signed code becomes the unlock's execution
engine. Volatile, auto-restored, no EEPROM.

**Validated on OUR firmware**: the emulator (booter_emu.py) runs our
gsp_tu10x.bin 610.57.04 end-to-end — 16 BAR0 writes, 0 deviations, the
same halt loop as the native flow.

**What remains is die-specific discovery** (the campaign designed, the
first run pending):

1. The baseline fire: V=0x4a7 on our GA104 → the MAILBOX0 oracle read.
2. The V sweep: candidate addresses, one driver cycle each, the
   mailbox oracle mapping the booter's code paths without ever reading
   the encrypted image.
3. The chain: the PLM registers opened (FEAT first, verified by BAR0
   read-back), then the power-limit register hunt (250 → 280 W) in the
   FEAT_OVR space.
4. The hardware runs are staged (one target per cycle, the verdict by
   read-back) and volatile (the reboot = stock).

## The standing results (real, on the machine now)

| Item | State | Source |
|---|---|---|
| Resizable BAR | 8192 MiB BAR1 | ring 18 |
| Core offset | +225 MHz — **max graphics 2325 MHz, above the 2200 target** | the VF campaign (vague 2) |
| Undervolt | 1995 MHz @ 987 mV (vs 1890 @ 1075 stock) — the effective 280 W | the VF campaign |
| Power limit | 250 W (the VBIOS ceiling; 280 W = the CERT20 target) | LACT |
| Memory OC | **not applied** — GDDR6 typically +1000-1500 MHz = +5-10 % bandwidth | pending |
| The unlock ROM | built, verified, ready (2200 MHz + 265/280 W) | ring 42 / unlock-v2-REALCHIP |

## The wall (proven, documented)

| Layer | Mechanism | Verdict |
|---|---|---|
| EEPROM image write | Falcon VV (CERT20/VDPA RSA-3072 manifest) | SIG_INVALID on any modified byte |
| EEPROM programming | PMU EWR OK-to-flash check | refuses, then stops answering |
| GSP-RM firmware | SEC2 Boot ROM, fused keys | patch = rejected at load |
| Host-side table patch | the parse lives in the GSP-RM (closed) | not reachable |
| InfoROM policies | PPO object absent on GeForce | not applicable |
| HULK license | needs NVIDIA's signature | partner process only |

The full map: the CHANGELOG CERT20 entry, the memory of record, and the
cmp170hx wiki (278k words, cloned at `../cmp170hx-wiki/`).

## The tools (all in tools/, committed)

- `cert20-plm-feat-test.py` — the staged GA104 PLM test (4 hardware runs,
  2 tool crashes fixed, the tu10x section discovery, the PLM-unchanged
  verdict). The ROP chain, the ELF growth, the log tee, the restore.
- `vfio-flash-session.sh` v14 — the VM flash pipeline (the signed images).
- `nvflash-5.792-k4/nvflash-k4-vv` + `nvflash-5.867/x64/nvflash-patched` —
  the verification/protectoff tools.
- `vbios-unlock-mod.py --source` — the unlock builder (the real chip dump).
- `gsp-extract/` — the GSP-RM extracted (rm-full.asm = 5M lines of
  RISC-V disassembly), the booter disassembled (bootloader.asm), the
  vague 4.x script suite, rm-strings.txt.
- `../cmp170hx-wiki/` + the cmpunlocker clone (re-clone if wiped) — the
  published research.

## Open questions

1. Does the GA104's SEC2 BROM share the GA100's gadgets? (The fill value
   V=0x4a7 = the first probe.)
2. Where are the GA104's PLM/FEAT_OVR registers? (The GA100 addresses =
   the starting hypothesis; the register map = die-specific.)
3. Is there a power-limit override register in the FEAT_OVR space?
4. The Jon paper (Zenodo, June 2026): not found by the search terms —
   the wiki's citation tags point to an unreleased corpus.

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
- The GPU: zero NVRM Xid across the entire campaign; every read was
  passive; the EEPROM write attempts never reached a partial state.
