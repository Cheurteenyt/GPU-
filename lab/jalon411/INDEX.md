# lab/jalon411 — the RM cartography & the power-enforcement hunt (the master index)

The wave of passes 4.14 → 4.29: from the rm.elf dispatch cartography to
the EDPp enforcement hunt. Every pass = one findings file + the
instruments (the `v4xx_*.py` scripts + their JSONs). **The entry point
for the next session = pass 4.26 (the recv capture, armed).**

## The passes

| pass | findings | what it established | the verdict |
|---|---|---|---|
| 4.14 | datflow | the vtable installs, the companion census | the bases = carried, not formed |
| 4.15 | aliased-slot-and-o2 | the 0x588 alias, the O2 verdict | no dominant allocator |
| 4.16 | boundary-proof | the recursive descent, the 66 % verified | the dispatch-driven architecture |
| 4.17 | stategraph | the 665 slots, the derivation graph | one state shape, many bases |
| 4.18 | hubfill | the hub fills, the first X resolutions | 0 named targets |
| 4.19 | prov588-entrypoints | the full provenance table | the family = 3 semantics |
| 4.20 | rpc-anchors | **the RPC dispatch table found (1156 entries)** | the anchors survive the runtime-bind |
| 4.21 | pfm-worker-runtime-data | the mW scan, the ceiling = runtime data | 280000 = zero hits in rm.elf |
| 4.22 | power-transport | the open kernel sends no tables | the BIT parser = the closed x86 blob |
| 4.23 | transport-edpp | the transport instrumented end to end | the machine degraded — restored |
| 4.24 | payload-fieldmap **(FALSIFIED 4.23's assumption)** | the 1616 = cmd 0x2080d031, the handler = unconsumed | 250000 @104 = rides unread |
| 4.24 | edpp-flow | the EDPp lifecycle modeled from the open source | the client vs the platform limits |
| 4.24 | gsp-lz | the LZ4 codec + the container built and verified | 13/13, byte-exact |
| 4.24 | citation-audit | every 4.24 claim re-executed | clean |
| 4.25 | x86-marshal | win.elf falsified (a RISC-V artifact), the 0x2080d0 family = 19 controls | the offsets = HYPOTHESIS |
| 4.25 | recv-edpp | the GSP→CPU completion chain proven | **the 96-B prediction armed — the capture = 4.26** |
| 4.27 | gspbin-container | gsp_ga10x.bin acquired, the provenance proven | byte-exact rebuilder delivered |
| 4.28 | x86-substrate + the hunt closed | **nv-kernel.o_binary acquired; the issuer = NVML userspace PROVEN** | **the "250000" = the LACT clock-VF offset, NOT power** |
| 4.29 | lz-real-roundtrip | **the pair premise falsified at phdr level (comp-725KB = vgpu.elf, flat); no NVIDIA LZ4 stream in 1.81 GB scanned** | codec unchanged, T6 = the real-bytes round-trip, permanent; recv76_analyze delivered |
| 4.30 | gspbin-pipeline | **the GFW directory grammar decoded (13 records, the +0x6d000 bias law, 5/5 byte-exact containments); the u32 patch premise falsified — the six 250000 = lui+addi pairs; the patch landed (18 B differ / 48 rewritten); the load path source-proven (GA104 = gsp_ga10x.bin)** | gspbuild patchrm + R14-R17; the signature coverage = UNDECIDABLE-BY-BYTES |
| 4.31 | booter-verify-hunt | **the LS-signature verify is NOT in our booter libos ELF (proven: no crypto CSRs 0x7d5-9, no SBI crypto ecall, no SHA/RSA constants, no 0xc0deca7e; the paper's 0x29C4/0x4d4/0x2e80/0x7dd9 are all < 0x8000 = BROM addresses); our secure interface = SBI ecalls (a7=0x900001EB, a6∈{0,7,8,9,0xa}, fail=a7=8) + the nvriscv region CSRs 0x5ca-0x5d1/0x8d0; TWO booters separated: the .ko BooterLoad is ENCRYPTED (IMAGE_PROD 0x87d7, NUM_SIGS=2, BROM-RSA-covered — patch refused by construction) while our plaintext libos booter = the gsp_ga10x.bin first section @container 0x40 (the container = a RISC-V ELF, new proof); booter_emu.py runs the real image (5/5) and the directed patch demo works: the 0x1014DC bounds check original→FAIL-oracle vs NOP'd→clean ret, exactly 4 bytes differ** | v431_booter_hunt 17/17; patch_booter locate-ko/locate-gsp/patch-gsp 5/5; tools/booter_emu.py 5/5 |
| 4.33 | firmware-optimization | **the four-lane optimization map of the closed RM: A = the 60-knob policy table (60 round values classified per first-consumer; the µs ladder re-confirmed; the 36 c.lui-100000 attributed to 34 ret-bounded bodies, 3 in s2/s3 — the 4.32e queue paid; the 4.30 patched container = 6/7 INCOHERENT, complete-or-revert registered); B = 145,117 exact duplicate families / 918,518 windows = 27% of instruction starts, shareable ≥ 12.2 MB, the #1 idiom present 26,060× (the patch-coherence tax, quantified); C = the call census follows the bytes — this firmware calls in auipc+jalr PIC pairs (300,245/148,314; only 600 jal) = 148,848 sites / 7,084 targets, top fan-in 52,114 and 31,329, the ecall-0x25 gate 7,284, the PIC targets 100% seen; D = layout CLOSED (0 file gaps, 3.8% inter-region zeros, the booter's 96.3% zeros = STRUCTURAL per the GFW bias law)** | v433c_knobs + v433b_callfanin + v433a_dupcode + v433d_layout, all selftested; 6 instrument lessons banked |

## The current state of the 280 W question (after 4.28)

- The power limit value **never travels** the fn=76 transport (the
  250000 = the LACT clock offset, the falsification).
- The enforcement = **the GSP-RM's EDPp policy object** (the 0x6d0
  object, the 4.20/4.21 passes), fed by mechanisms still to observe.
- **The only road to the real data = pass 4.26: the recv-hook capture**
  (the response-path instrument = merged and armed; the boot = the
  capture).

## The instruments (the naming convention)

`v4XX_<topic>.py` = the pass's instrument; `<topic>.json` = its output.
The chained verification = the flat results re-derived before every new
pass (the discipline since 4.19).
