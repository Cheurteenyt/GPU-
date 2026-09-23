# lab/jalon411 — the RM cartography & the power-enforcement hunt (the master index)

The wave of passes 4.14 → 4.34: from the rm.elf dispatch cartography to
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
| 4.34 | time-queue-and-430-closure | **PART A the 4.30 closure: the split-form finder enters gspbuild (capstone clobber check) and finds EXACTLY the 7th site (lui a4 @rm+0xb99c4a, addi @+0xb99c52, gap 8); the 7/7 patch produced (21 B differ: 18 contiguous + 3 split, the `sub s2,s10,s2` byte-preserved, all 7 pairs re-decode 280000; artifact fwimage-77 sha 5962342b…, outside the repo) — VERDICT REVERT for any boot: 4.32 proved TIME-not-power, the runbook now REFUSES the 6/6/7 half-turned container and gates the 7/7 behind RUNBOOK_77_ACK=1; PART B the 34 c.lui-100000 bodies classified by first consumer: 6 CALL-ARG (c.jalr), 4 MUL (×1e5/div converters), 5 STORE-DATA (state fields, +0x5d0), 3 COMPARE (one vs a rdtime delta!), 8 ARITH, 11 slice-interrupted (4 proven c.j value-blocks, 0 dead) — 100000 = the RM's fine time quantum, never a power knob; PART C the TICK RATE PROVEN: 451 rdtime reads; the literal chain @0x1bc75f0-76 `s2=1e9 → divu → seconds → mul 0xF4240(1e6) → µs` ⇒ 1 tick = 1 ns (1 GHz); 31.25 MHz = ZERO hits in code AND data — the 4.32 µs ladder is the policy layer on the nanosecond counter; the 100000-vs-rdtime threshold = 100 µs** | v434a_patch77 + v434b_cl100_bodies + v434c_tickrate (+ JSONs); gspbuild extended (R18-R20, S1-S8); tests 27 PASS / 0 FAIL; 6 instrument lessons (the zlib-packed map, the capstone register-NUMBER identity, the c.lui rd-field, the linear-slice honesty, the load-dest ≠ read, the split patch = two separate writes) |
| 4.35 | optimization-hunt2 | **the optimization hunt, round 2 — the knob cards + the SAFE lane proven: (A) the 60 knobs carded (unit hypothesis + risk class + owner fan-in; the banked counts reproduce): 1000000 = TIME-CONVERSION DO-NOT-TOUCH-BLIND, 10000000 = TIME-QUANTA (10 ms vs the 1-ns tick), a coherent CLK-270k-FAMILY of 14 knobs (270000 × {1..100}), the GATED-TUNABLE shortlist ranked by leverage (500000/100000000/4000000 @fan-in-794 region 0x10844a4; 1435840000 = a 1.43584-GHz clock threshold with a 16-entry data twin @0x1c0d38c); (B) THE REGKEY LANE = the no-patch lever, PROVEN: 864 Rm*/RM* names in the firmware, 251 with direct PIC code xrefs (366 xrefs, 291 PASS-TO-CALL — the lookup-by-name pattern cited: string→a1→call→status gate), name-pointer tables in the wild (RmVgpcSkyline ×27+masks @0x1d858b8, RmCePceMap @0x1c492e0), FNV-1a-32 hash machinery (basis 0x811C9DC5 ×3, hash-context init window), the top tunables named (RML2MaxWaysSysmem = the L2-ways partitioning knob, RmClk2Enable, RMUseTc0NonCoherent…); (C) the data twins: the 22×1000000 default table @0x404b4b0 (the top knob's compiled defaults), the 2^n size-class ladders @0x1c4ad68/0x1c4ab68, the duplicated config blocks (the clone mass's data twin), NVDUMPCONFIGSIG at the data base; the d4d856ff ×666 DECODED = a live fill-value table (u32 0xff56d8d4 among descending 0xff57xx records, step ≈ −0x24) — the lane-D 'waste' reading corrected for this family (the banked 666 = the a_img-aligned 16-B unit, reproduced exactly); the two VA universes formalized (runtime = campaign + 0x38, from the container phdrs)** | v435a_knobcards + v435b_regkeys + v435c_datacensus (+JSONs); the 280 W rm.elf lane stays CLOSED (4.34 REVERT) — round 2 adds the SAFE host-regkey lane and refuses the time-math knobs by card |
| 4.36 | regkey-flow | **the regkey-to-knob flow map + the function owners + the slice resolution — and the CAMPAIGN VERDICT: the static hunt has reached its floor. TASK A (v436a): the regkey canal is NOT in-situ — 0/12 shortlist knobs carry a regkey xref in their ret-bounded function AND 0/12 at covered-region level (331 distinct xrefs windowed; the wider net nets zero); the field flow cartographed instead (400000 -> sd a5, -0xa0(s0) @0x5dcfc8 with 5 same-field stores, 1250000 -> sw a5, 0x274(a0)/0x27c(a0) two adjacent fields; zero ret-stores of a0 anywhere); the census discipline held (the banked 4.32 counts, the 36 c.lui site-equal to v434b, the regkeys 864/251/366, the RmValidateClientData xref re-decoded, the PIC edges 148249 with the banked callee 0x188EF44 fan-in 50 exact); the C.LUI byte-probe settles the layout: QUADRANT 1, funct3 011, FULL 5-bit rd at [11:7] (0x6a61 -> s4). TASK B (v436b): 18/300 sites get a ret-bounded window, ALL with PIC fan-in 0 (leaf fragments and value-blocks, not call-entered prologues); zero RPC-anchor ties, zero name-pointer ties at region level — the 4.35a region cards remain the finest static attribution. TASK C (v436c): the 11 (12 re-derived, delta 1 documented) interrupted sites re-attacked with a FORKING CFG slice — 5 BOTH-ARMS-AGREE:ARITH-CHAIN (the 4.34 value-blocks confirmed at CFG level + 0x1280da4 newly promoted), 7 UNRESOLVED with the mechanism cited (backward polling-loop edges — the rd is consumed in a later iteration; the HYPOTHESIS label stands). VERDICT: the SAFE lane = the host regkey experiments on STOCK firmware (the 4.35 tunables); the real data = the 4.26 capture; the 280 W rm.elf lane stays CLOSED** | v436a_regkey_flow + v436b_funcowners + v436c_slice7 (+JSONs) + findings-4.36-regkey-flow.md; 6 instrument lessons (the byte-probe before the bit-layout faith, the two-parity u32-view trap, the flat-equality format matching, fork-less slices under-report loops, a negative cross is a result, echo-proof instrument writing) |

## The current state of the 280 W question (after 4.34)

- **4.34 verdict: the rm.elf lane is CLOSED — REVERT.** The seven
  250000 sites are TIME logic (proven 4.32); the 7/7-complete patch
  exists as the completeness proof (fwimage sha 5962342b…, v434a), NOT
  as a boot recommendation; `runbook-280.sh` refuses the half-turned
  6/7 container and gates the 7/7 behind RUNBOOK_77_ACK=1.
- The tick domain is resolved: rdtime = 1 tick = 1 ns (proven 4.34
  Part C); the policy thresholds stay µs (the 4.32 ladder); 100000 =
  the fine quantum (100 µs vs raw rdtime deltas).
- The power limit value **never travels** the fn=76 transport (the
  250000 = the LACT clock offset, the falsification).
- The enforcement = **the GSP-RM's EDPp policy object** (the 0x6d0
  object, the 4.20/4.21 passes), runtime-fed through a vtable (4.32
  TASK 3) — **the host-side limit API is the lever** (4.34).
- **The only road to the real data = pass 4.26: the recv-hook capture**
  (the response-path instrument = merged and armed; the boot = the
  capture, on the STOCK firmware).
- **Round 2 (4.35) adds the SAFE lane:** the host-regkey surface is
  proven real (864 names, 251 with code consumers, lookup-by-name +
  tables + FNV-1a-32) — the no-patch lever list and the knob cards
  live in `findings-4.35-optimization-hunt2.md`.

## The instruments (the naming convention)

`v4XX_<topic>.py` = the pass's instrument; `<topic>.json` = its output.
The chained verification = the flat results re-derived before every new
pass (the discipline since 4.19).
