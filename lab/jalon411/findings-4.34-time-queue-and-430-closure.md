# 4.34 — the 4.30 closure: 7/7 produced, REVERT recommended; the TIME
# queue paid: the 34 c.lui-100000 bodies classified, and the tick rate
# PROVEN at 1 tick = 1 ns

Substrates: `tools/analysis/gsp-extract/binaries/fwimage.bin` (the
committed 84,258,816-B .fwimage; rm.elf at +0x19f000, size 0x1071000)
and `binaries/gsp-rm-17MB.bin` under the proven law **`B_file = A_img -
0x38`** (re-asserted in every instrument; the v416 map is zlib-packed —
decompress before indexing, a lesson caught in flight). Instruments:
`lab/jalon411/v434a_patch77.py` + `v434b_cl100_bodies.py` +
`v434c_tickrate.py` (+ JSONs), the extended
`tools/gsp-container/gspbuild.py` (split-form finder + 7/7 patch), and
`tools/gsp-container/tests_gspbuild.py` — **27 PASS / 0 FAIL** (incl.
the new R18–R20 and the always-on S1–S8 fwimage lane).

## Verdict first

| part | what it asked | what the bytes say | verdict |
|---|---|---|---|
| A — the 4.30 closure | complete the half-turned patch to 7/7, or revert? | the split-form finder (capstone clobber check) finds EXACTLY the 7th site (lui a4 @rm+0xb99c4a, addi @+0xb99c52, gap 8, the `sub s2,s10,s2` between); the 7/7 patch rewrites 21 B (18 contiguous + 3 split), all sites re-decode 280000, the sub is byte-preserved; artifact `fwimage-77-patched.bin` sha256 `5962342b…` | **REVERT for any boot**: 4.32 PROVED the seven 250000 sites are TIME logic, not power — the 7/7 artifact is the completeness proof, not a boot recommendation; the runbook now REFUSES the 6/7 container by construction and gates the 7/7 behind `RUNBOOK_77_ACK=1` |
| B — the 34 c.lui-100000 bodies | what is 100000 FOR? | 36 sites classified by first consumer: **6 CALL-ARG (c.jalr), 4 MUL (conversion chains), 5 STORE-DATA (state fields), 3 COMPARE (thresholds — one against a rdtime delta!), 8 ARITH-USE, 11 slice-interrupted (4 proven c.j value-blocks, 7 branched paths)** | the family is the RM's FINE TIME QUANTUM: proven per-site consumers, the domain per site (ns vs µs) resolved by Part C for the COMPARE class |
| C — the tick rate | what does one rdtime tick MEAN? | **451 rdtime reads**; the literal conversion chain @VA 0x1bc75f0–76: `s2 = 1e9` (lui 0x3b9ad, addi −0x600) → `divu ticks, s2` → seconds → `mul 0xF4240 (1e6)` → µs + the remainder term; 31.25 MHz appears ZERO times (code and data); 27 MHz = 4 sites (a different role) | **PROVEN: 1 tick = 1 ns (1 GHz)** for the RISC-V time CSR the RM reads; the 4.32 µs ladder is the policy layer ON TOP of a nanosecond counter |

**The global answer: the 280 W rm.elf lane is CLOSED (REVERT), and the
TIME domain is now fully resolved: policy thresholds live in µs
(the 4.32 ladder), the hardware counter ticks in ns, and 100000 is the
fine quantum (100 µs when compared against raw rdtime deltas — the
@0x141b654 window reads rdtime in the same basic block).**

## 1. PART A — the 4.30 closure (v434a)

The 4.30 pass patched six CONTIGUOUS lui+addi 250000→280000 pairs
(registre: rm_off 0x190c6/0x1a02a/0x1f09a8/0x7c467c/0xb99bb4/0xb99c90);
4.32e proved the seventh SPLIT-form site survives (the contiguous scan
is blind to gap > 4). This pass:

1. **The split finder enters gspbuild** (`riscv_lui_addi_split_sites`):
   exhaustive 2-byte steps, gaps {6, 8}, capstone-decoded clobber check
   (every instruction between lui and addi must not write rd; an insn
   straddling the addi rejects the site). On the real rm window it
   returns EXACTLY `[(0xb99c4a, 0xb99c52, 14, 'addi')]` — and 0 sites
   for 280000 and 100000 (no post-patch collisions, no false positives).
2. **The 7/7 patch** (`patch_rm_constant(..., expected_split=1)`): the
   two split instructions are patched SEPARATELY — the gap bytes are
   never touched. Diff on the committed fwimage: **21 bytes** (18
   contiguous + 3 split: `37 d7 03`→`37 47 04` in the lui, `09`→`5c` in
   the addi), every differing byte inside a rewritten window. All seven
   pairs re-decode 280000; the `sub s2,s10,s2` (0x412d0933) is
   byte-preserved.
3. **The artifact** lives OUTSIDE the repo (>5 MB rule):
   `/home/z/my-project/artifacts/fwimage-77-patched.bin` (fwimage only;
   the founder reproduces the 7/7 CONTAINER with one command:
   `gspbuild.py patchrm <gsp_ga10x.bin> 0x19f000 0x1071000 250000
   280000 <out> sites=6 split=1`).
4. **The verdict is REVERT** — recorded in the JSON and in the runbook:
   - semantics: 4.32 PROVED the seven sites are the request/budget
     engine's TIME hysteresis band ([250000, 500000] µs), not a power
     policy — turning them cannot reach 280 W;
   - coherence: the 4.30 container (sha 6a3c1a06…) is half-turned (6/7);
     booting it was registered as the blocking defect in 4.33;
   - the 280 W path stays the HOST FEED (the EDPp object is
     runtime-fed through a vtable — 4.32 TASK 3).
   `tools/edpp/runbook-280.sh` now refuses the 6/7 container outright
   and gates the 7/7 behind an explicit `RUNBOOK_77_ACK=1` opt-in with
   the TIME-not-power warning printed.

## 2. PART B — the 34 c.lui-100000 bodies (v434b)

The 4.33 queue item, paid. The 36 sites (34 ret-bounded bodies, 2
bodies carry 2 sites, 3 inside the s2/s3 regions) each got a
forward-slice from the materializing register (capstone operands by
REGISTER NUMBER — the ABI-name comparison was an in-flight bug this
pass caught: `reg_name()` returns 's4', not 'x20'):

| first consumer | sites | reading |
|---|---|---|
| USE:c.jalr (CALL-ARG) | 6 | 100000 passed as an argument (a2/a3) into an indirect call — e.g. @0x124f602: `a2 = 100000`, `a3 = 0x20`, then `c.jalr a5` (the body also carries a full-form 10000000 = 10 ms) |
| MUL | 4 | conversion chains — @0x11c22e2: `mul s6, s10, a5` (a5 = 100000) then `divu s6, s6, a2` (a2 zero-extended u32): the ×1e5/div converter shape; two of the four are the s2/s3 sites |
| STORE-DATA | 5 | state-field writes — @0x11d44ca: `sw a4, 0x5d0(s1)` stores 100000 into the state frame field +0x5d0 (next to a zeroed +0x5b0) |
| COMPARE | 3 | thresholds — @0x141b654: `bltu a4, a5` with a4 = 100000 and **`rdtime a0` in the same window** (the Part C trigger); @0x17c1212 (s2/s3): `bltu a5, a4` |
| USE (arith/mv/addi/c.add) | 8 | the value flows into arithmetic chains before any other consumer |
| slice interrupted | 11 | 4 PROVEN c.j value-blocks (each block materializes a different constant then jumps to the shared tail — the 4.33 identification-chain shape); 7 branched paths the linear slice cannot resolve — HONEST HYPOTHESIS, not dead code (0 truly DEAD sites) |

The s2/s3 attribution (the 4.33 queue item): 0x11eb6f0 → MUL, 0x11f04c6
→ MUL, 0x17c1212 → COMPARE — all three now have a consumer class.

**The family reading:** 100000 is the RM's fine time quantum. It is
compared against time deltas, multiplied in conversion chains, stored
as state defaults, and passed as call arguments — but NEVER used as a
power/wattage knob (the 4.32 falsification, now positive-side proven:
36 real sites, zero STORE-DATA into the EDPp object's fields).

## 3. PART C — the tick rate (v434c)

The census: **4,993 system ops (0x73) at seen starts; 451 are
rdtime reads** (0xC01 via csrrs rd, x0) — the RISC-V time CSR is the
RM's clock. The windows cluster (0x1c501e–0x1c55d6 = 20 reads in one
region, 0x9b530–0x9b684 = 8, ...) — the time-query plumbing is
concentrated, not smeared.

**The conversion chain (the proof):** @VA 0x1bc75f0 the code
materializes `s2 = 0x3B9AC000 = 1,000,000,000` (lui 0x3b9ad, addi
−0x600) and stores it as an argument; @0x1bc7650, in the same body:

```
remu  a4, a5, s2           ; a4 = ticks % 1e9   (the sub-second remainder)
divu  a5, a5, s2           ; a5 = ticks / 1e9   (whole seconds)
lui   a3, 0xf4
addi  a3, a3, 0x240        ; a3 = 0xF4240 = 1,000,000
mul   a5, a5, a3           ; a5 = seconds * 1e6 = MICROSECONDS
...
c.add a5, a4               ; + the remainder term
```

ticks ÷ 1e9 = seconds ⇒ **one rdtime tick = one nanosecond (1 GHz)**.
The µs ladder of 4.32/4.33 is the POLICY layer on top: thresholds in µs
(1e6 µs = 1 s), the counter in ns, conversions at the boundary (1e9 =
76 full-form sites, 1e6 = 123 — the two biggest knobs in the 4.33
census, now explained).

The frequency hunt closes the alternatives: **31.25 MHz appears ZERO
times** in the code (full-form) AND the data image (aligned u32) — the
classic GSP/PTIMER tick is NOT what rdtime delivers; 27 MHz = 4 sites
(the reference-clock role, not the counter); 25/15.625/3.90625 MHz = 0.

The Part B COMPARE site now reads cleanly: `a4 = 100000` vs a5, with
`rdtime` in the same basic block ⇒ the threshold is **100000 ns =
100 µs** against a raw counter delta (PROVEN for this site; the other
COMPARE/STORE/MUL sites keep their per-site domain label — µs where the
4.32 ladder context applies).

## 4. The instrument lessons banked (the discipline: named, not hidden)

1. **The v416 map is zlib-packed** — index AFTER `zlib.decompress`
   (a raw-file index returns garbage silently; the s1 assert caught it).
2. **capstone register identity is the NUMBER, not the ABI name** —
   `reg_name()` returns 's4'; comparing against 'x20' silently matches
   nothing (the first Part B run classified all 36 sites DEAD; the
   corrected operand-number comparison restored the real histogram).
3. **A compressed c.lui has NO rd field at word bits [11:7]** — the
   pair must be decoded by capstone, not by the padded 32-bit word.
4. **The linear forward-slice under-reports through c.j value-blocks
   and branches** — 11/36 sites report "interrupted"; the honest label
   is kept instead of forcing DEAD.
5. **A load's destination is NOT a read** — the LOADS branch of the
   role check separates base-read from dest-write (LOAD-BASE vs
   CLOBBER).
6. **The split-form patch must patch the two instructions separately**
   — the gap bytes (the `sub`) are load-bearing; packing <II> across
   the gap would corrupt a live instruction (the S8 test pins it).

## 5. The queue after 4.34

- the 7 branched-path sites (Part B): a CFG-aware slice would resolve
  them — low value, the family reading is already banked;
- the state field +0x5d0 (Part B STORE-DATA): which object owns s1+
  0x5d0, and is 100000 the refresh quantum? — the next provenance
  question if the founder wants it;
- the host-feed 280 W experiment (the 4.32/4.34 path): the runbook's
  validate/capture steps work against the STOCK firmware;
- the founder's boot decisions stay the founder's — no boot, no merge.
