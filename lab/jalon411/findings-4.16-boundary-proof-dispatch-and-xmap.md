# 4.16 — the boundary-proof census, the dispatch chase, and the wide -0x588 family

Substrate: `tools/gsp-extract/rm-full.elf` (v414 — ONE RWX LOAD `0x1000000`,
`filesz==memsz=0xE9B000`, `shnum=0`; fingerprint re-verified in-flight).
Instruments: `v416_rdescensus.py` (recursive descent + verified map, dumped to
`v416_map.bin`), `v416_chase.py` (indirect-dispatch census over the verified
map), `v416_map588.py` (the `lui X − 0x588` slot-family map).
JSONs: `v416_rdescensus.json`, `v416_chase.json`, `v416_map588.json`.

## 1. The recursive descent — the desync question is retired

The 4.15 verdict named the linear-sweep desync (44,076 invalid edges,
mid-insn artifacts) as the limit of the census method. 4.16 replaces it with a
recursive-descent instruction map:

- **Seeds** (tiers, honestly labeled): `entry` 0x1000000 (padding — dies at
  data, harmless), **13,645 prologue-idiom starts** (`c.addi16sp` / `addi
  sp,sp,-N` followed within 6 insns by a `ra` store), vtable-slot0 seeds
  (rebuilt strict installs — **0 kept after the prologue-adjacency filter**,
  see §4), processed **ascending** so the earliest start wins.
- **Walk rules**: linear within a region; calls (`jal`, `c.jal`, formed
  `auipc+jalr` pairs — sign-extended, 800-byte pairing window, in-image
  validated) seed the callee and the stream continues; conditional branches
  seed both paths' targets; **ret/c.jr ra stop**; unresolved indirect tails
  (`c.jr a5` — switch/state dispatch) do NOT stop the stream (site banked);
  a hard stop at undecodable bytes and at **overlap conflicts** (a new insn
  may not begin inside a verified insn's body).
- **Post-ret continuation blocks** are seeded (tier `post-ret`) so padding
  and shared-epilogue gaps bridge — every block keeps its honest tier.

**Result: 66.03% of the image boundary-verified** (3,400,949 insns,
52,946 regions), **81,871 distinct validated call edges** (600 out-of-image
rejected — vs 44,076 invalid edges in the 4.15 linear sweep: the desync is
gone), only 10 overlap conflicts, 274 data stops. Median walk 35 insns —
the firmware's functions are small; the giant "functions" of the earlier
passes are **spans of small functions plus dispatch-reached blocks**.

Two instrument bugs were caught and fixed en route (banked here for the
record): the auipc branch did not advance the walk (every walk died at its
first auipc — coverage 5.6%, edges 0), and `norm()` collapses `c.add/c.lui`
into `add/lui` so the compressed forms must be told apart by operand count
and instruction size.

## 2. The dispatch-driven architecture (the big structural finding)

- The banked mega-constructor span is **not one function**. The walk from
  the real prologue `0x1325df4` runs 226 insns and ends at a hard
  **`c.jr ra` @0x1326080** — a genuine return boundary — and the companion
  write `0x1326394` lives PAST it, in a block with **no static entry**: no
  branch target from any verified region reaches it, no prologue seed exists
  inside. It is reached only through runtime dispatch.
- The chase confirms the mechanism at scale. Over the verified map:
  **221,201 verified indirect transfers** — **47,961 object-vtable
  dispatches** (feeder `ld rd, off(a-reg)` or off >= 0: virtual calls through
  object pointers), **1,201 state-frame dispatches** (feeder
  `ld rd, off(s-reg)`, off < 0 — the `ld a5, -0x6f0(s2); jalr a5` state-table
  idiom), 172,026 carried/ret-class. The state-table slots are **diffuse**:
  the top slots (`s6−0x688` 11 sites, `s5−0x688` 11, `s6−0x7e0` 9, …) hold
  7–11 sites each — no dominant dispatcher, consistent with the 4.15 O2
  verdict ("not a single hot call").
- **The four banked constructors (0x1158c9c, 0x1325e00, 0x130b712, 0x11dd0ec)
  have NO static direct callers** in 81,871 edges — they are dispatch targets
  (function pointers installed in the state structure), which is exactly the
  "handed down" model of 4.14.

## 3. The census under boundaries (the 0x588 family, verified subset)

Re-census of the marker family restricted to boundary-verified insns:

- `+0x588` direct stores: **37 verified sites** (of the 112 in the 4.15
  linear census) — e.g. `0x10bf34a` (the single `sb`, NOW boundary-verified:
  the 4.15 "probable desync artifact" is in fact a REAL verified insn),
  `0x114d5b6`, `0x115668e`, `0x119c23c` …
- `-0x588` (aliased/negative form): **24 verified sites** (of 59) —
  `0x10a8b9e`, `0x10a8c0c`, `0x10a98de` …
- The companion cluster is fully verified: `0x1326394` (release),
  `0x130b786` (twin release), `0x11dd146/19a/1ac` (counter write-backs),
  and the magic store `0x116b3c4 → 0xff000065`.
- **The honest gap**: the `0x1158c9c`-family companion writes (`0x115a986`,
  `0x115ad8a`, `0x115b5c8`, `0x115c7c0`) and the anchor `0x115d324` remain
  OUTSIDE the verified map — the function's prologue is verified, its deep
  body is dispatch-reached. For these sites the 4.15 linear census remains
  the evidence; the descent adds: they live in runtime-dispatched blocks.

## 4. The anchor arbitration — byte-exact, both predecessors corrected

The window decodes:

```
0x115d31c: auipc a5, 0xaee      # a5 = 0x115d31c + 0xaee000 = 0x1c4b31c
0x115d320: addi  a5, a5, 0x56c  # a5 = 0x1c4b888
0x115d324: c.sd  a5, 0(s1)      # the anchor install: VT = 0x1c4b888
```

**VT = 0x1c4b888.** The 4.13 value (0x1c4b890) and the 4.14 "honest
correction" (0x1c4b56c) are both superseded: 4.14 used the page-aligned pc
(0x115d000 instead of 0x115d31c) in the auipc arithmetic — the difference is
exactly 0x31c, the low 12 bits of the auipc's own address.

The strict-vtable rebuild (linear tracker, 800-byte expiry) found 382
offset-0 installs but all share one over-attributed slot0 (0x114bc84, data
not code) — **0 survive the prologue-adjacency filter**; the banked 4.14
strict count (57/55) is not reproduced by this method and the discrepancy is
recorded, not hidden. The descent did not need the vtable seeds: the
prologue tier carried it.

## 5. The wide -0x588 family — the X map (queue item closed)

64 stores at displacement `-0x588` captured; the base-formation walk
(normalized forms — `c.lui`/`c.add` told apart by operand count and size)
resolves **16 sites into X-page families**:

| family | sites | slot (s_reg + (X<<12) − 0x588) |
|--------|-------|-------------------------------|
| X=0x4 + s11 | 1 | **0x3A78** — the banked companion slot |
| X=0x4 + s1 / s2 | 2 | 0x3A78 on other state bases |
| X=0x8 + s1 / s2 / s6 | 4 | **0x7A78** |
| X=0x3 + s1 | 2 | 0x2A78 |
| X=0x5 + s1 | 2 | 0x4A78 |
| X=0x1 + s1 / s9 | 4 | 0x0A78 |
| X=? (base carried / load-formed) | 48 | honest gap |

The recurring structure: **the −0x588 displacement hits offset ≡ 0xA78 (mod
0x1000) on SEVERAL page bases** — sibling slots of the same shape across
state instances. The 4.15 "wide slot family" lead is confirmed and mapped:
it is the same companion-slot field replicated across the state pages, not a
new structure.

## 6. Queue for 4.17

- Extend the descent with the 1,201 state-frame dispatch slots as
  pseudo-seeds (the slot VALUES are runtime, but the slot OFFSETS are static:
  a slot-site census per state structure gives the dispatch graph's shape).
- The 48 X=? sites: widen the formation window or resolve via the s-reg
  provenance pass (the 4.14 `entry-value` instrument, re-run on the map).
- The `0x1158c9c` deep body: slot-site chase around its companion writes to
  bind them to their dispatch parent blocks.

## Discipline

Local commits on `pr1/queue`, pushed fast-forward to the PR branch
`docs/hardware-path-and-pc-only-research` — **push explicitly authorized by
the founder on 2026-09-21 ("je ne t'ai pas interdit de faire des commits, je
t'ai juste interdit de merge")**; zero merge, zero force-push, main untouched.
