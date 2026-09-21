# 4.19 — the full -0x588 provenance table, the entry-point census, and hub 3's external fills

Substrate: `tools/gsp-extract/rm-full.elf` (v414 — fingerprint unchanged).
Instruments: `v419_prov588.py` (the whole family through the 4.18 machine),
`v419_entrypoints.py` (the base provenance at every cross-register dispatch
site), `v419_hub3ext.py` (the net consumer's external fills). JSONs:
`v419_prov588.json`, `v419_entrypoints.json`, `v419_hub3ext.json`.

Reproducibility first, as always: the flat 4.16 family table re-derived
byte-exact (all 12 families, 64 sites), and the 4.18 machine re-run fresh
on every site it had already classified — mismatch-free on all shared
verdicts (asserted in the instrument).

## 1. The full -0x588 provenance table — the family is three different things

All 64 `-0x588` stores classified by the 4.18 provenance machine
(verified-trail backward walk, first return = function boundary, merges
chased to the page constant). The 4.19 semantic axis:

| semantics | sites | provenance breakdown |
|-----------|-------|----------------------|
| **state-slot** | **17** | entry-arg 5, c.lui+merge 4, ABI-carried 2, sum-of-carried 2, sum-of-carried-and-arg 1, loaded-from-arg 1, loaded-from-carried 1, abi-carried-plus-reg 1 |
| **data** | **4** | c.lui NO-merge 3 (absolute 0x7A78 ×2, absolute 0x3A78 ×1), auipc 1 (0x6706A78) |
| **frame** | **3** | sp-derived (`addi s0, sp, imm`) |
| no-trail | 40 | dispatch-reached hosts — no verified trail exists |

Three honest corrections to the 4.16 flat map, all from the verified-trail
machine:

- **The flat merges were partly linear-sweep artifacts.** `0x10a8b9e`,
  `0x10a98de` and **`0x1326394`** — which the flat 260-insn window had
  filed under `X=0x8+s1/s2` and `X=0x4+s11` (page + carried merge) — have
  NO merge inside their verified trail: the base is a bare `c.lui` and the
  store hits the ABSOLUTE low addresses 0x7A78 / 0x3A78. The 0x1326394
  cluster — 4.16's calibration site for the whole companion family — is
  therefore a **fixed low-memory data write**, not a state-structure slot
  write. The verified trail is the trustworthy reading; the flat window
  had picked up merges from before the base's redefinition.
- **Six flat-X-resolved sites downgrade honestly to no-trail** (the
  formation lives beyond the verified trail): 0x115b1ce, 0x115b1fa,
  0x135fc00, 0x170d150, 0x172d77e, 0x172d7c0.
- **Five sites gain provenance for the first time** — entry-arg (the base
  is a moved function argument): 0x10bd03c, 0x11dd146, 0x130b786,
  0x18c5a64, 0x1b27e36. With 4.18's four c.lui+merge resolutions, the
  family's state-slot side is now 17/24 trails-deep classified.

The 4.16 "wide family" umbrella is now fully resolved into its three
semantics: real state slots (0x3A78/0x7A78 pages on handed-down bases),
local frame fields, and fixed low-memory data writes — no fourth kind
survived the machine.

## 2. The entry-point census — the circulating pointers are a DERIVATION GRAPH

The 4.18 machine applied to the base of EVERY state-frame dispatch site on
the 103 cross-register offsets (>=3 distinct carried bases): **969 sites
classified** (trail cap 1024 verified insns):

| provenance | sites | share |
|------------|-------|-------|
| entry-arg (`mv base, aX`) | 219 | 22.6% |
| static-formed(c.lui+merge) | 172 | 17.7% |
| sum-of-carried-and-arg | 123 | 12.7% |
| sum-of-carried | 120 | 12.4% |
| abi-carried-plus-reg | 108 | 11.1% |
| ABI-carried | 55 | 5.7% |
| other-def | 77 | 7.9% |
| loaded-from-arg / carried | 49 / 41 | 9.3% |
| c.lui bare / auipc+merge / restored | 3 / 1 / 1 | 0.5% |

Two structural facts:

- **The merges are arguments.** Of the 173 page-merged bases, 169 merge an
  ARGUMENT register (`add base, aX`) and 4 a carried one. The X page
  constant is `0x1` on every top offset (-0x688 ×17, -0xb8 ×11, -0x680
  ×11, -0x128 ×11, -0x7e0 ×6, ...). So the dominant formation is
  **`base = aX + 0x1000`**: the callee receives a pointer, adds one page,
  and indexes the state fields at negative offsets (slot = aX + 0x1000 +
  offset).
- **Nothing is formed from nothing.** Bare static formation is 4 sites of
  969 (0.4%). Every other base is an argument, a page-merged argument, a
  sum of carried pointers, an ABI arrival, or a pointer loaded from a
  structure. The "handed down" chain of 4.15-4.18 is not a single pointer
  passed around — it is a **derivation graph over argument pointers**,
  re-anchored at every dispatch (~40% argument-anchored, ~26% sums, ~17%
  ABI, ~9% structure-loads).

## 3. Hub 3's external fills — the offsets are the shape, not the table

Hub 3 (`[0x133cd26-0x1355c32]`, ~100 KB, 35 distinct dispatch offsets, 61
dispatches, 33 in-hub fills — the net consumer of 4.18). Widening the fill
search to the whole image: those 35 slot offsets are stored from
callee-saved bases **3,338 times outside the hub**, across **307 distinct
regions** — every one of the 35 offsets (35/35). Value classes: carried
2,884, ld-copied 445, lui 9, **auipc+addi resolved 0 — named targets 0**.

Reading: hub 3 is not a table fed by a specific external builder — its
slot offsets are ubiquitous fields of the ONE state shape (4.17's model),
written all over the image on whichever state pointer the writer holds.
Together with 4.18 (0/204 named inside the top-3 hubs) the count stands at
**0 named targets in 3,542 fills**: no state-table function pointer is
ever formed statically at these sites. The dispatch graph is
runtime-bound end to end, and the biggest external writer regions
(`[0x1b08c5c-0x1b288a6]` 452 fills, `[0x1a762f4-0x1a93400]` 151) are the
next builder candidates to inspect.

## 4. Queue for 4.20

- **One level up**: for the 169 page-merge (arg + 0x1000) dispatch bases,
  chase the argument through the verified call edges of 4.16 — who calls
  these functions, and with which pointer? The first caller census of the
  derivation graph.
- **The sum census**: the 243 sum-of-carried bases (sA+sB) — classify the
  pairs (pointer+pointer vs pointer+index) and their offsets; the sums are
  the derivation graph's interior nodes.
- **The 40 no-trail -0x588 hosts**: the 4.16 pseudo-seed idea (slot-site
  pseudo-seeds) remains the only route into the dispatch-reached regions —
  prototype it on the 40.

## Discipline

Local commit on `pr1/queue`, pushed fast-forward to the PR branch — commits
authorized by the founder (2026-09-21); **zero merge, zero force-push,
main untouched**.
