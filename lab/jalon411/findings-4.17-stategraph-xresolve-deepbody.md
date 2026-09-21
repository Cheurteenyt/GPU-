# 4.17 — the state-frame dispatch graph, the X=? exhaustion, and the deep-body island

Substrate: `tools/gsp-extract/rm-full.elf` (v414 — fingerprint unchanged;
ONE RWX LOAD `0x1000000`, `filesz==memsz=0xE9B000`, `shnum=0`, RISC-V 64).
Instruments: `v417_stategraph.py` (dispatch graph over the verified map),
`v417_xresolve.py` (the carried-base resolution attempt), `v417_deepbody.py`
(the `0x1158c9c` island). JSONs: `v417_stategraph.json`,
`v417_xresolve.json`, `v417_deepbody.json`.

## 1. The dispatch graph — the census reproduces, then the shape appears

The 4.16 chase is re-derived first as a cross-check and reproduces exactly:
**221,201 verified indirect transfers, 1,201 state-frame dispatches, 665
(reg, off) slots**. Then the new layer:

- **Dropping the register, only 225 distinct offsets remain** — and **103
  offsets are shared by >= 3 distinct callee-saved bases**. The top offsets
  are genuinely poly-pointer: `−0x688` (59 sites, **10 distinct bases**, 18
  regions), `−0x7e0` (49 sites, 10 bases, 12 regions), `−0xb8` (44 sites,
  11 bases), `−0x340` (43 sites, 11 bases). The state structure has **one
  shape addressed through dozens of carried pointers** — the "handed down"
  model of 4.14/4.16 is now measurable: the bases differ, the fields
  coincide.
- **Degree histograms**: 404 of the 665 slots fire at exactly 1 site, 146 at
  2, long tail to 11 — **no dominant dispatcher** (the 4.15 O2 verdict,
  re-proven at graph level). Region side: 63 regions use >= 4 distinct
  slots; the densest verified runs are true dispatch hubs — the top one,
  `[0x1498788–0x14b01d6]` (~97 KB of boundary-verified code), dispatches
  through **61 distinct state slots**; runner-ups `0x133cd26–0x1355c32`
  (50 slots) and `0x125d240–0x126cf62` (46).
- **The companion offset is in the dispatch graph**: 5 sites load
  `−0x588` (bases s2/s4/s5) as a function pointer and call it. The 4.15/4.16
  companion field (offset ≡ 0xA78 mod 0x1000 — released as an object
  pointer at `0x1326394`/`0x130b786`, refcounted at `0x11dd0ec`) is
  therefore **not exclusively an object-pointer field**: either polymorphic
  use of one structure, or sibling state shapes sharing the 0xA78
  page-offset. Banked as an open question, honestly.

## 2. The X=? exhaustion — the carried bases resist, by construction

The 4.16 flat table reproduces **exactly** (all 12 families, same counts;
note the 4.16 summary's "48 X=?" excluded the `X=?+s3` variant — 49
X-unresolved sites total).

Method upgrade banked as the 4.17 rule: the backward walk follows the
**verified instruction trail** — each backstep must be a boundary-verified
insn start whose decode ends exactly at the previous step; ambiguity or an
unverified offset stops the trail (the trail length is itself reported).
The 4.16 formation rules then run inside the trail (c.lui/lui told apart by
insn size — the exact 4.16 fix).

Verdicts over the 49 sites:

| verdict | sites | meaning |
|---------|-------|---------|
| `no-verified-trail` | **34** | NO verified context behind the site — the host block itself is dispatch-reached |
| `honest-gap` | 11 | verified trails of 512+ insns, base redefined by untracked formations |
| `copied-from` | 4 | base = `mv` of a5/a1 — whose own formation is further upstream |
| `X-resolved` | **0** | no page constant inside any verified trail |

**Zero local resolutions.** Combined with the 34 trail-less hosts, the wide
`−0x588` family's bases are formed **deep upstream or handed through
dispatch** — the "carried" verdict of 4.16 is now confirmed by exhaustion
of local methods, not by default. Notable: `0x11dd19a/0x11dd1ac` (the 4.15
counter write-backs) sit in the honest-gap set with base s5 — consistent
with their 4.15 windows.

## 3. The deep body of 0x1158c9c — a quantified island

Span census `[0x1158c9c, 0x115d400)`: **coverage 0.48%** — exactly ONE
verified run, `[0x1158c9c–0x1158cf4]` (88 bytes: the prologue), then ~18 KB
of dispatch-reached code. The five banked sites all sit outside the map,
inside honest islands:

| site | role | island before | island after | store re-confirmed byte-exact |
|------|------|---------------|--------------|-------------------------------|
| 0x115a986 | companion | 0x1c96 | 0x557e | `sd s11, +0x588(a5)` |
| 0x115ad8a | companion | 0x209a | 0x517a | `sd t4, +0x588(ra)` |
| 0x115b5c8 | companion | 0x28d8 | 0x493c | `sd a6, +0x588(s1)` |
| 0x115c7c0 | companion | 0x3ad0 | 0x3744 | `sd a2, +0x588(a4)` |
| 0x115d324 | anchor | 0x4634 | 0x2be0 | `sd a5, 0(s1)` (VT install) |

- The companion bases are **carried registers of every flavor — including
  `ra` used as a scratch base** (0x115ad8a): O2-level pointer reuse,
  consistent with the exhausted local resolution of §2.
- **Zero indirect transfers within ±0x100 of every site** (vs 13 in the
  proven `0x1326394` calibration window): the deep-body sites are dispatch
  TARGETS in a code island, not local dispatchers. The island's parent
  dispatch (who fills the state slots that reach it) remains the open
  question — it is runtime state, and the static map cannot name it.

## 4. Queue for 4.18

- **The hub census**: `[0x1498788–0x14b01d6]` (61 slots) and its two
  runner-ups — which stores FILL those slots inside the hub (the
  state-table builders should live next to their dispatchers).
- **The 5 `−0x588` dispatch sites** (s2/s4/s5): wide windows to bind them
  to state instances — the polymorphism question of §1.
- **The upstream-formation pass**: the 4.14 entry-value instrument re-run
  over the verified map, aimed at the 15 long-trail sites of §2 — who
  forms the state pointers that reach the wide-slot sites.

## Discipline

Local commit on `pr1/queue`, pushed fast-forward to the PR branch
`docs/hardware-path-and-pc-only-research` — commits authorized by the
founder (2026-09-21); **zero merge, zero force-push, main untouched**.
