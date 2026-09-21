# 4.18 — the hub fill census, the first X resolutions, and the provenance classes

Substrate: `tools/gsp-extract/rm-full.elf` (v414 — fingerprint unchanged).
Instruments: `v418_hubfill.py` (who fills the dispatch slots), `v418_upstream.py`
(the upstream-formation pass), `v418_dispatch588.py` (the companion-offset
dispatch sites). JSONs: `v418_hubfill.json`, `v418_upstream.json`,
`v418_dispatch588.json`.

## 1. The hub fill census — the tables are built in place, but the pointers CIRCULATE

The 4.17 census reproduces (221,201 verified indirects / 225 distinct slot
offsets). Top-3 hubs re-ranked by distinct offsets (the 4.17 (reg,off) slots
merge when the register is dropped — 61 → 44, 50 → 38, 46 → 35):

| hub (verified run) | offsets | dispatches | fills in-hub | fill value classes |
|--------------------|---------|-----------|--------------|--------------------|
| `[0x1498788–0x14b01d6]` (~97 KB) | 44 | 87 | **120** | carried 97, ld-copied 23 |
| `[0x125d240–0x126cf62]` | 38 | 48 | 51 | carried 42, ld-copied 8, lui 1 |
| `[0x133cd26–0x1355c32]` | 35 | 61 | 33 | carried 32, ld-copied 1 |

- The fillers ARE co-located (fill/dispatch ratios 1.4 / 1.1 / 0.5 — the
  third hub is a net consumer): state tables are built next to their
  dispatchers.
- **But zero static targets**: across 204 fills, 0 `auipc`, 1 `lui`, 23+8+1
  `ld-copied`, the rest carried. **No slot fill names a code address.** The
  state-table entries hold pointers that were formed elsewhere and CAME
  here through registers or other tables — the "handed down" chain does
  not terminate statically inside the hubs. The dispatch graph is
  runtime-bound end to end.

## 2. The upstream-formation pass — the first X resolutions since 4.16

New rule banked as the 4.18 method: the backward verified-trail walk stops
at the first **return crossed** (a function boundary the walk never
crosses), and the base register's defining event inside the site's own
function classifies the pointer's provenance. Formation rules now follow
the 4.16 merge idiom (`c.lui/lui bas, X` + `add bas, sY`) to the end.

The 15 long-trail sites of 4.17 (11 honest-gap + 4 copied-from) are ALL
classified — zero honest-gaps remain:

| provenance | sites | meaning |
|------------|-------|---------|
| `static-formed(c.lui+merge)` | **4** | **X RESOLVED** — see below |
| `ABI-carried` | 2 | the base arrived through the callee-saved ABI (the dispatcher put it there) |
| `sp-derived-frame` | 3 | base = `addi s0, sp, imm` — these `-0x588` stores hit LOCAL FRAME fields, not the state structure |
| `sum-of-carried` | 2 | base = `s1+s8` — the 4.15 counter write-backs `0x11dd19a/1ac` |
| `sum-of-carried-and-arg` | 1 | base = `s1+a0` |
| `loaded-from-arg` | 1 | base = `lw s5, 0x7a4(a0)` — the pointer is READ from the argument structure |
| `loaded-from-carried` | 1 | base = `lw a5, -0x7c(s0)` |
| `static-formed(auipc)` | 1 | absolute slot 0x6706A78 — a data page, not the state structure |

**The X resolutions (first since 4.16)**:

- `0x10a9fbc`, `0x10b32e2`, `0x10b3838`: base = `c.lui 8` + `a5` →
  **slot = a5 + 0x7A78** — the X=8 family of the 4.16 map, now proven by
  formation (the base merges a carried ARGUMENT into the page).
- `0x130608a`: base = `c.lui 4` + `a1` → **slot = a1 + 0x3A78 — THE
  COMPANION SLOT**, formed from the state pointer passed as argument.
  The first companion-family site resolved to its exact construction.

Honest framing: the wide `−0x588` family is now KNOWN to mix three kinds of
use — state-structure slots (0x3A78/0x7A78 pages on carried bases), local
frame fields (the sp-derived sites), and one data-page store. The 4.16
"48 X=?" umbrella hid real semantic diversity.

Instrument bugs caught and banked en route: a backward step died when ANY
candidate offset was unverified (candidates must be skipped, not fatal);
`beqz` was treated as a writer (branches READ); `c.lui` (size 2) fell
through the lui test (size 4); the `add bas, sY` merges returned early
instead of walking on to the page constant.

## 3. The 5 companion-offset dispatch sites — bounded, bases inherited

All 5 sites re-confirmed (`ld rd, −0x588(sX); jalr rd`). Base provenance:
3 copied-carried (one hop to another carried reg), 1 short-form static,
1 further form — all inherited, none formed at the site. The slot
neighbors (memory ops on the same base within ±0x40 of the slot): only
1–4 per site — the dispatch slot lives in a quiet neighborhood, NOT a
dense structure region. The polymorphism question (object pointer vs
function pointer in the 0xA78 field) stays open but is now bounded: the
dispatchers use inherited bases and quiet slots; the binding to concrete
state instances is runtime-only.

## 4. Queue for 4.19

- Re-apply the 4.18 provenance machine (ret-frontière + c.lui/merge chase
  + slot capture) to the 5 dispatch sites and to ALL `−0x588` sites — a
  full provenance table of the family (state-slot vs frame vs data).
- Extend the provenance pass to the 103 cross-register offsets of 4.17 —
  who forms the state pointers that circulate (the entry-point census).
- Hub 3 (the net consumer): widen the fill search outside the hub — where
  are its 61 dispatches' slots filled?

## Discipline

Local commit on `pr1/queue`, pushed fast-forward to the PR branch — commits
authorized by the founder (2026-09-21); **zero merge, zero force-push,
main untouched**.
