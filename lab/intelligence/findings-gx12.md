# findings-gx12 — the twelfth ring: the devinit program has a shape

Scope: the day-0 live dump plus the three verified acquisitions, one
instrument (`gx12-callgraph.py`), the ring-10 walker imported (its grammar
imported there from nouveau init.c). Selftest green (0 failures).

## What is measured

**The program shape.** The live dump's 317 devinit scripts decompose into
**259 roots** (never called — the entry points) and **58 subroutines**,
bound by **216 direct calls** (0x5b SUB_DIRECT, u16 offsets), maximum
call depth **2**. The hottest routines: `0x6951` (called 48×), `0x675f`
(47×), `0x58c6`/`0x58ed` (24× each) — utility layers shared by the whole
program. A correction is banked en route: the raw overlapped scan
suggested 186 index-based calls (0x6b SUB); the validated inventory
counts **zero** — those were mid-instruction matches, and the macro-index
table pointer (NVINIT+2) is 0x0000 anyway (measured ring 10). All calls
are direct.

**The TPU captures share their wound.** Both LHR-era acquisitions
(primary and Ventus) inventory **259 scripts with the same subroutine
offsets and the same hot callees as each other** — both lost the same
divergent region the same way. The launch-era build (a genuinely
different layout) reads 251 scripts with its routines shifted (~0x50
lower: 0x6901, 0x670f…). The amputation is a property of the capture
pipeline, now seen twice.

**The script lists of the memory-clock header** (ring 8's named
ScriptListPtr 0x84dd / CmdScriptListPtr 0x84e9): dense on the live card,
**entirely zeroed in the acquisitions** — a third instance of the same
loss, with the list's pointer domain still unresolved (registered, not
guessed).

## Consequences

1. The devinit layer is no longer a bag of scripts: it is a **program**
   — 259 entries calling 58 shared routines two deep, with measurable
   hot paths. Future questions ("what does the card write when X") now
   resolve to named scripts.
2. The capture-loss law gains a second witness: any TechPowerUp-style
   acquisition of this generation must be presumed amputated in the
   0x7E00+ region until proven otherwise — the live dump is the
   reference, and cross-source differs must start from this law.

## Honesty ledger

- Proven: the decomposition, the 216 resolved direct calls, depth 2,
  the hot callees, the zero index-calls, the two-witness amputation,
  selftest 0 failures across all four admitted images.
- Inferred: the capture-pipeline attribution (two independent TPU
  captures, same wound — the pipeline is the common factor).
- Unknown: the memory-script-list pointer domain; the semantic roles of
  the hot routines (0x6951/0x675f unnamed — the register-write census of
  ring 10 is their best current description); everything behind the
  GSP-RM packing.
