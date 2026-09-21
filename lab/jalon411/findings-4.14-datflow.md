# 4.14 — the data-flow around the vtable installs (who allocates the O2, who binds it)

Substrate: `tools/gsp-extract/rm-full.elf` (the v414 image), fingerprint re-verified
in-flight: ONE RWX LOAD `vaddr=0x1000000 filesz==memsz=0xE9B000`, `shnum=0`.
Instrument: `lab/jalon411/v414_datflow.py` (streaming linear sweep, backward-window
resolution at sites), JSON: `lab/jalon411/v414_datflow.json`.

## Headline results

1. **The C2 map rebuilt.** Loose net (every offset-0 store of an auipc-formed
   static value): **946 installs / 780 functions**. Strict net (true vtables —
   slot0 at the target is a code pointer inside the LOAD): **57 installs / 55
   functions** — same order as the banked 4.13 "88 / 85" (that tool's filter
   and desync handling differ; both counts are upper/lower bounds of the same
   population).
2. **The anchor is byte-exact now.** The banked site `0x115d324` is
   `c.sd a5, 0(s1)` with `a5` formed by `auipc a5, 0xaee @0x115d31c` +
   `addi a5, a5, 0x56c` → **VT = 0x1c4b56c**. The 4.13 wall comment said
   `VT(0x1c4b890)` — the SITE matches, the formed value differs by 0x324;
   the bytes here are explicit, so the honest correction is **0x1c4b56c**
   unless the 4.13 instrument is re-run to arbitrate.
3. **The companion census rebuilt** (markers: displacement `0x588` = the
   `state+0x4000-0x588` family, and `0x4000` = the state-base marker):
   **87 sites / 29 functions** vs the banked "64 writes / ~26 giant functions"
   — consistent.
4. **Where the companion-writing bases come from (the 4.14 question):**
   `entry-value 51/87` — the base register is a **callee-saved register
   carried into the region** (the state base arrives already bound; it is not
   formed at the write sites); `clobbered-pattern 19`, `derived-other 7`,
   `stack-frame 3`, `memory-load 3`, **`argument 2`**, `static-formed 1`,
   `li-imm 1`. Reading: the companion is bound upstream and *handed down* —
   the mega-constructors mostly write through a carried `s11`-family base,
   which is exactly the "state base" model; only 2 sites take a base straight
   from an argument register.
5. **The structural link re-confirmed byte-exact**: fn `0x1158c9c`
   (window `0x1158c9c..0x116ec9c`) carries **4 companion-marker writes**
   (`0x115a986`, `0x115ad8a`, `0x115b5c8`, `0x115c7c0` — all displacement
   `0x588`) **and 2 true vtable installs** (`0x11593f2 → 0x1c4a6a6`,
   `0x115d324 → 0x1c4b56c`). Dynamic construction and companion writes
   genuinely live in the same giant function.
6. **A stray caught by the loose net**: `0x116b3c4 → 0xff000065` — not a
   vtable (excluded by the strict filter): a magic-constant store
   (`0xff000000|0x65`), likely a state tag. Kept in the JSON as a lead.
7. **Honest gap**: the banked companion write `@0x1326394` inside fn
   `0x1325df4` is **not** caught by the `{0x588, 0x4000}` marker set — that
   site uses another displacement. Queued for 4.15: per-census marker
   extension + the O2 allocator hunt (the `mv a0`-after-call pool = 22,375
   raw candidates needs the call-graph pass before it means anything).

## Discipline

Local commit on `pr1/queue` (on top of the PR head `806a2fa`) — **zero push,
zero merge**. Shipped as `0006-the-4.14-pass-datflow-vtable-installs.patch`;
the founder applies (`git am`) and lands when they decide.
