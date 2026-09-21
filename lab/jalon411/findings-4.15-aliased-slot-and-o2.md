# Findings — pass 4.15: the aliased companion slot & the O2 verdict

Substrate: `tools/gsp-extract/rm-full.elf` (v414 — ONE RWX LOAD `0x1000000`, `filesz==memsz=0xE9B000`, `shnum=0`; fingerprint re-verified in-flight).
Instruments: `v415_gap.py` (window probe), `v415_sweep2.py` (full sweep, run 2 — validated targets), `v415_audit.py` (site-for-site + false-pair audit). JSONs: `v415_gap.json`, `v415_census2.json`, `v415_o2hunt.json`.

## 1. The honest gap — closed byte-exact

The banked companion write `@0x1326394` (fn banked as `0x1325df4`; prologue-marker here `0x1325e00`) is:

```
0x1326390: lui  a5, 4          # a5 = 0x4000
0x1326392: add  a5, s11        # a5 = state + 0x4000
0x1326394: sd   zero, -0x588(a5)   # slot = state + 0x4000 - 0x588 = state + 0x3A78
```

It **escapes the 4.14 marker set** `{+0x588, +0x4000}` because it is the **negative alias form**: absolute slot **state+0x3A78** (= the `COMP_OFF` constant) written through a `lui 4 + add s-reg` base. It is not a fresh install — it is the **release**: store ZERO after the destructor call.

## 2. The slot lifecycle (byte-exact windows)

- **Pointer + refcount release (2 functions)**: `ld slot → lw obj+0x90 (refcount) → dec → sw back → if zero: indirect destroy call → sd zero, -0x588(a5)`. Sites `0x1326394` (fn `0x1325e00`) and the twin `0x130b786` (fn `0x130b712`) — same idiom, byte-verified in both windows.
- **Counter + cleanup (fn `0x11dd0ec`)**: `lw -0x588(a3)` reads a **32-bit counter** (not a pointer), `addiw a2, a5, -1`, **`sw a2, -0x588(a3)`** write-back (sites `0x11dd146`, `0x11dd19a`, `0x11dd1ac` — all `sw`, one function), and on zero a cleanup loop clears the bytes after the slot (`sb -0x584(a3)`, bound from `lw 0x7d0(s2)`).
- **Readers**: 8 alias-confirmed loads / 5 functions (`ld`×5, `lw`×3); 105 other-base loads resolve elsewhere (37 static-formed, 31 static-plus-reg, 16 derived-add…).

So the state+0x3A78 slot family carries **two lifecycles**: an object pointer released through the +0x90 refcount idiom, and a counter gating a bounded cleanup.

## 3. Census v2 (sweep run 2 — targets validated)

- **Union: 117 sites / 46 functions** (banked 4.14: 87 / 29, sd-only, direct forms only).
- `fam588` direct: **112 sites / 43 fns** — widths **sd 87 / sw 20 / sh 4 / sb 1**, null-stores 7. The **sd-only population is exactly 87 — matching the banked 4.14 census site-for-site** on the visible prefix (`0x10060c6, 0x114d5b6, 0x114dd7e, 0x114e1da, 0x114e9f0, 0x115668e, 0x1156ca8, 0x115a986, …`).
- `fam4000` direct: 0. `fam3A78` direct: 0. off==0 branch: 0.
- Alias forms: install 3 (`sw`, the counter write-backs) / release 2 (`sd zero`).
- **New lead**: 59 stores at `-0x588` from **other** bases — 44 `static-plus-reg` with `lui ≠ 0x4000` — a wider slot family at `s-reg + (lui X − 0x588)`; the X map is queued 4.16.

## 4. The O2 verdict (call-graph pass)

- Strict pool (`a0` saved into a callee-saved register within 40 insns of the call): **11,852 sites** (raw any-dst 15,688 — the 4.14 instrument counted 22,375 with a looser window); resolved targets 8,200.
- **No dominant allocator**: the top callees hold 6–8 strict saves each — two orders of magnitude from an "everyone calls it" signature.
- **The call graph is desync-limited (named, byte-exact)**: linear sweep loses instruction boundaries over data/padding; the desynced stream forms **false `auipc+jalr` pairs** — 44,076 out-of-image edges rejected by the run-2 validation, and in-image mid-instruction artifacts (call targets landing inside `auipc` bytes in the `0x1aa2xxx` region) named in the audit. Both the 4.14 and 4.15 instruments share this lineage; one census site (`0x10bf34a`, the single `sb`) is a probable desync artifact, identical in both runs.
- Verdict: the O2 binding is **not a single hot direct call** — consistent with 4.14 ("the bases are handed down"). The next levers, queued **4.16**: recursive-descent census (boundary-proof), the indirect-dispatch chase (33,050 indirect tails; the state-table idiom `ld a5, -0x6f0(s2); jalr a5` is visible in the gap window), and the `lui X − 0x588` slot-family map.
