#!/usr/bin/env python3
"""4.17 pass — the 0x1158c9c deep body: slot-site chase.

Queue item 3 of 4.16: the 0x1158c9c-family companion writes (0x115a986,
0x115ad8a, 0x115b5c8, 0x115c7c0) and the anchor 0x115d324 remain OUTSIDE
the verified map — the prologue is verified, the deep body is
dispatch-reached. For these sites the 4.15 linear census remains the
evidence. This instrument adds the dispatch layer:

  for each site:
    - map status (seen/covered) — expected OUTSIDE;
    - the island gap: distance to the nearest covered byte before/after —
      the size of the dispatch-reached span that hosts the site;
    - a local window (+/-0x100) is decoded (skipdata, honestly
      non-verified): the companion store is re-confirmed byte-exact and
      every indirect transfer in the window gets its feeder chased
      (state-frame slots = the dispatch parent's table read);
  the same measurements are taken for the PROVEN 4.16 pattern
  (0x1326394 in its no-static-entry block, bounded by the verified
  c.jr ra @0x1326080) as the calibration row.

Output: lab/jalon411/v417_deepbody.json
"""
import json
import struct
import zlib
from bisect import bisect_left, bisect_right

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v417_deepbody.json"

IMG_LO = 0x1000000
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
SITES = [0x115a986, 0x115ad8a, 0x115b5c8, 0x115c7c0, 0x115d324]
CALIB = 0x1326394          # the proven 4.16 dispatch-reached companion write
PROLOGUE = 0x1158c9c
SPAN_LO, SPAN_HI = 0x1158c9c, 0x115d400
WIN = 0x100


def load():
    d = open(SUBSTRATE, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize = struct.unpack_from("<H", d, 54)[0]
    e_phnum = struct.unpack_from("<H", d, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", d, o)
        p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        if p_type == 1:
            return d[p_off:p_off + p_filesz]


def load_map():
    blob = zlib.decompress(open(MAP, "rb").read())
    half = len(blob) // 2
    return blob[:half], blob[half:]


def norm(m):
    return m[2:] if m.startswith("c.") else m


def island(seen, pc):
    """distance to nearest covered byte before/after pc (0 if covered)."""
    n = len(seen)
    if seen[pc]:
        return 0, 0
    d_before = None
    i = pc - 1
    while i >= 0 and pc - i < 0x8000:
        if seen[i]:
            d_before = pc - i
            break
        i -= 1
    d_after = None
    j = pc + 1
    while j < n and j - pc < 0x8000:
        if seen[j]:
            d_after = j - pc
            break
        j += 1
    return d_before, d_after


def chase_window(code, md, center):
    """decode [center-WIN, center+WIN); return stores + indirect transfers
    with their chased state-frame feeder slots."""
    lo, hi = max(0, center - WIN), center + WIN
    stores, xfers = [], []
    pc = lo
    while pc < hi - 2:
        try:
            insn = next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
        except StopIteration:
            pc += 2
            continue
        m, ops = insn.mnemonic, insn.op_str
        if m in (".byte", "(bad)"):
            pc += 2
            continue
        mn = norm(m)
        if mn in ("sd", "sw", "sh", "sb"):
            p1 = ops.split(", ")
            if len(p1) == 2 and "(" in p1[1]:
                try:
                    off_s, bas = p1[1][:-1].split("(", 1)
                    stores.append({"pc": hex(IMG_LO + pc), "width": mn,
                                   "src": p1[0].strip(),
                                   "off": int(off_s.strip(), 0),
                                   "base": bas.strip(),
                                   "is_center": (pc == center)})
                except Exception:
                    pass
        if m in ("jalr", "c.jalr", "c.jr", "jr") and norm(m) != "jr":
            # chase the single-def feeder in a small backward scan
            parts = [x.strip() for x in ops.split(",")]
            rs = parts[-1] if m == "jalr" and len(parts) == 3 else (
                parts[-1] if m != "jalr" else None)
            slot = None
            if m == "jalr":
                if "(" in ops:
                    p = ops.replace("(", ",").replace(")", "").split(",")
                    rs = p[2].strip()
                elif len(parts) == 1:
                    rs = parts[0]
                else:
                    rs = parts[1]
            else:
                rs = parts[-1]
            # backward linear scan for the feeder (<= 16 insns)
            k = pc
            steps = 0
            fwin = []
            while k > lo and steps < 16:
                try:
                    jns = next(md.disasm(code[k:k + 16], IMG_LO + k))
                except StopIteration:
                    break
                fwin.append((jns.mnemonic, jns.op_str, jns.size))
                k += jns.size if jns.size > 0 else 2
                steps += 1
            for jm, jops, jsize in reversed(fwin[:-1]):
                jn = norm(jm)
                jp = [t.strip() for t in jops.split(",")]
                wr = jp[0] if jp else None
                if wr == rs and jn in ("ld", "c.ld") and len(jp) == 2 and "(" in jp[1]:
                    try:
                        off_s, bas = jp[1][:-1].split("(", 1)
                        off = int(off_s.strip(), 0)
                        if bas.strip() in S_REGS and off < 0:
                            slot = f"{bas.strip()}+{hex(off)}"
                    except Exception:
                        pass
                    break
                if wr == rs:
                    break
            xfers.append({"pc": hex(IMG_LO + pc), "xfer": m, "ops": ops,
                          "state_slot": slot})
        pc += insn.size if insn.size > 0 else 2
    return stores, xfers


def main():
    code = load()
    seen, covered = load_map()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    rows = []
    for site in SITES + [CALIB, PROLOGUE]:
        pc = site - IMG_LO
        db, da = island(seen, pc)
        stores, xfers = chase_window(code, md, pc)
        comp = [s for s in stores if s["is_center"]]
        slots = sorted({x["state_slot"] for x in xfers if x["state_slot"]})
        rows.append({
            "site": hex(site),
            "role": ("calibration-proven-4.16" if site == CALIB
                     else "prologue" if site == PROLOGUE
                     else "companion" if site != 0x115d324 else "anchor"),
            "seen": bool(seen[pc]) if 0 <= pc < len(seen) else False,
            "island_before": (hex(db) if db is not None else ">=0x8000/none"),
            "island_after": (hex(da) if da is not None else ">=0x8000/none"),
            "store_at_site": comp,
            "window_stores_n": len(stores),
            "window_xfers": xfers,
            "window_state_slots": slots,
        })

    # the span census: verified coverage inside [PROLOGUE, SPAN_HI)
    lo, hi = SPAN_LO - IMG_LO, SPAN_HI - IMG_LO
    cov = sum(1 for i in range(lo, hi) if covered[i])
    total = hi - lo
    # nearest covered islands inside the span
    runs = []
    i = lo
    while i < hi:
        if covered[i]:
            j = i
            while j < hi and covered[j]:
                j += 1
            runs.append((hex(IMG_LO + i), hex(IMG_LO + j), j - i))
            i = j
        else:
            i += 1
    runs.sort(key=lambda r: -r[2])

    out = {
        "pass": "4.17-deepbody",
        "substrate": SUBSTRATE,
        "sites": rows,
        "span": {"lo": hex(SPAN_LO), "hi": hex(SPAN_HI),
                 "bytes": total, "covered": cov,
                 "coverage_pct": round(100.0 * cov / total, 2),
                 "covered_runs_top8": runs[:8]},
    }
    json.dump(out, open(OUT, "w"), indent=1)
    for r in rows:
        print(f"{r['site']} {r['role']:24s} seen={r['seen']} "
              f"island(-{r['island_before']}/+{r['island_after']}) "
              f"slots={r['window_state_slots'][:3]}")
    print("span coverage:", out["span"]["coverage_pct"], "%")
    print("OUT", OUT)


if __name__ == "__main__":
    main()
