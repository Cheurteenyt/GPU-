#!/usr/bin/env python3
"""4.50 TASK B (v2) — the FB/L2 ingestion map, corrected.

v2 changes (the v1 lesson): the config-store bases are NOT auipc
materializations — they are the c.lui N + c.add rX, s3 idiom (s3 = a1 =
the config base, PROUVÉ 4.49), and the per-key stores live either
INLINE after the fetch or in handler blocks reached by BRANCHES.
So v2:
  1. decodes [0x1307AFC, 0x1308800) whole;
  2. names the 24 fetch sites (call 0x103C08C, name materialized before);
  3. after each fetch, to the next fetch: collects inline stores whose
     base reg = c.lui N (+c.add rX, s3) -> config offset = (N<<12)+disp,
     and branch targets that lead to handler blocks;
  4. decodes every unique handler block (to its first ret): the same
     store extraction + the flag-word ori bits;
  5. emits the per-key card table ordered by the walk.

Selftests: ways -> u32 @config+0x3D84 + flag bit0; G5xPromote -> bit1;
the fetch present on every key.

Output: lab/jalon411/v450b_fb_l2_map.json (overwrites v1)
"""
import json
import re
import struct
import zlib
from pathlib import Path

import numpy as np
import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
IMG_LEN = 0xE9B000
ING_LO, ING_HI = 0x1307AFC, 0x1308800
FAM_LO, FAM_HI = 0x1E343C0, 0x1E34660
FETCH = 0x103C08C

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
REG = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
       "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
       "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
       "t3", "t4", "t5", "t6"]
CFG_REGS = {"s3"}          # a1's carried copy (PROUVÉ 4.49: s3 = a1)


def dec_at(img, off):
    if img[off] & 3 == 3:
        ins = next(md.disasm(img[off:off + 4], IMG_LO + off), None)
        return (ins, 4) if ins else (None, 0)
    ins = next(md.disasm(img[off:off + 2], IMG_LO + off), None)
    return (ins, 2) if ins else (None, 0)


def render(ins):
    return "<invalid>" if ins is None else f"{ins.mnemonic:<8} {ins.op_str}"


def parse_meminsn(ops):
    m = re.match(r"(\w+), (-?0x[0-9a-f]+|-?\d+)\((\w+)\)$", ops)
    if not m:
        return None
    return m.group(1), int(m.group(2), 0), m.group(3)


def decode_range(img, off, end):
    lines = []
    o = off
    while o < end:
        ins, sz = dec_at(img, o)
        lines.append(f"{IMG_LO + o:#x}: {render(ins)}")
        o += sz if sz else 2
    return lines


def extract_stores(img, off, end, keys_out):
    """Walk [off,end): track c.lui N (+c.add rX, s3) bases; report every
    store through such a base as (config offset, width, insn); report
    flag-word oris/andis and the first ret."""
    bases = {}      # reg -> N (the c.lui immediate, <<12 applied)
    val = {}        # reg -> "cfg+N" after c.add rX, s3
    res = {"stores": [], "flag_ops": [], "branches": [], "ret": None}
    o = off
    while o < end:
        ins, sz = dec_at(img, o)
        if ins is None:
            o += 2
            continue
        va = IMG_LO + o
        mn, ops = ins.mnemonic, ins.op_str
        u = struct.unpack_from("<I", img, o)[0] if sz == 4 else None
        if mn == "c.lui":
            m = re.match(r"(\w+), (-?0x[0-9a-f]+|-?\d+)$", ops)
            if m:
                bases[m.group(1)] = int(m.group(2), 0) << 12
                val.pop(m.group(1), None)
        elif mn == "c.add":
            m = re.match(r"(\w+), (\w+)$", ops)
            if m and m.group(1) in bases and m.group(2) in CFG_REGS:
                val[m.group(1)] = bases[m.group(1)]
        elif mn in ("sw", "sb", "sh", "sd"):
            p = parse_meminsn(ops)
            if p and p[2] in val:
                res["stores"].append({"site": hex(va), "insn": ops,
                                      "width": mn,
                                      "config_off": val[p[2]] + p[1]})
        elif mn in ("ori", "c.ori", "andi", "c.andi"):
            m = re.match(r"(\w+), (\w+), (-?0x[0-9a-f]+|-?\d+)$", ops)
            if m:
                res["flag_ops"].append({"site": hex(va), "insn": ops,
                                        "imm": int(m.group(3), 0)})
        elif mn == "auipc" and u is not None:
            pass
        elif mn.startswith("b") and mn != "c.j" and ops:
            mm = re.search(r"(-?0x[0-9a-f]+|-?\d+)$", ops)
            if mm:
                res["branches"].append({"site": hex(va), "insn": ops,
                                        "target": va + int(mm.group(1), 0)})
        elif mn == "ret" or (ins.mnemonic == "c.ret"):
            res["ret"] = va
            break
        o += sz
    return res


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    img = da[0x40:0x40 + IMG_LEN]
    blob = zlib.decompress(MAP.read_bytes())
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        assert img[o:o + 16] == db[o - 0x38:o - 0x38 + 16]
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        cnt += int((uarr & 0x7F == 0x17).sum())
    assert cnt == 416206, f"auipc census {cnt} != 416206"
    out = {"pass": "4.50", "task": "B", "instrument": "v450b_fb_l2_map",
           "version": 2,
           "baseline": {"auipc": cnt, "law": "512/512"}}

    # -- decode whole -------------------------------------------------------
    insns = []
    o = ING_LO - IMG_LO
    while o < ING_HI - IMG_LO:
        ins, sz = dec_at(img, o)
        insns.append((IMG_LO + o, ins,
                      struct.unpack_from("<I", img, o)[0] if sz == 4 else None))
        o += sz if sz else 2

    # -- the fetch walk: name materializations + fetch calls ----------------
    def string_at(va):
        p = va - IMG_LO
        e = img.find(b"\x00", p, p + 96)
        s = img[p:e] if e > 0 else b""
        return s.decode("ascii", "replace") if all(
            0x20 <= c < 0x7F for c in s) and len(s) >= 2 else None

    reg_base, reg_full = {}, {}
    last_name = None
    fetches = []     # {site, name, name_site, next}
    for va, ins, u in insns:
        if ins is None:
            continue
        mn, ops = ins.mnemonic, ins.op_str
        if mn == "auipc" and u is not None:
            rd = REG[(u >> 7) & 31]
            imm20 = (u >> 12) & 0xFFFFF
            if imm20 & 0x80000:
                imm20 -= 0x100000
            reg_base[rd] = va + (imm20 << 12)
            reg_full.pop(rd, None)
        elif mn == "addi" and u is not None:
            m = re.match(r"(\w+), (\w+), (-?0x[0-9a-f]+|-?\d+)$", ops)
            if m and m.group(2) in reg_base:
                full = reg_base[m.group(2)] + int(m.group(3), 0)
                reg_full[m.group(1)] = full
                if FAM_LO <= full < FAM_HI:
                    last_name = {"va": full, "site": hex(va)}
        elif mn == "jalr" and u is not None:
            rs1 = REG[(u >> 15) & 31]
            imm = (u >> 20) & 0xFFF
            if imm & 0x800:
                imm -= 0x1000
            tgt = reg_full.get(rs1, reg_base.get(rs1))
            if tgt is not None and tgt + imm == FETCH and last_name:
                fetches.append({"site": hex(va),
                                "name": string_at(last_name["va"]) or
                                f"@{last_name['va']:#x}",
                                "name_va": last_name["va"],
                                "name_site": last_name["site"]})
                last_name = None
    print(f"[walk] {len(fetches)} fetch calls named")

    # -- per-key: inline stores to the next fetch + branch-led handlers ------
    fetch_sites = [int(f["site"], 16) for f in fetches] + [ING_HI]
    # v3: the handler blocks are dense-packed (4-12 B apart). First pass:
    # collect EVERY conditional-branch target in the whole region, sort
    # them — handler k = [t_k, t_k+1). Then slice.
    all_tgts = set()
    for i, f in enumerate(fetches):
        lo = int(f["site"], 16) + 4
        hi = fetch_sites[i + 1]
        st = extract_stores(img, lo - IMG_LO, hi - IMG_LO, f)
        for b in st["branches"]:
            if ING_LO <= b["target"] < ING_HI:
                all_tgts.add(b["target"])
    entries = sorted(all_tgts)
    # v4: ONE linear pass over the handler region with CARRIED bases
    # (the c.lui/c.add idiom is established once and reused by the tiny
    # dense-packed handlers); every store/flag-op is attributed to the
    # slice [entry_k, entry_k+1) it falls in.
    def linear_pass(lo, hi):
        bases, val = {}, {}
        ev = []          # events attributed to slices
        o = lo
        while o < hi:
            ins, sz = dec_at(img, o)
            if ins is None:
                o += 2
                continue
            va = IMG_LO + o
            mn, ops = ins.mnemonic, ins.op_str
            if mn == "c.lui":
                m = re.match(r"(\w+), (-?0x[0-9a-f]+|-?\d+)$", ops)
                if m:
                    bases[m.group(1)] = int(m.group(2), 0) << 12
                    val.pop(m.group(1), None)
            elif mn == "c.add":
                m = re.match(r"(\w+), (\w+)$", ops)
                if m and m.group(1) in bases and m.group(2) in CFG_REGS:
                    val[m.group(1)] = bases[m.group(1)]
            elif mn in ("sw", "sb", "sh", "sd"):
                p = parse_meminsn(ops)
                if p and p[2] in val:
                    ev.append({"kind": "store", "va": va, "insn": ops,
                               "width": mn, "config_off": val[p[2]] + p[1]})
            elif mn in ("ori", "c.ori", "andi", "c.andi"):
                m = re.match(r"(\w+), (\w+), (-?0x[0-9a-f]+|-?\d+)$", ops)
                if m:
                    ev.append({"kind": "flag", "va": va, "insn": ops,
                               "imm": int(m.group(3), 0)})
            o += sz
        return ev

    # the handler region: from the first entry to the region end; the
    # entries come from branches whose SITE is inside a fetch segment.
    seg_targets = []
    for i, f in enumerate(fetches):
        lo = int(f["site"], 16) + 4
        hi = fetch_sites[i + 1] if i + 1 < len(fetches) else \
            min(int(f["site"], 16) + 0x80, ING_HI)      # v4: cap the LAST
        st = extract_stores(img, lo - IMG_LO, hi - IMG_LO, f)
        f["_branches"] = st["branches"]
        for b in st["branches"]:
            if ING_LO <= b["target"] < ING_HI:
                seg_targets.append(b["target"])
    entries = sorted(set(seg_targets))
    region_lo = entries[0] if entries else ING_HI
    region_hi = ING_HI
    events = linear_pass(ING_LO - IMG_LO, region_hi - IMG_LO)
    events = [e for e in events if e["va"] >= region_lo]
    def owner(va):
        cur = None
        for t in entries:
            if t <= va:
                cur = t
            else:
                break
        return cur
    # cut each slice at its first unconditional jump/ret (the handlers
    # end by c.j to the common tail — the tail's events must not pollute)
    jumps = {}
    o = region_lo - IMG_LO
    while o < region_hi - IMG_LO:
        ins, sz = dec_at(img, o)
        if ins is not None and ins.mnemonic in ("c.j", "j", "c.jr", "jalr", "ret", "c.ret"):
            va = IMG_LO + o
            own = owner(va)
            if own is not None and own not in jumps:
                jumps[own] = va
        o += sz if sz else 2
    slice_map = {}
    for e in events:
        own = owner(e["va"])
        if own in jumps and e["va"] >= jumps[own]:
            continue
        slice_map.setdefault(own, []).append(e)
    handler_cache = {}
    for i, f in enumerate(fetches):
        lo = int(f["site"], 16) + 4
        hi = fetch_sites[i + 1] if i + 1 < len(fetches) else \
            min(int(f["site"], 16) + 0x80, ING_HI)
        st = f["_branches"]
        first_br = min((int(b["site"], 16) for b in st
                        if ING_LO <= b["target"] < ING_HI), default=hi)
        f["inline_stores"] = [s for s in extract_stores(
            img, lo - IMG_LO, first_br - IMG_LO, f)["stores"]]
        f["inline_flag_ops"] = []
        # v6: the APPLY BLOCK — the stub jumps BACK to a per-key apply
        # window right after the fetch; decode [fetch+4, fetch+0x50) and
        # extract its cfg-idiom stores (the c.lui 4/8 + c.add s3 bases).
        ap = extract_stores(img, lo - IMG_LO, lo - IMG_LO + 0x50, f)
        f["apply_block"] = {
            "window": [hex(lo), hex(lo + 0x50)],
            "stores": ap["stores"],
            "flag_ops": ap["flag_ops"],
            "body": decode_range(img, lo - IMG_LO, lo - IMG_LO + 0x50),
        }
        tgts = sorted({b["target"] for b in st
                       if ING_LO <= b["target"] < ING_HI})
        f["handler_targets"] = [hex(t) for t in tgts]
        hs = []
        for t in tgts:
            if t in handler_cache:
                hs.append(handler_cache[t])
                continue
            k = entries.index(t)
            end = entries[k + 1] if k + 1 < len(entries) else region_hi
            evs = slice_map.get(t, [])
            entry = {"target": hex(t), "end": hex(end),
                     "stores": [{"site": hex(e["va"]), "insn": e["insn"],
                                 "width": e["width"],
                                 "config_off": e["config_off"]}
                                for e in evs if e["kind"] == "store"],
                     "flag_ops": [{"site": hex(e["va"]), "insn": e["insn"],
                                   "imm": e["imm"]}
                                  for e in evs if e["kind"] == "flag"],
                     "body": decode_range(img, t - IMG_LO, end - IMG_LO)}
            handler_cache[t] = entry
            hs.append(entry)
        f["handlers"] = hs

    out["keys"] = fetches
    WAYS = 0x3D84
    ways = [f for f in fetches if f["name"] == "RML2MaxWaysSysmem"]
    g5x = [f for f in fetches if f["name"] == "RMG5xL2VidmemPromote"]
    ways_ok = bool(ways) and any(
        any(s["config_off"] == WAYS for s in h["stores"])
        for h in ways[0]["handlers"])
    bit1_ok = bool(g5x) and any(
        any(op["imm"] == 2 for op in h["flag_ops"])
        for h in g5x[0]["handlers"])
    fermi = [f for f in fetches if f["name"] == "RMFermiL2CacheBypass"]
    bit2_fermi = bool(fermi) and any(
        any(op["imm"] == 2 for op in h["flag_ops"])
        for h in fermi[0]["handlers"])
    out["selftests"] = {
        "auipc_416206": True,
        "law_512": "PASS",
        "fetches_named": len(fetches),
        "ways_store_0x3d84": ways_ok,
        "g5x_bit1": bit1_ok,
        "fermi_l2_bit2": bit2_fermi,
    }
    print(f"[selftests] {out['selftests']}")
    for f in fetches:
        ap = " ".join(f"{s['width']}@{s['config_off']:#x}"
                      for s in f["apply_block"]["stores"]) or "-"
        hst = []
        for h in f["handlers"]:
            ss = [f"{s['width']}@{s['config_off']:#x}" for s in h["stores"]]
            bb = [op["insn"] for op in h["flag_ops"]]
            hst.append(f"{h['target']}: stores={ss} flag={bb}")
        print(f"  {f['name']:<36} fetch={f['site']} "
              f"apply=[{ap}] handlers=[{'; '.join(hst) or '-'}]")
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
