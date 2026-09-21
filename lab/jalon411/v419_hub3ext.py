#!/usr/bin/env python3
"""4.19 pass — hub 3's external fills (where is the net consumer's table fed?).

Queue item 3 of 4.18: hub 3 ([0x133cd26-0x1355c32], 3rd-ranked dispatch hub:
38 distinct offsets / 61 dispatches / only 33 fills in-hub, fill/dispatch
0.5 — a NET CONSUMER) — widen the fill search to the WHOLE image: every
store sd/sw to one of the hub's dispatch-slot OFFSETS from any callee-saved
base, OUTSIDE the hub region.

Per external filler:
  - location (region, distance to the hub);
  - same base-register match vs the hub's slot (the (reg,off) slot filled
    outside) or offset-only;
  - the VALUE formation chased backward (<= 24 insns, exact 4.18 hubfill
    rules: auipc+addi resolved / lui / ld-copied / carried);
  - every resolved auipc value tested against the verified map (a static
    naming of the dispatch target).

Aggregates: how many of the 61 dispatches' slots get filled elsewhere, the
region histogram of the external fillers, and whether ANY static target
names appear outside the hubs (the 4.18 result was zero inside).

Output: lab/jalon411/v419_hub3ext.json
"""
import json
import struct
import zlib
from bisect import bisect_right
from collections import defaultdict

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v419_hub3ext.json"

IMG_LO = 0x1000000
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
A_REGS = {f"a{i}" for i in range(8)}
BACK = 8
HUB_RANK = 3        # the net consumer
VAL_BACK = 24


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


def build_regions(covered):
    starts, ends = [], []
    n = len(covered)
    i = 0
    while i < n:
        if covered[i]:
            j = i
            while j < n and covered[j]:
                j += 1
            if j - i >= 2:
                starts.append(i)
                ends.append(j)
            i = j
        else:
            i += 1
    return starts, ends


def norm(m):
    return m[2:] if m.startswith("c.") else m


def sign_ext(v, bits):
    return v - (1 << bits) if v > (1 << (bits - 1)) - 1 else v


def main():
    code = load()
    n = len(code)
    seen, covered = load_map()
    reg_starts, reg_ends = build_regions(covered)
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    def region_of(pc):
        k = bisect_right(reg_starts, pc) - 1
        if k >= 0 and reg_starts[k] <= pc < reg_ends[k]:
            return k
        return None

    # ---- pass 1: census re-derivation (reproducibility) ----
    total = 0
    by_offset = defaultdict(lambda: {"sites": 0, "regs": set()})
    region_slots = defaultdict(lambda: defaultdict(int))  # region idx -> off -> n
    pc = 0
    win = []
    while pc < n - 2:
        try:
            insn = next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
        except StopIteration:
            win.clear()
            pc += 2
            continue
        m, ops = insn.mnemonic, insn.op_str
        size = insn.size
        if m not in (".byte", "(bad)"):
            win.append((m, ops, pc))
            if len(win) > BACK + 2:
                win.pop(0)
        if m in ("jalr", "c.jalr", "c.jr", "jr") and seen[pc]:
            total += 1
            if m == "jalr":
                if "(" in ops:
                    p = ops.replace("(", ",").replace(")", "").split(",")
                    rs = p[2].strip()
                else:
                    parts = [x.strip() for x in ops.split(",")]
                    rs = parts[0] if len(parts) == 1 else parts[1]
            else:
                rs = [x.strip() for x in ops.split(",")][-1]
            feeder = None
            for jm, jops, jpc in reversed(win[:-1]):
                if jpc == pc:
                    continue
                jm_n = norm(jm)
                p1 = [t.strip() for t in jops.split(",")]
                wr = None
                if jm_n in ("ld", "c.ld", "ldsp", "c.ldsp") and p1:
                    wr = p1[0]
                elif p1 and jm_n not in ("sd", "sw", "c.sd", "c.sdsp", "sdsp", "swsp"):
                    wr = p1[0]
                if wr == rs:
                    if jm_n in ("ld", "c.ld", "ldsp", "c.ldsp") and len(p1) == 2 and "(" in p1[1]:
                        try:
                            off_s, bas = p1[1][:-1].split("(", 1)
                            feeder = (bas.strip(), int(off_s.strip(), 0))
                        except Exception:
                            feeder = None
                    break
            if feeder:
                bas, foff = feeder
                if bas in S_REGS and foff < 0:
                    by_offset[foff]["sites"] += 1
                    by_offset[foff]["regs"].add(bas)
                    r = region_of(pc)
                    if r is not None:
                        region_slots[r][foff] += 1
        pc += size

    ranked = sorted(((len(s), r) for r, s in region_slots.items()), reverse=True)
    cnt, hub_r = ranked[HUB_RANK - 1]
    hub_lo, hub_hi = reg_starts[hub_r], reg_ends[hub_r]
    slot_offsets = set(region_slots[hub_r].keys())
    hub_disp = sum(region_slots[hub_r].values())
    disp_by_off = region_slots[hub_r]
    print(f"census: {total} indirects | hub-3 = [{hex(IMG_LO+hub_lo)}-{hex(IMG_LO+hub_hi)}] "
          f"offsets={len(slot_offsets)} dispatches={hub_disp}")

    # ---- pass 2: external fill census (whole image, outside the hub) ----
    fills = []
    fill_off = defaultdict(int)
    val_classes = defaultdict(int)
    regions_hist = defaultdict(int)
    named_targets = []
    pc = 0
    win = []
    while pc < n - 2:
        try:
            insn = next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
        except StopIteration:
            win.clear()
            pc += 2
            continue
        m, ops = insn.mnemonic, insn.op_str
        size = insn.size
        if m not in (".byte", "(bad)"):
            win.append((m, ops, pc, size))
            if len(win) > VAL_BACK + 2:
                win.pop(0)
        mn = norm(m)
        if mn in ("sd", "sw") and seen[pc] and not (hub_lo <= pc < hub_hi):
            p1 = ops.split(", ")
            if len(p1) == 2 and "(" in p1[1]:
                try:
                    off_s, bas = p1[1][:-1].split("(", 1)
                    off = int(off_s.strip(), 0)
                    bas = bas.strip()
                except Exception:
                    pc += size
                    continue
                if off in slot_offsets and bas in S_REGS:
                    fill_off[off] += 1
                    r = region_of(pc)
                    rname = (hex(IMG_LO + reg_starts[r]) + "-" + hex(IMG_LO + reg_ends[r])
                             if r is not None else "UNCOVERED")
                    regions_hist[rname] += 1
                    # value chase (exact 4.18 hubfill rules)
                    val = p1[0].strip()
                    vclass = "carried"
                    target = None
                    vaipc = None
                    vaddi = None
                    for jm, jops, jpc, jsize in reversed(win[:-1]):
                        jn = norm(jm)
                        jp = [t.strip() for t in jops.split(",")]
                        wr = jp[0] if jp else None
                        if wr != val:
                            continue
                        if jn == "auipc" and len(jp) == 2:
                            try:
                                vaipc = (jpc, int(jp[1], 0))
                            except Exception:
                                vaipc = None
                            for km, kops, kpc, ksize in reversed(win[:-1]):
                                kn = norm(km)
                                kp = [t.strip() for t in kops.split(",")]
                                if kp and kp[0] == val and kn in ("add", "addi", "c.add") \
                                   and len(kp) == 3 and kp[1] == val and kpc != jpc:
                                    try:
                                        vaddi = int(kp[2], 0)
                                    except Exception:
                                        vaddi = 0
                                    break
                            if vaipc and vaddi is not None:
                                val_abs = (vaipc[0] + (sign_ext(vaipc[1] & 0xFFFFF, 20) << 12)
                                           + sign_ext(vaddi & 0xFFF, 12))
                                vclass = "auipc+addi"
                                t_off = val_abs - IMG_LO
                                if 0 <= t_off < n and seen[t_off]:
                                    target = val_abs
                            else:
                                vclass = "auipc-no-addi"
                            break
                        if jn in ("lui",) and len(jp) == 2:
                            vclass = "lui"
                            break
                        if jn == "ld" and len(jp) == 2 and "(" in jp[1]:
                            vclass = "ld-copied"
                            break
                        if jn in ("mv", "add") and len(jp) == 2:
                            val = jp[1]
                            continue
                        break
                    val_classes[vclass] += 1
                    entry = {"fill": hex(IMG_LO + pc), "width": mn,
                             "slot": f"{bas}+{hex(off)}", "region": rname,
                             "dist_to_hub": (hub_lo - pc) if pc < hub_lo else (pc - hub_hi),
                             "val": val, "class": vclass}
                    if target:
                        entry["target"] = hex(target)
                        named_targets.append({"fill": entry["fill"],
                                              "slot": entry["slot"],
                                              "target": entry["target"]})
                    fills.append(entry)
        pc += size

    # per-offset external fill coverage
    off_cover = {hex(o): {"dispatches_in_hub": disp_by_off.get(o, 0),
                          "fills_external": fill_off.get(o, 0)}
                 for o in sorted(slot_offsets)}

    out = {
        "pass": "4.19-hub3ext",
        "substrate": SUBSTRATE,
        "census_reproduced": {"indirects": total, "offsets": len(by_offset)},
        "hub3": {"range": [hex(IMG_LO + hub_lo), hex(IMG_LO + hub_hi)],
                 "hub_bytes": hub_hi - hub_lo,
                 "distinct_offsets": len(slot_offsets),
                 "dispatches": hub_disp,
                 "fills_in_hub_418": 33},
        "external_fills": len(fills),
        "external_fill_value_classes": dict(val_classes),
        "external_fill_regions_top16": dict(sorted(regions_hist.items(),
                                                   key=lambda kv: -kv[1])[:16]),
        "n_external_regions": len(regions_hist),
        "named_targets": named_targets[:24],
        "fills_first32": fills[:32],
        "offset_coverage": off_cover,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print(f"external fills: {len(fills)} classes={dict(val_classes)} "
          f"regions={len(regions_hist)} named={len(named_targets)}")
    print("OUT", OUT)


if __name__ == "__main__":
    main()
