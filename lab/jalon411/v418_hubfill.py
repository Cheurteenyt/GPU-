#!/usr/bin/env python3
"""4.18 pass — the hub fill census (who fills the dispatch slots?).

Queue item 1 of 4.17: the top dispatch hubs ([0x1498788-0x14b01d6] with 61
distinct state slots, runners-up 50 and 46) — the state-table builders
should live next to their dispatchers if the tables are built in place.

Method: re-derive the 4.17 stategraph census (same chase, same window —
reproducibility first), rank the covered runs by distinct dispatch slots,
take the top 3, then inside each hub:

  - the hub's dispatch-slot OFFSET set (off < 0, s-reg feeder, as 4.17);
  - every STORE (sd/sw) to one of those offsets from ANY callee-saved base,
    inside the hub region = FILLER candidates;
  - each filler's VALUE formation chased backward (<= 24 insns, verified
    trail only):  auipc+addi resolved / lui+addi resolved / ld (copied
    pointer) / carried (no local formation);
  - every resolved auipc value is tested against the verified map:
    a value landing on a boundary-verified insn start NAMES the dispatch
    target statically — the table entry itself.

Fill/dispatch ratios per offset: filled-in-hub vs dispatched-in-hub —
"builders co-located" vs "table built elsewhere, hub is a pure consumer".

Output: lab/jalon411/v418_hubfill.json
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
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v418_hubfill.json"

IMG_LO = 0x1000000
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
A_REGS = {f"a{i}" for i in range(8)}
BACK = 8
HUB_N = 3
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

    # ---- pass 1: the 4.17 census (reproducibility) + per-region slot sets ----
    total = 0
    by_offset = defaultdict(lambda: {"sites": 0, "regs": set()})
    region_slots = defaultdict(lambda: defaultdict(int))  # region -> off -> n
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
    print("census:", total, "indirects,", len(by_offset), "offsets")
    hubs = []
    for cnt, r in ranked[:HUB_N]:
        hubs.append({"idx": r, "lo": reg_starts[r], "hi": reg_ends[r],
                     "slots": len(region_slots[r]), "dispatches": sum(region_slots[r].values())})
    for h in hubs:
        print(f"hub [{hex(IMG_LO+h['lo'])}-{hex(IMG_LO+h['hi'])}] slots={h['slots']} dispatches={h['dispatches']}")

    # ---- pass 2: per-hub fill census ----
    out_hubs = []
    for h in hubs:
        lo, hi = h["lo"], h["hi"]
        slot_offsets = set(region_slots[h["idx"]].keys())
        fills = []
        fill_off = defaultdict(int)
        val_classes = defaultdict(int)
        named_targets = []
        # linear scan INSIDE the hub region only
        pc2 = lo
        win2 = []
        while pc2 < hi - 2:
            try:
                insn = next(md.disasm(code[pc2:pc2 + 16], IMG_LO + pc2))
            except StopIteration:
                win2.clear()
                pc2 += 2
                continue
            m, ops = insn.mnemonic, insn.op_str
            size = insn.size
            if m not in (".byte", "(bad)"):
                win2.append((m, ops, pc2, size))
                if len(win2) > VAL_BACK + 2:
                    win2.pop(0)
            mn = norm(m)
            if mn in ("sd", "sw") and seen[pc2]:
                p1 = ops.split(", ")
                if len(p1) == 2 and "(" in p1[1]:
                    try:
                        off_s, bas = p1[1][:-1].split("(", 1)
                        off = int(off_s.strip(), 0)
                        bas = bas.strip()
                    except Exception:
                        pc2 += size
                        continue
                    if off in slot_offsets and bas in S_REGS:
                        fill_off[off] += 1
                        # chase the VALUE register formation
                        val = p1[0].strip()
                        vclass = "carried"
                        target = None
                        vaipc = None
                        vaddi = None
                        for jm, jops, jpc, jsize in reversed(win2[:-1]):
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
                                # look one step further for the addi on the same reg
                                for km, kops, kpc, ksize in reversed(win2[:-1]):
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
                        entry = {"fill": hex(IMG_LO + pc2), "width": mn,
                                 "slot": f"{bas}+{hex(off)}", "val": val,
                                 "class": vclass}
                        if target:
                            entry["target"] = hex(IMG_LO + (target - IMG_LO))
                            named_targets.append({"fill": hex(IMG_LO + pc2),
                                                  "slot": f"{bas}+{hex(off)}",
                                                  "target": hex(target)})
                        fills.append(entry)
            pc2 += size
        disp = {hex(o): region_slots[h["idx"]][o] for o in sorted(slot_offsets)}
        out_hubs.append({
            "hub": [hex(IMG_LO + lo), hex(IMG_LO + hi)],
            "hub_bytes": hi - lo,
            "distinct_slots": h["slots"],
            "dispatches_by_offset": disp,
            "fills_in_hub": len(fills),
            "fills_by_offset": {hex(o): c for o, c in sorted(fill_off.items())},
            "fill_value_classes": dict(val_classes),
            "named_targets": named_targets[:24],
            "fills_first24": fills[:24],
        })
        print(f"hub {hex(IMG_LO+lo)}: fills={len(fills)} classes={dict(val_classes)} named={len(named_targets)}")

    out = {
        "pass": "4.18-hubfill",
        "substrate": SUBSTRATE,
        "census_reproduced": {"indirects": total, "offsets": len(by_offset)},
        "hubs": out_hubs,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print("OUT", OUT)


if __name__ == "__main__":
    main()
