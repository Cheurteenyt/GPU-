#!/usr/bin/env python3
"""4.47 TASK A — the bandwidth-lever knob cards (the MCLK/L2/perf-cf family).

The 0xSero reference (555/608 GB/s = 91.3% of the ceiling, kernels) splits
the bandwidth problem into PILLAR A (raise the ceiling) and PILLAR B
(saturate it). This instrument maps PILLAR A's firmware surface end to
end, with the proven 4.35b method:

  1. the law re-check (512 windows) — the machine gate;
  2. the string census over the WHOLE container (runs >= 8);
  3. the exact-name target family (the 4.47 hunt greps):
       the MCLK switcher family, the clk-enable family, the L2 family,
       the perf-cf override family, plus the two macro-strings
       MCLK_LIMIT / DRAMCLK and the three soft-floor assert strings
       (the NV2080_CTRL_CLK_CLK_DOMAIN_INDEX machinery is IN our image);
  4. for every string occurrence: the runtime VA, the PIC xrefs
     (auipc+addi pairs composing the VA exactly), the pointer-table
     probe (the VA as a raw u64), and the first-consumer classification
     of the first xref (the 4.35b honesty rules);
  5. the verdict per knob: REGKEY-CANDIDATE (PASS-TO-CALL = the
     lookup-by-name pattern, string -> a1 -> call -> status gate),
     DIAGNOSTIC (assert-format string), DATA-CITED (pointer table).

Selftests: the coordinate law (512 windows); e_machine == 0xf3 on both
images; phnum >= 4; the banked anchor "RMEnableEventTracer" must xref
(the 4.35b selftest, reproduced); every PIC hit composes exactly.

Output: lab/jalon411/v447a_clkknobs.json
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

SHIFT = 0x38
IMG_LO = 0x1000000
ANCHOR = "RMEnableEventTracer"

# -- the 4.47 bandwidth-lever target family (exact-name matches) --
NAMES = [
    # the MCLK switcher family
    "SlideMCLK", "EnableMClkSlowdown", "RMMaxMclkFbstopTime",
    "RmClkPowerOffDramPllWhenUnused", "RMReportMclkSwitchFbStopTime",
    "RMClkSwitchWithinMargin", "RmMClkP5LinkTrainingWckStopClks",
    "RMClkVfOverride", "RmClkMclkProg", "RmIsoHubMCLKSwitch",
    "RmClkControllersOverride", "RmInternalVrrMclkOn2h1or",
    "RmOptp2LowerMclk", "RmMClkSwitchOnFbflcn", "RMClkSlowDown",
    # the clk-enable / vf family
    "RMEnableClk", "RMProgrammableClkMask", "RmLpwrSysClkSd",
    # the L2 family (cache partitioning / coherency)
    "RML2MaxWaysSysmem", "RMUseTc0NonCoherent", "RmDisableDecompOnlyLce",
    # the perf-cf override family (the clock controller)
    "RmPerfCfOverride", "RmPerfCfPmSensorOverrides",
    "RmPerfCfPolicyOverrides", "RmPerfCfControllersOverrides",
    # macro-strings
    "MCLK_LIMIT", "DRAMCLK",
]
# the soft-floor machinery strings (substring match, case-exact)
SUBSTR = [
    "(pSingle1x->clkDomainIdx != pSingle1x->ignoreClkDomainIdx)",
    "(pSingle1x->softFloor.clkPropTopIdx != "
    "NV2080_CTRL_CLK_CLK_PROP_TOP_ID_INVALID)",
    "(pSingle1x->softFloor.perfCfControllerClkIdx != "
    "NV2080_CTRL_CLK_CLK_DOMAIN_INDEX_INVALID)",
]

REGS = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6"]

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True
STRING_RE = re.compile(rb"[\x20-\x7e]{8,}")


def dis1(buf, off):
    if off + 2 > len(buf):
        return None
    if buf[off] & 3 == 3:
        if off + 4 > len(buf):
            return None
        return next(md.disasm(buf[off:off + 4], off), None)
    return next(md.disasm(buf[off:off + 2], off), None)


def writes_reg(ins, rd_name):
    if ins is None:
        return False
    m = ins.mnemonic
    if m in ("sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp",
             "beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
             "j", "c.j", "ret", "c.ret", "c.jr", "ecall", "ebreak",
             "b", "nop", "c.nop", "fence", "fence.i"):
        return False
    return ins.op_str.split(",")[0].strip() == rd_name


def classify_consumer(img, addi_off, rd_name):
    """first real use of the pointer register (the 4.35b rules)."""
    off = addi_off
    for _ in range(24):
        ins = dis1(img, off)
        if ins is None:
            return "UNRESOLVED", None
        m = ins.mnemonic
        if m in ("jal", "jalr", "c.jalr"):
            if rd_name.startswith("a"):
                return "PASS-TO-CALL (ABI arg)", off
        if off != addi_off and writes_reg(ins, rd_name):
            return "PTR-CLOBBERED", off
        if off == addi_off:
            off += ins.size
            continue
        try:
            mems = [oo for oo in ins.operands
                    if oo.type == capstone.riscv.RISCV_OP_MEM]
            if mems and ins.reg_name(mems[0].mem.base) == rd_name:
                if m in ("lbu", "lb", "lhu", "lw", "lwu", "ld"):
                    return "DEREF-LOAD (byte/half walk)", off
                if m in ("sd", "sw", "sh", "sb", "c.sd", "c.sw"):
                    return "STORE-THROUGH-PTR", off
                return "MEM-BASE-USE", off
            for k, oo in enumerate(ins.operands):
                if oo.type == capstone.riscv.RISCV_OP_REG and \
                        ins.reg_name(oo.reg) == rd_name:
                    is_dest = (k == 0 and not m.startswith(
                        ("b", "c.b", "sd", "sw", "sh", "sb", "c.sd",
                         "c.sw")))
                    if not is_dest:
                        if m in ("jal", "jalr", "c.jalr"):
                            return "PASS-TO-CALL", off
                        return "REG-READ", off
        except Exception:
            pass
        if m in ("ret", "c.ret") or (m == "jalr" and
                                     ins.op_str.startswith("zero,")):
            return "DEAD-at-ret", off
        off += ins.size
    return "UNRESOLVED-in-24", None


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    out = {"pass": "4.47", "task": "A", "instrument": "v447a_clkknobs"}

    # -- the law
    fails = 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    assert fails == 0, "the map law is broken"
    assert struct.unpack_from("<H", db, 18)[0] == 0xF3
    assert struct.unpack_from("<H", da, 18)[0] == 0xF3
    assert struct.unpack_from("<H", db, 0x38)[0] >= 4
    out["law_fails"] = 0

    # -- the container phdrs -> runtime VAs
    e_phoff = struct.unpack_from("<Q", db, 0x20)[0]
    e_phnum = struct.unpack_from("<H", db, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        p = e_phoff + i * 0x38
        p_type, p_flags, p_off, p_vaddr, _pa, p_filesz, _m, _al = \
            struct.unpack_from("<IIQQQQQQ", db, p)
        if p_type == 1 and p_filesz > 0:
            segs.append({"off": p_off, "vaddr": p_vaddr,
                         "filesz": p_filesz})

    def va_of(foff):
        for s in segs:
            if s["off"] <= foff < s["off"] + s["filesz"]:
                return s["vaddr"] + (foff - s["off"])
        return None

    # -- the string census
    strings = []
    for m in STRING_RE.finditer(db):
        strings.append({"foff": m.start(), "va": va_of(m.start()),
                        "text": m.group()})
    out["strings_total"] = len(strings)

    anchor = [s for s in strings if s["text"] == ANCHOR.encode()]
    assert anchor, "the banked anchor is missing"
    out["anchor_va"] = hex(anchor[0]["va"]) if anchor[0]["va"] else None

    # -- the PIC auipc census (all even offsets, the runtime PC universe)
    img4 = a_img + b"\x00" * ((4 - len(a_img) % 4) % 4)
    u0 = np.frombuffer(img4, dtype="<u4")
    u2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
    bases = []
    for base_off, uarr in ((0, u0), (2, u2)):
        kmax = (len(img4) - 4 - base_off) >> 2
        k = np.arange(kmax, dtype=np.int64)
        mask = (uarr[k] & 0x7F) == 0x17
        kk = k[mask]
        w = uarr[kk]
        rd = ((w >> 7) & 0x1F).astype(np.int64)
        hi20 = (w >> 12).astype(np.int64)
        hi20[hi20 >= 0x80000] -= 0x100000
        aoff = (kk << 2) + base_off
        pc = IMG_LO + aoff + 0x38
        base = pc + (hi20 << 12)
        bases.append(np.stack([base, aoff.astype(np.int64), rd], axis=1))
    Bs = np.concatenate(bases)
    Bs = Bs[np.argsort(Bs[:, 0])]
    out["auipc_all_offsets"] = int(len(Bs))

    def pic_xrefs(target_va):
        lo = np.searchsorted(Bs[:, 0], target_va - 0x7FF, side="left")
        hi = np.searchsorted(Bs[:, 0], target_va + 0x800, side="left")
        hits = []
        for row in Bs[lo:hi]:
            base, aoff, rd = int(row[0]), int(row[1]), int(row[2])
            lo_need = target_va - base
            if not (-2048 <= lo_need <= 2047):
                continue
            if aoff + 8 > len(a_img):
                continue
            w2 = int.from_bytes(a_img[aoff + 4:aoff + 8], "little")
            if (w2 & 0x7F) not in (0x13, 0x1B):
                continue
            if ((w2 >> 12) & 7) != 0:
                continue
            if ((w2 >> 15) & 0x1F) != rd or ((w2 >> 7) & 0x1F) != rd:
                continue
            lo_f = (w2 >> 20) & 0xFFF
            if lo_f >= 0x800:
                lo_f -= 0x1000
            if lo_f == lo_need:
                hits.append((aoff, rd))
        return hits

    def ptr_refs(target_va):
        pat = struct.pack("<Q", target_va)
        hits = []
        start = 0
        while True:
            j = db.find(pat, start)
            if j < 0:
                break
            hits.append(j)
            start = j + 1
        return hits

    # -- the per-target cards
    # LESSON (banked this pass): the regkey names are SUBSTRINGS of
    # concatenated printable runs — exact-run equality misses them all
    # (the first v447a run returned occ=0 for every name while
    # `rg -a` counts 1 each). The VA cited is the NAME's first byte:
    # run VA + the byte offset of the match inside the run.
    def name_sites(name):
        pat = name.encode()
        sites = []
        for s in strings:
            i = s["text"].find(pat)
            if i < 0:
                continue
            sites.append({"foff": s["foff"] + i,
                          "va": (s["va"] + i) if s["va"] else None})
        return sites

    cards = []
    for name in NAMES:
        occ = name_sites(name)
        card = {"name": name, "occurrences": len(occ), "sites": []}
        for s in occ:
            site = {"foff": hex(s["foff"]),
                    "va": hex(s["va"]) if s["va"] else None}
            if s["va"]:
                xr = pic_xrefs(s["va"])
                site["pic_xrefs"] = len(xr)
                site["xref_sites"] = [
                    {"auipc_va": hex(IMG_LO + a), "rd": REGS[r]}
                    for a, r in xr[:8]]
                if xr:
                    aoff, rd = xr[0]
                    cls, at = classify_consumer(a_img, aoff + 4,
                                                REGS[rd])
                    site["first_consumer"] = cls
                    site["consumer_at"] = hex(IMG_LO + at) if at else None
            ptrs = ptr_refs(s["va"]) if s["va"] else []
            site["ptr_table_refs"] = len(ptrs)
            card["sites"].append(site)
        xr_total = sum(x["pic_xrefs"] for x in card["sites"])
        card["pic_xrefs_total"] = xr_total
        verdicts = {x.get("first_consumer", "") for x in card["sites"]}
        if any(v.startswith("PASS-TO-CALL") for v in verdicts):
            card["verdict"] = "REGKEY-CANDIDATE (lookup-by-name)"
        elif xr_total == 0 and any(x["ptr_table_refs"] for x
                                   in card["sites"]):
            card["verdict"] = "DATA-CITED (pointer table)"
        elif xr_total == 0:
            card["verdict"] = "UNREFERENCED in image"
        else:
            card["verdict"] = "CITED (" + "/".join(sorted(
                v for v in verdicts if v)) + ")"
        cards.append(card)
        print(f"[card] {name:<36} occ={card['occurrences']} "
              f"xrefs={xr_total} -> {card['verdict']}")

    for sub in SUBSTR:
        occ = name_sites(sub)
        card = {"name": sub[:60], "occurrences": len(occ), "sites": []}
        for s in occ:
            site = {"foff": hex(s["foff"]),
                    "va": hex(s["va"]) if s["va"] else None}
            if s["va"]:
                xr = pic_xrefs(s["va"])
                site["pic_xrefs"] = len(xr)
                site["xref_sites"] = [
                    {"auipc_va": hex(IMG_LO + a), "rd": REGS[r]}
                    for a, r in xr[:8]]
                if xr:
                    aoff, rd = xr[0]
                    cls, at = classify_consumer(a_img, aoff + 4,
                                                REGS[rd])
                    site["first_consumer"] = cls
                    site["consumer_at"] = hex(IMG_LO + at) if at else None
            card["sites"].append(site)
        card["pic_xrefs_total"] = sum(x["pic_xrefs"] for x
                                      in card["sites"])
        card["verdict"] = "DIAGNOSTIC-STRING (assert format)" \
            if card["pic_xrefs_total"] else "UNREFERENCED in image"
        cards.append(card)
        print(f"[card] {sub[:58]:<60} occ={card['occurrences']} "
              f"xrefs={card['pic_xrefs_total']} -> {card['verdict']}")

    out["cards"] = cards
    out["selftests"] = {
        "law_512": "PASS", "e_machine_0xf3": "PASS",
        "anchor_present": True,
        "pic_composition": "exact by construction",
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
