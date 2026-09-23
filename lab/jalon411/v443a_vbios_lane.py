#!/usr/bin/env python3
"""4.43 pass, TÂCHE 1 instrument — the VBIOS/SPI/I2C read lane in GSP-RM.

Question: does the GSP-RM read the VBIOS itself (SPI/I2C/PCIe), i.e. is
the power policy bounded in the firmware?

Method (the banked 4.35b rules):
  1. the string census over the CONTAINER (gsp-rm-17MB.bin, the 2-LOAD
     runtime truth), printable runs >= 8, curated power/VBIOS families:
     RMLpwr*/RmPmgr*/RMI2c*/RMPower*/RMEdp*/RmPerfCf*/THERM_*/FWSECLIC/
     PMGR_PWR/BOOST/THERMAL/vbios/RMDisableSpi — plus RMDisableSpi;
  2. per string: the PIC xref (auipc+addi exact composition, runtime
     universe) AND the raw-u64 pointer-table probe AND the neighborhood
     grammar (pointers/values around the string);
  3. the consumer classification + cited window per xref;
  4. the SPI-opcode fingerprint census: clusters (<=0x400 window) with
     >= 4 distinct flash opcodes {06,05,03,0B,9F,02,D8,52,6B,EB,B7,E9,
     66,99} among decoded li/addi immediates over the covered regions.

Self-checks: the coordinate law (512 windows); the ELF containers; the
banked string anchor; every reported xref composed exactly.

Output: lab/jalon411/v443a_vbios_lane.json
"""
import json
import re
import struct
import zlib
from collections import defaultdict
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

FAMILY_RE = re.compile(
    rb"(RMLpwr|RmLpwr|RmPmgr|RMI2c|RMPower|RMAdaptive|RMEdp|RmPerfCf"
    rb"|RmBootGspRm|RMDisableSpi|THERM_|FWSECLIC|PMGR_PWR|TURBO_BOOST"
    rb"|CUSTOMER_BOOST|GPU_BOOST|BOOST_LOW|THERMAL|NETIR_THERMAL"
    rb"|vbios|VBIOS|RMDebugSyspipe)")

STRING_RE = re.compile(rb"[\x20-\x7e]{8,}")
SPI_OPS = {0x06, 0x05, 0x03, 0x0B, 0x9F, 0x02, 0xD8, 0x52, 0x6B, 0xEB,
           0xB7, 0xE9, 0x66, 0x99}
REGS = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6"]

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True


def dis1(buf, off, va=None):
    if off + 2 > len(buf):
        return None
    if buf[off] & 3 == 3:
        if off + 4 > len(buf):
            return None
        return next(md.disasm(buf[off:off + 4], (va or off)), None)
    return next(md.disasm(buf[off:off + 2], (va or off)), None)


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


def window_lines(img, off, n=12):
    lines = []
    o = off
    for _ in range(n):
        ins = dis1(img, o)
        if ins is None:
            lines.append(f"0x{IMG_LO + o:x}: <invalid>")
            break
        lines.append(f"0x{IMG_LO + o:x}: {ins.mnemonic:<8} {ins.op_str}")
        o += ins.size
    return lines


def regions(covered):
    starts, ends = [], []
    i, n = 0, len(covered)
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


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    starts, ends = regions(covered)

    def covered_at(aoff):
        for s0, e0 in zip(starts, ends):
            if s0 <= aoff < e0:
                return True
        return False

    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000"}

    # -- the coordinate law
    fails = 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    assert fails == 0
    out["law_recheck_fails"] = 0

    # -- the container segments
    e_phoff = struct.unpack_from("<Q", db, 0x20)[0]
    e_phnum = struct.unpack_from("<H", db, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        p = e_phoff + i * 0x38
        p_type, p_flags = struct.unpack_from("<II", db, p)
        p_off, p_vaddr, _pa, p_filesz, _m = struct.unpack_from("<QQQQQ",
                                                               db, p + 8)
        if p_type == 1 and p_filesz > 0:
            segs.append({"off": p_off, "vaddr": p_vaddr,
                         "filesz": p_filesz, "flags": p_flags})
    assert len(segs) == 2, f"expected code+data LOADs, got {len(segs)}"
    out["segments"] = [
        {"off": hex(s["off"]), "vaddr": hex(s["vaddr"]),
         "filesz": hex(s["filesz"]), "flags": hex(s["flags"])}
        for s in segs]

    def va_of(foff):
        for s in segs:
            if s["off"] <= foff < s["off"] + s["filesz"]:
                return s["vaddr"] + (foff - s["off"])
        return None

    # -- the string census, curated families
    strings = []
    for m in STRING_RE.finditer(db):
        if FAMILY_RE.search(m.group()):
            strings.append({"foff": m.start(), "va": va_of(m.start()),
                            "text": m.group()})
    out["family_strings_n"] = len(strings)
    print(f"[strings] curated-family runs >= 8: {len(strings)}")

    # -- the PIC auipc census (all even offsets, code image, runtime PC)
    CODE_FILESZ = segs[0]["filesz"]
    assert CODE_FILESZ == 0xE9B000
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
    Bm = np.concatenate(bases)
    order = np.argsort(Bm[:, 0])
    Bs = Bm[order]
    out["auipc_all_offsets"] = int(len(Bm))
    print(f"[pic] auipc census: {len(Bm)}")

    def pic_xrefs(target_va):
        lo_win = np.searchsorted(Bs[:, 0], target_va - 0x7FF, side="left")
        hi_win = np.searchsorted(Bs[:, 0], target_va + 0x800, side="left")
        hits = []
        for row in Bs[lo_win:hi_win]:
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
                hits.append({"auipc_va": hex(IMG_LO + aoff),
                             "addi_va": hex(IMG_LO + aoff + 4),
                             "rd": REGS[rd]})
        return hits

    def ptr_table_refs(target_va):
        pat = struct.pack("<Q", target_va)
        hits = []
        start = 0
        while True:
            i = db.find(pat, start)
            if i < 0:
                break
            hits.append({"foff": hex(i),
                         "va": hex(va_of(i)) if va_of(i) else None})
            start = i + 1
            if len(hits) >= 8:
                break
        return hits

    def neighborhood(va, span=0x50):
        foff = None
        for s in segs:
            if s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
                foff = s["off"] + (va - s["vaddr"])
        if foff is None:
            return []
        lo = max(0, foff - span)
        blob2 = db[lo:foff + span]
        ptrs = []
        for i in range(0, max(0, len(blob2) - 7), 8):
            u, = struct.unpack_from("<Q", blob2, i)
            if 0x1000000 <= u < 0x1e9b038 or 0x4000000 <= u < 0x41d5000:
                ptrs.append({"u64": hex(u),
                             "at": hex(va_of(lo + i)) if va_of(lo + i)
                             else None})
        return ptrs[:8]

    # -- per-string cards
    cards = []
    for s in strings:
        tva = s["va"]
        if tva is None:
            continue
        xrefs = pic_xrefs(tva)
        cons = []
        for x in xrefs[:6]:
            addi_a = int(x["addi_va"], 16) - IMG_LO
            cls, at = classify_consumer(a_img, addi_a, x["rd"])
            cons.append({"class": cls,
                         "at": hex(at + IMG_LO) if at else None,
                         "rd": x["rd"],
                         "window": window_lines(a_img, addi_a, 12)})
        cards.append({
            "name": s["text"].decode(errors="replace"),
            "va_runtime": hex(tva),
            "va_campaign": hex(tva - 0x38) if tva < 0x2000000 else None,
            "pic_xrefs": len(xrefs),
            "xref_detail": cons,
            "ptr_table_refs": ptr_table_refs(tva),
            "neighborhood_ptrs": neighborhood(tva)})
    out["cards"] = cards
    n_x = sum(c["pic_xrefs"] for c in cards)
    print(f"[cards] {len(cards)} strings, {n_x} PIC xrefs")

    # -- the SPI-opcode fingerprint census over the covered regions
    clusters = defaultdict(list)
    n_dec = 0
    for s0, e0 in zip(starts, ends):
        off = s0
        while off < e0:
            ins = dis1(a_img, off)
            if ins is None:
                off += 2
                continue
            n_dec += 1
            m = ins.mnemonic
            if m in ("li", "addi", "c.li", "andi", "ori", "c.addi") and \
                    "," in ins.op_str:
                try:
                    v = int(ins.op_str.split(",")[-1].strip(), 0)
                except ValueError:
                    v = None
                if v in SPI_OPS:
                    clusters[(off >> 10)].append(
                        (off, hex(v), f"{m} {ins.op_str}"))
            off += ins.size
    dense = []
    for bucket, hits in clusters.items():
        vals = {h[1] for h in hits}
        if len(vals) >= 4:
            dense.append({"window_a": hex(bucket << 10),
                          "distinct_ops": sorted(vals),
                          "n_sites": len(hits),
                          "covered": covered_at(bucket << 10),
                          "sample": [f"{hex(o)}: {t}" for o, _, t in
                                     hits[:6]]})
    dense.sort(key=lambda d: -d["n_sites"])
    out["spi_opcode_clusters"] = dense[:24]
    out["spi_decoded_insns"] = n_dec
    print(f"[spi] decoded {n_dec} insns; dense opcode clusters: "
          f"{len(dense)}")

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
