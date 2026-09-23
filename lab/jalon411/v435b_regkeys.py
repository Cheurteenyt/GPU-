#!/usr/bin/env python3
"""4.35 TASK B — the regkey lane: the firmware's host-facing tunables.

The optimization verdict of 4.33 was "only the knob table is open, and
every turn is gated by semantics". The SAFEST possible optimization
surface for a closed firmware is one designed for tuning: the registry
keys the host RM feeds the GSP at init. This instrument maps that
surface end to end:

  1. the string census (whole file, printable runs >= 8);
  2. the regkey-name candidates (Rm*/RM* camel-case conventions);
  3. TWO independent reference mechanisms hunted for every string:
       a. the PIC data-xref: auipc+addi (adjacent, rs1==auipc.rd) whose
          composed address lands EXACTLY on the string VA — the auipc
          census is restricted to the code segment, over ALL even
          offsets (data refs may sit in uncovered islands), and each
          hit is verified against the immediate;
       b. the pointer-table probe: the string VA stored as a raw u64
          anywhere in the file (a {name-ptr, ...} table entry).
  4. the consumer classification for every xref (first real use of the
     pointer register: DEREF-LOAD (byte-walk = inline compare/scan),
     STORE-THROUGH-PTR, PASS-TO-CALL, REG-READ, clobbers named), with
     the window cited;
  5. the hash-alternative check: the standard string-hash constants
     (FNV-1a 32 prime/basis, DJB2 5381, CRC32 polys, Knuth) censused
     in full-form pairs over the code image — if the dispatch is
     hashed rather than strcmp'd, the constants betray it.

Selftests: the coordinate law (512 windows + 7 sites); the ELF header
(e_machine == 0xf3, e_phnum >= 4); the banked string anchor
"RMEnableEventTracer" must exist in the census; every PIC xref's
composed address equals the string VA exactly (by construction, the
lo12 is asserted against the needed offset).

Output: lab/jalon411/v435b_regkeys.json
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
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82
BANKED_ANCHOR = "RMEnableEventTracer"

HASH_CONSTS = {
    16777619: "FNV-1a-32 prime", 2166136261: "FNV-1a-32 basis",
    5381: "DJB2 init (0x1505)", 3988292384: "CRC32 poly 0xEDB88320",
    79764919: "CRC32 poly 0x04C11DB7", 2654435769: "Knuth 0x9E3779B9",
}

REGS = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6"]

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

STRING_RE = re.compile(rb"[\x20-\x7e]{8,}")
NAME_RE = re.compile(rb"^(Rm|RM)[A-Z][A-Za-z0-9]{4,}$")


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
    """first real use of the pointer register forward from the addi.

    Honesty rules: a load/store with the pointer as the MEM BASE is a
    dereference (capstone keeps the base inside RISCV_OP_MEM, not as a
    separate REG operand); a call CONSUMES the a-regs as its ABI
    arguments BEFORE clobbering them — so a call while the pointer
    lives in an a-reg is PASS-TO-CALL, not a clobber; a call clobbers
    the t/s regs only from the caller's point of view of RETURN values.
    """
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
            # the pair's own addi reads rd by construction — skip it
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


def window_lines(img, off, n=10):
    lines = []
    for _ in range(n):
        ins = dis1(img, off)
        if ins is None:
            lines.append(f"0x{IMG_LO + off:x}: <invalid>")
            break
        lines.append(f"0x{IMG_LO + off:x}: {ins.mnemonic:<8} "
                     f"{ins.op_str}")
        off += ins.size
    return lines


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000"}

    # -- the law
    fails = 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    for boff in SITES_B:
        if db[boff:boff + 8] != a_img[boff + SHIFT:boff + SHIFT + 8]:
            fails += 1
    assert fails == 0 and (a_img[CLAIM7_A] & 0x7F) == 0x37
    out["law_recheck"] = {"fails": fails}

    # -- the ELF headers: the CONTAINER is the real runtime image
    #    (rm-full.elf = the code-only 1-LOAD re-wrap; the campaign's
    #    VA convention is the rm-full universe = runtime VA - 0x38).
    #    The xref composition MUST use runtime VAs from the container
    #    phdrs (the loader's ground truth), consistently for both the
    #    auipc PC and the string target — the +/-0x38 shift cancels
    #    only when BOTH sides share one universe.
    e_machine = struct.unpack_from("<H", db, 18)[0]
    e_phoff = struct.unpack_from("<Q", db, 0x20)[0]
    e_phnum = struct.unpack_from("<H", db, 0x38)[0]
    assert e_machine == 0xF3, f"e_machine {e_machine}"
    assert e_phnum >= 4, f"e_phnum {e_phnum}"
    em_check = struct.unpack_from("<H", da, 18)[0]
    assert em_check == 0xF3, f"rm-full e_machine {em_check}"
    segs = []
    for i in range(e_phnum):
        p = e_phoff + i * 0x38
        p_type, p_flags, p_off, p_vaddr, _pa, p_filesz, _m, _al = \
            struct.unpack_from("<IIQQQQQQ", db, p)
        if p_type == 1 and p_filesz > 0:
            segs.append({"off": p_off, "vaddr": p_vaddr,
                         "filesz": p_filesz, "flags": p_flags})
    assert len(segs) == 2, f"expected code+data LOADs, got {len(segs)}"
    out["segments"] = [
        {"off": hex(s["off"]), "vaddr": hex(s["vaddr"]),
         "filesz": hex(s["filesz"]), "flags": hex(s["flags"])}
        for s in segs]
    for s in segs:
        print(f"[elf] LOAD off={s['off']:#x} vaddr={s['vaddr']:#x} "
              f"filesz={s['filesz']:#x} flags={s['flags']:#x}")

    def va_of(foff):
        for s in segs:
            if s["off"] <= foff < s["off"] + s["filesz"]:
                return s["vaddr"] + (foff - s["off"])
        return None

    # -- the string census over the WHOLE CONTAINER (code + data)
    strings = []
    for m in STRING_RE.finditer(db):
        foff = m.start()
        strings.append({"foff": foff, "va": va_of(foff),
                        "text": m.group()})
    out["strings_total"] = len(strings)
    print(f"[strings] runs >= 8 printable: {len(strings)}")

    banked = [s for s in strings if s["text"] == BANKED_ANCHOR.encode()]
    assert banked, "banked string anchor missing"
    bva = banked[0]["va"]
    out["selftest_anchor"] = {
        "text": BANKED_ANCHOR,
        "va_runtime": hex(bva) if bva is not None else None,
        "foff_container": hex(banked[0]["foff"])}
    print(f"[selftest] anchor '{BANKED_ANCHOR}' @container "
          f"{banked[0]['foff']:#x} "
          f"va_runtime={hex(bva) if bva is not None else None}")

    # -- regkey-name candidates
    rk = [s for s in strings if NAME_RE.match(s["text"])]
    out["regkey_candidates_n"] = len(rk)
    print(f"[regkeys] Rm*/RM* candidates: {len(rk)}")

    # -- the PIC auipc census over ALL even offsets in the CODE image
    #    (a_img = rm-full universe; the runtime PC = campaign VA + 0x38:
    #     a_img[aoff] == container[aoff + 0x38], whose runtime VA is
    #     0x1000000 + aoff + 0x38 per the container's ph0)
    CODE_FILESZ = segs[0]["filesz"]
    assert CODE_FILESZ == 0xE9B000
    code_img = a_img
    img4 = code_img + b"\x00" * ((4 - len(code_img) % 4) % 4)
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
        aoff = (kk << 2) + base_off          # image coordinate
        pc = IMG_LO + aoff + 0x38            # RUNTIME VA (container)
        base = pc + (hi20 << 12)
        bases.append(np.stack([base, aoff.astype(np.int64), rd],
                              axis=1))
    Bm = np.concatenate(bases)
    order = np.argsort(Bm[:, 0])
    Bs = Bm[order]
    out["auipc_all_offsets"] = int(len(Bm))
    print(f"[pic] auipc census (code segment, all even offsets): "
          f"{len(Bm)}")

    seen_arr = np.frombuffer(seen, dtype=np.uint8)[:len(a_img)]

    def pic_xrefs(target_va):
        """auipc+addi pairs composing exactly target_va."""
        lo_win = np.searchsorted(Bs[:, 0], target_va - 0x7FF,
                                 side="left")
        hi_win = np.searchsorted(Bs[:, 0], target_va + 0x800,
                                 side="left")
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
                             "rd": REGS[rd],
                             "seen_start": bool(seen_arr[aoff])})
        return hits

    # -- the pointer-table probe: string VA stored as a raw u64
    def ptr_table_refs(target_va):
        pat = struct.pack("<Q", target_va)
        hits = []
        start = 0
        while True:
            i = da.find(pat, start)
            if i < 0:
                break
            hits.append({"foff": hex(i),
                         "va": hex(va_of(i)) if va_of(i) else None})
            start = i + 1
            if len(hits) >= 8:
                break
        return hits

    # -- per-candidate card (ALL candidates — the surface size matters)
    cards = []
    for s in rk:
        tva = s["va"]
        if tva is None:
            continue
        xrefs = pic_xrefs(tva)
        ptrefs = ptr_table_refs(tva)
        cons = []
        for x in xrefs[:4]:
            addi_a = int(x["addi_va"], 16) - IMG_LO
            cls, at = classify_consumer(a_img, addi_a, x["rd"])
            cons.append({"class": cls,
                         "at": hex(at + IMG_LO) if at else None,
                         "rd": x["rd"],
                         "window": window_lines(a_img, addi_a, 10)})
        cards.append({
            "name": s["text"].decode(), "va_runtime": hex(tva),
            "va_campaign": hex(tva - 0x38) if tva < 0x2000000 else None,
            "len": len(s["text"]),
            "pic_xrefs": len(xrefs),
            "xref_detail": cons if xrefs else [],
            "ptr_table_refs": ptrefs})
    out["regkey_cards"] = cards

    # -- the hash-alternative census (full-form pairs over the image)
    hash_hits = defaultdict(list)
    cands = []
    for base_off, uarr in ((0, u0), (2, u2)):
        kmax = (len(img4) - 4 - base_off) >> 2
        k = np.arange(kmax, dtype=np.int64)
        mask = (uarr[k] & 0x7F) == 0x37
        for kk in k[mask]:
            cands.append((int((kk << 2) + base_off), int(uarr[kk])))
    for aoff, w1 in cands:
        rd = (w1 >> 7) & 0x1F
        if rd == 0:
            continue
        hi_s = (w1 >> 12) - (1 << 20) if (w1 >> 12) >= 0x80000 \
            else (w1 >> 12)
        for d in (2, 4):
            if aoff + d + 4 > len(code_img):
                continue
            w2 = int.from_bytes(code_img[aoff + d:aoff + d + 4],
                                "little")
            if (w2 & 0x7F) not in (0x13, 0x1B):
                continue
            if ((w2 >> 12) & 7) != 0:
                continue
            if ((w2 >> 15) & 0x1F) != rd or ((w2 >> 7) & 0x1F) != rd:
                continue
            lo_f = (w2 >> 20) & 0xFFF
            if lo_f >= 0x800:
                lo_f -= 0x1000
            v = ((hi_s << 12) + lo_f) & 0xFFFFFFFF
            if v in HASH_CONSTS:
                if len(hash_hits[v]) < 4:
                    hash_hits[v].append({
                        "VA": hex(IMG_LO + aoff),
                        "val": HASH_CONSTS[v],
                        "form_gap": d})
            break
    out["hash_constants"] = {str(k): v for k, v in hash_hits.items()}

    # -- FNV sites: cite the windows (the prime may be shift-built —
    #    the basis alone is the smoking gun, the window shows the shape)
    fnv_windows = []
    for v, hits in hash_hits.items():
        if "FNV" not in HASH_CONSTS[v]:
            continue
        for h in hits:
            aoff = int(h["VA"], 16) - IMG_LO
            fnv_windows.append({
                "VA": h["VA"], "val": HASH_CONSTS[v],
                "window": window_lines(code_img, aoff, 12)})
    out["fnv_sites_windows"] = fnv_windows

    # -- the pointer-table grammar: decode the neighborhood of every
    #    u64 that points at a regkey string (RmCePceMap pattern)
    def decode_table_at(tva, radius=0xc0):
        foff = None
        for s in segs:
            if s["vaddr"] <= tva < s["vaddr"] + s["filesz"]:
                foff = s["off"] + (tva - s["vaddr"])
        if foff is None:
            return None
        lo = max(0, foff - radius)
        entries = []
        for i in range(0, len(db[lo:foff + radius]) - 7, 8):
            u, = struct.unpack_from("<Q", db, lo + i)
            ent = {"at": hex(va_of(lo + i)) if va_of(lo + i) else None,
                   "u64": hex(u)}
            if 0x1000000 <= u < 0x1e9b038 or \
                    0x4000000 <= u < 0x41d5000:
                sf = None
                for s2 in segs:
                    if s2["vaddr"] <= u < s2["vaddr"] + s2["filesz"]:
                        sf = s2["off"] + (u - s2["vaddr"])
                if sf is not None:
                    end = db.find(b"\x00", sf, sf + 64)
                    if end > sf:
                        txt = db[sf:end]
                        if len(txt) >= 3 and all(
                                0x20 <= b < 0x7f for b in txt):
                            ent["points_to"] = txt.decode()
                        else:
                            ent["points_to"] = f"<{end - sf} non-print bytes>"
                ent["kind"] = "ptr"
            elif u < 0x1000:
                ent["kind"] = f"small-int"
            entries.append(ent)
        return entries

    tbl = decode_table_at(0x1C49340)
    out["ptr_table_grammar_rmcepce"] = tbl

    # -- neighborhood grammar probe: pointers near each string
    def neighborhood_ptrs(va, span=0x60):
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
            at = lo + i
            at_va = va_of(at)
            if 0x1000000 <= u < 0x1e9b038:
                ptrs.append({"kind": "code", "va": hex(u),
                             "at": hex(at_va) if at_va else None})
            elif 0x4000000 <= u < 0x41d5000:
                ptrs.append({"kind": "data", "va": hex(u),
                             "at": hex(at_va) if at_va else None})
        return ptrs[:8]

    for c in cards[:60]:
        c["neighbor_ptrs"] = neighborhood_ptrs(int(c["va_runtime"], 16))

    OUT.write_text(json.dumps(out, indent=1))
    n_x = sum(c["pic_xrefs"] for c in cards)
    n_pt = sum(len(c["ptr_table_refs"]) for c in cards)
    print(f"[regkeys] cards={len(cards)} pic_xrefs={n_x} "
          f"ptr_table_refs={n_pt} hash_consts={len(hash_hits)}")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
