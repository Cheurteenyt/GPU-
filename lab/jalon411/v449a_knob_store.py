#!/usr/bin/env python3
"""4.49 TASK A — the L2 knob store hunt: the dispatcher decoded in full,
the family card, and the image-wide consumption census.

State: 4.48 re-scoped the 4.47 RML2MaxWaysSysmem "pointer-range switch"
@0x130697e-0x1306aec — it is the NAME dispatch of a per-branch trace
window; NO ways store is visible inside. The TÂCHE C question stands
re-scoped: the consumption sits outside the window. This instrument:

  1. decodes a generous window around the dispatcher
     [0x1306700, 0x1306C00) instruction-by-instruction, banked whole —
     every auipc(+addi) VA materialization, every branch target, every
     call target, the compare chain against the data-LOAD name base;
  2. extracts the family: the exact materialized data VAs the dispatch
     compares/reads, then dumps the interned-name runs around them
     (the L2/ROP regkey family card);
  3. censuses the CONSUMERS image-wide, two artifacts:
     (a) CODE: every auipc(+addi) composition producing a VA inside the
         family range, at BOTH 2-byte alignments (the 4.48 lesson),
         outside the dispatcher window — each with a +-8-insn context;
     (b) DATA: every u64 in the image (8- and 4-aligned) whose value
         falls inside the family range — the MCLK_LIMIT-style
         {name-ptr,...} records — plus the whole-FILE scan of the bin
         (the v447a citation space) for the same range;
  4. classifies each code consumer: does the enclosing ret-bounded
     frame call the trace logger 0x1a9e624, a lookup, or store?

Selftests: the auipc census 416,206; the 512-region map law; the
dispatcher window bounds contain the 4 banked sites.

Output: lab/jalon411/v449a_knob_store.json
"""
import json
import re
import struct
import zlib
from collections import Counter
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
DISP_LO, DISP_HI = 0x1306700, 0x1306C00      # the generous dispatcher window
BANKED_SITES = [0x130697E, 0x1306AB0, 0x1306AD0, 0x1306AEC]
TRACE_API = 0x1A9E624

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

REG = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
       "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
       "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
       "t3", "t4", "t5", "t6"]


def dec_at(img, off):
    if img[off] & 3 == 3:
        ins = next(md.disasm(img[off:off + 4], IMG_LO + off), None)
        return (ins, 4) if ins else (None, 0)
    ins = next(md.disasm(img[off:off + 2], IMG_LO + off), None)
    return (ins, 2) if ins else (None, 0)


def render(ins):
    if ins is None:
        return "<invalid>"
    return f"{ins.mnemonic:<8} {ins.op_str}"


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

    out = {"pass": "4.49", "task": "A", "instrument": "v449a_knob_store",
           "baseline": {"auipc": cnt, "law": "512/512"}}

    # -- 1. the dispatcher window, decoded whole ---------------------------
    body = []
    o = DISP_LO - IMG_LO
    end = DISP_HI - IMG_LO
    matz = []          # auipc(+addi) materializations
    calls = []         # auipc ra + jalr pairs
    branches = []
    auipc_val = {}     # reg -> (va_site, base_va_without_addi)
    while o < end:
        ins, sz = dec_at(img, o)
        va = IMG_LO + o
        e = {"va": hex(va), "insn": render(ins)}
        if ins is not None:
            u = struct.unpack_from("<I", img, o)[0] if sz == 4 else None
            if ins.mnemonic == "auipc":
                rd = REG[(u >> 7) & 31]
                imm20 = (u >> 12) & 0xFFFFF
                if imm20 & 0x80000:
                    imm20 -= 0x100000
                auipc_val[rd] = (va, va + (imm20 << 12))
                e["auipc"] = f"{rd} -> {va + (imm20 << 12):#x}(+imm)"
            elif ins.mnemonic in ("addi",) and auipc_val:
                m = re.match(r"(\w+), (\w+), (-?0x[0-9a-f]+|-?\d+)$",
                             ins.op_str)
                if m and m.group(2) in auipc_val:
                    iv = int(m.group(3), 0)
                    site, base = auipc_val[m.group(2)]
                    full = base + iv
                    e["mat"] = f"{m.group(1)} = {full:#x}"
                    matz.append({"site": hex(va), "rd": m.group(1),
                                 "va": full,
                                 "pair": hex(site)})
            elif ins.mnemonic in ("jalr",) and u is not None:
                rd = REG[(u >> 7) & 31]
                rs1 = REG[(u >> 15) & 31]
                imm = (u >> 20) & 0xFFF
                if imm & 0x800:
                    imm -= 0x1000
                if rs1 in auipc_val:
                    tgt = auipc_val[rs1][1] + imm
                    e["call"] = f"{rd}, {tgt:#x}"
                    calls.append({"site": hex(va), "rd": rd,
                                  "target": tgt, "rs1": rs1})
            elif ins.mnemonic.startswith("b") and ins.op_str:
                # resolve the pc-relative branch target (op_str's last
                # operand = the absolute address capstone prints)
                mm = re.search(r"(-?0x[0-9a-f]+|-?\d+)$", ins.op_str)
                if mm:
                    tv = int(mm.group(1), 0)
                    branches.append({"site": hex(va),
                                     "insn": e["insn"],
                                     "target": hex(va + tv)})
        body.append(e)
        o += sz if sz else 2   # the v448c guard: an undecodable byte must
                               # NEVER stall the walk (the OOM lesson)
    out["dispatcher"] = {
        "window": [hex(DISP_LO), hex(DISP_HI)],
        "banked_sites_present": all(hex(s) in {b["va"] for b in body}
                                    for s in BANKED_SITES),
        "materializations": [{"site": m["site"], "rd": m["rd"],
                              "va": hex(m["va"]), "pair": m["pair"]}
                             for m in matz],
        "calls": [{"site": c["site"], "target": hex(c["target"]),
                   "rd": c["rd"]} for c in calls],
        "branches": branches,
        "body": body,
    }
    print(f"[dispatcher] window decoded: {len(body)} insns, "
          f"{len(matz)} materializations, {len(calls)} calls, "
          f"{len(branches)} branches; banked sites present = "
          f"{out['dispatcher']['banked_sites_present']}")

    # the data-LOAD VAs the dispatcher materializes
    data_matz = [m for m in matz if m["va"] >= 0x1E00000]
    data_vas = sorted({m["va"] for m in data_matz})
    print("[dispatcher] data VAs materialized:",
          [hex(v) for v in data_vas])

    # -- 2. the family: strings around every materialized data VA ----------
    def va2off(va):
        return va - IMG_LO

    IMG_HI = IMG_LO + len(img)
    fam = {}
    nonfile = []          # the runtime-data pointers (outside the ELF)
    for va in data_vas:
        if not (IMG_LO <= va < IMG_HI):
            nonfile.append(hex(va))
            continue
        # walk the run backwards to its first NUL, forward likewise
        o = va2off(va)
        lo = o
        while lo > 0 and img[lo - 1] != 0:
            lo -= 1
        lo_va = IMG_LO + lo
        # collect the strings in [lo, lo+0x600)
        names = []
        p = lo
        while p < min(lo + 0x600, len(img)):
            e2 = img.find(b"\x00", p, p + 128)
            if e2 < 0:
                break
            s = img[p:e2]
            if len(s) >= 2 and all(0x20 <= c < 0x7F for c in s):
                names.append({"va": hex(IMG_LO + p), "name":
                              s.decode("ascii")})
            p = e2 + 1
        fam[hex(va)] = {"base_va": hex(lo_va), "names": names}
    out["family"] = fam
    out["nonfile_pointers"] = nonfile
    all_names = [n["name"] for f in fam.values() for n in f["names"]]
    print(f"[family] {len(all_names)} interned strings collected around "
          f"the dispatch VAs; non-file-backed pointers: {nonfile}")

    # the family range for the census: the L2/FB regkey block ONLY.
    # The wide [base, base+0x600) swallowed the EDC/HUBCLIENT id tables
    # (run 1: the first pass's 354 consumers were mostly HUBCLIENT noise).
    # The regkey run observed: GC6_CTX_HDR @0x1e343c0 ... up to
    # RmEnableL2CohErrorIntr, then the long ECC message @0x1e34660.
    fam_lo = 0x1E343C0
    fam_hi = 0x1E34660
    out["family_range"] = [hex(fam_lo), hex(fam_hi)]
    name_vas = {int(n["va"], 16): n["name"]
                for f in fam.values() for n in f["names"]}

    # -- 3a. the CODE consumers (both alignments, outside the window) ------
    cands = []
    for base in (0, 2):
        sub = img[base:]
        sub = sub[:len(sub) - (len(sub) % 4)]
        u32 = np.frombuffer(sub, dtype="<u4")
        idx = np.nonzero((u32 & 0x7F) == 0x17)[0]
        for k in idx:
            u = int(u32[k])
            imm20 = (u >> 12) & 0xFFFFF
            if imm20 & 0x80000:
                imm20 -= 0x100000
            va = IMG_LO + base + int(k) * 4
            page = va + (imm20 << 12)
            # candidates whose page can reach the family range
            if page - 0x1000 <= fam_hi and page + 0xFFF + 0x800 >= fam_lo:
                cands.append((va, page))
    code_hits = []
    for va, page in cands:
        # the following addi (2-4 bytes ahead, any alignment) completes it
        o = va - IMG_LO + 4
        for _ in range(2):
            if o + 4 > len(img):
                break
            u2 = struct.unpack_from("<I", img, o)[0]
            if (u2 & 0x7F) == 0x13 and ((u2 >> 12) & 7) == 0:
                rd = REG[(u2 >> 7) & 31]
                rs1 = REG[(u2 >> 15) & 31]
                imm = (u2 >> 20) & 0xFFF
                if imm & 0x800:
                    imm -= 0x1000
                # rd must match the auipc's rd; rs1 = the same reg
                u_auipc = struct.unpack_from(
                    "<I", img, va - IMG_LO)[0]
                if rd == REG[(u_auipc >> 7) & 31] and rs1 == rd:
                    full = page + imm
                    if fam_lo <= full < fam_hi:
                        code_hits.append({"site": hex(va),
                                          "mat_va": full,
                                          "name": name_vas.get(full,
                                                              f"@{full:#x}"),
                                          "rd": rd})
                    break
            o += 2
    # dedupe + exclude the dispatcher window itself
    seen = set()
    code_cons = []
    for h in code_hits:
        if h["site"] in seen:
            continue
        seen.add(h["site"])
        sv = int(h["site"], 16)
        if DISP_LO - 0x80 <= sv < DISP_HI + 0x80:
            continue
        code_cons.append(h)
    # context for each (wide: the argument setup precedes the call)
    for h in code_cons:
        sv = int(h["site"], 16) - IMG_LO
        lines = []
        o = sv - 0x40
        while o < sv + 0x40:
            ins, sz = dec_at(img, o)
            lines.append(f"{IMG_LO + o:#x}: {render(ins)}")
            o += sz if sz else 2
        h["ctx"] = lines
        # the enclosing frame: does it call the trace API?
        o = sv
        steps = 0
        calls_api = False
        call_targets = []
        while o < sv + 0x400 and steps < 200:
            ins, sz = dec_at(img, o)
            if ins is None:
                break
            u = struct.unpack_from("<I", img, o)[0] if sz == 4 else None
            if u is not None and (u & 0x7F) == 0x67 and \
                    ((u >> 12) & 7) == 0 and ((u >> 15) & 31) == 1:
                imm = (u >> 20) & 0xFFF
                if imm & 0x800:
                    imm -= 0x1000
                # need the auipc ra just before
                u0 = struct.unpack_from("<I", img, o - 4)[0]
                if (u0 & 0x7F) == 0x17 and ((u0 >> 7) & 31) == 1:
                    imm20 = (u0 >> 12) & 0xFFFFF
                    if imm20 & 0x80000:
                        imm20 -= 0x100000
                    tgt = (IMG_LO + o - 4) + (imm20 << 12) + imm
                    call_targets.append(hex(tgt))
                    if tgt == TRACE_API:
                        calls_api = True
            o += sz if sz else 2
            steps += 1
        h["calls_trace_api"] = calls_api
        h["calls_ahead"] = call_targets[:6]
    out["code_consumers"] = code_cons
    print(f"[code] {len(code_cons)} consumer sites outside the window")
    for h in code_cons:
        print(f"  @{h['site']} -> {h['mat_va']:#x} ({h['name']}) "
              f"trace={h['calls_trace_api']} calls={h['calls_ahead']}")

    # -- 3b. the DATA records (u64 into the family range) ------------------
    def u64_scan(buf, base_va, note):
        hits = []
        n = len(buf) // 8 * 8
        u = np.frombuffer(buf[:n], dtype="<u8")
        m = (u >= fam_lo) & (u < fam_hi)
        for k in np.nonzero(m)[0]:
            hits.append({"off": int(k) * 8, "va": base_va + int(k) * 8,
                         "val": int(u[k])})
        # the 4-aligned pass (pointers packed in u32 pairs)
        n4 = len(buf) // 4 * 4
        u4 = np.frombuffer(buf[:n4], dtype="<u4")
        m4 = (u4.astype(np.uint64) >= fam_lo) & \
             (u4.astype(np.uint64) < fam_hi)
        for k in np.nonzero(m4)[0]:
            if k % 2 == 0:  # low word of an 8-aligned u64 already caught
                continue
            v = int(u4[k])
            hits.append({"off": int(k) * 4, "va": base_va + int(k) * 4,
                         "val": v})
        out2 = []
        for h in hits:
            o = h["off"]
            near = buf[o:o + 48].hex()
            out2.append({"artifact": note, "off": hex(o),
                         "va_of_ref": hex(h["va"]),
                         "val": hex(h["val"]),
                         "neighborhood_hex": near})
        return out2

    data_hits = u64_scan(img, IMG_LO, "rm-full.elf image")
    bin_hits = u64_scan(db, 0x1000038, "gsp-rm-17MB.bin (bin=VA-0x38)")
    out["data_records"] = {"in_image": data_hits, "in_bin": bin_hits}
    print(f"[data] image u64-in-range: {len(data_hits)}; "
          f"bin: {len(bin_hits)}")
    for h in (data_hits + bin_hits)[:24]:
        print(f"  {h['artifact']} @{h['off']} val={h['val']}")

    # -- 4. the shared callees of the family consumers, decoded ------------
    # The first pass showed every consumer of the registration block
    # calling 0x103c08c — decode it (bounds + body), it is the candidate
    # regkey decode/parse primitive.
    def func_bounds(va):
        # backward: the nearest c.addi16sp/addi sp prologue (<= 0x800)
        o = va - IMG_LO
        pro = None
        p = o
        for _ in range(0x400):
            if p <= 0:
                break
            hw = struct.unpack_from("<H", img, p)[0]
            u4 = struct.unpack_from("<I", img, p)[0] if img[p] & 3 == 3 \
                else None
            if (hw & 3) == 1 and (hw >> 13) == 3:      # c.addi16sp
                pro = p
                break
            if u4 is not None and (u4 & 0x7F) == 0x13 and \
                    ((u4 >> 15) & 31) == 2 and ((u4 >> 7) & 31) == 2 and \
                    ((u4 >> 20) & 0xFFF) in (0x000, 0x010, 0x020, 0x040,
                                             0x050, 0x060, 0x080):
                # addi sp, sp, -N (the 12-bit imm is sign-extended;
                # the negative encodings share imm12 high bits)
                imm = (u4 >> 20) & 0xFFF
                if imm & 0x800:                        # negative -> prologue
                    pro = p
                    break
            p -= 2
        end = o
        q = o
        for _ in range(0x2000):
            if q + 2 > len(img):
                break
            hw = struct.unpack_from("<H", img, q)[0]
            if hw == 0x8082 or (img[q] & 3 == 3 and
                                struct.unpack_from("<I", img, q)[0]
                                == 0x8067):
                end = q
                break
            insx, szx = dec_at(img, q)
            q += szx if szx else 2
        else:
            end = min(o + 0x2000, len(img))
        return pro, end

    def decode_func(va, maxn=260):
        pro, end = func_bounds(va)
        lines = []
        o = (pro if pro is not None else va - IMG_LO)
        n = 0
        calls_f = []
        while o <= end and n < maxn:
            ins, sz = dec_at(img, o)
            lines.append(f"{IMG_LO + o:#x}: {render(ins)}")
            if ins is not None and ins.mnemonic == "jalr" and \
                    img[o] & 3 == 3:
                u = struct.unpack_from("<I", img, o)[0]
                imm = (u >> 20) & 0xFFF
                if imm & 0x800:
                    imm -= 0x1000
                calls_f.append(imm)
            o += sz if sz else 2
            n += 1
        return {"va": hex(va), "prologue": hex(IMG_LO + pro)
                if pro is not None else None,
                "end": hex(IMG_LO + end), "bytes": end - (pro or 0),
                "body": lines, "jalr_imms": calls_f}

    out["shared_callees"] = {
        "0x103c08c": decode_func(0x103C08C),
        "0x1aa3444": decode_func(0x1AA3444),
        "0x143f4f8": decode_func(0x143F4F8),
        "0x1a93218": decode_func(0x1A93218),
    }
    print("[callees] decoded 0x103c08c / 0x1aa3444 / 0x143f4f8 / 0x1a93218")

    # -- 4b. the SUCCESS HANDLERS of the ingestion block --------------------
    # The ingestion pattern per key: call 0x103c08c(s2, NAME, s0-0x70);
    # the status branches to a per-key handler. For RMAsrWakeup the
    # handler @0x1308178 was reached via bnez; the store visible inline
    # (sb a4, 0x67d(s3+0x8000) @0x1307c04). For RML2MaxWaysSysmem the
    # success branch = 0x130822C. Decode BOTH handlers with a generous
    # window, plus the enclosing function's prologue hunt.
    def window_decode(va, span=0x120):
        lines = []
        o = va - IMG_LO
        end = o + span
        while o < end:
            ins, sz = dec_at(img, o)
            lines.append(f"{IMG_LO + o:#x}: {render(ins)}")
            o += sz if sz else 2
        return lines

    out["success_handlers"] = {
        "rml2maxwayssysmem_0x130822c": window_decode(0x130822C, 0x140),
        "rmasrwakeup_0x1308178": window_decode(0x1308178, 0xC0),
        "ingestion_prologue_hunt": window_decode(0x1307840, 0x100),
    }
    print("[handlers] decoded 0x130822c (L2 ways) + 0x1308178 (AsrWakeup)")

    # -- 4c. the READER hunt for config+0x3D84 (+the flag word +0x3D68) -----
    # The store idiom (both alignments): c.lui rX,4 ; c.add rX,s3 ;
    #   sw value, -0x27c(rX)   -> config+0x3D84
    #   sw flags, -0x298(rX)   -> config+0x3D68   (|1 = ways-was-set)
    # 0x3D84 does NOT fit a signed imm12 as +0x3D84, but its encodings DO:
    #   -0x27c (0xd84) and -0x298 (0xd68) — scan every lw/ld/sw/sd carrying
    #   those immediates image-wide, both alignments.
    disp_scan = []
    for off in range(0, len(img) - 4, 2):
        if img[off] & 3 != 3:
            continue
        u = struct.unpack_from("<I", img, off)[0]
        opc = u & 0x7F
        if opc not in (0x03, 0x23):
            continue
        f3 = (u >> 12) & 7
        if opc == 0x03 and f3 not in (2, 3):    # lw / ld
            continue
        if opc == 0x23 and f3 not in (2, 3):    # sw / sd
            continue
        imm = (u >> 20) & 0xFFF
        if imm not in (0xD84, 0xD68):
            continue
        rd = REG[(u >> 7) & 31]
        rs1 = REG[(u >> 15) & 31]
        mn = {0x03: {2: "lw", 3: "ld"}, 0x23: {2: "sw", 3: "sd"}}[opc][f3]
        disp_scan.append({"va": hex(IMG_LO + off), "insn":
                          f"{mn} {rd}, -{(0x1000 - imm):#x}({rs1})",
                          "disp": -(0x1000 - imm)})
    for h in disp_scan:
        sv = int(h["va"], 16) - IMG_LO
        lines = []
        o = sv - 0x18
        while o < sv + 0x18:
            ins, sz = dec_at(img, o)
            lines.append(f"{IMG_LO + o:#x}: {render(ins)}")
            o += sz if sz else 2
        h["ctx"] = lines
    out["reader_scan"] = disp_scan
    print(f"[readers] {len(disp_scan)} -0x27c/-0x298 load-store sites "
          f"image-wide")
    for h in disp_scan[:16]:
        print(f"  @{h['va']} {h['insn']}")

    # -- 4d. THE CONSUMER: the function @0x1318d4a reads BOTH the flag
    # word (config+0x3D68, bit0) AND the ways value (config+0x3D84),
    # compares against 7, and stores 7 back on some paths. Decode its
    # full body + the far paths (value==0 / value==7).
    out["the_consumer"] = decode_func(0x1318D4A, maxn=900)
    out["consumer_far_paths"] = {
        "value0_0x13191c0": window_decode(0x13191B0, 0x50),
        "value7_0x13191bc": window_decode(0x13191A0, 0x50),
    }
    print(f"[consumer] decoded @0x1318d4a: "
          f"{out['the_consumer']['bytes']}B, "
          f"{len(out['the_consumer']['body'])} insns")

    # -- 5. the honest classification --------------------------------------
    out["selftests"] = {
        "auipc_416206": True,
        "law_512": "PASS",
        "banked_sites_in_window": out["dispatcher"]["banked_sites_present"],
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
