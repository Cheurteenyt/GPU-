#!/usr/bin/env python3
"""4.44 pass, TÂCHE A1 — the evaluator 0x1446d98 decoded IN FULL.

4.43 §2.4 banked the formula block (0x1446ef4-0x1446f48, partial — the
gap 0x1446f3e-0x1446f44 was NOT cited). The mission asks for the WHOLE
function: (a) the real load types (lwu/lw/c.lw) and what each sign/zero
extension means for the values; (b) the idx indexing (0..4 = the 5
vPstates? confirmed by what); (c) the EXACT destination of the 0x28
output (which register walks it, where the buffer lives, which fields
of the a2 object receive it).

Method: the full window decode (prologue -> the last ret before the
next function head on the verified map), PLUS:
  - every load {va, m, disp} classified (record / base / mask / flags);
  - every store {va, m, disp} classified (output pair / state field);
  - every constant materialization (li/lui/c.lui) with its register;
  - the match table @0x1C7B450 and the mask table @0x1C7B320 dumped
    RAW (16 dwords each) from the code image;
  - the scalers t1=0x64, t4=0x3E8 sites re-cited;
  - the memset(0x28) site re-cited and its buffer register traced.

Self-checks: the law 512/512; the formula block re-derivation (the
mul/divu/divuw @0x1446f14-f1c cited == the decode); the census 17/17
inherited from v4440 (run before this script).

Output: lab/jalon411/v444a_evaluator_full.json
"""
import json
import zlib
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
EVAL = 0x1446d98
WIN_END = 0x1448000          # the decode bound (the far branches 0x1447BFC/
                             # 0x1447D7C/0x1447E4C/0x1447E8A must be covered)
N_INSNS = 1400

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = False

da = A.read_bytes()
img = da[0x40:0x40 + 0xE9B000]


def dec(va, n=1, back=0):
    out = []
    o = va - IMG_LO - back
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append({"va": IMG_LO + o, "m": ins.mnemonic, "o": ins.op_str,
                    "size": ins.size})
        o += ins.size
    return out


def disp_of(o):
    if "(" not in o:
        return None
    d = o.split("(")[0].strip()
    try:
        return int(d, 0)
    except ValueError:
        return None


def main():
    out = {}
    # -- the law (cheap re-assert)
    import numpy as np
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):   # the two-parity census (the RVC layout)
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        k = np.arange((len(img4) - 4 - base_off) >> 2, dtype=np.int64)
        cnt += int(((uarr[k] & 0x7F) == 0x17).sum())
    out["auipc_census"] = cnt
    assert cnt == 416206, "auipc census broken"
    out["law_fails"] = 0
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        assert img[o:o + 16] == (ROOT /
             "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
             ).read_bytes()[o - 0x38:o - 0x38 + 16], "law broken"

    # -- 1. the FULL window decode
    wins = dec(EVAL, N_INSNS)
    # the function end = the first ret that is followed by a new-prologue
    # pattern (c.addi16sp/addi sp,sp,-N) within the window
    end_va = None
    for i, w in enumerate(wins):
        if w["m"] in ("ret", "c.ret"):
            nxt = dec(w["va"] + w["size"], 3)
            if nxt and nxt[0]["m"] in ("c.addi16sp", "addi") and \
                    "sp" in nxt[0]["o"].split(",")[0]:
                end_va = w["va"]
                break
            if i + 1 < len(wins) and wins[i + 1]["va"] >= WIN_END:
                end_va = w["va"]
                break
    out["function_end_candidate"] = hex(end_va) if end_va else None
    listing = [w for w in wins if end_va is None or w["va"] <= end_va]
    out["listing"] = [
        {"va": f"0x{w['va']:x}", "m": w["m"], "o": w["o"]} for w in listing]

    # -- 2. the structured census over the function body
    loads, stores, consts, muldiv = [], [], [], []
    for w in listing:
        m, o = w["m"], w["o"]
        va = w["va"]
        if m in ("ld", "lw", "lwu", "lbu", "lhu", "c.lw", "c.ld"):
            loads.append({"va": f"0x{va:x}", "m": m, "o": o,
                          "disp": disp_of(o)})
        elif m in ("sd", "sw", "sb", "sh", "c.sw", "c.sd", "c.swsp",
                   "c.sdsp"):
            stores.append({"va": f"0x{va:x}", "m": m, "o": o,
                           "disp": disp_of(o)})
        elif m in ("li", "c.li", "lui", "c.lui"):
            consts.append({"va": f"0x{va:x}", "m": m, "o": o})
        elif m in ("mul", "mulh", "divu", "divuw", "div", "remu", "rem"):
            muldiv.append({"va": f"0x{va:x}", "m": m, "o": o})

    out["loads"] = loads
    out["stores"] = stores
    out["consts"] = consts
    out["muldiv"] = muldiv

    # -- 3. the formula block re-derivation (the banked sites)
    banked = {0x1446f14: "mul a3, t6, a3", 0x1446f18: "divu a3, a3, t1",
              0x1446f1c: "divuw a3, a3, t4"}
    ok = {}
    for va, want in banked.items():
        w = dec(va, 1)[0]
        ok[f"0x{va:x}"] = {"want": want, "got": f"{w['m']} {w['o']}",
                           "match": f"{w['m']} {w['o']}" == want}
    out["formula_block_rederivation"] = ok
    assert all(v["match"] for v in ok.values()), "formula block moved"

    # -- 4. the scaler materializations (t1=0x64, t4=0x3E8 @0x1446ee4/ee8)
    out["scalers"] = dec(0x1446ee4, 4)

    # -- 5. the match table @0x1C7B450 and the mask table @0x1C7B320 (raw)
    def dump_words(va, n, how="u32"):
        o = va - IMG_LO
        if how == "u32":
            return [int.from_bytes(img[o + 4 * i:o + 4 * i + 4], "little")
                    for i in range(n)]
        return [int.from_bytes(img[o + 8 * i:o + 8 * i + 8], "little")
                for i in range(n)]
    out["match_table_1C7B450"] = {
        "u32x16": [f"0x{x:x}" for x in dump_words(0x1C7B450, 16)]}
    out["mask_table_1C7B320"] = {
        "u32x16": [f"0x{x:x}" for x in dump_words(0x1C7B320, 16)]}

    # -- 6. the memset(0x28) site @0x1446ebc — the window around it
    out["memset_window"] = dec(0x1446ebc, 6, back=24)

    # -- 7. the record/base field accesses classified
    rec_loads = [l for l in loads if l["disp"] is not None and
                 0x14 <= l["disp"] <= 0x18 and l["m"] in ("c.lw", "lwu",
                                                          "lw")]
    base_loads = [l for l in loads if l["disp"] == 0x18 and
                  l["m"] == "lwu"]
    out["record_field_loads"] = rec_loads
    out["base_field_loads"] = base_loads

    # -- 8. the s8-walk stores (the output pairs)
    s8_stores = [s for s in stores if "(s8)" in s["o"]]
    out["s8_output_stores"] = s8_stores

    # -- 9. the PIC pairs in the window: every auipc+addi target
    pics = []
    for i, w in enumerate(listing):
        if w["m"] != "auipc":
            continue
        imm = w["o"].split(", ")[1]
        immv = int(imm, 0)
        if immv >= 0x80000:
            immv -= 0x100000
        base = w["va"] + (immv << 12)
        rd = w["o"].split(", ")[0]
        # the next insn using rd with an addi
        tgt = None
        for w2 in listing[i + 1:i + 4]:
            if w2["m"] == "addi" and w2["o"].startswith(rd + ", " + rd):
                lo = int(w2["o"].split(", ")[2], 0)
                tgt = base + lo
                break
        pics.append({"va": f"0x{w['va']:x}", "rd": rd,
                     "target": hex(tgt) if tgt is not None else None,
                     "raw_base": hex(base)})
    out["pic_pairs"] = pics

    # -- 10. the direct call targets in the window
    calls = []
    for i, w in enumerate(listing):
        if w["m"] == "auipc":
            imm = w["o"].split(", ")[1]
            immv = int(imm, 0)
            if immv >= 0x80000:
                immv -= 0x100000
            base = w["va"] + (immv << 12)
            for w2 in listing[i + 1:i + 3]:
                if w2["m"] == "jalr" and w2["o"].startswith("ra, ra"):
                    off = int(w2["o"].split(", ")[2], 0)
                    calls.append({"va": f"0x{w['va']:x}",
                                  "callee": hex(base + off)})
                    break
    out["direct_calls"] = calls

    OUT.write_text(json.dumps(out, indent=1))
    print(f"function end candidate: {out['function_end_candidate']}")
    print(f"loads={len(loads)} stores={len(stores)} consts={len(consts)} "
          f"muldiv={len(muldiv)}")
    print(f"s8 stores: {[s['o'] for s in s8_stores]}")
    print(f"match table @0x1C7B450 u32x8: "
          f"{out['match_table_1C7B450']['u32x16'][:8]}")
    print(f"mask  table @0x1C7B320 u32x8: "
          f"{out['mask_table_1C7B320']['u32x16'][:8]}")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
