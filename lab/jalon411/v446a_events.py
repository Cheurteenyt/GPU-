#!/usr/bin/env python3
"""4.46 pass, TÂCHE A — the internal-event family 0x2080_9xxx/0x2080_Axxx
and the DISPATCHER-INSTALLER hunt (who fills *(state+0x138)?).

Banked chain (4.43 §2.3 + 4.44 §2.1): the recompute 0x143fdbc calls a
cached function pointer — `ld a6, 0x138(a5)` / `c.jalr a6` — with the
event id in a3 (0x20809009 the mask query, 0x20809064 the base query);
the RESPONSE LIST (the 0x208 buffer) feeds A/B/C/D at obj+0x600-0x660
and the mask at obj+0x65c. The handler = whatever was installed at
state+0x138. The 4.44 write set proves the recompute itself writes the
bases from the response — the VALUES are born in the handler.

This instrument:
  1. self-checks (auipc 416,206; the coordinate law 512/512);
  2. censuses EVERY 0x2080_8xxx..0x2080_Fxxx event-id materialization
     (lui 0x20808..0x2080f + addi/c.addi imm, both parities, full
     image) — the event-space map;
  3. for the banked events {0x20809009, 0x20809064, 0x2080A080}:
     re-cites the call window (the dispatcher load offset, the arg
     registers);
  4. hunts the INSTALLER: every `sd aX, 0x138(aY)` store in the image;
     for each, walks backward 24 insns to find the VALUE source — an
     auipc-composed static VA = the handler NAMED; a load = a
     vtable-fetched pointer (reported as such);
  5. decodes each named handler's head (140 insns): the PIC table refs,
     the call targets, the stores to (arg)+disp (the response writer),
     any round constants.

Output: lab/jalon411/v446a_events.json
"""
import json
import re
from pathlib import Path

import capstone
import numpy as np
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
IMG_SZ = 0xE9B000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

img = A.read_bytes()[0x40:0x40 + IMG_SZ]

BANKED_EVENTS = [0x20809009, 0x20809064, 0x2080A080]
RECOMP_SITES = {0x143fe1c: "0x20809009 (the mask query, 4.43 §2.3)",
                0x143fe94: "0x20809064 (the base query, 4.44 §2.1)"}


def dec(va, n, back=0):
    o = va - IMG_LO - back
    out = []
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append({"va": IMG_LO + o, "m": ins.mnemonic, "o": ins.op_str,
                    "size": ins.size})
        o += ins.size
    return out


def parse_reg(op):
    return op.split(",")[0].strip()


def parse_imm(op):
    m = re.findall(r"-?0x[0-9a-f]+|-?\d+", op)
    return int(m[-1], 0) if m else None


def parse_mem(op):
    # "... , disp(reg)" -> (disp, reg)
    m = re.search(r"(-?0x[0-9a-f]+|-?\d+)?\((\w+)\)\s*$", op)
    if not m:
        return None, None
    disp = int(m.group(1), 0) if m.group(1) else 0
    return disp, m.group(2)


def main():
    out = {}

    # -- 1. self-checks --------------------------------------------------
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        k = np.arange((len(img4) - 4 - base_off) >> 2, dtype=np.int64)
        cnt += int(((uarr[k] & 0x7F) == 0x17).sum())
    assert cnt == 416206, cnt
    law_fail = 0
    container = (ROOT / "tools/analysis/gsp-extract/binaries/"
                 "gsp-rm-17MB.bin").read_bytes()
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if img[o:o + 16] != container[o - 0x38:o - 0x38 + 16]:
            law_fail += 1
    assert law_fail == 0
    out["selfchecks"] = {"auipc": cnt, "law_fails": law_fail}

    # -- 2. the event-space census ---------------------------------------
    # lui rd, imm20  ->  opcode 0x37; imm20 = (word >> 12) & 0xFFFFF
    # we need lui rd, 0x2080x -> imm20 in {0x20808..0x2080f}
    # addi rd, rd, imm (opcode 0x13, funct3 0) or c.addi (quadrant 1)
    ev_sites = []
    words = np.frombuffer(img4, dtype="<u4")
    n_words = (IMG_SZ) >> 2
    for off2 in (0, 2):  # both parities for lui placement
        base = off2
        while base + 8 <= IMG_SZ:
            w = int.from_bytes(img[base:base + 4], "little")
            if (w & 0x7F) == 0x37:
                imm20 = (w >> 12) & 0xFFFFF
                if 0x20808 <= imm20 <= 0x2080F:
                    rd = (w >> 7) & 0x1F
                    # look ahead up to 8 bytes for addi rd, rd, imm
                    for da in (2, 4, 6, 8):
                        w2 = int.from_bytes(img[base + da:base + da + 4],
                                            "little")
                        # addi a5, a5, imm
                        if (w2 & 0x7F) == 0x13 and \
                           ((w2 >> 12) & 7) == 0 and \
                           ((w2 >> 15) & 0x1F) == rd and \
                           ((w2 >> 7) & 0x1F) == rd:
                            imm12 = w2 >> 20
                            if imm12 >= 0x800:
                                imm12 -= 0x1000
                            ev = (imm20 << 12) + imm12
                            ev_sites.append({
                                "site": IMG_LO + base,
                                "rd": rd, "imm20": imm20, "addi": imm12,
                                "event": ev, "gap": da})
                            break
                        # c.addi rd!=0, imm (quadrant 1, funct3 01)
                        if (w2 & 3) == 1:
                            opq = (w2 >> 13) & 7
                            if opq == 0:
                                crd = (w2 >> 7) & 7  # bits [9:7]
                                if crd == rd - 8 or (rd < 8 and crd == rd):
                                    # c.addi adds sign-extended nzimm[5]
                                    nzimm = ((w2 >> 12) & 1) << 5 | \
                                            (w2 >> 2) & 0x1F
                                    if nzimm >= 0x20:
                                        nzimm -= 0x40
                                    ev = (imm20 << 12) + nzimm
                                    ev_sites.append({
                                        "site": IMG_LO + base,
                                        "rd": rd, "imm20": imm20,
                                        "caddi": nzimm, "event": ev,
                                        "gap": da})
                                    break
            base += 4
    fam = {}
    for s in ev_sites:
        fam.setdefault(f"0x{s['event']:09X}", []).append(
            {"site": f"0x{s['site']:X}", "gap": s["gap"]})
    out["event_space"] = {
        "total_sites": len(ev_sites),
        "distinct_events": len(fam),
        "family_map": {k: v for k, v in sorted(fam.items())},
    }

    # -- 3. the banked call windows re-cited ------------------------------
    cites = {}
    for va, note in RECOMP_SITES.items():
        wins = dec(va - 0x20, 16)
        cites[f"0x{va:X}"] = {"note": note, "window": wins}
    out["call_windows"] = cites

    # -- 4. the installer hunt: sd aX, 0x138(aY) --------------------------
    installers = []
    for off in range(0, IMG_SZ - 4, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        # sd rs2, disp(rs1): opcode 0x23, funct3 3 (64-bit store)
        if (w & 0x7F) != 0x23 or ((w >> 12) & 7) != 3:
            continue
        imm = ((w >> 25) << 5) | ((w >> 7) & 0x1F)
        if imm >= 0x1000:
            imm -= 0x2000
        if imm != 0x138:
            continue
        va = IMG_LO + off
        ins = dec(va, 1)
        if not ins:
            continue
        rs1 = (w >> 15) & 0x1F
        rs2 = (w >> 20) & 0x1F
        # walk back 24 insns for the value source of rs2
        back = dec(va, 24, back=0)
        # rebuild a backward window
        bw = dec(va - 4 * 24, 24)
        src = None
        window = []
        for b in bw:
            window.append(f"0x{b['va']:X}  {b['m']} {b['o']}")
            if parse_reg(b["o"]) and b["m"] in (
                    "auipc", "ld", "c.ld", "c.ldsp", "mv", "c.mv", "addi",
                    "lui", "jalr", "add"):
                rd = parse_reg(b["o"])
                # rs2 reg number: map via capstone reg name rs2
                if rd == f"x{rs2}" or rd == ["zero", "ra", "sp", "gp",
                                              "tp", "t0", "t1", "t2",
                                              "s0", "s1", "a0", "a1",
                                              "a2", "a3", "a4", "a5",
                                              "a6", "a7", "s2", "s3",
                                              "s4", "s5", "s6", "s7",
                                              "s8", "s9", "s10", "s11",
                                              "t3", "t4", "t5", "t6"][rs2]:
                    src = {"va": f"0x{b['va']:X}", "m": b["m"],
                           "o": b["o"]}
                    if b["m"] in ("auipc", "lui"):
                        src["class"] = "static-compose"
                    elif b["m"] in ("ld", "c.ld", "c.ldsp"):
                        src["class"] = "load (vtable/got)"
                    else:
                        src["class"] = "derived"
                    break
        installers.append({
            "va": f"0x{va:X}", "rs1": rs1, "rs2": rs2,
            "disasm": f"{ins[0]['m']} {ins[0]['o']}",
            "value_source": src, "back_window": window[-8:]})
    out["installer_hunt"] = {
        "total_sd_0x138": len(installers),
        "sites": installers,
    }

    # -- 5. named-handler head decode -------------------------------------
    heads = {}
    for it in installers:
        srcva = None
        if it["value_source"] and it["value_source"]["m"] == "auipc":
            # decode the auipc + addi pair composition
            bw = it["back_window"]
            for i, line in enumerate(bw):
                if "auipc" in line:
                    m = re.search(
                        r"auipc\s+\w+,\s*(-?0x[0-9a-f]+|-?\d+)", line)
                    if m:
                        pc = int(line.split()[0].rstrip(":"), 16)
                        up = int(m.group(1), 0)
                        tgt = pc + (up << 12)
                        # look for the following addi in the window
                        for j in range(i + 1, min(i + 4, len(bw))):
                            m2 = re.search(
                                r"addi\s+\w+,\s*\w+,\s*"
                                r"(-?0x[0-9a-f]+|-?\d+)", bw[j])
                            if m2:
                                tgt += int(m2.group(1), 0)
                                break
                        srcva = tgt
        if srcva:
            hd = dec(srcva, 140)
            pic_refs = []
            calls = []
            stores = []
            consts = set()
            for i, b in enumerate(hd):
                if b["m"] == "auipc":
                    m = re.search(r",\s*(-?0x[0-9a-f]+|-?\d+)$", b["o"])
                    if m:
                        up = int(m.group(1), 0)
                        # find paired addi/jalr/ld within 8 bytes
                        for j in range(i + 1, min(i + 4, len(hd))):
                            mm = re.search(
                                r",\s*(-?0x[0-9a-f]+|-?\d+)$",
                                hd[j]["o"])
                            if mm and hd[j]["m"] in (
                                    "addi", "lw", "ld", "jalr", "flw"):
                                tgt = (b["va"] + (up << 12) +
                                       int(mm.group(1), 0))
                                if hd[j]["m"] == "jalr":
                                    calls.append(f"0x{tgt:X}")
                                else:
                                    pic_refs.append(f"0x{tgt:X}")
                                break
                if b["m"] in ("sd", "sw", "c.sd", "c.sw"):
                    d, r = parse_mem(b["o"])
                    if r and d is not None and 0 <= d <= 0x400:
                        stores.append(f"0x{b['va']:X} {b['m']} {b['o']}")
                if b["m"] in ("addi", "lui"):
                    imm = parse_imm(b["o"])
                    if imm and abs(imm) >= 1000 and imm % 1000 == 0:
                        consts.add(imm)
            heads[f"0x{srcva:X}"] = {
                "installed_at": it["va"],
                "head": [f"0x{b['va']:X}  {b['m']} {b['o']}"
                         for b in hd[:60]],
                "pic_refs": pic_refs[:24], "call_targets": calls[:16],
                "obj_stores": stores[:32],
                "round_consts": sorted(consts)}
    out["named_handlers"] = heads

    OUT.write_text(json.dumps(out, indent=1))
    print(f"event sites: {out['event_space']['total_sites']} "
          f"({out['event_space']['distinct_events']} distinct)")
    print(f"sd ...,0x138 installers: {len(installers)}")
    for k in heads:
        print(f"named handler: {k} (installed at "
              f"0x{heads[k]['installed_at']})")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
