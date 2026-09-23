#!/usr/bin/env python3
"""4.44 pass, TÂCHE B2 — the gadget inventory REBUILT (the 4.40 scan was
not committed as a tool) + the minimal write-chain design.

The counts banked 4.40: 84 rets, 515 auipc in OUR plaintext booter
(bootloader.bin, VMA 0x100000, 0x6d000 B). This instrument:
  1. reproduces both counts (byte-level: ret = 0x00008067, c.ret =
     0x8082; auipc = opcode 0x17 both parities);
  2. walks the image linearly (the 4.40 method, 5,370 insns expected —
     re-counted here), and for EVERY ret site decodes the BACKWARD
     window (up to 8 insns from the nearest of 3 anchoring methods) to
     classify:
       - CHAINABLE: the gadget reloads ra from the stack (ld ra, off(sp)
         / c.ldsp ra) before the ret — the ROP chain links;
       - TERMINAL: the plain ret (the chain end / the one-shot);
  3. hunts the chain WORK-GADGETS: (a) ld a1/a0/a5, off(rx) ... ret
     (the DEREF links), (b) addi a1, a1, imm ... ret (the OFFSET
     links), (c) mv/li forms;
  4. emits the JSON inventory the findings cite.

Output: lab/jalon411/v444e_gadget_chain.json
"""
import json
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / "tools/analysis/gsp-extract/binaries/bootloader.bin"
OUT = Path(__file__).with_suffix(".json")

VMA = 0x100000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

img = BOOT.read_bytes()


def main():
    out = {}
    # -- 1. the byte-level counts (both parities for auipc — the RVC
    #       streams host 2-byte-aligned auipc encodings too)
    rets = []
    crets = []
    auipc = 0
    for o in range(0, len(img) - 4, 2):
        w4 = int.from_bytes(img[o:o + 4], "little") if o + 4 <= len(img) else 0
        if o % 4 == 0:
            if w4 == 0x00008067:
                rets.append(VMA + o)
        if w4 == 0x00008067 and o % 2 == 0:
            pass
        # the auipc opcode 0x17 — both parities
        if (w4 & 0x7F) == 0x17 and o % 4 == 0:
            auipc += 1
    for o in range(0, len(img) - 2, 2):
        w2 = int.from_bytes(img[o:o + 2], "little")
        if w2 == 0x8082:
            crets.append(VMA + o)
    # the 2-byte-parity auipc: a 4-byte word at odd-4 offsets is not
    # instruction-aligned in RVC; the honest count = the 4-aligned words
    # PLUS the words starting at any 2-byte offset whose LOW half is not
    # a valid compressed insn — approximated by counting all offsets
    auipc2 = 0
    for o in range(2, len(img) - 4, 4):
        w4 = int.from_bytes(img[o:o + 4], "little")
        if (w4 & 0x7F) == 0x17:
            auipc2 += 1
    asm = (ROOT / "tools/analysis/gsp-extract/bootloader.asm").read_text().splitlines()
    asm_auipc = sum(1 for l in asm if "\tauipc" in l or l.strip().startswith("auipc"))
    asm_ret = sum(1 for l in asm if l.strip() == "ret")
    out["bootloader_asm_counts"] = {"auipc": asm_auipc, "ret": asm_ret}
    out["counts"] = {"ret4": len(rets), "c_ret2": len(crets),
                     "rets_total": len(rets) + len(crets),
                     "auipc_parity0": auipc, "auipc_parity2": auipc2,
                     "auipc_both": auipc + auipc2}
    print(f"ret(4B)={len(rets)} c.ret(2B)={len(crets)} "
          f"total={len(rets) + len(crets)} auipc p0={auipc} "
          f"p2={auipc2} both={auipc + auipc2}")

    # -- 2. the code-region bounds: the walk = the image's executable
    #       span [0x100000, 0x100000+filesz); the 4.40's 5,370 = the
    #       objdump .text line count — the linear walk here covers the
    #       full image and the data-decoded noise is handled by the
    #       backward re-decode below.
    insns = []
    o = 0
    while o < len(img):
        try:
            ins = next(md.disasm(img[o:o + 4], VMA + o))
        except StopIteration:
            o += 2
            continue
        insns.append({"va": ins.address, "m": ins.mnemonic, "o": ins.op_str,
                      "size": ins.size, "off": o})
        o += ins.size
    out["linear_insn_count"] = len(insns)
    print(f"linear walk: {len(insns)} insns")

    byva = {i["va"]: i for i in insns}
    order = sorted(byva)

    def backward_window(va, n=8):
        """the LONGEST contiguous run of insns (<= n) ending at va,
        rebuilt by trying the 2-byte-granular start offsets from the
        deepest first (the RVC-honest backward decode; the ambiguity =
        named — the chain gadgets get re-verified in the emulator)."""
        best = []
        for back_bytes in range(n * 2, 1, -2):
            start = va - back_bytes
            if start < VMA:
                continue
            seq = []
            o2 = start - VMA
            ok = True
            while o2 < va - VMA:
                try:
                    ins = next(md.disasm(img[o2:o2 + 4], VMA + o2))
                except StopIteration:
                    ok = False
                    break
                seq.append({"va": ins.address, "m": ins.mnemonic,
                            "o": ins.op_str, "size": ins.size})
                o2 += ins.size
            if ok and o2 == va - VMA and seq:
                if len(seq) > len(best):
                    best = seq
        return best

    # -- 3. classify every ret site (the 84 c.ret + the 4-byte rets)
    chainable = []
    terminal = []
    for rva in rets + crets:
        w = backward_window(rva, 8)
        ra_load = None
        step = None
        for ins in w:
            if ins["m"] == "ld" and ins["o"].startswith("ra, "):
                ra_load = f"{ins['m']} {ins['o']}"
            if ins["m"] == "c.ldsp" and ins["o"].startswith("ra,"):
                ra_load = f"{ins['m']} {ins['o']}"
            if ins["m"] == "addi" and ins["o"].startswith("sp, sp, "):
                step = int(ins["o"].split(", ")[2], 0)
            if ins["m"] == "c.addi16sp":
                try:
                    step = int(ins["o"].split(", ")[1], 0)
                except (ValueError, IndexError):
                    pass
        entry = {"ret_va": hex(rva), "ra_load": ra_load, "sp_step": step,
                 "window": [f"0x{i2['va']:x}: {i2['m']} {i2['o']}"
                            for i2 in w]}
        if ra_load is not None:
            chainable.append(entry)
        else:
            terminal.append(entry)
    out["chainable_count"] = len(chainable)
    out["chainable"] = chainable
    out["terminal_count"] = len(terminal)

    # -- 4. the work gadgets ending in ret (the 2-byte-granular backward
    #       windows from every ret; the gadget = the tail run whose first
    #       insn performs the work)
    work = {"ld_a1": [], "ld_a0": [], "addi_a1": [], "mv_a1": [],
            "li_a1": [], "add_a1": []}
    seen_gadget = set()
    for rva in rets + crets:
        w = backward_window(rva, 6)
        if not w:
            continue
        for ins in w[:-1]:   # every insn in the tail run (before the ret)
            key = (ins["va"], rva)
            if key in seen_gadget:
                continue
            seen_gadget.add(key)
            g = f"{ins['m']} {ins['o']}"
            if ins["m"] == "ld" and ins["o"].startswith("a1, "):
                work["ld_a1"].append({"va": hex(ins["va"]),
                                      "ret": hex(rva), "g": g})
            elif ins["m"] == "ld" and ins["o"].startswith("a0, "):
                work["ld_a0"].append({"va": hex(ins["va"]),
                                      "ret": hex(rva), "g": g})
            elif ins["m"] in ("addi", "c.addi") and \
                    ins["o"].startswith("a1, a1"):
                work["addi_a1"].append({"va": hex(ins["va"]),
                                        "ret": hex(rva), "g": g})
            elif ins["m"] in ("mv", "c.mv") and ins["o"].startswith("a1, "):
                work["mv_a1"].append({"va": hex(ins["va"]),
                                      "ret": hex(rva), "g": g})
            elif ins["m"] in ("li", "c.li") and ins["o"].startswith("a1, "):
                work["li_a1"].append({"va": hex(ins["va"]),
                                      "ret": hex(rva), "g": g})
            elif ins["m"] in ("add", "c.add") and ins["o"].startswith("a1, "):
                work["add_a1"].append({"va": hex(ins["va"]),
                                       "ret": hex(rva), "g": g})
    out["work_gadgets"] = work

    OUT.write_text(json.dumps(out, indent=1))
    print(f"chainable (ra-reloading) rets: {len(chainable)}")
    print(f"terminal rets: {len(terminal)}")
    for k, v in work.items():
        print(f"work[{k}]: {len(v)}")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
