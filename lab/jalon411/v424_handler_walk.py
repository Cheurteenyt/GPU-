#!/usr/bin/env python3
"""4.24 pass I-b — the 0x2080d031 handler walk.

The dispatch table (4.20) binds cmd 0x2080d031 -> handler 0x11267fc
(boundary-verified), tag = 0x608 = 1544 = the EXACT paramsSize of the
captured 1616-byte payload. This walk disassembles the handler from
rm-full.elf and annotates:
  - the constants formed (lui/addi/c.lui) — hunting 0x608, 0x40 (the
    250000 offset), power-scale immediates;
  - every load/store on the params pointer (which arg register carries
    it — the GSP-RM control convention: a1 = pParams after a0 = pGpu-ish
    state, verified per-site, not assumed);
  - the page-5 / -0x168 idiom (the EDPp policy object, 4.20).

Output: lab/jalon411/v424_handler_walk.json + stdout listing.
"""
import json
import struct

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ELF = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/rm-full.elf"
IMG_LO = 0x1000000
HANDLER = 0x11267fc
N_INSN = 400
OUT = "/home/z/my-project/work/gpu-repo/lab/jalon411/v424_handler_walk.json"


def load_image():
    d = open(ELF, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    phentsize = struct.unpack_from("<H", d, 54)[0]
    phnum = struct.unpack_from("<H", d, 56)[0]
    for i in range(phnum):
        o = e_phoff + i * phentsize
        if struct.unpack_from("<I", d, o)[0] == 1:  # PT_LOAD
            p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
            if p_filesz == p_memsz:
                return d[p_off:p_off + p_filesz], p_vaddr
    raise SystemExit("no PT_LOAD")


def main():
    img, vaddr_base = load_image()
    img_lo = vaddr_base
    hoff = HANDLER - img_lo
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.detail = True

    listing = []
    reg_val = {}  # the constant-tracker: rd -> (value, by)
    interesting = []
    off = hoff

    # the entry insn: capstone's 32-bit-first strategy cannot decode the
    # 2-byte prologue alone (the 4.16 map: 0x11267fc NOT seen, 0x11267fe
    # seen — the recursive descent arrived by fall-through). Manual:
    # 0xd227 = c.swsp rs2=x9(s1), imm=36(sp) — a standard prologue store.
    listing.append(f"{HANDLER:08x}  c.swsp   s1, 36(sp)   [MANUAL: capstone 4-byte-first skips it; bytes 27 d2]")
    off = hoff + 2  # walk from the verified start 0x11267fe
    for i in range(N_INSN):
        try:
            ins = next(md.disasm(img[off:off + 4], img_lo + off))
        except StopIteration:
            break
        note = ""
        m, ops = ins.mnemonic, ins.op_str

        # the constant formation tracker
        if m in ("lui", "c.lui") and "," in ops:
            rd, imm = ops.split(", ")
            try:
                v = int(imm, 0) << 12
                # riscv lui sign-extends the 20-bit field already handled by capstone's signed imm
                reg_val[rd] = (v, f"{m} {ops} @{HANDLER + off - hoff:#x}")
            except ValueError:
                pass
        elif m in ("addi", "c.add", "add", "c.li", "li") and "," in ops:
            parts = [p.strip() for p in ops.split(",")]
            rd = parts[0]
            if m in ("li", "c.li") and len(parts) == 2:
                try:
                    reg_val[rd] = (int(parts[1], 0), f"li {ops}")
                except ValueError:
                    pass
            elif len(parts) == 3 and parts[1] in reg_val:
                try:
                    imm = int(parts[2], 0)
                    v = (reg_val[parts[1]][0] + imm) & 0xFFFFFFFFFFFFFFFF
                    reg_val[rd] = (v, f"{reg_val[parts[1]][1]} ; {m} {ops}")
                    if v in (0x608, 0x3D090, 0x3A980, 0x186A0, 0x40, 0x38, 0x8, 0x24, 0x28):
                        note = f"  <<< const {v:#x} (from: {reg_val[rd][1]})"
                        interesting.append({"va": hex(img_lo + off), "note": note.strip()})
                except ValueError:
                    pass

        # the memory ops on candidate base regs
        if m in ("ld", "lw", "lbu", "lhu", "sd", "sw", "sb", "sh") and "(" in ops:
            base = ops.split("(")[1].rstrip(")")
            try:
                disp = int(ops.split("(")[0].replace(" ", ""), 16) if ops.split("(")[0].strip().startswith("0x") else int(ops.split("(")[0].strip())
            except ValueError:
                disp = None
            if disp is not None:
                note += f"   [base={base} disp={disp:#x}]"
                if base in ("a1", "a2", "a3", "s1", "s2", "s3", "s4", "s5", "s6"):
                    interesting.append({"va": hex(img_lo + off), "insn": f"{m} {ops}",
                                        "base": base, "disp": disp})

        listing.append(f"{img_lo + off:08x}  {m:<8s} {ops}{note}")
        off += ins.size

    json.dump({"handler": hex(HANDLER), "img_lo": hex(img_lo),
               "insns_disassembled": len(listing),
               "interesting": interesting,
               "listing": listing},
              open(OUT, "w"), indent=1)
    print("\n".join(listing[:220]))
    print(f"\n>>> {len(listing)} insns -> {OUT}")


if __name__ == "__main__":
    main()
