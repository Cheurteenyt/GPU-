#!/usr/bin/env python3
"""4.24 pass I-c — the dispatch table raw-entry calibration + the tail
continuation of the 0x2080d031 handler.

1. Raw 0x20-byte entries for 0x20800afd (GET_EDPP — handler confirmed in
   4.20), 0x20800ad0 (UPDATE_EDPP — stub per 4.20) and 0x2080d031 (this
   payload's cmd) — byte-exact, so the handler field reading is calibrated
   against KNOWN-GOOD entries, not assumed.
2. The 0x11266be continuation (the c.j -0x168 target) disassembled.
3. The 0x1458bec GET_EDPP handler prologue for the convention check.
"""
import struct

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ELF = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/rm-full.elf"
IMG_LO = 0x1000000
TABLE = 0x1C183B8
N_ENTRIES = 1156
STRIDE = 0x20


def load_image():
    d = open(ELF, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    phentsize = struct.unpack_from("<H", d, 54)[0]
    for i in range(struct.unpack_from("<H", d, 56)[0]):
        o = e_phoff + i * phentsize
        if struct.unpack_from("<I", d, o)[0] == 1:
            p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
            if p_filesz == p_memsz:
                return d[p_off:p_off + p_filesz], p_vaddr
    raise SystemExit("no PT_LOAD")


def disasm(img, img_lo, va, n, skip_manual=None):
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    out, off = [], va - img_lo
    if skip_manual:
        out.append(f"{va:#x}  {skip_manual}")
        off += 2
        va = img_lo + off
    for _ in range(n):
        try:
            ins = next(md.disasm(img[off:off + 4], img_lo + off))
        except StopIteration:
            break
        out.append(f"{img_lo + off:08x}  {ins.mnemonic:<8s} {ins.op_str}")
        off += ins.size
    return out


def main():
    img, img_lo = load_image()
    t_off = TABLE - img_lo
    want = {0x20800AFD: "GET_EDPP_LIMIT_INFO (the 4.20-confirmed handler)",
            0x20800AD0: "UPDATE_EDPP_LIMIT (the 4.20 stub)",
            0x2080D031: "THIS PAYLOAD'S CMD"}
    for idx in range(N_ENTRIES):
        o = t_off + idx * STRIDE
        cid = struct.unpack_from("<I", img, o)[0]
        if cid in want:
            tag = struct.unpack_from("<I", img, o + 4)[0]
            pA = struct.unpack_from("<Q", img, o + 8)[0]
            handler = struct.unpack_from("<Q", img, o + 0x10)[0]
            sz0, sz1 = struct.unpack_from("<II", img, o + 0x18)
            print(f"=== entry[{idx}] {want[cid]}")
            print(f"    raw = {img[o:o+0x20].hex()}")
            print(f"    id={cid:#x} tag={tag:#x} pA={pA:#x} handler={handler:#x} sz0={sz0:#x} sz1={sz1:#x}")
            if cid == 0x2080D031:
                print("\n=== the 0x11266be continuation (c.j -0x168 target) ===")
                print("\n".join(disasm(img, img_lo, 0x11266BE, 70)))
    print("\n=== the 0x1458bec GET_EDPP handler prologue (the convention calibration) ===")
    print("\n".join(disasm(img, img_lo, 0x1458BEC, 14, skip_manual=None)))


if __name__ == "__main__":
    main()
