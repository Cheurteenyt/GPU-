#!/usr/bin/env python3
"""4.24 pass I-d — the pA glue 0x1c23870: the common dispatch family
descriptor shared by all 1,156 entries (4.20). If it is code, it shows
the handler calling convention (what a4/a5 hold at handler entry, where
the params pointer goes) — the missing piece for the 0x2080d031 reading.
"""
import struct

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ELF = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/rm-full.elf"
IMG_LO = 0x1000000
PA = 0x1C23870


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


def main():
    img, img_lo = load_image()
    off = PA - img_lo
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    print(f"=== 0x{PA:x} — first 90 decoded (linear; may desync on data) ===")
    n = 0
    while n < 90:
        try:
            ins = next(md.disasm(img[off:off + 4], img_lo + off))
        except StopIteration:
            break
        print(f"{img_lo + off:08x}  {ins.mnemonic:<8s} {ins.op_str}")
        off += ins.size
        n += 1


if __name__ == "__main__":
    main()
