#!/usr/bin/env python3
"""4.44 pass, TÂCHE A2/B1 — the allocator descriptors 0x4190DC0/0x4190DE8:
file-backed? seed-bearing? and the allocator semantics.

The chain (4.43 §2.2 + the 4.44a discovery): the creation window
@0x1458cf8 AND the evaluator's far phases (0x14471bc..0x1447e94, 21+
sites) all call 0x18C373C/0x18C3734/0x18C3F80 with these two
descriptors. The mission asks: are the descriptors FILE-BACKED (the
voie-descriptor = patch the descriptors before the allocation so the
object is BORN with 280), and does the allocator copy any VALUE bytes
from them?

Steps:
  1. parse the container gsp-rm-17MB.bin phdrs (the 4.43 §1.2 method),
     locate the LOAD covering 0x4190DC0/0x4190DE8, compute the file
     offsets, dump 0x80 bytes of each descriptor;
  2. decode the allocator 0x18C373C (and 0x18C3734/0x18C3F80 heads):
     what it reads from a0 (the descriptor) — metadata (size/tag) vs
     VALUE bytes copied into the object;
  3. re-cite the creation-window memset (the object born ZEROED);
  4. the s7 cell @0x4190FA0 (the evaluator's tail xor-check) dumped.

Self-checks: the law 512/512; the auipc census 416,206.

Output: lab/jalon411/v444b_descriptors.json
"""
import json
import struct
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

img = A.read_bytes()[0x40:0x40 + 0xE9B000]
container = B.read_bytes()


def dec(va, n):
    o = va - IMG_LO
    out = []
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append({"va": f"0x{IMG_LO + o:x}", "m": ins.mnemonic,
                    "o": ins.op_str, "size": ins.size})
        o += ins.size
    return out


def main():
    out = {}
    # -- 0. the law + the census
    import numpy as np
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        k = np.arange((len(img4) - 4 - base_off) >> 2, dtype=np.int64)
        cnt += int(((uarr[k] & 0x7F) == 0x17).sum())
    assert cnt == 416206
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        assert img[o:o + 16] == container[o - 0x38:o - 0x38 + 16]
    out["selfchecks"] = {"auipc": cnt, "law_fails": 0}

    # -- 1. the container phdrs (ELF64)
    assert container[:4] == b"\x7fELF"
    e_phoff = struct.unpack_from("<Q", container, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", container, 0x36)[0]
    e_phnum = struct.unpack_from("<H", container, 0x38)[0]
    phdrs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, \
            p_align = struct.unpack_from("<IIQQQQQQ", container, o)
        phdrs.append({"type": p_type, "off": p_off, "vaddr": p_vaddr,
                      "filesz": p_filesz, "memsz": p_memsz})
    out["container_phdrs"] = phdrs

    def file_off_for(va):
        for p in phdrs:
            if p["type"] == 1 and p["vaddr"] <= va < p["vaddr"] + p["filesz"]:
                return p["off"] + (va - p["vaddr"]), p
        return None, None

    descs = {}
    for name, va in (("desc_0x4190DC0", 0x4190DC0),
                     ("desc_0x4190DE8", 0x4190DE8),
                     ("tail_cell_0x4190FA0", 0x4190FA0)):
        fo, p = file_off_for(va)
        if fo is None:
            descs[name] = {"va": hex(va), "file_backed": False}
            continue
        raw = container[fo:fo + 0x80]
        u32 = [int.from_bytes(raw[4 * i:4 * i + 4], "little")
               for i in range(0x80 // 4)]
        u64 = [int.from_bytes(raw[8 * i:8 * i + 8], "little")
               for i in range(0x80 // 8)]
        descs[name] = {"va": hex(va), "file_backed": True,
                       "phdr": {k2: (hex(v) if isinstance(v, int) else v)
                                for k2, v in p.items()},
                       "file_off": hex(fo), "hex80": raw.hex(),
                       "u32x32": [f"0x{x:08x}" for x in u32],
                       "u64x16": [f"0x{x:016x}" for x in u64]}
    out["descriptors"] = descs

    # -- 2. the allocators decoded (the head windows)
    out["alloc_18C373C_head"] = dec(0x18C373C, 90)
    out["alloc_18C3734_head"] = dec(0x18C3734, 12)
    out["alloc_18C3F80_head"] = dec(0x18C3F80, 40)

    # -- 3. the creation window (the memset proof) re-cited
    out["creation_window"] = dec(0x1458cec, 20)

    # -- 4. the two phase-3 allocation sites with their a1 args
    out["phase3_site_14471bc"] = dec(0x14471ba, 14)
    out["phase3_site_1447282"] = dec(0x144727c, 16)

    OUT.write_text(json.dumps(out, indent=1))
    for n2, d in descs.items():
        if d.get("file_backed"):
            print(f"{n2}: file-backed @container+{d['file_off']} "
                  f"u64x4={[u for u in d['u64x16'][:4]]}")
        else:
            print(f"{n2}: NOT file-backed")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
