#!/usr/bin/env python3
"""
v431b_capstone_relist.py — listing capstone propre de bootloader.bin.
Le listing objdump committé (bootloader.asm) désaligne localement (sweeps
linéaires qui mordent dans les données: <unknown>, insns fantômes dans les
strings @0x103c1e+). Capstone 5.0.7 CS_ARCH_RISCV/64|C re-listing complet,
marquage des octets non décodés, sortie v431b_relist.asm + index JSON.
"""
import json
import struct
import sys
from pathlib import Path

from capstone import (
    CS_ARCH_RISCV,
    CS_MODE_RISCVC,
    CS_MODE_RISCV64,
    Cs,
)

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BIN = REPO / "tools/analysis/gsp-extract/binaries/bootloader.bin"
OUT_ASM = HERE / "v431b_relist.asm"
OUT_JSON = HERE / "v431b_relist.json"

VMA_BASE = 0x100000


def main():
    b = BIN.read_bytes()
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.detail = False

    lines = []
    decoded = bytearray(len(b))  # 1 = instruction bytes
    n_ok = 0
    n_bad = 0
    cur = 0
    while cur < len(b):
        got = False
        for sz in (4, 2):  # try 32-bit then 16-bit
            if cur + sz > len(b):
                continue
            w = b[cur + 2] if sz == 4 else None
            # 32-bit iff low 2 bits == 11
            low2 = b[cur] & 0x3
            sz_use = 4 if low2 == 0x3 else 2
            if sz_use != sz:
                continue
            try:
                ins = next(md.disasm(b[cur : cur + sz], VMA_BASE + cur))
            except StopIteration:
                continue
            lines.append(f"{ins.address:6x}: {ins.bytes.hex():10s} {ins.mnemonic}\t{ins.op_str}")
            for k in range(sz):
                decoded[cur + k] = 1
            cur += sz
            n_ok += 1
            got = True
            break
        if not got:
            lines.append(f"{VMA_BASE + cur:6x}: {b[cur:cur+2].hex():10s} .data")
            cur += 2
            n_bad += 1

    OUT_ASM.write_text("\n".join(lines) + "\n")
    n_ins = sum(1 for l in lines if ".data" not in l)
    rep = {
        "bin_len": len(b),
        "decoded_insns": n_ok,
        "data_halfwords": n_bad,
        "coverage_ins_bytes": sum(decoded),
        "sha256": __import__("hashlib").sha256(b).hexdigest(),
        "objdump_comparison": {
            "note": "objdump committé = 5370 insns parsées; capstone = re-decode indépendant",
            "capstone_total_lines": len(lines),
        },
    }
    OUT_JSON.write_text(json.dumps(rep, indent=2))
    print(f"[v431b] {OUT_ASM}: {n_ok} insns, {n_bad} data halfwords, {len(lines)} lines")
    # selftest: known ground truths
    txt = "\n".join(lines)
    checks = [
        ("crt0 auipc t0", "100000: 0006c297" in txt.replace(" ", "") or "0006c297" in txt),
        ("main sp-0x620", "addi\tsp, sp, -1568" in txt or "addi\tsp, sp, -0x620" in txt),
        ("csr 0x5d0 present", "0x5d0" in txt),
        ("satp present", "satp" in txt or "csrw\t0x180" in txt),
        ("ecall present", "ecall" in txt),
    ]
    ok = 0
    for name, v in checks:
        print(f"  selftest {name}: {'PASS' if v else 'FAIL'}")
        ok += v
    return 0 if ok == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
