#!/usr/bin/env python3
"""xref-dials — localise les strings des dials clés dans rm.elf (driver 580.178.04),
scanne le texte RISC-V pour les paires auipc/addi qui référencent ces VAs,
et sauve des fenêtres de désassemblage autour de chaque site d'appel.

Layout rm.elf : PH0 text R+E file 0x0..0xe85000 @ VA 0x1000000
                PH1 data RW  file 0xe85000..0x1021000 @ VA 0x4000000
"""
import struct
import sys
from pathlib import Path

import capstone

RM = Path("gsp-rm-17MB.bin")
OUT = Path("xrefs")
OUT.mkdir(exist_ok=True)

TEXT_OFF, TEXT_VA, TEXT_SZ = 0x0, 0x1000000, 0xE85000
DATA_OFF, DATA_VA, DATA_SZ = 0xE85000, 0x4000000, 0x19C000

KEY_DIALS = [
    "RmPerfLimitsOverride",
    "RmSramVminCheckIgnore",
    "RmVoltThresholdCtrlCtrl",
    "RMDisablePerfIntersect",
    "RMClkVfOverride",
    "RmPerfCfOverride",
    "RmBootGspRmWithBoostClocks",
    "CUSTOMER_BOOST_MAX",
    "RMEnablePowerSupplyCapacity",
    "RMPowerSupplyCapacity",
    "RmPerfRatedTdpLimit",
    "RMEnableOverclockingAllPstates",
    "RMOverrideVfsConfig",
    "RmClkControllersOverride",
    "RMExtPerfControl",
    "RMPriorityBoost",
    "RMProgrammableClkMask",
]

def off_to_va(off: int) -> int:
    if off < TEXT_SZ:
        return TEXT_VA + off
    return DATA_VA + (off - DATA_OFF)

def va_to_off(va: int):
    if TEXT_VA <= va < TEXT_VA + TEXT_SZ:
        return va - TEXT_VA
    if DATA_VA <= va < DATA_VA + DATA_SZ:
        return DATA_OFF + (va - DATA_VA)
    return None

def main():
    rm = RM.read_bytes()

    # 1) localiser les strings (NUL-terminées) dans toute l'image
    targets = {}
    for dial in KEY_DIALS:
        needle = dial.encode() + b"\x00"
        pos = rm.find(needle)
        if pos < 0:
            print(f"!! {dial} : ABSENT du driver image")
            continue
        targets[dial] = off_to_va(pos)
        print(f"{dial:<32} VA {off_to_va(pos):#x} (file {pos:#x})")

    # 2) scanner le texte : auipc (0x17) puis addi sur le même rd dans la fenêtre
    md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 |
                     capstone.CS_MODE_RISCVC)
    md.detail = True

    text = rm[:TEXT_SZ]
    results = {d: [] for d in targets}
    n = len(text)
    # pré-scan des auipc
    auips = []
    for off in range(0, n - 8, 2):
        w = struct.unpack_from("<I", text, off)[0]
        if (w & 0x7F) == 0x17:  # AUIPC
            rd = (w >> 7) & 0x1F
            imm20 = (w >> 12) & 0xFFFFF
            if imm20 & 0x80000:
                imm20 -= 1 << 20
            auips.append((off, rd, imm20))

    print(f"\nauipc scannés : {len(auips)}")

    # pour chaque auipc, regarder les quelques instructions suivantes (C-ext 2/4 bytes)
    for off, rd, imm20 in auips:
        hi = off + (imm20 << 12)  # page base (file offset ≈ VA-TEXT_VA)
        for lookahead in range(2, 30, 2):
            lo_off = off + lookahead
            if lo_off + 4 > n:
                break
            w2 = struct.unpack_from("<I", text, lo_off)[0]
            op = w2 & 0x7F
            if op == 0x13 and ((w2 >> 7) & 0x1F) == rd:  # ADDI rd, rd, lo12
                lo = (w2 >> 20) & 0xFFF
                if lo & 0x800:
                    lo -= 1 << 12
                target_file = hi + lo
                target_va = target_file + TEXT_VA if target_file < TEXT_SZ else None
                for dial, sva in targets.items():
                    if target_va == sva:
                        results[dial].append((off, lo_off))
    print()
    for dial, sites in results.items():
        va = targets.get(dial)
        print(f"{dial:<32} VA {va:#x} — xrefs: {len(sites)}")
        for site, addi in sites[:6]:
            print(f"    auipc @{site+TEXT_VA:#x}  addi @{addi+TEXT_VA:#x}")

    # 3) fenêtres de désassemblage autour des sites les plus intéressants
    for dial, sites in results.items():
        if not sites:
            continue
        fname = OUT / f"disasm-{dial}.txt"
        with open(fname, "w") as fh:
            for site, addi in sites[:6]:
                start = max(0, site - 0x180)
                end = min(n, addi + 0x300)
                fh.write(f"=== {dial} — fenêtre {start+TEXT_VA:#x} .. {end+TEXT_VA:#x} ===\n")
                code = text[start:end]
                for ins in md.disasm(code, start + TEXT_VA):
                    fh.write(f"{ins.address:#x}:  {ins.mnemonic:<10} {ins.op_str}\n")
                fh.write("\n")
        print(f"[{fname.name} écrit — {len(sites)} site(s)]")

if __name__ == "__main__":
    main()
