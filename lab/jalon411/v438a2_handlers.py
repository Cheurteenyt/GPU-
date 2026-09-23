#!/usr/bin/env python3
"""4.38 TASK A, instrument 2 — the internal-event handlers that feed the
EDPp policy object, disassembled with the store census:

  0x2080A080 -> handler 0x16502d0 (tag 0x34 = 52 B — the worker's buffer
                size exactly; fills buf[0x10] which the worker stores into
                obj+0x660)
  0x2080A618 -> handler 0x1768bc4 (tag 0x4e20 = 20,000 B — the init-path
                call whose result region feeds the 8-dword block copy into
                obj+0x668..0x684)

For each handler: the full window (up to ~200 insns from the handler VA),
every STORE with its mem offset, every lui+addi constant pair decoded,
every rdtime, every call target. The question: WHAT value lands in
buf[0x10] / the block — a runtime field copy, a computed value, a table
load, a constant?

Output: lab/jalon411/v438a2_handlers.json
"""
import json
import re
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

STORES = {"sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp"}
CALLS = {"jal", "jalr", "c.jal", "c.jalr"}


def lui_addi_pairs(window):
    """decode lui+addi constant materializations in a window."""
    vals = []
    i = 0
    while i < len(window):
        w = window[i]
        m = re.match(r"^(\w+), (0x[0-9a-f]+)$", w["o"]) if w["m"] == "lui" else None
        if m:
            rd, hi = m.group(1), int(m.group(2), 16)
            # sign-extend 20-bit
            hv = hi if hi < 0x80000 else hi - 0x100000
            val = hv << 12
            # look ahead up to 4 insns for addi/addiw rd, rd, imm
            for j in range(i + 1, min(i + 5, len(window))):
                w2 = window[j]
                m2 = re.match(rf"^addiw?, {re.escape(rd)}, {re.escape(rd)}, (-?0x[0-9a-f]+|-?\d+)$", w2["o"])
                if m2:
                    val += int(m2.group(1), 0)
                    vals.append({"va": hex(w["va"]), "value": val & 0xFFFFFFFF,
                                 "signed": val, "rd": rd,
                                 "form": f"lui+addi @ {hex(w['va'])}+{hex(w2['va'])}"})
                    break
                # stop if rd clobbered by anything else
                if w2["m"].split()[0] not in ("nop",):
                    m3 = re.match(rf"^(\w+), ", w2["o"])
                    if m3 and m3.group(1) == rd and w2["m"] not in ("addi", "addiw"):
                        break
        i += 1
    return vals


def walk(img, off, n):
    out = []
    o = off
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append({"va": IMG_LO + o, "m": ins.mnemonic, "o": ins.op_str,
                    "size": ins.size})
        o += ins.size
    return out


def analyze(img, va, n=200, name=""):
    off = va - IMG_LO
    w = walk(img, off, n)
    stores = []
    for x in w:
        if x["m"] in STORES:
            stores.append({"va": hex(x["va"]), "m": x["m"], "o": x["o"]})
    calls = [{"va": hex(x["va"]), "m": x["m"], "o": x["o"]}
             for x in w if x["m"] in CALLS]
    rdtime = [{"va": hex(x["va"]), "m": x["m"]}
              for x in w if x["m"] == "rdtime"]
    consts = lui_addi_pairs(w)
    lines = [{"va": hex(x["va"]), "m": x["m"], "o": x["o"]} for x in w]
    return {"handler": hex(va), "name": name, "n_insns": len(w),
            "stores": stores, "calls": calls, "rdtime": rdtime,
            "constants": consts, "window": lines}


def main():
    da = A.read_bytes()
    img = da[0x40:0x40 + 0xE9B000]

    out = {
        "ev_0x2080A080": analyze(img, 0x16502D0, 260,
                                 "the 52-B buffer filler (obj+0x660 source)"),
        "ev_0x2080A618": analyze(img, 0x1768BC4, 220,
                                 "the 20000-B region filler (init block copy source)"),
        "ev_0x2080A081": analyze(img, 0x1660FA0, 120,
                                 "the sibling event (tag 0x750)"),
    }
    OUT.write_text(json.dumps(out, indent=1))

    for k, v in out.items():
        print(f"\n===== {k} {v['name']} ({v['handler']}) =====")
        print(f"insns={v['n_insns']} stores={len(v['stores'])} "
              f"calls={len(v['calls'])} rdtime={len(v['rdtime'])}")
        print("constants:", json.dumps(v["constants"]))
        print("first 60 insns:")
        for l in v["window"][:60]:
            print(f"  {l['va']}: {l['m']:<8} {l['o']}")
    print(f"\nwritten {OUT}")


if __name__ == "__main__":
    main()
