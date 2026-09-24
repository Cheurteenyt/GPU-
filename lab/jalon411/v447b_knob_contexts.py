#!/usr/bin/env python3
"""4.47 TASK B — the knob contexts: what the bandwidth levers feed.

Reads v447a_clkknobs.json and, for the high-value knobs, banks the
CONTEXT evidence:

  1. the disassembly window (10 insns forward from each auipc) for
     RmClkMclkProg, RMClkVfOverride, RML2MaxWaysSysmem (all xrefs),
     RMUseTc0NonCoherent (first 2), RmDisableDecompOnlyLce (first 2),
     RmOptp2LowerMclk — the call the name is passed to, and the value
     the load feeds;
  2. the MCLK_LIMIT pointer-table neighborhood: 0x80 bytes around the
     u64 site, rendered as u64s and as ASCII — the {name-ptr, ...}
     record shape and its siblings (the 4.35 RmVgpcSkyline shape);
  3. the DRAMCLK probe at threshold 4 (the v447a census missed the
     7-char name at the >= 8 threshold — closed here).

Selftests: the law (512 windows); the v447a JSON exists and carries
the expected card names.

Output: lab/jalon411/v447b_knob_contexts.json
"""
import json
import struct
import zlib
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
IN = Path(__file__).with_name("v447a_clkknobs.json")
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

WINDOWS = {
    "RmClkMclkProg": 8,
    "RMClkVfOverride": 8,
    "RML2MaxWaysSysmem": 8,
    "RMUseTc0NonCoherent": 2,
    "RmDisableDecompOnlyLce": 2,
    "RmOptp2LowerMclk": 8,
}


def disasm_window(img, aoff, n=10):
    lines = []
    off = aoff
    for _ in range(n):
        if off + 2 > len(img):
            break
        if img[off] & 3 == 3:
            ins = next(md.disasm(img[off:off + 4], off), None)
            size = 4
        else:
            ins = next(md.disasm(img[off:off + 2], off), None)
            size = 2
        if ins is None:
            lines.append(f"0x{IMG_LO + off:x}: <invalid>")
            break
        lines.append(f"0x{IMG_LO + off:x}: {ins.mnemonic:<8} {ins.op_str}")
        off += size
    return lines


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    assert len(blob) > 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        assert a_img[o:o + 16] == db[o - 0x38:o - 0x38 + 16]

    a447 = json.loads(IN.read_text())
    names = {c["name"] for c in a447["cards"]}
    for w in WINDOWS:
        assert w in names, f"{w} missing from v447a"

    out = {"pass": "4.47", "task": "B", "instrument": "v447b_knob_contexts"}

    # -- 1. the xref disassembly windows
    ctx = []
    for c in a447["cards"]:
        if c["name"] not in WINDOWS:
            continue
        take = WINDOWS[c["name"]]
        for site in c["sites"]:
            for x in site.get("xref_sites", [])[:take]:
                auipc_va = int(x["auipc_va"], 16)
                aoff = auipc_va - IMG_LO
                ctx.append({
                    "name": c["name"],
                    "auipc_va": x["auipc_va"],
                    "rd": x["rd"],
                    "window": disasm_window(a_img, aoff, 10),
                })
    out["xref_windows"] = ctx
    for e in ctx:
        print(f"[ctx] {e['name']} @ {e['auipc_va']} "
              f"({e['window'][0].split(': ', 1)[-1]})")

    # -- 2. the MCLK_LIMIT pointer-table neighborhood
    mclk = next(c for c in a447["cards"] if c["name"] == "MCLK_LIMIT")
    hood = []
    for site in mclk["sites"]:
        va = site["va"]
        for foff_hex in [site["foff"]]:
            pass
    # re-derive: the ptr site = the file offset whose u64 == the VA
    for site in mclk["sites"]:
        va = int(site["va"], 16)
        pat = struct.pack("<Q", va)
        start = 0
        while True:
            j = db.find(pat, start)
            if j < 0:
                break
            lo = max(0, j - 0x40)
            hi = min(len(db), j + 0x48)
            chunk = db[lo:hi]
            u64s = [struct.unpack_from("<Q", chunk, k)[0]
                    for k in range(0, len(chunk) - 7, 8)]
            ascii_txt = "".join(chr(b) if 0x20 <= b < 0x7f else "."
                                for b in chunk)
            hood.append({
                "ptr_foff": hex(j), "va": hex(va),
                "neighbors_u64": [hex(u) for u in u64s],
                "ascii": ascii_txt,
            })
            start = j + 1
    out["mclk_limit_ptr_hoods"] = hood
    for h in hood:
        print(f"[hood] ptr @ {h['ptr_foff']} ascii={h['ascii'][:80]}")

    # -- 3. the DRAMCLK probe (threshold 4)
    import re
    pat = re.compile(rb"[\x20-\x7e]{4,}")
    hits = []
    for m in pat.finditer(db):
        i = m.group().find(b"DRAMCLK")
        if i >= 0:
            hits.append({"foff": hex(m.start() + i),
                         "run": m.group().decode("ascii", "replace")[:60]})
    out["dramclk_probe"] = hits
    print(f"[probe] DRAMCLK: {len(hits)} hits at threshold 4")

    out["selftests"] = {"law_512": "PASS",
                        "v447a_cards_present": True}
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
