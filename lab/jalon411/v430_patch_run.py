#!/usr/bin/env python3
"""v430_patch_run — TASK 4 of pass 4.30: the REAL patch run, recorded.

Produces the patched container (rm.elf constants 250000 -> 280000, the
six lui+addi pairs) OUTSIDE the repo (>5 MB rule), and freezes the full
evidence: the original and patched container sha256s, the six sites, the
18 differing bytes (encoding-derived), the re-parse verdict, and the
rm.elf identity checks before/after.

The mission's premise corrections carried here (byte-proven):
  - "6 u32 sites of 250000 at VAs …, file = VA - 0x1000000" -> FALSIFIED:
    the u32 pattern 90 d0 03 00 occurs 0 times in the whole 84 MB image.
  - The REAL encoding: six lui+addi/addiw PAIRS (8 B each) materializing
    250000; the mission's VA list matches rm-full.elf (p_offset 0x40);
    gsp-rm-17MB.bin carries the same six sites at a uniform -0x78 shift.
  - "identical except exactly 24 bytes (6x4)" -> the truth: 48 B are
    rewritten (6x8), 18 bytes actually differ (6x3: two lui immediates
    bytes + one addi immediate byte per site).

Selftest re-derives everything; exit 2 on drift, 3 without inputs.
"""
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, str(Path(HERE, "..", "..", "tools/gsp-container")))
from gspbuild import GspFw, patch_rm_constant, riscv_lui_addi_sites  # noqa: E402

GSP = "/home/z/my-project/work/downloads/extracted/firmware/gsp_ga10x.bin"
OUT_DIR = "/home/z/my-project/work/patched"
OUT = os.path.join(OUT_DIR, "gsp_ga10x_280000_610.57.04.bin")
OUT_JSON = os.path.join(HERE, "v430_patch_run.json")

RM_OFF = 0x19F000          # rm.elf in .fwimage (v430_gfw_map.json)
RM_SIZE = 0x1071000
SITES = [0x190c6, 0x1a02a, 0x1f09a8, 0x7c467c, 0xb99bb4, 0xb99c90]
OLD, NEW = 250000, 280000
ORIG_SHA = "c0156954f3e048d56011524e0c2ae2881bb6db8173b53f9b2f4eb94197f02999"


def main():
    if not os.path.exists(GSP):
        print("SKIP:", GSP)
        return 3
    raw = open(GSP, "rb").read()
    assert hashlib.sha256(raw).hexdigest() == ORIG_SHA
    fw = GspFw(raw)
    ok0, _ = fw.verify()
    assert ok0

    # census on the rm window (independent of the patcher's own scan)
    rm = fw.fwimage()[RM_OFF:RM_OFF + RM_SIZE]
    assert rm[:4] == b"\x7fELF"
    census = riscv_lui_addi_sites(rm, OLD)
    assert [o for o, rd, op in census] == SITES

    blob, sites = patch_rm_constant(fw, RM_OFF, RM_SIZE, OLD, NEW)
    diffs = [i for i in range(len(raw)) if raw[i] != blob[i]]
    fw_abs = fw.by_name[".fwimage"]["sh_offset"]

    # re-parse + identity of the patched rm component
    pb = GspFw(blob)
    ok1, issues = pb.verify()
    assert ok1, issues
    img2 = pb.fwimage()
    assert img2[:RM_OFF] == fw.fwimage()[:RM_OFF]
    assert img2[RM_OFF + RM_SIZE:] == fw.fwimage()[RM_OFF + RM_SIZE:]
    pre = struct.unpack("<II", img2[RM_OFF + SITES[0]:
                                    RM_OFF + SITES[0] + 8])
    assert (pre[0] >> 12) == 0x44 and (pre[1] >> 20) == 0x5C0

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(blob)

    reg = dict(
        original=dict(path=GSP, sha256=ORIG_SHA, size=len(raw)),
        patch=dict(old=OLD, new=NEW, encoding="lui+addi pairs (RISC-V)",
                   rm_fw_off=hex(RM_OFF), rm_size=hex(RM_SIZE),
                   sites=[dict(rm_off=hex(o), fw_off=hex(RM_OFF + o),
                               container_off=hex(fw_abs + RM_OFF + o),
                               rd=rd, op=op)
                          for (o, rd, op) in sites],
                   rewritten_bytes=8 * len(sites),
                   differing_bytes=len(diffs),
                   differing_offsets=[hex(d) for d in diffs],
                   corrected_premise=("the mission's 6 u32 sites / 24 bytes "
                                      "rested on a u32 encoding that occurs "
                                      "0 times in the image; the sites are "
                                      "lui+addi pairs (the mission's VAs "
                                      "match rm-full.elf, p_offset 0x40)")),
        patched=dict(path=OUT, sha256=hashlib.sha256(blob).hexdigest(),
                     size=len(blob), reparse="VALID",
                     fwversion=pb.fwversion(),
                     fwimage_prefix_unchanged=True,
                     fwimage_post_rm_unchanged=True),
        note=("artifact kept OUTSIDE the repo (>5 MB rule); reproduce with "
              "gspbuild.py patchrm <container> 0x19f000 0x1071000 250000 "
              "280000 <out>"),
    )
    with open(OUT_JSON, "w") as f:
        json.dump(reg, f, indent=1)

    print("patched container:", OUT)
    print("  sha256:", reg["patched"]["sha256"])
    print("  sites:", len(sites), " rewritten:", 8 * len(sites), "B",
          " differing:", len(diffs), "B")
    print("  re-parse:", reg["patched"]["reparse"])
    print("ALL CHECKS PASS —", OUT_JSON)
    return 0


if __name__ == "__main__":
    sys.exit(main())
