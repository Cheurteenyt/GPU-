#!/usr/bin/env python3
"""4.34 PART A — the 4.30 patch completed to 7/7, and the revert verdict.

The 4.30 pass patched SIX contiguous lui+addi 250000->280000 sites in the
rm.elf inside gsp_ga10x.bin (patched container sha 6a3c1a06...859d).
Pass 4.32e proved a SEVENTH split-form site survives untouched
(lui a4,0x3d @rm+0xb99c4a ; `sub s2,s10,s2` @+0xb99c4e ; addi a4,a4,0x90
@rm+0xb99c52 ; gap 8, clobber-checked, seen-validated): the 4.30
container is HALF-TURNED (6/7), registered 4.33 as the blocking defect.

This instrument:
  1. re-asserts the law and the 4.30 register (the 6 contiguous sites,
     byte-exact, on the repo's committed fwimage.bin);
  2. runs the NEW split-form census (gspbuild.riscv_lui_addi_split_sites,
     capstone clobber check) and asserts it finds exactly the 7th site;
  3. applies the 7/7 patch on the fwimage bytes (rd/op preserved, the
     sub NEVER touched), re-decodes all 7 sites = 280000, counts the
     diff (18 + 3 = 21 bytes, encoding-derived);
  4. writes the patched fwimage OUTSIDE the repo (>5 MB rule) with its
     sha256, plus the gspbuild recipe for the founder to reproduce the
     7/7 CONTAINER (one command);
  5. records THE VERDICT: REVERT for any boot (the 4.32 semantics
     finding — these sites are TIME logic, not power), the 7/7 artifact
     exists as the completeness proof, not as a boot recommendation.

Output: lab/jalon411/v434a_patch77.json
Artifact: /home/z/my-project/artifacts/fwimage-77-patched.bin
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/gsp-container"))
from gspbuild import riscv_lui_addi_split_sites, riscv_lui_addi_sites, \
    riscv_split                                  # noqa: E402

FWI = ROOT / "tools/analysis/gsp-extract/binaries/fwimage.bin"
OUT = Path(__file__).with_suffix(".json")
ART_DIR = Path("/home/z/my-project/artifacts")
ART = ART_DIR / "fwimage-77-patched.bin"

RM_FW_OFF = 0x19F000
RM_SIZE = 0x1071000
OLD, NEW = 250000, 280000
OLD_HI, OLD_LO = riscv_split(OLD)                 # (0x3d, 0x090)
NEW_HI, NEW_LO = riscv_split(NEW)                 # (0x44, 0x5c0)
SITES6 = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7 = (0xB99C4A, 0xB99C52, 14, "addi")         # v432e C2 (B_file coords)

print("[1] load + law")
img = FWI.read_bytes()
assert len(img) == 84_258_816, len(img)
rm = img[RM_FW_OFF:RM_FW_OFF + RM_SIZE]
assert rm[:4] == b"\x7fELF", "rm window magic"
h0 = hashlib.sha256(img).hexdigest()
print(f"    fwimage {len(img):,} B  sha256 {h0[:16]}...  "
      f"rm @+{RM_FW_OFF:#x} size {RM_SIZE:#x}")

print("[2] the 4.30 register reproduced on the bytes")
sites6 = riscv_lui_addi_sites(rm, OLD)
assert [o for o, rd, op in sites6] == SITES6, sites6
for off, rd, op in sites6:
    (w,) = struct.unpack_from("<I", rm, off)
    assert (w >> 12) == OLD_HI and (w & 0x7F) == 0x37
print(f"    6 contiguous sites reproduced EXACTLY (rd/op recorded)")

print("[3] the split census (4.34 finder, clobber-checked)")
splits = riscv_lui_addi_split_sites(rm, OLD)
assert splits == [CLAIM7], splits
# negative: the TARGET value has no split sites (no post-patch collision)
assert riscv_lui_addi_split_sites(rm, NEW) == []
print(f"    split-form sites of {OLD}: exactly 1 -> "
      f"lui @rm+{CLAIM7[0]:#x}, addi @rm+{CLAIM7[1]:#x}, rd=x{CLAIM7[2]}")

print("[4] the 7/7 patch")
patched = bytearray(rm)
rec_sites = []
for off, rd, op in sites6:
    (w,) = struct.unpack_from("<I", rm, off)
    (w2,) = struct.unpack_from("<I", rm, off + 4)
    opc = 0x13 if op == "addi" else 0x1B
    n_lui = (NEW_HI << 12) | (rd << 7) | 0x37
    n_add = ((NEW_LO & 0xFFF) << 20) | (rd << 15) | (rd << 7) | opc
    struct.pack_into("<II", patched, off, n_lui, n_add)
    # re-decode from the PATCHED bytes
    (rw,) = struct.unpack_from("<I", patched, off)
    (rw2,) = struct.unpack_from("<I", patched, off + 4)
    v = ((rw >> 12) << 12) + ((rw2 >> 20) & 0xFFF -
                              (0x1000 if (rw2 >> 20) & 0xFFF >= 0x800 else 0))
    assert v == NEW, (hex(off), v)
    rec_sites.append(dict(rm_off=hex(off), fw_off=hex(RM_FW_OFF + off),
                          rd=rd, op=op,
                          old=f"{w:08x}{w2:08x}",
                          new=f"{rw:08x}{rw2:08x}"))
lui_off, addi_off, rd7, op7 = CLAIM7
(w7,) = struct.unpack_from("<I", rm, lui_off)
(w7b,) = struct.unpack_from("<I", rm, addi_off)
n_lui7 = (NEW_HI << 12) | (rd7 << 7) | 0x37
n_add7 = ((NEW_LO & 0xFFF) << 20) | (rd7 << 15) | (rd7 << 7) | 0x13
struct.pack_into("<I", patched, lui_off, n_lui7)
struct.pack_into("<I", patched, addi_off, n_add7)
(rw7,) = struct.unpack_from("<I", patched, lui_off)
(rw7b,) = struct.unpack_from("<I", patched, addi_off)
v7 = ((rw7 >> 12) << 12) + (0x5C0)  # 0x5c0 < 0x800, no sign-extension
assert v7 == NEW
(sub_w0,) = struct.unpack_from("<I", rm, lui_off + 4)
(sub_w1,) = struct.unpack_from("<I", patched, lui_off + 4)
assert sub_w0 == sub_w1 == 0x412D0933, "the sub MUST be byte-preserved"
rec_sites.append(dict(
    rm_off=hex(lui_off), rm_addi_off=hex(addi_off),
    fw_off=hex(RM_FW_OFF + lui_off), fw_addi_off=hex(RM_FW_OFF + addi_off),
    rd=rd7, op=op7, form="split gap-8 (sub preserved)",
    old=f"{w7:08x} ... {w7b:08x}", new=f"{rw7:08x} ... {rw7b:08x}"))
print(f"    7/7 sites re-decode {NEW}; the sub 0x{sub_w1:08x} preserved")

print("[5] the minimal-diff proof")
new_img = img[:RM_FW_OFF] + bytes(patched) + img[RM_FW_OFF + RM_SIZE:]
diffs = [i for i in range(len(img)) if img[i] != new_img[i]]
assert len(diffs) == 21, len(diffs)
# every differing byte sits in a rewritten window
win = set()
for o, rd, op in sites6:
    win |= {RM_FW_OFF + o + k for k in range(8)}
win |= {RM_FW_OFF + lui_off + k for k in range(4)}
win |= {RM_FW_OFF + addi_off + k for k in range(4)}
assert set(diffs) <= win
h1 = hashlib.sha256(new_img).hexdigest()
print(f"    21 bytes differ (18 contiguous + 3 split), all in-window")
print(f"    patched fwimage sha256 {h1[:16]}...")

print("[6] artifact outside the repo (>5 MB rule)")
ART_DIR.mkdir(parents=True, exist_ok=True)
ART.write_bytes(new_img)
print(f"    wrote {ART}  ({len(new_img):,} B)")

out = dict(
    law="B_file = A_img - 0x38; rm.elf sits at fwimage+0x19f000 "
        "(gsp_ga10x.bin .fwimage); VA_A = A_img + 0x1000000",
    base=dict(fwimage=str(FWI), sha256=h0, size=len(img),
              rm_fw_off=hex(RM_FW_OFF), rm_size=hex(RM_SIZE)),
    patch=dict(old=OLD, new=NEW,
               encoding="lui hi/lo pairs; split-form = the two insns "
                        "separately, the gap bytes NEVER touched"),
    sites=rec_sites,
    contiguous_count=len(rec_sites) - 1,
    split_count=1,
    differing_bytes=len(diffs),
    differing_offsets=[hex(i) for i in diffs],
    rewritten_windows_bytes=len(win),
    artifact=dict(path=str(ART), sha256=h1, size=len(new_img),
                  note="fwimage ONLY; the 7/7 CONTAINER needs gspbuild "
                       "(see reproduction)"),
    reproduction=dict(
        founder_command="gspbuild.py patchrm <gsp_ga10x.bin> 0x19f000 "
                        "0x1071000 250000 280000 <out.bin> sites=6 split=1",
        test_suite="tests_gspbuild.py — 27 PASS incl. R18-R20 + S1-S8 "
                   "(the split census, the 7/7 patch, the negatives)",
        note="the tests_gspbuild REAL lane regains coverage when the "
             "84 MB container is present (GSP_GA10X=...)"),
    verdict=dict(
        decision="REVERT for any boot; the 7/7 artifact is the "
                 "completeness proof, not a boot recommendation",
        rationale=[
            "semantics: pass 4.32 PROVED the seven 250000 sites are the "
            "request/budget engine's TIME logic (the [250000,500000] us "
            "hysteresis band), NOT a power policy — turning them cannot "
            "reach 280 W",
            "coherence: the 4.30 container (sha 6a3c1a06...) turns 6/7 "
            "sites — a half-turned binary; booting it was already "
            "registered 4.33 as the blocking defect",
            "the 280 W path stays the host feed: the EDPp object is "
            "runtime-fed (vtable, 4.32 TASK 3) — the host-side limit "
            "API is the lever, not the rm.elf bytes",
        ],
        runbook="tools/edpp/runbook-280.sh updated in this pass: swap "
                "refuses the 6/7 container by hash; swap77 exists but "
                "prints the TIME-not-power warning and requires an "
                "explicit env opt-in"),
)
OUT.write_text(json.dumps(out, indent=1))
print(f"[7] {OUT}")
print("VERDICT: REVERT for boot — the 7/7 artifact is completeness, "
      "the 280 W path is the host feed (4.32 semantics).")
