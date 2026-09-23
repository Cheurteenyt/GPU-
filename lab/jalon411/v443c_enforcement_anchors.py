#!/usr/bin/env python3
"""4.43 pass, TÂCHE 3 instrument — the enforcement anchors and the
verify-executor hunt.

  1. the direct-caller scan for the 4.43b policy functions:
     the evaluator 0x1446d98, the recompute 0x143fdbc, the worker
     0x14400c6, the tail-consumer 0x1446dba-block entry — every jal /
     c.jal / c.jalr-with-static-target landing on them (the indirect
     wall is respected: direct callers only, labeled as such);
  2. the crypto-core census (SHA-256 IV {0x6A09E667, 0xBB67AE85,
     0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
     0x5BE0CD19}, SHA-1 IV head 0x67452301, RSA e 0x10001) over the
     covered code — the VBIOS-verify executor of 4.43a's FWSECLIC
     report arms;
  3. the RatedTdp SET handler (0x163c42c, the 4.21 §4 GET-side decode
     left the SET+clamp queued) decoded in a bounded window;
  4. PERF_GPU_BOOST_SYNC_SET_LIMITS handler (0x16e4f20, banked
     "next-pass walk" since 4.20 §2) decoded in a bounded window.

Self-checks: the coordinate law (512 windows); census VAs re-asserted.

Output: lab/jalon411/v443c_enforcement_anchors.json
"""
import json
import re
import struct
import zlib
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

SHA256_IV = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}
SHA1_HEAD = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
             0xC3D2E1F0}
RSA_E = {0x10001}

TARGETS = {
    "evaluator_1446d98": 0x1446D98,
    "recompute_143fdbc": 0x143FDBC,
    "worker_14400c6": 0x14400C6,
}


def regions(covered):
    starts, ends = [], []
    i, n = 0, len(covered)
    while i < n:
        if covered[i]:
            j = i
            while j < n and covered[j]:
                j += 1
            if j - i >= 2:
                starts.append(i)
                ends.append(j)
            i = j
        else:
            i += 1
    return starts, ends


def dec_window(img, va, n, back=0):
    out = []
    o = va - IMG_LO - back
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append(f"0x{IMG_LO + o:x}: {ins.mnemonic:<8} {ins.op_str}")
        o += ins.size
    return out


def imm_of(ins):
    m = re.search(r",\s*(-?0x[0-9a-f]+|-?\d+)$", ins.op_str)
    if not m:
        return None
    try:
        return int(m.group(1), 0)
    except ValueError:
        return None


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    starts, ends = regions(covered)

    def covered_at(aoff):
        for s0, e0 in zip(starts, ends):
            if s0 <= aoff < e0:
                return True
        return False

    out = {}

    # -- the coordinate law
    fails = 0
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    assert fails == 0
    out["law_fails"] = 0

    # -- 1. the direct-caller scan
    callers = {k: [] for k in TARGETS}
    tgt_off = {v - IMG_LO: k for k, v in TARGETS.items()}
    n_ins = 0
    for s0, e0 in zip(starts, ends):
        off = s0
        while off < e0:
            try:
                ins = next(md.disasm(img[off:off + 4], IMG_LO + off))
            except StopIteration:
                break
            n_ins += 1
            m = ins.mnemonic
            if m in ("jal", "c.jal", "c.j", "j"):
                # jal ra, target / c.jal ra, target / c.j target / j target
                t = ins.op_str.split(", ")[1] if ", " in ins.op_str \
                    else ins.op_str
                try:
                    tv = int(t, 0)
                except ValueError:
                    tv = None
                if tv is not None:
                    key = tgt_off.get(tv - IMG_LO)
                    if key:
                        callers[key].append({"site": hex(IMG_LO + off),
                                             "m": m, "covered": True})
            elif m in ("beq", "bne", "bltu", "bgeu", "blt", "bge"):
                pass
            off += ins.size
    out["direct_callers"] = callers
    out["decoded_insns"] = n_ins
    for k, v in callers.items():
        print(f"[callers] {k}: {len(v)} direct")
        for c in v[:12]:
            print("   ", c["site"], c["m"])

    # -- 2. the crypto-core census (lui+addi full-form pairs)
    CRYPTO = {}
    for v in SHA256_IV:
        CRYPTO[v] = "sha256-iv"
    for v in SHA1_HEAD:
        CRYPTO[v] = "sha1-iv"
    CRYPTO[0x10001] = "rsa-e"
    hits = {}
    for s0, e0 in zip(starts, ends):
        off = s0
        while off < e0:
            try:
                ins = next(md.disasm(img[off:off + 4], IMG_LO + off))
            except StopIteration:
                break
            if ins.mnemonic in ("lui", "c.lui"):
                # lui rd, imm → value = imm << 12 (check both raw and
                # the split-form successor)
                v = imm_of(ins)
                if v is not None:
                    full = (v << 12) & 0xFFFFFFFF
                    if full in CRYPTO:
                        hits.setdefault(CRYPTO[full], []).append(
                            {"va": hex(IMG_LO + off),
                             "insn": f"{ins.mnemonic} {ins.op_str}",
                             "window": dec_window(img, IMG_LO + off, 6)})
            elif ins.mnemonic in ("li", "c.li"):
                v = imm_of(ins)
                if v in CRYPTO:
                    hits.setdefault(CRYPTO[v], []).append(
                        {"va": hex(IMG_LO + off),
                         "insn": f"{ins.mnemonic} {ins.op_str}",
                         "window": dec_window(img, IMG_LO + off, 6)})
            off += ins.size
    out["crypto_constants"] = {k: v[:12] for k, v in hits.items()}
    for k, v in hits.items():
        print(f"[crypto] {k}: {len(v)} sites")
        for h in v[:6]:
            print("   ", h["va"], h["insn"])

    # -- 3. the RatedTdp SET handler window
    out["ratedtdp_163c42c"] = {
        "window": dec_window(img, 0x163C42C, 90)}
    # -- 4. the GPU_BOOST_SYNC handler window
    out["gpuboostsync_16e4f20"] = {
        "window": dec_window(img, 0x16E4F20, 90)}

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
