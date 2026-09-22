#!/usr/bin/env python3
"""4.29 pass — task A.1: the real-component pair, forensically.

The pass brief's premise: "comp-725KB.bin (725,616 B) = the RM component
COMPRESSED as embedded in gsp.bin; gsp-rm-17MB.bin (17,236,632 B) = the
DECOMPRESSED RM". This instrument tests that premise ON THE BYTES, with
no appeal to the 4.24 conclusions (fresh proof, same branch standard):

  1. IDENTITY — both files' ELF headers parsed from the bytes (class,
     machine, type, entry, phdrs). A compressed stream does not carry an
     ELF identification; two different entries = two different files.
  2. THE DECODE ATTEMPT — comp-725KB.bin handed to the campaign codec
     (tools/gsp-lz/lz4block.py) and to the REFERENCE decoder
     (python-lz4), with the expected output size of gsp-rm-17MB.bin.
     The exact failure mode is banked (exception class + message, or the
     first-divergence offset if a decode ever completes). The reverse
     direction (17 MB as stream, 725,616 B out) is attempted too, for
     symmetry. No codec "fix" can apply here: if the input is not an
     LZ4 stream of the target, the failure is in the premise, not the
     codec — this instrument exists to prove which one it is.
  3. THE CONTAINMENT TEST — both files located byte-exact inside
     fwimage.bin (the gsp.bin component image, 4.27 provenance). Flat
     containment of BOTH = the storage is uncompressed (the 4.24 pass
     III-a result, re-derived live on this branch).

Output: lab/jalon411/v429_lz_pair_forensics.json.
The selftest re-derives every anchor live and exits 2 on drift (the
frozen-register discipline: lab/jalon411 conventions, AGENTS.md §2).
"""
import json
import struct
import sys

sys.path.insert(0, "/home/z/my-project/work/gpu-repo/tools/gsp-lz")
import lz4block                                     # the campaign codec

try:
    import lz4.block as ref_block                   # the reference decoder
    HAVE_REF = True
except ImportError:
    HAVE_REF = False

BASE = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/"
COMP = BASE + "comp-725KB.bin"
RM = BASE + "gsp-rm-17MB.bin"
FW = BASE + "fwimage.bin"
OUT = "/home/z/my-project/work/gpu-repo/lab/jalon411/v429_lz_pair_forensics.json"


def parse_elf_identity(path):
    """The ELF64 identity, read from the file's own bytes."""
    with open(path, "rb") as f:
        h = f.read(64)
    ident_is_elf = h[:4] == b"\x7fELF"
    if not ident_is_elf:
        return {"path": path, "is_elf": False, "first16": h[:16].hex()}
    e_type, e_machine = struct.unpack_from("<HH", h, 16)
    e_entry, e_phoff, e_shoff = struct.unpack_from("<QQQ", h, 24)
    e_phnum, = struct.unpack_from("<H", h, 56)
    with open(path, "rb") as f:
        # lesson banked: the first freeze attempt read the phdrs as a
        # read-continuation from offset 0 (misaligned by the 64-byte ELF
        # header — p_type came back as the \x7fELF magic); the phdr table
        # starts at e_phoff, SEEK to it.
        f.seek(e_phoff)
        phs = []
        for i in range(min(e_phnum, 8)):
            p = f.read(56)
            if len(p) < 56:
                break
            p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, _ = \
                struct.unpack("<IIQQQQQQ", p)
            phs.append({"type": "0x%08x" % p_type, "off": p_off,
                        "vaddr": "0x%x" % p_vaddr,
                        "filesz": p_filesz, "memsz": p_memsz})
    return {"path": path, "is_elf": True,
            "ei_class": h[4], "ei_data": h[5],
            "e_type": e_type, "e_machine": e_machine,
            "machine_name": {243: "RISC-V"}.get(e_machine, "?"),
            "entry": "0x%x" % e_entry, "phnum": e_phnum,
            "phdrs": phs}


def decode_attempt(decoder_name, stream, out_size, expected=None):
    """One LZ4 decode attempt; the failure mode banked either way."""
    rec = {"decoder": decoder_name, "stream_size": len(stream),
           "requested_out": out_size}
    try:
        if decoder_name == "ours":
            got = lz4block.decompress(stream, out_size)
        else:
            got = ref_block.decompress(stream, uncompressed_size=out_size)
    except Exception as exc:                        # the honest failure record
        rec["outcome"] = "exception"
        rec["exception"] = type(exc).__name__
        rec["message"] = str(exc)[:200]
        return rec
    rec["outcome"] = "completed"
    if expected is not None and got == expected:
        rec["byte_exact_vs_target"] = True
    else:
        rec["byte_exact_vs_target"] = False
        if expected is not None:
            n = min(len(got), len(expected))
            first = next((i for i in range(n) if got[i] != expected[i]),
                         n if len(got) != len(expected) else -1)
            rec["first_divergence"] = first
            eq = sum(1 for i in range(0, n, 4096)      # sampled equality count
                     if got[i:i + 4096] == expected[i:i + 4096])
            rec["equal_4k_blocks_sampled"] = eq
            rec["of_4k_blocks"] = (n + 4095) // 4096
    return rec


def find_flat(hay_path, needle_path):
    """Locate needle byte-exact inside hay (the containment test)."""
    with open(needle_path, "rb") as f:
        needle = f.read()
    with open(hay_path, "rb") as f:
        hay = f.read()
    probe = needle[:4096]
    hits = []
    start = 0
    while True:
        i = hay.find(probe, start)
        if i < 0:
            break
        start = i + 1
        if hay[i:i + len(needle)] == needle:        # the FULL byte-exact check
            hits.append(i)
    return {"needle_size": len(needle), "hay_size": len(hay),
            "byte_exact_hits": hits}


def build():
    comp = open(COMP, "rb").read()
    rm = open(RM, "rb").read()
    reg = {
        "identities": [parse_elf_identity(COMP), parse_elf_identity(RM)],
        "sizes": {"comp-725KB.bin": len(comp), "gsp-rm-17MB.bin": len(rm)},
        "decode_attempts": [
            decode_attempt("ours", comp, len(rm), rm),
            decode_attempt("ours", rm, len(comp), comp),
        ],
        "containment": {
            "comp_in_fwimage": find_flat(FW, COMP),
            "rm_in_fwimage": find_flat(FW, RM),
        },
    }
    if HAVE_REF:
        reg["decode_attempts"] += [
            decode_attempt("reference", comp, len(rm), rm),
        ]
    c = reg["containment"]["comp_in_fwimage"]["byte_exact_hits"]
    r = reg["containment"]["rm_in_fwimage"]["byte_exact_hits"]
    reg["verdict"] = {
        "comp_is_elf_not_stream": reg["identities"][0]["is_elf"],
        "rm_is_elf_not_stream": reg["identities"][1]["is_elf"],
        "decode_of_comp_as_rm_succeeded": reg["decode_attempts"][0]
            .get("byte_exact_vs_target", False),
        "both_stored_flat_in_fwimage": bool(c) and bool(r),
        "containment_windows_overlap": (
            "OVERLAP" if c and r and
            any(not (ch + reg["sizes"]["comp-725KB.bin"] <= rh
                     or rh + reg["sizes"]["gsp-rm-17MB.bin"] <= ch)
                for ch in c for rh in r) else "DISJOINT"),
    }
    return reg


def selftest():
    """Re-derive the anchors live; exit 2 on drift (the frozen register)."""
    frozen = json.load(open(OUT))
    fresh = build()
    drifts = []
    for key in ("sizes", "identities", "decode_attempts",
                "containment", "verdict"):
        if fresh[key] != frozen.get(key):
            drifts.append(key)
    if drifts:
        print("SELFTEST DRIFT on: %s" % ", ".join(drifts))
        sys.exit(2)
    print("SELFTEST OK — the 4.29 pair-forensics register reproduces live:")
    v = frozen["verdict"]
    print("  comp-725KB is-ELF: %s | gsp-rm-17MB is-ELF: %s" %
          (v["comp_is_elf_not_stream"], v["rm_is_elf_not_stream"]))
    for a in frozen["decode_attempts"]:
        o = a.get("outcome")
        msg = a.get("message", "") if o == "exception" else \
              ("byte_exact=%s" % a.get("byte_exact_vs_target")
               if o == "completed" else "?")
        print("  decode[%s, %d -> %d]: %s %s" %
              (a["decoder"], a["stream_size"], a["requested_out"], o, msg))
    c = frozen["containment"]["comp_in_fwimage"]["byte_exact_hits"]
    r = frozen["containment"]["rm_in_fwimage"]["byte_exact_hits"]
    print("  containment: comp @%s, rm @%s in fwimage — flat=%s, %s" %
          (["0x%x" % x for x in c], ["0x%x" % x for x in r],
           v["both_stored_flat_in_fwimage"], v["containment_windows_overlap"]))


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        reg = build()
        with open(OUT, "w") as f:
            json.dump(reg, f, indent=1)
        print(json.dumps(reg["verdict"], indent=1))
        print("register written: %s" % OUT)
