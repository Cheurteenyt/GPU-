#!/usr/bin/env python3
"""4.29 pass — task A.2: the encode direction, on the REAL component.

The brief: "compress gsp-rm-17MB.bin with our codec and compare
byte-exact with comp-725KB.bin; if not identical, decode both streams
side by side, identify the exact conventions of NVIDIA's compressor,
iterate until byte-exact OR document every remaining gap."

Task A.1 (v429_lz_pair_forensics.py) falsified the pair's premise on
the bytes: comp-725KB.bin is vgpu.elf (a plaintext component ELF whose
two LOAD sizes match the GFW directory's vgpu row), gsp-rm-17MB.bin is
rm.elf — two DIFFERENT flat components. The artifact set therefore
holds NO NVIDIA-produced encoder output for the RM, and no encoder —
ours or anyone's — can be byte-exact against a target that is not an
encoding of the source. The brief's "iterate until byte-exact" leg is
closed by A.1; the "document every remaining gap" leg is delivered
here, in the only form the bytes support:

  1. THE VERBATIM COMPARISON — ours.compress(rm.elf) vs comp-725KB.bin:
     sizes + sha256, the non-encoding verdict restated at stream level.
  2. THE SIDE-BY-SIDE CONVENTION STUDY — ours (the campaign codec,
     lz4block.py) vs the REFERENCE encoder (python-lz4 wrapping lz4's
     official block codec, default mode AND HC): both streams of the
     REAL 17,236,632-byte RM tokenized per the LZ4 block grammar,
     validated by reconstruction (literals+matches == 17,236,632),
     then diffed: first divergence, per-encoder stats, offset and
     match-length histograms. These are the encoder conventions the
     artifacts can actually name — ours vs the reference implementation
     — quantified on real firmware bytes.

NVIDIA's own compressor conventions: ABSENT-BY-BYTES from this
artifact set (the package-wide hunt is v429_lz_package_hunt.py; the
4.24 ledger item 1 stands, now sharpened).

Output: lab/jalon411/v429_lz_conventions.json (+ selftest, exit 2 on
drift — the frozen-register discipline).
"""
import hashlib
import json
import struct
import sys
import time

sys.path.insert(0, "/home/z/my-project/work/gpu-repo/tools/gsp-lz")
import lz4block

try:
    import lz4.block as ref_block
    HAVE_REF = True
except ImportError:
    HAVE_REF = False

BASE = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/"
RM = BASE + "gsp-rm-17MB.bin"
COMP = BASE + "comp-725KB.bin"
OUT = "/home/z/my-project/work/gpu-repo/lab/jalon411/v429_lz_conventions.json"


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def tokenize(block, expected_out):
    """The LZ4 block grammar, parsed; validated by reconstruction.

    Returns (sequences, ok) — sequences = [(lit_len, offset, match_len)]
    with the final literals-only sequence carried as (lit_len, 0, 0).
    """
    seqs = []
    pos = 0
    out = 0
    n = len(block)
    while pos < n:
        tok = block[pos]
        pos += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                b = block[pos]
                pos += 1
                lit += b
                if b != 255:
                    break
        out += lit
        pos += lit
        if out >= expected_out or pos >= n:
            break                       # the final literals-only sequence
        offset = block[pos] | (block[pos + 1] << 8)
        pos += 2
        ml = (tok & 0xF) + 4
        if (tok & 0xF) == 15:
            while True:
                b = block[pos]
                pos += 1
                ml += b
                if b != 255:
                    break
        out += ml
        seqs.append((lit, offset, ml))
    return seqs, (out == expected_out and pos <= n)


def stats(seqs):
    """The encoder-convention fingerprint of one tokenized stream."""
    n_seq = len(seqs)
    lit_total = sum(s[0] for s in seqs)
    match_total = sum(s[2] for s in seqs)
    lit_sat = sum(1 for s in seqs if s[0] >= 15)      # the 255-extension runs
    ml_sat = sum(1 for s in seqs if s[2] >= 15 + 4)   # nibble-saturating matches
    off = [s[1] for s in seqs if s[1]]
    buckets = {
        "offset_1_3_RLE": sum(1 for o in off if o <= 3),
        "offset_4_255": sum(1 for o in off if 4 <= o <= 255),
        "offset_256_4095": sum(1 for o in off if 256 <= o <= 4095),
        "offset_4096_65535": sum(1 for o in off if o >= 4096),
    }
    return {
        "sequences": n_seq,
        "literal_bytes": lit_total,
        "match_bytes": match_total,
        "lit_ext_sequences": lit_sat,
        "match_ext_sequences": ml_sat,
        "max_literal_run": max((s[0] for s in seqs), default=0),
        "max_match": max((s[2] for s in seqs), default=0),
        **buckets,
    }


def first_divergence(a, b, depth=12):
    """The first sequence-level differences between two tokenizations."""
    diffs = []
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            sa, sb = a[i], b[i]
            field = ("lit_len" if sa[0] != sb[0] else
                     "offset" if sa[1] != sb[1] else "match_len")
            diffs.append({"seq": i, "field": field,
                          "ours": list(sa), "reference": list(sb)})
            if len(diffs) >= depth:
                break
    return diffs


def build():
    rm = open(RM, "rb").read()
    comp = open(COMP, "rb").read()
    reg = {"rm_size": len(rm), "comp_size": len(comp)}

    # --- 1. the verbatim comparison the brief asks for ---
    t0 = time.perf_counter()
    mine = lz4block.compress(rm)
    t_mine = time.perf_counter() - t0
    reg["ours_vs_comp725KB"] = {
        "ours_stream_size": len(mine), "ours_sha256": sha256(mine),
        "comp_sha256": sha256(comp), "comp_size": len(comp),
        "byte_exact": mine == comp,
        "verdict": ("not an encoding of rm.elf — comp-725KB.bin is "
                    "vgpu.elf stored flat (v429_lz_pair_forensics.json)"),
        "ours_compress_seconds": round(t_mine, 2),
    }

    # --- 2. the side-by-side convention study (ours vs reference) ---
    if not HAVE_REF:
        reg["reference"] = "python-lz4 absent — study skipped"
        return reg
    ref_default = ref_block.compress(rm, store_size=False)
    ref_hc = ref_block.compress(rm, store_size=False,
                                mode="high_compression", compression=9)
    tok_mine, ok_mine = tokenize(mine, len(rm))
    tok_ref, ok_ref = tokenize(ref_default, len(rm))
    tok_hc, ok_hc = tokenize(ref_hc, len(rm))
    reg["reference"] = {
        "ref_default_size": len(ref_default), "ref_default_sha256": sha256(ref_default),
        "ref_hc9_size": len(ref_hc), "ref_hc9_sha256": sha256(ref_hc),
        "ours_size": len(mine), "ours_sha256": sha256(mine),
        "ours_minus_ref_default": len(mine) - len(ref_default),
        "ours_minus_ref_hc9": len(mine) - len(ref_hc),
        "reconstruction_ok": {"ours": ok_mine, "ref_default": ok_ref,
                              "ref_hc9": ok_hc},
        "stats_ours": stats(tok_mine),
        "stats_ref_default": stats(tok_ref),
        "stats_ref_hc9": stats(tok_hc),
        "first_divergence_ours_vs_ref_default":
            first_divergence(tok_mine, tok_ref),
        "sequence_count_ratio_ours_per_ref":
            round(len(tok_mine) / max(1, len(tok_ref)), 3),
    }
    return reg


def selftest():
    frozen = json.load(open(OUT))
    fresh = build()
    # lesson banked: the first selftest run drifted on ours_compress_seconds
    # — a wall-clock measurement can never re-derive identically; the frozen
    # comparison normalizes the timing fields out (the register keeps them).
    for d in (frozen, fresh):
        d.get("ours_vs_comp725KB", {}).pop("ours_compress_seconds", None)
    if fresh != frozen:
        for key in frozen:
            if frozen[key] != fresh.get(key):
                print("SELFTEST DRIFT on: %s" % key)
                sys.exit(2)
        print("SELFTEST DRIFT (structure)")
        sys.exit(2)
    print("SELFTEST OK — the 4.29 conventions register reproduces live:")
    r = frozen["reference"]
    print("  sizes: ours %d | ref-default %d | ref-HC9 %d | comp-725KB %d (not an encoding)" % (
        r["ours_size"], r["ref_default_size"], r["ref_hc9_size"],
        frozen["comp_size"]))
    print("  sequences: ours %d | ref %d | recon %s" % (
        r["stats_ours"]["sequences"], r["stats_ref_default"]["sequences"],
        all(r["reconstruction_ok"].values())))
    fd = r["first_divergence_ours_vs_ref_default"]
    if fd:
        d = fd[0]
        print("  first divergence @seq %d (%s): ours %s vs ref %s" % (
            d["seq"], d["field"], d["ours"], d["reference"]))


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        reg = build()
        with open(OUT, "w") as f:
            json.dump(reg, f, indent=1)
        print(json.dumps(reg.get("ours_vs_comp725KB"), indent=1))
        if "reference" in reg and isinstance(reg["reference"], dict):
            r = reg["reference"]
            print("ours %d B | ref-default %d B | ref-HC9 %d B" %
                  (r["ours_size"], r["ref_default_size"], r["ref_hc9_size"]))
            print("sequences: ours %d vs ref %d" %
                  (r["stats_ours"]["sequences"],
                   r["stats_ref_default"]["sequences"]))
        print("register written: %s" % OUT)
