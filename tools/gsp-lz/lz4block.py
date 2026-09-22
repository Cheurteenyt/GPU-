#!/usr/bin/env python3
"""gsp-lz — the LZ4 raw-block codec for the GSP firmware path (4.24 pass III).

WHY THIS EXISTS (the honest framing):

  The pass brief pointed at envytools lz*.rst — those files DO NOT exist
  (4.24 finding: the envytools tree holds 267 .rst files, ZERO with LZ in
  name or content; remote branches and the wiki checked too). And this
  campaign's artifact set holds NO compressed rm.elf: the GFW archive
  stores the components FLAT (v424_gfw_directory.py: the flat RM image
  @0x132000 size 0xe9b000, the full dev ELF @0x19f000 byte-exact, the
  725 KB component ELF @0x1210000 — all uncompressed). So an
  "NVIDIA-format-compatible" compressor has no ground-truth stream here
  to validate against.

  What IS deliverable and verifiable: the LZ4 BLOCK format — the format
  this campaign's lz-probe.py already assumed for the bindata streams,
  and the only NVIDIA-adjacent ucode compression with a real public
  specification (the LZ4 Block Format spec, reference implementation
  lz4/lz4 block.c). This module implements:

    compress(data)   -> a VALID LZ4 raw block, decodable by the reference
                        lz4.block decoder (compatibility PROVEN by test)
    decompress(block, uncompressed_size) -> byte-exact original

  Verification standard (the brief's byte-exactness standard, applied to
  the real spec): round-trip byte-exactness + differential validation
  against the reference implementation on adversarial inputs
  (tests_gsplz.py runs them).

The codec itself is dependency-free (the firmware-loader shape: the
caller knows the component size from the directory, so the raw block —
no frame header — is the right container).
"""
import struct

MIN_MATCH = 4
LAST_LITERALS = 5
MFLIMIT = 12            # a match cannot start within the last 12 bytes
MAX_OFFSET = 0xFFFF
HASH_LOG = 16
HASH_SIZE = 1 << HASH_LOG


def _hash(v):
    return ((v * 2654435761) & 0xFFFFFFFF) >> (32 - HASH_LOG)


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _put_varlen(out, value):
    """the 255-run extension for a length nibble that saturated at 15"""
    rem = value - 15
    while rem >= 255:
        out.append(255)
        rem -= 255
    out.append(rem)


def compress(data: bytes) -> bytes:
    """Greedy single-pass LZ4 block compressor (hash table, no chains).

    Produces the exact sequence grammar of the LZ4 block spec:
      token [lit-ext] literals offset [match-ext], ending in literals only.
    """
    n = len(data)
    out = bytearray()
    if n == 0:
        return b"\x00"

    table = [0] * HASH_SIZE          # stores pos+1; 0 = empty
    anchor = 0
    pos = 0

    while pos + MFLIMIT <= n:
        seq = _u32(data, pos)
        h = _hash(seq)
        ref = table[h] - 1            # -1: 0 = empty slot
        table[h] = pos + 1
        if (ref >= 0
                and ref < pos
                and pos - ref <= MAX_OFFSET
                and _u32(data, ref) == seq):
            # extend the match (overlap allowed), keep the last 5 bytes literal
            ml = MIN_MATCH
            limit = n - LAST_LITERALS
            while pos + ml < limit and data[ref + ml] == data[pos + ml]:
                ml += 1
            lit_len = pos - anchor
            # --- emit the sequence ---
            lit_nib = lit_len if lit_len < 15 else 15
            ml_nib = (ml - MIN_MATCH) if (ml - MIN_MATCH) < 15 else 15
            out.append((lit_nib << 4) | ml_nib)
            if lit_len >= 15:
                _put_varlen(out, lit_len)
            out += data[anchor:pos]
            offset = pos - ref
            out.append(offset & 0xFF)
            out.append((offset >> 8) & 0xFF)
            if ml - MIN_MATCH >= 15:
                _put_varlen(out, ml - MIN_MATCH)
            pos += ml
            anchor = pos
            if pos + MFLIMIT <= n:
                table[_hash(_u32(data, pos))] = pos + 1
        else:
            pos += 1

    # the tail: the FINAL sequence is literals-only (the spec's end-of-block)
    lit_len = n - anchor
    if lit_len < 15:
        out.append(lit_len << 4)
    else:
        out.append(0xF0)
        _put_varlen(out, lit_len)
    out += data[anchor:]
    return bytes(out)


def decompress(block: bytes, uncompressed_size: int) -> bytes:
    """The standard LZ4 raw-block decoder (the documented algorithm).

    The raw block carries no size — the caller supplies the expected
    output size (exactly the firmware-loader situation: the component
    size comes from the GFW directory). Stops when the output is full or
    the input is exhausted; the final sequence is literals-only.
    """
    out = bytearray(uncompressed_size)
    opos = 0
    ipos = 0
    n = len(block)
    while ipos < n:
        token = block[ipos]
        ipos += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                b = block[ipos]
                ipos += 1
                lit_len += b
                if b != 255:
                    break
        if opos + lit_len > uncompressed_size:
            raise ValueError("literal overrun")
        out[opos:opos + lit_len] = block[ipos:ipos + lit_len]
        ipos += lit_len
        opos += lit_len
        if opos == uncompressed_size or ipos >= n:
            break
        offset = block[ipos] | (block[ipos + 1] << 8)
        ipos += 2
        if offset == 0:
            raise ValueError("zero offset")
        if offset > opos:
            raise ValueError("offset before start")
        match_len = (token & 0xF) + MIN_MATCH
        if (token & 0xF) == 15:
            while True:
                b = block[ipos]
                ipos += 1
                match_len += b
                if b != 255:
                    break
        if opos + match_len > uncompressed_size:
            raise ValueError("match overrun")
        start = opos - offset
        for i in range(match_len):        # byte-wise copy: overlap allowed
            out[opos] = out[start + i]
            opos += 1
    if opos != uncompressed_size:
        raise ValueError(f"short output: {opos} != {uncompressed_size}")
    return bytes(out)
