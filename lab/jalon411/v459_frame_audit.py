#!/usr/bin/env python3
"""4.59 offline audit for the GA104 POSTBL/ROP placement hypothesis.

This tool is intentionally offline: it does not patch a driver, write a GPU
register, reboot a machine, or flash firmware. It cross-checks the committed
4.45 frame facts against the 4.58 chain layout and emits a machine-readable
candidate matrix for the next experiment.

Inputs (defaults are repo-relative):
  lab/jalon411/v445a_booter_copy.json
  tools/booter-patch/v448_tail_write.c

Key facts re-checked here:
  - main frame = 0x620 bytes
  - main saved-RA slot = 0x618
  - v448 chain = 0xf754..0xf7f8 (0xa8 bytes / 42 dwords)

For a direct payload->stack offset model (bias 0), a chain start can overwrite
RA iff start <= 0x618 < start+0xa8. The script then inspects the exact dword
that would occupy the RA slot. Known gadget dwords are listed separately.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

FRAME_FUNC = 0x101E0A
FRAME_SIZE = 0x620
RA_SLOT = 0x618
CHAIN_START = 0xF754
CHAIN_END = 0xF7F8
GADGETS = {0x0CBD, 0x1FBD, 0x0CCB, 0x7F2F}
PROPOSED = [0x300, 0x400, 0x480, 0x500, 0x580]
WORD_RE = re.compile(r"p\[(0x[0-9a-fA-F]+) \+ 0\] = (0x[0-9a-fA-F]+);")
BYTE_RE = re.compile(r"p\[(0x[0-9a-fA-F]+) \+ ([0-3])\] = (0x[0-9a-fA-F]+);")


def load_frame_facts(path: Path) -> tuple[int, int]:
    doc = json.loads(path.read_text())
    target = None
    for row in doc.get("stack_analysis", []):
        if row.get("func") == FRAME_FUNC:
            target = row
            break
    if target is None:
        # Fallback to the independent banked frame record.
        for row in doc.get("frames", []):
            if row.get("func") == FRAME_FUNC:
                frame = abs(int(row["frame"]))
                if frame != FRAME_SIZE:
                    raise ValueError(f"unexpected main frame: {frame:#x}")
                return frame, RA_SLOT
        raise ValueError(f"main function {FRAME_FUNC:#x} not found")
    frame = abs(int(target["frame"]))
    ra_slot = target.get("ra_slot")
    if ra_slot is None:
        raise ValueError("main function has no ra_slot")
    return frame, int(ra_slot)


def parse_chain(path: Path) -> dict[int, int]:
    text = path.read_text()
    # Prefer the byte assignments: they are the source of truth in v448.
    words: dict[int, list[int]] = {}
    for m in BYTE_RE.finditer(text):
        base = int(m.group(1), 16)
        byte_index = int(m.group(2), 10)
        value = int(m.group(3), 16)
        if base < CHAIN_START or base > CHAIN_END:
            continue
        if base not in words:
            words[base] = [None, None, None, None]  # type: ignore[list-item]
        slot = words[base]
        if slot[byte_index] is not None:
            raise ValueError(f"duplicate byte assignment at {base:#x}+{byte_index}")
        slot[byte_index] = value
    out: dict[int, int] = {}
    for base, slots in sorted(words.items()):
        if any(v is None for v in slots):
            raise ValueError(f"incomplete dword at {base:#x}: {slots}")
        value = sum((int(v) & 0xFF) << (8 * i) for i, v in enumerate(slots))
        out[base] = value
    if not out:
        raise ValueError("no chain words parsed")
    expected = set(range(CHAIN_START, CHAIN_END + 1, 4))
    if set(out) != expected:
        missing = sorted(expected - set(out))
        extra = sorted(set(out) - expected)
        raise ValueError(f"chain coverage mismatch; missing={missing} extra={extra}")
    return out


def analyze_start(start: int, chain_words: dict[int, int], frame_size: int, ra_slot: int) -> dict:
    chain_len = CHAIN_END - CHAIN_START + 4
    end_exclusive = start + chain_len
    ra_hit = start <= ra_slot < end_exclusive
    ra_word = None
    ra_source = None
    ra_kind = "NOT_OVERWRITTEN"
    if ra_hit:
        rel = ra_slot - start
        aligned = (rel % 4) == 0
        if aligned and CHAIN_START + rel in chain_words:
            ra_source = CHAIN_START + rel
            ra_word = chain_words[ra_source]
            if ra_word in GADGETS:
                ra_kind = "KNOWN_GADGET"
            elif ra_word == 0:
                ra_kind = "ZERO"
            elif ra_word == 0xC0DECA7E:
                ra_kind = "CANARY"
            else:
                ra_kind = "DATA_OR_UNKNOWN"
        else:
            ra_kind = "MISALIGNED_OR_UNKNOWN"
    return {
        "start": start,
        "start_hex": f"0x{start:04x}",
        "end_exclusive": end_exclusive,
        "end_exclusive_hex": f"0x{end_exclusive:04x}",
        "chain_len": chain_len,
        "fits_full_chain_in_frame": end_exclusive <= frame_size,
        "ra_slot": ra_slot,
        "ra_slot_hex": f"0x{ra_slot:04x}",
        "ra_overwritten": ra_hit,
        "ra_word_source": None if ra_source is None else f"0x{ra_source:04x}",
        "ra_word_value": None if ra_word is None else f"0x{ra_word:08x}",
        "ra_kind": ra_kind,
    }


def focused_starts(chain_words: dict[int, int], ra_slot: int) -> list[dict]:
    rows = []
    for src, value in sorted(chain_words.items()):
        if value not in GADGETS:
            continue
        start = ra_slot - (src - CHAIN_START)
        if start < 0 or start % 8:
            continue
        rows.append({
            "start": start,
            "start_hex": f"0x{start:04x}",
            "ra_word_source": f"0x{src:04x}",
            "ra_word_value": f"0x{value:08x}",
            "fits_full_chain_in_frame": start + (CHAIN_END - CHAIN_START + 4) <= FRAME_SIZE,
        })
    return rows


def audit(frame_json: Path, chain_c: Path) -> dict:
    frame_size, ra_slot = load_frame_facts(frame_json)
    chain = parse_chain(chain_c)
    chain_len = CHAIN_END - CHAIN_START + 4
    if frame_size != FRAME_SIZE:
        raise ValueError(f"frame changed: expected {FRAME_SIZE:#x}, got {frame_size:#x}")
    if ra_slot != RA_SLOT:
        raise ValueError(f"RA slot changed: expected {RA_SLOT:#x}, got {ra_slot:#x}")
    proposed = [analyze_start(x, chain, frame_size, ra_slot) for x in PROPOSED]
    focused = focused_starts(chain, ra_slot)
    return {
        "instrument": "v459_frame_audit",
        "basis": {
            "frame_function": f"0x{FRAME_FUNC:06x}",
            "frame_size": frame_size,
            "frame_size_hex": f"0x{frame_size:04x}",
            "ra_slot": ra_slot,
            "ra_slot_hex": f"0x{ra_slot:04x}",
            "chain_start": CHAIN_START,
            "chain_start_hex": f"0x{CHAIN_START:04x}",
            "chain_end": CHAIN_END,
            "chain_end_hex": f"0x{CHAIN_END:04x}",
            "chain_len": chain_len,
            "chain_len_hex": f"0x{chain_len:02x}",
        },
        "proposed_4_58": proposed,
        "focused_known_gadget_starts": focused,
        "interpretation": {
            "direct_offset_model": "payload_offset == stack_offset",
            "status": "MODEL_ONLY — copy destination bias is still unproven",
            "notable_candidate": "0x578 starts the chain at an 8-byte-aligned offset, places 0x00000ccb at the saved-RA slot 0x618, and the 0xa8-byte chain ends exactly at 0x620",
            "next_needed_proof": "establish the copy-destination stack bias before treating any start offset as the machine-day target",
        },
    }


def selftest() -> int:
    # Build a synthetic chain directly from the canonical table so the tests
    # stay independent of repo layout while still checking the core math.
    chain_vals = [
        0xFFFFFFFF, 0xC0DECA7E, 0x00000CBD, 0xC0DECA7E, 0, 0,
        0x001FA7C4, 0, 0x00001FBD, 0xC0DECA7E, 0, 0, 0, 0x000010AA,
        0x0000815A, 0x00008E18, 0xC0DECA7E, 0x0000815A, 0,
        0xC0DECA7E, 0x00001FBD, 0, 0, 0x0000FFBC, 0, 0x0000582D,
        0, 0, 0xC0DECA7E, 0x00000CBD, 0, 0, 0, 3, 0, 0x00001FBD,
        0, 0, 0, 0, 0x00000CCB, 0x00007F2F,
    ]
    assert len(chain_vals) == 42
    chain = {CHAIN_START + i * 4: v for i, v in enumerate(chain_vals)}
    rows = {r["start"]: r for r in [analyze_start(x, chain, FRAME_SIZE, RA_SLOT) for x in PROPOSED]}
    assert rows[0x580]["ra_overwritten"] is True
    assert rows[0x580]["ra_word_source"] == "0xf7ec"
    assert rows[0x580]["ra_word_value"] == "0x00000000"
    assert rows[0x580]["fits_full_chain_in_frame"] is False
    row578direct = analyze_start(0x578, chain, FRAME_SIZE, RA_SLOT)
    assert row578direct["fits_full_chain_in_frame"] is True
    assert row578direct["ra_word_source"] == "0xf7f4"
    assert row578direct["ra_word_value"] == "0x00000ccb"
    focused = focused_starts(chain, RA_SLOT)
    starts = {r["start"] for r in focused}
    assert 0x578 in starts
    row578 = next(r for r in focused if r["start"] == 0x578)
    assert row578["ra_word_source"] == "0xf7f4"
    assert row578["ra_word_value"] == "0x00000ccb"
    assert row578["fits_full_chain_in_frame"] is True
    assert 0x580 not in starts
    print("selftest v459_frame_audit: 8/8 PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--frame-json", type=Path, default=Path("lab/jalon411/v445a_booter_copy.json"))
    ap.add_argument("--chain-c", type=Path, default=Path("tools/booter-patch/v448_tail_write.c"))
    ap.add_argument("--out", type=Path, default=Path("lab/jalon411/v459_frame_audit.json"))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    doc = audit(args.frame_json, args.chain_c)
    args.out.write_text(json.dumps(doc, indent=1) + "\n")
    print(json.dumps(doc, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
