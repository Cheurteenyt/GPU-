#!/usr/bin/env python3
"""4.24 pass I — the 1616-byte payload field map.

Input:  tools/edpp/edpp_payload_1616.bin (captured at the fn=76 send time,
        rpc_message_data[] onward — the rpc_gsp_rm_control_v03_00 body).
Method: (1) parse the rpc_gsp_rm_control_v03_00 prefix (PROVEN layout,
        g_rpc-structures.h:1423); (2) hunt the mW signatures
        {100000=0x186A0, 240000=0x3A980, 250000=0x3D090} at every u32
        offset (aligned AND unaligned); (3) test the
        NV2080_CTRL_CMD_INTERNAL_PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO_PARAMS
        field order (limitMin/limitRated/limitMax/limitCurr/
        limitBattRated/limitBattMax — ctrl2080internal.h:3988) against the
        found positions; (4) full u32 census of the params with power-like
        annotations. Every verdict = PROVEN (bytes shown) or HYPOTHESIS
        (pattern only).

Output: lab/jalon411/v424_payload_map.json
"""
import json
import struct
from collections import Counter

BIN = "/home/z/my-project/work/gpu-repo/tools/edpp/edpp_payload_1616.bin"
OUT = "/home/z/my-project/work/gpu-repo/lab/jalon411/v424_payload_map.json"

SIGS = {
    100000: ("0x186A0", "100 W (min candidate)"),
    120000: ("0x1D4C0", "120 W"),
    210000: ("0x33450", "210 W (the -pl probe)"),
    220000: ("0x35B60", "220 W"),
    240000: ("0x3A980", "240 W (default candidate)"),
    250000: ("0x3D090", "250 W (max candidate)"),
    260000: ("0x3F880", "260 W (the rewrite probe)"),
    280000: ("0x44570", "280 W (the target)"),
}

# rpc_gsp_rm_control_v03_00 (g_rpc-structures.h:1423)
RMCTRL_FIELDS = [
    (0x00, "hClient", "NvHandle"),
    (0x04, "hObject", "NvHandle"),
    (0x08, "cmd", "NvU32"),
    (0x0C, "status", "NvU32"),
    (0x10, "paramsSize", "NvU32"),
    (0x14, "rmapiRpcFlags", "NvU32"),
    (0x18, "rmctrlFlags", "NvU32"),
    (0x1C, "rmctrlAccessRight", "NvU32"),
    (0x20, "reserved0", "NvU64"),
]
PARAMS_OFF = 0x28  # 40

KNOWN_CMDS = {
    0x20800AFD: "NV2080_CTRL_CMD_INTERNAL_PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO (0xFD)",
    0x20800AD0: "NV2080_CTRL_CMD_INTERNAL_PMGR_PFM_REQ_HNDLR_UPDATE_EDPP_LIMIT (0xD0)",
}

# GET_EDPP_LIMIT_INFO_PARAMS field order (ctrl2080internal.h:3988)
EDPP_INFO_FIELDS = ["limitMin", "limitRated", "limitMax",
                    "limitCurr", "limitBattRated", "limitBattMax"]


def u32le(data, off):
    return struct.unpack_from("<I", data, off)[0]


def hunt(data, targets):
    """find every occurrence (aligned + unaligned) of each u32 target"""
    hits = {}
    for val, (_, label) in SIGS.items():
        if val not in targets:
            continue
        sig = struct.pack("<I", val)
        start, found = 0, []
        while True:
            off = data.find(sig, start)
            if off == -1:
                break
            found.append(off)
            start = off + 1
        hits[val] = {"label": label, "offsets": found}
    return hits


def main():
    data = open(BIN, "rb").read()
    out = {"file": BIN, "size": len(data), "sha256": None}
    import hashlib
    out["sha256"] = hashlib.sha256(data).hexdigest()

    # --- 0. the capture-length law (4.24 discovery) ---
    # rpc_common.c:182: pVgpuRpcHeader->length = sizeof(rpc_message_header_v)
    #                    + paramLength  ->  the length INCLUDES the 32-byte
    #                    RPC header.  The dump base = rpc_message_data (the
    #                    body start).  So every RPCDUMP76 capture is 32 bytes
    #                    LONGER than the message body.
    RPC_HEADER_SIZE = 32
    declared_params = u32le(data, 0x10)
    # the dumped file starts at the BODY (rpc_message_data) and runs for
    # header.length = 32 + 40 + paramsSize bytes -> the LAST 32 bytes of the
    # file lie beyond the message.  Valid body = dumped - 32.
    body_valid = len(data) - RPC_HEADER_SIZE                     # 1584
    out["capture_length_law"] = {
        "dumped": len(data),
        "body_valid_bytes": body_valid,
        "overcapture_bytes": len(data) - body_valid,
        "evidence": "rpc_common.c:182 (length = header + paramLength); "
                    "the dump base = rpc_message_data (kernel_gsp.c patch v4)",
        "verdict": "PROVEN — 32 bytes @1584..1615 = the queue residue, NOT the message",
    }

    # --- 1. the rpc_gsp_rm_control_v03_00 prefix ---
    hdr = {}
    for off, name, typ in RMCTRL_FIELDS:
        if typ == "NvU64":
            hdr[name] = struct.unpack_from("<Q", data, off)[0]
        else:
            hdr[name] = u32le(data, off)
    cmd = hdr["cmd"]
    hdr["cmd_resolved"] = KNOWN_CMDS.get(cmd, f"closed-only FINN interface 0x{(cmd >> 8):x}, msg id 0x{(cmd & 0xff):x}")
    hdr["paramsSize_matches_body"] = (declared_params == body_valid - PARAMS_OFF)
    hdr["params_actual_size"] = body_valid - PARAMS_OFF
    out["rpc_header"] = hdr

    # --- 1b. the dispatch-table cross-check (4.20 table @0x1c183b8) ---
    out["dispatch_cross_check"] = {
        "table": "0x1c183b8, 1156 entries, stride 0x20 (findings-4.20)",
        "entry": {"id": hex(cmd), "tag": "0x608 (=1544 = paramsSize, EXACT)",
                  "pA": "0x1c23870", "handler": "0x11267fc",
                  "handler_boundary_verified": True, "sz0": "0x44"},
        "raw_entry_hex": "31d08020080600007038c20100000000fc671201000000004400000000000000",
        "verdict": "PROVEN — the cmd EXISTS in the firmware dispatch table; "
                   "tag == declared paramsSize byte-exact",
        "handler_walk": "lab/jalon411/v424_handler_walk.py / v424_entry_calib.py — "
                        "the handler block [0x11267fc..0x1126826) sets bit 0x400000 at "
                        "state+0x520 and state+0x52c, zeroes state+0x3d0, then joins the "
                        "shared path returning NV_ERR_INVALID_STATE (0x40, nvstatuscodes.h:93). "
                        "It NEVER loads/stores the RPC params.",
    }

    # --- 2. the signature hunt, whole payload ---
    all_hits = hunt(data, list(SIGS.keys()))
    out["signature_hits_whole"] = {str(k): v for k, v in all_hits.items() if v["offsets"]}

    # --- 3. the GET_EDPP_LIMIT_INFO_PARAMS structural test ---
    # limitMax=250000 @104 => the struct would start at 96
    struct_test = {"hypothesis_base": None, "verdict": None, "window": {}}
    off250 = all_hits[250000]["offsets"]
    if off250:
        base = off250[0] - 8  # limitMin is 2 u32 before limitMax
        struct_test["hypothesis_base"] = base
        window = {}
        for i, name in enumerate(EDPP_INFO_FIELDS):
            o = base + 4 * i
            window[name] = {"offset": o, "raw": u32le(data, o),
                            "W": u32le(data, o) / 1000.0}
        struct_test["window"] = window
        # the proven test: limitMin == 100000 AND limitRated == 240000 AND limitMax == 250000
        vals = [window[f]["raw"] for f in EDPP_INFO_FIELDS[:3]]
        if vals == [100000, 240000, 250000]:
            struct_test["verdict"] = ("PROVEN — limitMin=100000 @%d, limitRated=240000 @%d, "
                                      "limitMax=250000 @%d are CONSECUTIVE u32s in the header's "
                                      "field order" % (base, base + 4, base + 8))
        else:
            struct_test["verdict"] = "NOT PROVEN at this base — vals %s" % vals
    out["edpp_info_struct_test"] = struct_test

    # --- 4. the full u32 census of the params (aligned only) ---
    census = []
    for off in range(PARAMS_OFF, len(data) - 3, 4):
        v = u32le(data, off)
        note = ""
        for val, (_, label) in SIGS.items():
            if v == val:
                note = label
        poff = off - PARAMS_OFF
        census.append({"poff": poff, "raw": v, "note": note})
    out["params_u32_census_nonzero"] = [c for c in census if c["raw"] != 0]

    # --- 5. the stats ---
    vals = [c["raw"] for c in census]
    out["params_stats"] = {
        "u32_count": len(census),
        "nonzero_count": sum(1 for v in vals if v != 0),
        "powerlike_count": sum(1 for v in vals if 50000 <= v <= 400000 and v % 500 == 0),
        "distinct_nonzero": len(set(v for v in vals if v != 0)),
        "top_nonzero": [(hex(v), n) for v, n in Counter(vals).most_common(12) if v],
    }
    json.dump(out, open(OUT, "w"), indent=1)

    # --- the report ---
    print(f"payload {len(data)} B, sha256 {out['sha256'][:16]}…")
    print(f"cmd=0x{cmd:08x} {hdr['cmd_resolved']}")
    print(f"paramsSize={hdr['paramsSize']} (declared) vs {hdr['params_actual_size']} (actual) "
          f"match={hdr['paramsSize_matches_body']}")
    print(f"hClient=0x{hdr['hClient']:x} hObject=0x{hdr['hObject']:x} status=0x{hdr['status']:x} "
          f"rmapiRpcFlags=0x{hdr['rmapiRpcFlags']:x} rmctrlFlags=0x{hdr['rmctrlFlags']:x} "
          f"rmctrlAccessRight=0x{hdr['rmctrlAccessRight']:x} reserved0=0x{hdr['reserved0']:x}")
    print("\n=== signature hits (whole payload) ===")
    for val, h in all_hits.items():
        if h["offsets"]:
            print(f"  {val:>7} ({h['label']}): offsets {h['offsets']}")
    print("\n=== the GET_EDPP_LIMIT_INFO_PARAMS test ===")
    print(f"  base hypothesis: {struct_test['hypothesis_base']}")
    print(f"  verdict: {struct_test['verdict']}")
    for name, w in struct_test["window"].items():
        print(f"    {name:>15}: @{w['offset']} = {w['raw']:>12} ({w['W']:>8.1f} W)")
    print(f"\nparams: {out['params_stats']['u32_count']} u32s, "
          f"{out['params_stats']['nonzero_count']} nonzero, "
          f"{out['params_stats']['powerlike_count']} power-like")
    print("top values:", out["params_stats"]["top_nonzero"])


if __name__ == "__main__":
    main()
