#!/usr/bin/env python3
"""4.24 post-PR citation audit — the windowed file:line re-check.

Re-checks every file:line citation of the 4.24 open-source passes
(findings-4.24-edpp-flow.md, findings-4.24-payload-fieldmap.md) against
the RAW open-gpu-kernel-modules TAG 610.57.04 sources. For each citation
(file, cited line, needle) the script searches a ±6-line window and
classifies: EXACT / DECALE (drift, with the delta) / INTROUVABLE.

The sources are fetched once from raw.githubusercontent.com into a
local cache dir (default: lab/jalon411/.ogkm-610-cache/) and reused
from there on later runs. No network at audit time once cached.

Run:  python3 v424_citation_audit.py [--refetch]
Output: the per-citation verdict table + the final tally.
Exit: 0 iff no INTROUVABLE.
"""
import os
import sys
import urllib.request

TAG = "610.57.04"
BASE = f"https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/{TAG}"
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ogkm-610-cache")

FILES = {
    "platform_request_handler.c": "src/nvidia/src/kernel/platform/platform_request_handler.c",
    "platform_request_handler_ctrl.c": "src/nvidia/src/kernel/platform/platform_request_handler_ctrl.c",
    "rpc_common.c": "src/nvidia/src/kernel/rmapi/rpc_common.c",
    "rpc.c": "src/nvidia/src/kernel/vgpu/rpc.c",
    "g_rpc-structures.h": "src/nvidia/generated/g_rpc-structures.h",
    "g_rpc-message-header.h": "src/nvidia/generated/g_rpc-message-header.h",
    "nvstatuscodes.h": "src/common/sdk/nvidia/inc/nvstatuscodes.h",
    "ctrl2080internal.h": "src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080internal.h",
    "platform_request_handler_utils.h": "src/nvidia/inc/kernel/platform/platform_request_handler_utils.h",
    "g_platform_request_handler_nvoc.h": "src/nvidia/generated/g_platform_request_handler_nvoc.h",
}

# (file, cited line, needle substrings (alternation), label)
CITES = [
    # --- edpp-flow: platform_request_handler.c ---
    ("platform_request_handler.c", 384, ["pfmreqhndlrStateInit_IMPL"], "2.0 init fn"),
    ("platform_request_handler.c", 425, ["controlData.bEDPpeakUpdateEnabled"], "2.0 reset init"),
    ("platform_request_handler.c", 502, ["STATE_LOAD_SYNC"], "2.0 load sync"),
    ("platform_request_handler.c", 925, ["_pfmreqhndlrPmgrPmuPostLoadWorkItem"], "2.1 work item"),
    ("platform_request_handler.c", 947, ["bEDPpeakLimitUpdateRequest"], "2.1 toggle cond"),
    ("platform_request_handler.c", 951, ["pfmreqhndlrHandleEdppeakLimitUpdate"], "2.1 toggle call"),
    ("platform_request_handler.c", 983, ["bDifferPlatformEdppLimit"], "2.1 platform defer"),
    ("platform_request_handler.c", 985, ["pfmreqhndlrHandlePlatformEdppLimitUpdate"], "2.1 platform call"),
    ("platform_request_handler.c", 997, ["bDifferPlatformEdppLimit = NV_FALSE"], "2.1 clear flag"),
    ("platform_request_handler.c", 661, ["_SMBPBI_OP_CLEAR"], "SMBPBI 0"),
    ("platform_request_handler.c", 669, ["pfmreqhndlrOperatingLimitUpdate"], "SMBPBI call"),
    # --- edpp-flow: platform_request_handler_ctrl.c ---
    ("platform_request_handler_ctrl.c", 146, ["PFM_REQ_HNDLR_IS_EDPPEAK_UPDATE_REQUIRED"], "1.A macro"),
    ("platform_request_handler_ctrl.c", 1001, ["CMD_GETEDPPLIMIT"], "DSM GETEDPPLIMIT"),
    ("platform_request_handler_ctrl.c", 1019, ["GPS_FUNC_GETEDPPLIMIT"], "GETEDPPLIMIT end"),
    ("platform_request_handler_ctrl.c", 1022, ["CMD_SETEDPPLIMITINFO"], "DSM SETEDPPLIMITINFO"),
    ("platform_request_handler_ctrl.c", 1037, ["GPS_FUNC_SETEDPPLIMITINFO"], "SETEDPPLIMITINFO end"),
    ("platform_request_handler_ctrl.c", 1170, ["_pfmreqhndlrCallPshareStatus(pPlatformRequestHandler, NV_TRUE)"], "2.0 init sensors"),
    ("platform_request_handler_ctrl.c", 1488, ["pfmreqhndlrHandleStatusChangeEvent"], "2.2 event entry"),
    ("platform_request_handler_ctrl.c", 1501, ["_pfmreqhndlrCallPshareStatus"], "2.2 pshare call"),
    ("platform_request_handler_ctrl.c", 1597, ["pfmreqhndlrHandleEdppeakLimitUpdate_IMPL"], "1.A fn"),
    ("platform_request_handler_ctrl.c", 1609, ["UPDATE_EDPP_LIMIT_PARAMS params = { 0 }"], "1.A {0} init"),
    ("platform_request_handler_ctrl.c", 1611, ["params.bEnable = bEnable"], "1.A bEnable"),
    ("platform_request_handler_ctrl.c", 1615, ["PFM_REQ_HNDLR_UPDATE_EDPP_LIMIT"], "1.A rpc cmd"),
    ("platform_request_handler_ctrl.c", 1627, ["controlData.bEDPpeakUpdateEnabled"], "1.A cache upd"),
    ("platform_request_handler_ctrl.c", 1647, ["pfmreqhndlrHandlePlatformEdppLimitUpdate_IMPL"], "1.B fn"),
    ("platform_request_handler_ctrl.c", 1661, ["params.clientLimit = platformEdppLimit"], "1.B clientLimit"),
    ("platform_request_handler_ctrl.c", 1665, ["if (platformEdppLimit == 0)"], "the value 0: if"),
    ("platform_request_handler_ctrl.c", 1667, ["params.bEnable = NV_FALSE"], "the value 0: reset"),
    ("platform_request_handler_ctrl.c", 1672, ["PFM_REQ_HNDLR_UPDATE_EDPP_LIMIT"], "1.B rpc cmd"),
    ("platform_request_handler_ctrl.c", 1697, ["pfmreqhndlrHandlePlatformGetEdppLimit_IMPL"], "1.B get fn"),
    ("platform_request_handler_ctrl.c", 1722, ["*pPlatformEdppLimit"], "1.B result[0]"),
    ("platform_request_handler_ctrl.c", 1738, ["pfmreqhndlrHandlePlatformSetEdppLimitInfo_IMPL"], "2 info fn"),
    ("platform_request_handler_ctrl.c", 1757, ["GET_EDPP_LIMIT_INFO"], "2 info rpc"),
    ("platform_request_handler_ctrl.c", 1762, ["edppLimitInfo.limitMin"], "2 info cache"),
    ("platform_request_handler_ctrl.c", 2337, ["_pfmreqhndlrCallPshareStatus"], "def"),
    ("platform_request_handler_ctrl.c", 2369, ["_PLATFORM_GETEDPPEAKLIMIT_SET"], "PSHARE decode 1"),
    ("platform_request_handler_ctrl.c", 2370, ["_PLATFORM_SETEDPPEAKLIMITINFO_SET"], "PSHARE decode 2"),
    ("platform_request_handler_ctrl.c", 2376, ["_EDPPEAK_LIMIT_UPDATE"], "PSHARE decode 3"),
    ("platform_request_handler_ctrl.c", 2386, ["IS_EDPPEAK_UPDATE_REQUIRED"], "1.A transition"),
    ("platform_request_handler_ctrl.c", 2402, ["bQueryEdppRequired"], "1.B branch"),
    ("platform_request_handler_ctrl.c", 2407, ["HandlePlatformGetEdppLimit(pPlatformRequestHandler"], "1.B GET call"),
    ("platform_request_handler_ctrl.c", 2416, ["PFMREQHNDLRACPIData.platformEdppLimit = platformEdppLimit"], "1.B cache write"),
    ("platform_request_handler_ctrl.c", 2422, ["bDifferPlatformEdppLimit = NV_TRUE"], "1.B defer set"),
    ("platform_request_handler_ctrl.c", 2493, ["bPlatformEdpUpdate"], "2 info branch"),
    ("platform_request_handler_ctrl.c", 2814, ["HandlePlatformSetEdppLimitInfoWorkItem"], "2 work item"),
    ("platform_request_handler_ctrl.c", 2837, ["ulVersion"], "2 ACPI fill start"),
    ("platform_request_handler_ctrl.c", 2849, ["limitBattMax"], "2 ACPI fill end"),
    ("platform_request_handler_ctrl.c", 2858, ["pfmreqhndlrCallACPI"], "2 ACPI call"),
    # --- payload-fieldmap: the transport ---
    ("rpc_common.c", 184, ["pVgpuRpcHeader->length"], "LOI DE LONGUEUR"),
    ("rpc_common.c", 150, ["portMemSet"], "memset send path"),
    ("rpc.c", 10794, ["rpc_params->hClient"], "hClient"),
    ("rpc.c", 10795, ["rpc_params->hObject"], "hObject"),
    ("rpc.c", 10798, ["rmapiRpcFlags  = RMAPI_RPC_FLAGS_NONE"], "flags NONE"),
    ("rpc.c", 10800, ["rmctrlAccessRight = 0"], "accessRight"),
    ("g_rpc-structures.h", 1423, ["rpc_gsp_rm_control_v03_00"], "layout"),
    ("g_rpc-message-header.h", 41, ["rpc_message_header_v03_00"], "header struct"),
    ("nvstatuscodes.h", 93, ["NV_ERR_INVALID_STATE"], "0x40"),
    # --- payload-fieldmap / edpp-flow: the SDK headers ---
    ("ctrl2080internal.h", 3220, ["Updates EDPpeak Limit"], "doc block"),
    ("ctrl2080internal.h", 3238, ["UPDATE_EDPP_LIMIT_PARAMS"], "params struct"),
    ("ctrl2080internal.h", 3239, ["bEnable"], "bEnable field"),
    ("ctrl2080internal.h", 3240, ["clientLimit"], "clientLimit field"),
    ("ctrl2080internal.h", 3988, ["GET_EDPP_LIMIT_INFO_PARAMS"], "info struct"),
    ("ctrl2080internal.h", 3989, ["limitMin"], "limitMin field"),
    ("platform_request_handler_utils.h", 82, ["EDPP_LIMIT_INFO_V1"], "V1 struct"),
    ("platform_request_handler_utils.h", 83, ["ulVersion"], "ulVersion"),
    ("platform_request_handler_utils.h", 84, ["limitLast"], "limitLast"),
    ("platform_request_handler_utils.h", 85, ["limitMin"], "limitMin"),
    ("platform_request_handler_utils.h", 92, ["EDPP_LIMIT_INFO_V1"], "struct end"),
    ("g_platform_request_handler_nvoc.h", 152, ["bEDPpeakLimitUpdateRequest"], "sensorData"),
    ("g_platform_request_handler_nvoc.h", 223, ["bDifferPlatformEdppLimit"], "controlData defer"),
    ("g_platform_request_handler_nvoc.h", 255, ["edppLimit"], "controlData edpp"),
]


def ensure_sources(refetch=False):
    os.makedirs(CACHE, exist_ok=True)
    for short, rel in FILES.items():
        dst = os.path.join(CACHE, short)
        if refetch or not os.path.exists(dst) or os.path.getsize(dst) == 0:
            url = f"{BASE}/{rel}"
            print(f"  fetch {rel} ...")
            urllib.request.urlretrieve(url, dst)


def main():
    refetch = "--refetch" in sys.argv
    ensure_sources(refetch)
    stats = {"EXACT": 0, "DECALE": 0, "INTROUVABLE": 0}
    for fname, cited, needles, label in CITES:
        lines = open(os.path.join(CACHE, fname), encoding="utf-8",
                     errors="replace").read().splitlines()
        found = None
        for w in range(0, 7):
            for ln in ([cited - w] if w == 0 else [cited - w, cited + w]):
                if 1 <= ln <= len(lines) and any(a in lines[ln - 1] for a in needles):
                    found = (ln, lines[ln - 1].strip())
                    break
            if found:
                break
        if not found:
            stats["INTROUVABLE"] += 1
            print(f"[INTROUVABLE] {fname}:{cited} ({label}) needles={needles}")
        else:
            ln, content = found
            delta = ln - cited
            if delta == 0:
                stats["EXACT"] += 1
                print(f"[EXACT      ] {fname}:{cited} ({label})")
            else:
                stats["DECALE"] += 1
                print(f"[DECALE {delta:+d} ] {fname}:{cited} -> {ln} ({label}): {content[:60]}")
    print(f"\nBILAN: {stats['EXACT']} exactes, {stats['DECALE']} decalees, "
          f"{stats['INTROUVABLE']} introuvables / {len(CITES)}")
    sys.exit(1 if stats["INTROUVABLE"] else 0)


if __name__ == "__main__":
    main()
