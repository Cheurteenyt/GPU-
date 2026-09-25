#!/usr/bin/env python3
"""4.57 pass, T1 — THE TRANSPOSE: the cmpunlocker mechanism ported to
610.57.04/GA104 (device 0x2488).

The reference = imports/cmpunlocker/sec2-postbl.patch (470 lines, read
and decoded 2026-09-25): the SEC2 POSTBL timing lane — the Booter
RE-EXECUTED as the write primitive. This instrument:
  1. applies the transpose by EXACT ANCHORS to a pristine 610.57.04
     tree (every anchor asserted count==1 — no fuzz, no offsets);
  2. emits lab/jalon411/sec2-postbl-ga104-610.57.04.patch (the DKMS-day
     artifact, -p1 style like the reference);
  3. selftests the transpose (the law: the selftest catches the bugs
     BEFORE the founder/machine):
     V1  anchors unique in the pristine sources;
     V2  the emitted patch re-applies with patch(1) --dry-run, zero
         fuzz, on a pristine mock tree;
     V3  value invariants — the device gate 0x2488, the 0xf800
         memdesc, the 0x4a7 fill, the 0xc0deca7e canaries, the ROP
         chain tail 0xf754..0xf7f8 byte-exact vs the reference table,
         the 11-entry PLM table, the WPR2 re-write pair, the LMR/CFG1
         else-branch values, the refill ORDER (map->fill->unmap->
         flush(sig)->re-point->flush(desc) = THE r0/r1 lesson), the
         rebuild, the hook position (after kgspPrepareForBootstrap_HAL);
     V4  zero linux headers in the added text (the TU RM law);
     V5  THE 4.44 LAW: the C fill = byte-exact vs the python builder
         model (the PutU32 calls parsed from the transposed source and
         replayed against a 0xf800 buffer);
     V6  determinism: two runs = identical patch bytes.

The documented deviations from the reference (the founder reviews):
  D1  the rebuild ALSO flushes the signature memdesc after the stock
      copy (the reference flushes the WPR_META desc only) — our 4.45
      stale-cache lesson applies to the final booter run too;
  D2  the dmem.bin loader is NOT ported (os_open_and_read_file does
      not exist in 610.57.04) — the built-in payload = the only fill;
  D3  the device gate = 0x2488 alone; the LMR/CFG1 = the reference's
      else branch {0x02669000, 0x28A} per the mission 4.57 (g) — the
      8GB GA104 encoding = INDECIDABLE-BY-BYTES (named in findings);
  D4  the static-info FB remap hunk (the reference's 9th hunk) is NOT
      ported — CMP-specific, outside the mission's (a)-(g).

Output: lab/jalon411/sec2-postbl-ga104-610.57.04.patch
"""
import argparse
import difflib
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "lab/jalon411/sec2-postbl-ga104-610.57.04.patch"

# The pristine 610.57.04 tree (outside the repo, the 4.56 convention).
SRC_DEFAULT = Path("/home/z/my-project/ogkm-610")

K_C = "src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
H_NVOC = "src/nvidia/generated/g_kernel_gsp_nvoc.h"

# ---------------------------------------------------------------------------
# The C text blocks (r-strings — the \n inside them = the C source's own).
# ---------------------------------------------------------------------------

NVOC_ANCHOR = (
    "    MEMORY_DESCRIPTOR *pGspUCodeRadix3Descriptor;\n"
    "    MEMORY_DESCRIPTOR *pSignatureMemdesc;"
)
NVOC_NEW = (
    "    MEMORY_DESCRIPTOR *pGspUCodeRadix3Descriptor;\n"
    "    NvU8 *pStockSignatureData;\n"
    "    NvU64 stockSignatureSize;\n"
    "    MEMORY_DESCRIPTOR *pSignatureMemdesc;"
)

C_DEFINES_ANCHOR = '#include "crashcat/crashcat_report.h"\n'

C_DEFINES = r'''
//
// SEC2 POSTBL timing transpose (pass 4.57) — the cmpunlocker mechanism
// (imports/cmpunlocker/sec2-postbl.patch) ported to 610.57.04/GA104.
// The write primitive = the Booter RE-EXECUTED (kgspExecuteBooterLoad_HAL)
// — the POSTBL lane, NOT the 4.45 portMemCopy lane. The cache flush x2 in
// the refill = the r0/r1 machine lesson paid.
//
#define SEC2_POSTBL_TIMING_GA104_PCI_DEVICE_ID          0x2488
#define SEC2_POSTBL_TIMING_SIGNATURE_SIZE               0x0000f800ULL
#define SEC2_POSTBL_TIMING_FILL_DWORD                   0x000004a7U

// 610.57.04 uses the plain WPR meta (no V1); the guard keeps the
// transpose portable across the drivers that renamed the struct.
#ifdef GSP_FW_WPR_META_V1_H_
#define SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)      ((pKernelGsp)->pWprMetaV1)
#define SEC2_POSTBL_TIMING_WPR_META_DESC(pKernelGsp) ((pKernelGsp)->pWprMetaV1Descriptor)
#else
#define SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)      ((pKernelGsp)->pWprMeta)
#define SEC2_POSTBL_TIMING_WPR_META_DESC(pKernelGsp) ((pKernelGsp)->pWprMetaDescriptor)
#endif

NV_STATUS kgspSec2PostblTimingRefillPayload(OBJGPU *pGpu, KernelGsp *pKernelGsp,
                                            NvU32 writeAddr, NvU32 writeValue);
NV_STATUS kgspSec2PostblTimingRebuildStockSignature(OBJGPU *pGpu, KernelGsp *pKernelGsp);

static NvBool
_kgspSec2PostblTimingEnabled(OBJGPU *pGpu)
{
    NvU32 devId = pGpu->idInfo.PCIDeviceID >> 16;
    return (devId == SEC2_POSTBL_TIMING_GA104_PCI_DEVICE_ID);
}
'''

WPR2_BYPASS_OLD = (
    "    // Fail early if WPR2 is up\n"
    "    if (kgspIsWpr2Up_HAL(pGpu, pKernelGsp) &&\n"
)
WPR2_BYPASS_NEW = (
    "    // Fail early if WPR2 is up (bypassed on the POSTBL-timing device:\n"
    "    // the reference's exact behavior — the gated lane proceeds even\n"
    "    // when a previous attempt left WPR2 up)\n"
    "    if (!_kgspSec2PostblTimingEnabled(pGpu) && kgspIsWpr2Up_HAL(pGpu, pKernelGsp) &&\n"
)

POPULATE_ANCHOR = (
    "    NV_CHECK_OK_OR_RETURN(LEVEL_ERROR, kgspPopulateWprMeta_HAL(pGpu, pKernelGsp, pGspFw));\n"
    "\n"
    "    {\n"
    "        // If the new FB layout requires a scrubber ucode to scrub additional space, prepare it now\n"
)
POPULATE_NEW = (
    "    NV_CHECK_OK_OR_RETURN(LEVEL_ERROR, kgspPopulateWprMeta_HAL(pGpu, pKernelGsp, pGspFw));\n"
    "\n"
    "    if (_kgspSec2PostblTimingEnabled(pGpu))\n"
    "    {\n"
    "        NV_PRINTF(LEVEL_ERROR,\n"
    "                  \"SEC2_DEBUG: WPR meta fbSize=0x%016llx wprEnd=0x%016llx \"\n"
    "                  \"heapSize=0x%016llx\\n\",\n"
    "                  SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->fbSize,\n"
    "                  SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->gspFwWprEnd,\n"
    "                  SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->gspFwHeapSize);\n"
    "    }\n"
    "\n"
    "    {\n"
    "        // If the new FB layout requires a scrubber ucode to scrub additional space, prepare it now\n"
)

HOOK_ANCHOR = (
    "    // Setup arguments for bootstrapping GSP\n"
    "    NV_CHECK_OK_OR_RETURN(LEVEL_ERROR, kgspPrepareForBootstrap_HAL(pGpu, pKernelGsp, KGSP_BOOT_MODE_NORMAL));\n"
)

C_HOOK = r'''

    if (_kgspSec2PostblTimingEnabled(pGpu))
    {
        NvU32 devId = pGpu->idInfo.PCIDeviceID >> 16;
        NvU32 plmIdx, attempt;
        NV_STATUS plmStatus;

        static const struct { NvU32 addr; NvU32 value; const char *name; } plmTable[] = {
            { 0x001fa7ccU, 0xfffff0ffU, "WPR_CFG" },
            { 0x009a0148U, 0xffffffffU, "FBPA" },
            { 0x001fa7c4U, 0xffffffffU, "WPR" },
            { 0x00823804U, 0xffffffffU, "FEAT" },
            { 0x00088ff4U, 0xffffffffU, "XVE" },
            { 0x00088ab4U, 0xffffffffU, "XVE_B" },
            { 0x00088ff8U, 0xffffffffU, "XVE_C" },
            { 0x00823b00U, 0xffffffffU, "FEAT2" },
            { 0x008200fcU, 0xffffffffU, "OPT_PLM" },
            { 0x0000c840U, 0xffffffffU, "PJTAG_PLM" },
            { 0x0000c848U, 0xffffffffU, "PJTAG_SEC_PLM" },
        };
        // The PLM addresses = the reference (cmpunlocker, GA100 CMP) — the
        // GA104 decode = INDECIDABLE-BY-BYTES (the O5 map, pass 4.56): the
        // read-back below = the only judge on OUR silicon.

        NvU32 wpr2Lo = GPU_REG_RD32(pGpu, 0x001fa824U);
        NvU32 wpr2Hi = GPU_REG_RD32(pGpu, 0x001fa828U);
        NV_PRINTF(LEVEL_ERROR,
                  "SEC2_DEBUG: saved WPR2 lo=0x%08x hi=0x%08x\n",
                  wpr2Lo, wpr2Hi);

        for (plmIdx = 0; plmIdx < 11; plmIdx++)
        {
            NvBool opened = NV_FALSE;
            for (attempt = 0; attempt < 2 && !opened; attempt++)
            {
                GPU_REG_WR32(pGpu, 0x001fa824U, wpr2Lo);
                GPU_REG_WR32(pGpu, 0x001fa828U, wpr2Hi);

                plmStatus = kgspSec2PostblTimingRefillPayload(pGpu, pKernelGsp,
                    plmTable[plmIdx].addr, plmTable[plmIdx].value);
                if (plmStatus != NV_OK)
                    continue;

                // THE WRITE PRIMITIVE: the booter RE-EXECUTED — the POSTBL
                // signature pass = the hijacked lane (the refilled payload
                // = the ROP source; the WPR_META desc = the mailbox arg).
                plmStatus = kgspExecuteBooterLoad_HAL(pGpu, pKernelGsp,
                    memdescGetPhysAddr(SEC2_POSTBL_TIMING_WPR_META_DESC(pKernelGsp), AT_GPU, 0));

                NvU32 regVal = GPU_REG_RD32(pGpu, plmTable[plmIdx].addr);
                NV_PRINTF(LEVEL_ERROR,
                          "SEC2_DEBUG: PLM[%u] %s(0x%x) attempt=%u status=0x%x reg=0x%08x\n",
                          plmIdx, plmTable[plmIdx].name,
                          plmTable[plmIdx].addr, attempt, plmStatus, regVal);

                if (regVal == plmTable[plmIdx].value)
                    opened = NV_TRUE;
            }
            if (!opened)
                NV_PRINTF(LEVEL_ERROR,
                          "SEC2_DEBUG: FAILED to open %s after 2 attempts\n",
                          plmTable[plmIdx].name);
        }

        GPU_REG_WR32(pGpu, 0x001fa824U, wpr2Lo);
        GPU_REG_WR32(pGpu, 0x001fa828U, wpr2Hi);

        NV_PRINTF(LEVEL_ERROR,
                  "SEC2_DEBUG: PLMs: FEAT=0x%08x FBPA=0x%08x WPR=0x%08x WPR_CFG=0x%08x\n",
                  GPU_REG_RD32(pGpu, 0x00823804U),
                  GPU_REG_RD32(pGpu, 0x009a0148U),
                  GPU_REG_RD32(pGpu, 0x001fa7c4U),
                  GPU_REG_RD32(pGpu, 0x001fa7ccU));

        {
            // The LMR/CFG1 re-config = the reference's else branch = OUR
            // values (mission 4.57 (g)). INDECIDABLE-BY-BYTES for the 8GB
            // GA104 encoding — the read-back = the ledger; the runbook §2
            // records what sticks.
            NvU32 cfg1Value = 0x02669000U;
            NvU32 lmrValue  = 0x0000028AU;

            GPU_REG_WR32(pGpu, 0x0082381cU, 0x88888888U);
            GPU_REG_WR32(pGpu, 0x00823820U, 0x00000008U);
            GPU_REG_WR32(pGpu, 0x009a0204U, cfg1Value);
            GPU_REG_WR32(pGpu, 0x00100ce0U, lmrValue);

            NV_PRINTF(LEVEL_ERROR,
                      "SEC2_DEBUG: POST-WRITE SS0=0x%08x SS1=0x%08x "
                      "CFG1=0x%08x LMR=0x%08x (devId=0x%x)\n",
                      GPU_REG_RD32(pGpu, 0x0082381cU),
                      GPU_REG_RD32(pGpu, 0x00823820U),
                      GPU_REG_RD32(pGpu, 0x009a0204U),
                      GPU_REG_RD32(pGpu, 0x00100ce0U),
                      devId);
        }

        plmStatus = kgspSec2PostblTimingRebuildStockSignature(pGpu, pKernelGsp);
        if (plmStatus != NV_OK)
        {
            NV_PRINTF(LEVEL_ERROR,
                      "SEC2_DEBUG: rebuild stock signature failed: 0x%x\n", plmStatus);
            return plmStatus;
        }

        NV_CHECK_OK_OR_RETURN(LEVEL_ERROR, kgspPopulateWprMeta_HAL(pGpu, pKernelGsp, pGspFw));

        NV_PRINTF(LEVEL_ERROR,
                  "SEC2_DEBUG: WPR meta updated fbSize=0x%016llx wprStart=0x%016llx "
                  "wprEnd=0x%016llx heapOffset=0x%016llx heapSize=0x%016llx\n",
                  SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->fbSize,
                  SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->gspFwWprStart,
                  SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->gspFwWprEnd,
                  SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->gspFwHeapOffset,
                  SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->gspFwHeapSize);
    }
'''

HELPERS_ANCHOR = "static NV_STATUS\n_kgspCreateSignatureMemdesc\n(\n"

C_HELPERS = r'''
static void
_kgspSec2PostblTimingPutU32(NvU8 *pBuffer, NvU32 offset, NvU32 value)
{
    pBuffer[offset + 0] = (NvU8)(value >>  0);
    pBuffer[offset + 1] = (NvU8)(value >>  8);
    pBuffer[offset + 2] = (NvU8)(value >> 16);
    pBuffer[offset + 3] = (NvU8)(value >> 24);
}

static void
_kgspSec2PostblTimingFillPayload(NvU8 *pSignatureVa, NvU64 signatureSize,
                                NvU32 writeAddr, NvU32 writeValue)
{
    NvU64 i;

    for (i = 0; i + sizeof(NvU32) <= signatureSize; i += sizeof(NvU32))
        _kgspSec2PostblTimingPutU32(pSignatureVa, (NvU32)i, SEC2_POSTBL_TIMING_FILL_DWORD);

    _kgspSec2PostblTimingPutU32(pSignatureVa, 0x1100, 0x00000007U);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0x5b40, 0xc0deca7eU);

    // The ROP chain tail — the reference layout (the GA100 BROM gadgets
    // 0x0cbd/0x1fbd/0x7f2f/0x0ccb). For the GA104 = INDECIDABLE-BY-BYTES
    // (the ROM differs — findings-4.57): the layout stays byte-exact =
    // the emulator's model; the gadget sweep = the named contingence.
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf754, writeValue);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf758, 0xc0deca7eU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf75c, 0x00000cbdU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf76c, writeAddr);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf774, 0x00001fbdU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf780, 0x00000000U);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf788, 0x000010aaU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf78c, 0x0000815aU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf790, 0x00008e18U);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf794, 0xc0deca7eU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf798, 0x0000815aU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf79c, 0x00000000U);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7a0, 0xc0deca7eU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7a4, 0x00001fbdU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7b0, 0x0000ffbcU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7b8, 0x0000582dU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7c4, 0xc0deca7eU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7c8, 0x00000cbdU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7d8, 0x00000003U);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7e0, 0x00001fbdU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7f4, 0x00000ccbU);
    _kgspSec2PostblTimingPutU32(pSignatureVa, 0xf7f8, 0x00007f2fU);
}

// THE CRITICAL SEQUENCE (the r0/r1 lesson paid): map -> fill -> unmap ->
// flush(signature) -> re-point WPR_META -> flush(WPR_META desc). The
// booter's DMA reads the SYSMEM copy — the stale CPU-cache data = what
// the 4.45 machine day starved on.
NV_STATUS
kgspSec2PostblTimingRefillPayload(OBJGPU *pGpu, KernelGsp *pKernelGsp,
                                 NvU32 writeAddr, NvU32 writeValue)
{
    NvU8 *pSignatureVa;

    if (pKernelGsp->pSignatureMemdesc == NULL)
        return NV_ERR_INVALID_STATE;

    pSignatureVa = memdescMapInternal(pGpu, pKernelGsp->pSignatureMemdesc, TRANSFER_FLAGS_NONE);
    if (pSignatureVa == NULL)
        return NV_ERR_INSUFFICIENT_RESOURCES;

    _kgspSec2PostblTimingFillPayload(pSignatureVa,
        memdescGetSize(pKernelGsp->pSignatureMemdesc), writeAddr, writeValue);

    memdescUnmapInternal(pGpu, pKernelGsp->pSignatureMemdesc, 0);
    memdescFlushCpuCaches(pGpu, pKernelGsp->pSignatureMemdesc);

    if (SEC2_POSTBL_TIMING_WPR_META(pKernelGsp) != NULL)
    {
        SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->sysmemAddrOfSignature =
            memdescGetPhysAddr(pKernelGsp->pSignatureMemdesc, AT_GPU, 0);
        SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->sizeOfSignature =
            memdescGetSize(pKernelGsp->pSignatureMemdesc);
    }

    if (SEC2_POSTBL_TIMING_WPR_META_DESC(pKernelGsp) != NULL)
        memdescFlushCpuCaches(pGpu, SEC2_POSTBL_TIMING_WPR_META_DESC(pKernelGsp));

    return NV_OK;
}

'''

SIGSIZE_OLD = (
    "    NV_STATUS status = NV_OK;\n"
    "    NvU8 *pSignatureVa = NULL;\n"
    "    NvU64 flags = MEMDESC_FLAGS_NONE;\n"
)
SIGSIZE_NEW = (
    "    NV_STATUS status = NV_OK;\n"
    "    NvU8 *pSignatureVa = NULL;\n"
    "    NvBool bPostbl = _kgspSec2PostblTimingEnabled(pGpu);\n"
    "    NvU64 sigSize = bPostbl ? SEC2_POSTBL_TIMING_SIGNATURE_SIZE\n"
    "                            : NV_ALIGN_UP(pGspFw->signatureSize, 256);\n"
    "    NvU64 flags = MEMDESC_FLAGS_NONE;\n"
)

MEMDSC_OLD = (
    "        memdescCreate(&pKernelGsp->pSignatureMemdesc, pGpu,\n"
    "            NV_ALIGN_UP(pGspFw->signatureSize, 256), 256,\n"
)
MEMDSC_NEW = (
    "        memdescCreate(&pKernelGsp->pSignatureMemdesc, pGpu,\n"
    "            sigSize, 256,\n"
)

FILL_OLD = (
    "    portMemCopy(pSignatureVa, memdescGetSize(pKernelGsp->pSignatureMemdesc),\n"
    "        pGspFw->pSignatureData, pGspFw->signatureSize);\n"
    "\n"
    "    memdescUnmapInternal(pGpu, pKernelGsp->pSignatureMemdesc, 0);\n"
)

FILL_NEW = (
    "    if (bPostbl)\n"
    "    {\n"
    "        // The stock signature = saved for the rebuild (the end of\n"
    "        // boot); the memdesc content = the POSTBL payload from\n"
    "        // creation on.\n"
    "        if (pGspFw->pSignatureData != NULL && pGspFw->signatureSize > 0)\n"
    "        {\n"
    "            pKernelGsp->stockSignatureSize = pGspFw->signatureSize;\n"
    "            pKernelGsp->pStockSignatureData = portMemAllocNonPaged(pGspFw->signatureSize);\n"
    "            if (pKernelGsp->pStockSignatureData != NULL)\n"
    "            {\n"
    "                portMemCopy(pKernelGsp->pStockSignatureData, pGspFw->signatureSize,\n"
    "                            pGspFw->pSignatureData, pGspFw->signatureSize);\n"
    "                NV_PRINTF(LEVEL_ERROR,\n"
    "                          \"SEC2_DEBUG: saved stock signature (%llu bytes)\\n\",\n"
    "                          (unsigned long long)pGspFw->signatureSize);\n"
    "            }\n"
    "        }\n"
    "\n"
    "        // The built-in payload only — the reference's dmem.bin loader\n"
    "        // is NOT ported: os_open_and_read_file does not exist in\n"
    "        // 610.57.04 (deviation D2, findings-4.57).\n"
    "        _kgspSec2PostblTimingFillPayload(pSignatureVa,\n"
    "            memdescGetSize(pKernelGsp->pSignatureMemdesc),\n"
    "            0x009a0148U, 0xffffffffU);\n"
    "        memdescFlushCpuCaches(pGpu, pKernelGsp->pSignatureMemdesc);\n"
    "    }\n"
    "    else\n"
    "    {\n"
    "        portMemCopy(pSignatureVa, memdescGetSize(pKernelGsp->pSignatureMemdesc),\n"
    "            pGspFw->pSignatureData, pGspFw->signatureSize);\n"
    "    }\n"
    "\n"
    "    memdescUnmapInternal(pGpu, pKernelGsp->pSignatureMemdesc, 0);\n"
)

REBUILD_ANCHOR = (
    "fail_create:\n"
    "    memdescDestroy(pKernelGsp->pSignatureMemdesc);\n"
    "    pKernelGsp->pSignatureMemdesc = NULL;\n"
    "\n"
    "    return status;\n"
    "}\n"
)

C_REBUILD = r'''

NV_STATUS
kgspSec2PostblTimingRebuildStockSignature(OBJGPU *pGpu, KernelGsp *pKernelGsp)
{
    NV_STATUS status = NV_OK;
    NvU8 *pSignatureVa = NULL;
    NvU64 sigSize;
    NvU64 flags = MEMDESC_FLAGS_NONE;

    if (pKernelGsp->pStockSignatureData == NULL || pKernelGsp->stockSignatureSize == 0)
        return NV_ERR_INVALID_STATE;

    if (pKernelGsp->pSignatureMemdesc != NULL)
    {
        memdescFree(pKernelGsp->pSignatureMemdesc);
        memdescDestroy(pKernelGsp->pSignatureMemdesc);
        pKernelGsp->pSignatureMemdesc = NULL;
    }

    sigSize = NV_ALIGN_UP(pKernelGsp->stockSignatureSize, 256);
    flags |= MEMDESC_FLAGS_ALLOC_IN_UNPROTECTED_MEMORY;

    NV_CHECK_OK_OR_RETURN(LEVEL_ERROR,
        memdescCreate(&pKernelGsp->pSignatureMemdesc, pGpu,
            sigSize, 256,
            NV_TRUE, ADDR_SYSMEM, NV_MEMORY_CACHED, flags));

    memdescTagAlloc(status,
            NV_FB_ALLOC_RM_INTERNAL_OWNER_UNNAMED_TAG_16, pKernelGsp->pSignatureMemdesc);
    NV_CHECK_OK_OR_GOTO(status, LEVEL_ERROR, status, rebuild_fail_create);

    pSignatureVa = memdescMapInternal(pGpu, pKernelGsp->pSignatureMemdesc, TRANSFER_FLAGS_NONE);
    NV_CHECK_OK_OR_GOTO(status, LEVEL_ERROR,
        (pSignatureVa != NULL) ? NV_OK : NV_ERR_INSUFFICIENT_RESOURCES,
        rebuild_fail_alloc);

    portMemCopy(pSignatureVa, memdescGetSize(pKernelGsp->pSignatureMemdesc),
                pKernelGsp->pStockSignatureData, pKernelGsp->stockSignatureSize);

    memdescUnmapInternal(pGpu, pKernelGsp->pSignatureMemdesc, 0);

    // Deviation D1 vs the reference: the signature memdesc is flushed
    // too — the final booter run DMA-reads the stock signature, and the
    // 4.45 stale-cache lesson applies here as well.
    memdescFlushCpuCaches(pGpu, pKernelGsp->pSignatureMemdesc);

    if (SEC2_POSTBL_TIMING_WPR_META(pKernelGsp) != NULL)
    {
        SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->sysmemAddrOfSignature =
            memdescGetPhysAddr(pKernelGsp->pSignatureMemdesc, AT_GPU, 0);
        SEC2_POSTBL_TIMING_WPR_META(pKernelGsp)->sizeOfSignature =
            memdescGetSize(pKernelGsp->pSignatureMemdesc);
    }

    if (SEC2_POSTBL_TIMING_WPR_META_DESC(pKernelGsp) != NULL)
        memdescFlushCpuCaches(pGpu, SEC2_POSTBL_TIMING_WPR_META_DESC(pKernelGsp));

    return NV_OK;

rebuild_fail_alloc:
    memdescFree(pKernelGsp->pSignatureMemdesc);

rebuild_fail_create:
    memdescDestroy(pKernelGsp->pSignatureMemdesc);
    pKernelGsp->pSignatureMemdesc = NULL;

    return status;
}
'''

# ---------------------------------------------------------------------------
# The transposition ops. Each op = (name, file, kind, payload):
#   kind "insert-after"  : (anchor, text)
#   kind "replace"       : (old, new)
# Every anchor/old string is asserted count==1 in the pristine source
# (no fuzz — the transpose dies loudly if the tree drifts).
# ---------------------------------------------------------------------------

OPS_K = [
    ("K1-defines",        K_C, "insert-after", (C_DEFINES_ANCHOR, C_DEFINES)),
    ("K2-wpr2-bypass",    K_C, "replace",      (WPR2_BYPASS_OLD, WPR2_BYPASS_NEW)),
    ("K3-populate-print", K_C, "replace",      (POPULATE_ANCHOR, POPULATE_NEW)),
    ("K4-the-hook",       K_C, "insert-after", (HOOK_ANCHOR, C_HOOK)),
    ("K5-helpers",        K_C, "insert-after", (HELPERS_ANCHOR, C_HELPERS)),
    ("K6a-sigsize",       K_C, "replace",      (SIGSIZE_OLD, SIGSIZE_NEW)),
    ("K6b-memdesc",       K_C, "replace",      (MEMDSC_OLD, MEMDSC_NEW)),
    ("K6c-fill",          K_C, "replace",      (FILL_OLD, FILL_NEW)),
    ("K7-rebuild",        K_C, "insert-after", (REBUILD_ANCHOR, C_REBUILD)),
    ("H1-nvoc-fields",    H_NVOC, "replace",   (NVOC_ANCHOR, NVOC_NEW)),
]


def apply_ops(text, fname):
    """Apply the ops for one file; assert every anchor count==1 first."""
    for name, f, kind, payload in OPS_K:
        if f != fname:
            continue
        old, new = payload
        n = text.count(old)
        if n != 1:
            raise AssertionError(f"{name}: anchor count={n} (expected 1) in {fname}")
        if kind == "insert-after":
            text = text.replace(old, old + new, 1)
        else:
            text = text.replace(old, new, 1)
    return text


def build_transposed(src_dir):
    c = (src_dir / K_C).read_text()
    h = (src_dir / H_NVOC).read_text()
    return apply_ops(c, K_C), apply_ops(h, H_NVOC)


def emit_diff(src_dir, new_c, new_h):
    old_c = (src_dir / K_C).read_text()
    old_h = (src_dir / H_NVOC).read_text()
    d1 = list(difflib.unified_diff(old_h.splitlines(keepends=True),
                                   new_h.splitlines(keepends=True),
                                   fromfile="a/" + H_NVOC, tofile="b/" + H_NVOC))
    d2 = list(difflib.unified_diff(old_c.splitlines(keepends=True),
                                   new_c.splitlines(keepends=True),
                                   fromfile="a/" + K_C, tofile="b/" + K_C))
    return "".join(d1) + "".join(d2)


# ---------------------------------------------------------------------------
# The selftest — the batteries V1..V6.
# ---------------------------------------------------------------------------

# The ROP chain tail = the reference table byte-exact (offset, value);
# writeAddr/writeValue = the two parameterized slots (None here).
CHAIN = [
    (0xf754, None),        # writeValue (param)
    (0xf758, 0xc0deca7e),
    (0xf75c, 0x00000cbd),  # gadget 1 (GA100 — INDECIDABLE on GA104)
    (0xf76c, None),        # writeAddr (param)
    (0xf774, 0x00001fbd),  # gadget 2
    (0xf780, 0x00000000),
    (0xf788, 0x000010aa),
    (0xf78c, 0x0000815a),
    (0xf790, 0x00008e18),
    (0xf794, 0xc0deca7e),
    (0xf798, 0x0000815a),
    (0xf79c, 0x00000000),
    (0xf7a0, 0xc0deca7e),
    (0xf7a4, 0x00001fbd),
    (0xf7b0, 0x0000ffbc),
    (0xf7b8, 0x0000582d),
    (0xf7c4, 0xc0deca7e),
    (0xf7c8, 0x00000cbd),
    (0xf7d8, 0x00000003),
    (0xf7e0, 0x00001fbd),
    (0xf7f4, 0x00000ccb),  # gadget 3
    (0xf7f8, 0x00007f2f),  # gadget 4
]

PLM_TABLE = [
    (0x001fa7cc, 0xfffff0ff, "WPR_CFG"),
    (0x009a0148, 0xffffffff, "FBPA"),
    (0x001fa7c4, 0xffffffff, "WPR"),
    (0x00823804, 0xffffffff, "FEAT"),
    (0x00088ff4, 0xffffffff, "XVE"),
    (0x00088ab4, 0xffffffff, "XVE_B"),
    (0x00088ff8, 0xffffffff, "XVE_C"),
    (0x00823b00, 0xffffffff, "FEAT2"),
    (0x008200fc, 0xffffffff, "OPT_PLM"),
    (0x0000c840, 0xffffffff, "PJTAG_PLM"),
    (0x0000c848, 0xffffffff, "PJTAG_SEC_PLM"),
]


def py_fill(size, write_addr, write_value):
    """The python builder model of _kgspSec2PostblTimingFillPayload."""
    buf = bytearray(size)
    for off in range(0, size - 3, 4):
        buf[off:off + 4] = (0x000004a7).to_bytes(4, "little")
    def put(o, v):
        buf[o:o + 4] = (v & 0xffffffff).to_bytes(4, "little")
    put(0x1100, 0x00000007)
    put(0x5b40, 0xc0deca7e)
    for off, val in CHAIN:
        put(off, write_addr if (off == 0xf76c) else
                 (write_value if off == 0xf754 else val))
    return bytes(buf)


def c_model_from_source(src_c):
    """Parse the PutU32 constants out of the TRANSPOSED C source and
    replay them over a 0xf800 buffer = the C's own byte map."""
    sig = src_c.index("_kgspSec2PostblTimingFillPayload(NvU8")
    body = src_c[sig:sig + 6000]
    body = body[:body.index("\n}\n") + 3]
    size = 0x0000f800
    buf = bytearray(size)
    for off in range(0, size - 3, 4):
        buf[off:off + 4] = (0x000004a7).to_bytes(4, "little")
    puts = re.findall(r"_kgspSec2PostblTimingPutU32\(pSignatureVa, "
                      r"(0x[0-9a-fA-F]+), ([^\)]+)\);", body)
    def val_of(expr):
        expr = expr.strip()
        if expr in ("writeValue", "writeAddr"):
            return expr
        return int(expr.rstrip("Uu"), 16) if expr.startswith("0x") else int(expr)
    for off_s, vexpr in puts:
        off = int(off_s, 16)
        v = val_of(vexpr)
        if v in ("writeValue",):
            v = 0x5A5A5A5A  # the model's stand-in for the parameter
        elif v in ("writeAddr",):
            v = 0xA5A5A5A5
        buf[off:off + 4] = v.to_bytes(4, "little")
    return bytes(buf)


def run_selftests(src_dir, verbose=True):
    fails = []

    def check(name, cond, detail=""):
        if verbose:
            print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" {detail}" if detail and not cond else ""))
        if not cond:
            fails.append(name)

    src_c = (src_dir / K_C).read_text()
    src_h = (src_dir / H_NVOC).read_text()

    # -- V1: the anchors unique in the pristine sources
    for name, f, _k, (old, _n) in OPS_K:
        text = src_c if f == K_C else src_h
        check(f"V1 {name} anchor unique", text.count(old) == 1,
              f"count={text.count(old)}")

    new_c = apply_ops(src_c, K_C)
    new_h = apply_ops(src_h, H_NVOC)

    # -- V3: the value invariants (on the transposed text)
    check("V3 device gate 0x2488",
          "SEC2_POSTBL_TIMING_GA104_PCI_DEVICE_ID          0x2488" in new_c)
    check("V3 gate is the ONLY enable", "0x20C2" not in new_c and "0x2082" not in new_c)
    check("V3 memdesc 0xf800", "SEC2_POSTBL_TIMING_SIGNATURE_SIZE               0x0000f800ULL" in new_c)
    check("V3 fill 0x4a7", "SEC2_POSTBL_TIMING_FILL_DWORD                   0x000004a7U" in new_c)
    check("V3 canaries x5", new_c.count("0xc0deca7eU") == 5)
    check("V3 sigSize used in memdescCreate", "            sigSize, 256," in new_c)
    check("V3 bPostbl computed", "NvBool bPostbl = _kgspSec2PostblTimingEnabled(pGpu);" in new_c)
    check("V3 nvoc fields", "NvU8 *pStockSignatureData;" in new_h and "NvU64 stockSignatureSize;" in new_h)

    # the PLM table: the 11 entries, values AND names, in order
    tbl_m = re.search(r"plmTable\[\] = \{(.*?)\};", new_c, re.S)
    check("V3 plmTable present", tbl_m is not None)
    if tbl_m:
        rows = re.findall(r"\{ (0x[0-9a-f]{8})U, (0x[0-9a-f]{8})U, \"([A-Z_0-9]+)\" \}",
                          tbl_m.group(1))
        got = [(int(a, 16), int(b, 16), n) for a, b, n in rows]
        check("V3 plmTable 11 entries byte-exact", got == PLM_TABLE, f"got={got!r}")

    # the WPR2 re-write pair + the save
    check("V3 WPR2 save pair",
          "GPU_REG_RD32(pGpu, 0x001fa824U)" in new_c and
          "GPU_REG_RD32(pGpu, 0x001fa828U)" in new_c)
    check("V3 WPR2 re-write pair per attempt + after loop",
          new_c.count("GPU_REG_WR32(pGpu, 0x001fa824U, wpr2Lo)") == 2 and
          new_c.count("GPU_REG_WR32(pGpu, 0x001fa828U, wpr2Hi)") == 2)
    check("V3 booter re-executed with WPR_META desc",
          "kgspExecuteBooterLoad_HAL(pGpu, pKernelGsp,\n"
          "                    memdescGetPhysAddr(SEC2_POSTBL_TIMING_WPR_META_DESC(pKernelGsp), AT_GPU, 0));" in new_c)
    check("V3 2 attempts", "attempt < 2 && !opened" in new_c)

    # the LMR/CFG1 else-branch values + SS0/SS1 + the read-back
    for pat in ["GPU_REG_WR32(pGpu, 0x0082381cU, 0x88888888U);",
                "GPU_REG_WR32(pGpu, 0x00823820U, 0x00000008U);",
                "NvU32 cfg1Value = 0x02669000U;",
                "NvU32 lmrValue  = 0x0000028AU;",
                "GPU_REG_WR32(pGpu, 0x009a0204U, cfg1Value);",
                "GPU_REG_WR32(pGpu, 0x00100ce0U, lmrValue);",
                "SEC2_DEBUG: POST-WRITE SS0=0x%08x SS1=0x%08x "]:
        check(f"V3 {pat[:44]}", pat in new_c)

    # the refill ORDER (the critical sequence): map < fill < unmap <
    # flush(sig) < repoint(sysmemAddrOfSignature=) < flush(desc)
    # (anchor = the DEFINITION — the prototype sits in the K1 block)
    rf = new_c.index("\nNV_STATUS\nkgspSec2PostblTimingRefillPayload")
    rbody = new_c[rf:rf + 2200]
    order = [rbody.index("memdescMapInternal"),
             rbody.index("_kgspSec2PostblTimingFillPayload(pSignatureVa"),
             rbody.index("memdescUnmapInternal"),
             rbody.index("memdescFlushCpuCaches(pGpu, pKernelGsp->pSignatureMemdesc)"),
             rbody.index("->sysmemAddrOfSignature ="),
             rbody.index("memdescFlushCpuCaches(pGpu, SEC2_POSTBL_TIMING_WPR_META_DESC")]
    check("V3 refill order map>fill>unmap>flush>repoint>flush",
          order == sorted(order), f"order={order}")

    # the rebuild: stock data + align + repoint + flush(sig) [D1] + flush(desc)
    # (anchor = the DEFINITION, not the K1 prototype)
    rb = new_c.index("\nNV_STATUS\nkgspSec2PostblTimingRebuildStockSignature")
    rbbody = new_c[rb:rb + 2600]
    check("V3 rebuild guards stock",
          "pKernelGsp->pStockSignatureData == NULL || pKernelGsp->stockSignatureSize == 0" in rbbody)
    check("V3 rebuild align 256", "NV_ALIGN_UP(pKernelGsp->stockSignatureSize, 256)" in rbbody)
    check("V3 rebuild flush sig (D1)",
          rbbody.index("memdescUnmapInternal") <
          rbbody.index("memdescFlushCpuCaches(pGpu, pKernelGsp->pSignatureMemdesc)") <
          rbbody.index("->sysmemAddrOfSignature ="))
    check("V3 rebuild flush desc", "memdescFlushCpuCaches(pGpu, SEC2_POSTBL_TIMING_WPR_META_DESC" in rbbody)

    # the hook POSITION: between PrepareForBootstrap and the relaxed locking
    i_pfb = new_c.index("kgspPrepareForBootstrap_HAL(pGpu, pKernelGsp, KGSP_BOOT_MODE_NORMAL)")
    i_hook = new_c.index("if (_kgspSec2PostblTimingEnabled(pGpu))\n    {\n        NvU32 devId", i_pfb)
    i_lock = new_c.index("_kgspShouldRelaxGspInitLocking", i_pfb)
    check("V3 hook after PrepareForBootstrap, before relaxed locking",
          i_pfb < i_hook < i_lock)
    check("V3 rebuild called in hook",
          new_c.index("kgspSec2PostblTimingRebuildStockSignature(pGpu, pKernelGsp);", i_hook) < i_lock)
    check("V3 populate re-called in hook",
          new_c.index("kgspPopulateWprMeta_HAL(pGpu, pKernelGsp, pGspFw));", i_hook) < i_lock)

    # -- V4: zero linux headers in the ADDED text
    added_c = new_c.replace(src_c, "")
    added_h = new_h.replace(src_h, "")
    for bad in ["#include <linux", '#include "linux', "linux/module", "linux/kernel"]:
        check(f"V4 no linux header ({bad[:20]})",
              bad not in added_c and bad not in added_h)

    # -- V5: THE 4.44 LAW — the C fill = byte-exact vs the python model
    ref = py_fill(0xf800, 0xA5A5A5A5, 0x5A5A5A5A)
    got = c_model_from_source(new_c)
    check("V5 C fill byte-exact vs python model (0xf800)", got == ref,
          "first diff at " + str(next((i for i in range(len(ref)) if ref[i] != got[i]), -1)))
    # the chain slots landed where the reference says
    for off, val in CHAIN:
        if val is None:
            continue
        check(f"V5 chain @0x{off:x}", got[off:off + 4] == val.to_bytes(4, "little"))
    # the parameters took their slots
    check("V5 chain writeValue slot @0xf754", got[0xf754:0xf758] == (0x5A5A5A5A).to_bytes(4, "little"))
    check("V5 chain writeAddr slot @0xf76c", got[0xf76c:0xf770] == (0xA5A5A5A5).to_bytes(4, "little"))
    # the fill field outside the chain = 0x4a7; the two specials
    check("V5 field fill @0x2000", got[0x2000:0x2004] == (0x000004a7).to_bytes(4, "little"))
    check("V5 special @0x1100 = 7", got[0x1100:0x1104] == (7).to_bytes(4, "little"))
    check("V5 canari @0x5b40", got[0x5b40:0x5b44] == (0xc0deca7e).to_bytes(4, "little"))

    return fails, new_c, new_h


def patch_tool_check(src_dir, patch_text, scratch):
    """V2 — the emitted patch applies with patch(1) --dry-run, zero fuzz,
    on a pristine mock tree (the paths a/ b/ stripped with -p1)."""
    tree = scratch / "tree"
    for rel in (K_C, H_NVOC):
        dst = tree / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src_dir / rel, dst)
    pf = scratch / "t.patch"
    pf.write_text(patch_text)
    r = subprocess.run(["patch", "-p1", "--dry-run", "-i", str(pf)],
                       cwd=tree, capture_output=True, text=True)
    ok = r.returncode == 0 and "FAIL" not in r.stdout and "fuzz" not in r.stdout
    return ok, (r.stdout + r.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC_DEFAULT),
                    help="the pristine 610.57.04 tree (kernel-open/src)")
    ap.add_argument("--emit", action="store_true",
                    help="write lab/jalon411/sec2-postbl-ga104-610.57.04.patch")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()
    src = Path(a.src)
    if not (src / K_C).exists():
        print(f"source introuvable: {src / K_C}", file=sys.stderr)
        return 2

    print(f"=== v457a — the transpose selftest (src={src}) ===")
    fails, new_c, new_h = run_selftests(src)
    n_pass = 0

    patch_text = emit_diff(src, new_c, new_h)

    # -- V2: patch(1) --dry-run on a pristine mock tree
    import tempfile
    with tempfile.TemporaryDirectory(dir=Path("/home/z/my-project/scripts")
                                     if Path("/home/z/my-project/scripts").exists()
                                     else None) as td:
        ok, log = patch_tool_check(src, patch_text, Path(td))
        print(f"[{'PASS' if ok else 'FAIL'}] V2 patch(1) --dry-run zero fuzz")
        if not ok:
            print(log)
            fails.append("V2")

    # -- V6: determinism (two builds = identical bytes)
    new_c2, new_h2 = build_transposed(src)
    patch_text2 = emit_diff(src, new_c2, new_h2)
    det = patch_text == patch_text2
    print(f"[{'PASS' if det else 'FAIL'}] V6 determinism")
    if not det:
        fails.append("V6")

    if a.emit:
        out = Path(a.out)
        out.write_text(patch_text)
        n_lines = patch_text.count("\n")
        print(f"emit: {out} ({n_lines} lignes)")

    total = len(fails)
    print(f"=== v457a selftest: {'TOUT VERT' if not fails else f'{total} FAIL'} ===")
    for f in fails:
        print("  FAIL:", f)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
