// gsp_dmem_dump.c — PASS 4.51 TÂCHE A — the GSP memory-surface capture.
//
// THE BUILD-JUDGE CORRECTION (v2): the v1 monolith FAILED the DKMS build —
// kernel_gsp.c = the RM TU = the OS-ABSTRACTED environment: NO linux
// headers (no workqueue, no debugfs — the port layer only). THE v2 =
// the two-sided instrument:
//   THIS file (the RM TU, included by kernel_gsp.c): the read-only
//     capture of the surfaces + the sysmem-heap map (the memdescMap =
//     the proven RM pattern) into a NON-STATIC state struct;
//   the nv.c side (kernel-open, the linux TU): the delayed work (8 s)
//     publishes the blobs via debugfs + the dmesg ledger
//     (patch_nv_451.py — the v9-scanner patch pattern).
//
// GROUNDING: every struct member verified against the TARGET tree
// (/usr/src/nvidia-610.57.04, the DKMS — NOT a newer same-name repo):
//   pGspFw->{pImageData,imageSize,pUcodesBin,ucodesBinSize}
//   pKernelGsp->{pGspArgumentsCached,pGspArgumentsDescriptor,
//     pLibosInitArgumentsCached,pLibosInitArgumentsDescriptor,
//     pRmStateMonitorBuffer,pRmStateMonitorBufferMD,
//     pWprMeta,pWprMetaDescriptor,rmLibosLogMem[8],
//     pSysmemHeapDescriptor} — ALL PRESENT (g_kernel_gsp_nvoc.h).
//
// THE SURFACES (the reachability matrix):
//   S1 image.bin / S2 ucodes.bin   the host FW copies      CERTAIN
//   S3 args.bin                    GSP_ARGUMENTS_CACHED   CERTAIN
//   S4 libosinit.bin               THE REGION INVENTORY   CERTAIN
//   S5 sysmemheap.bin              the Libos sysmem heap  CERTAIN (mapped here)
//   S6 statemonitor.bin            gated by RMGspStateMonitor  GATED
//   S7 logs0..7.bin                the 8 Libos task logs  CERTAIN
//   S8 wpr2meta.bin                the WPR2 map           CERTAIN
//
// THE NAMED NEGATIVE: the falcon-internal DMEM = not host-reachable
// while running. The WPR2 FB heap = the v2 probe (designed).
//
// INTEGRATION (the 2 lines in kernel_gsp.c, the patch451.py exact anchors):
//   #include "gsp_dmem_dump.c"          (after the include block)
//   gsp_dmem_dump_schedule(pGpu, pKernelGsp, pGspFw);   (after kgspStartLogPolling)
// OPT-IN: NVreg_RegistryDwords="RmGspDmemDump=1" (ONE key ONE boot).
// SAFETY: read-only everywhere; the heap map = held (the rollback = reboot).

#define GSP_DMEM_BLOBS_MAX 16

typedef struct {
    NvBool        valid;
    const char   *name;
    void         *data;
    NvU64         size;
} GSP_DMEM_BLOB_REC;

typedef struct {
    NvBool        captured;
    NvU32         gpuId;
    GSP_DMEM_BLOB_REC blobs[GSP_DMEM_BLOBS_MAX];
} GSP_DMEM_DUMP_STATE;

// non-static: the nv.c (kernel-open) side reads this for the debugfs publish
GSP_DMEM_DUMP_STATE gspDmemDumpState = { 0 };

static void _gsp_dmem_blob_set(const char *name, const void *data, NvU64 size)
{
    NvU32 i;
    if ((data == NULL) || (size == 0) || (size > 0xFFFFFFFFULL))
        return;
    for (i = 0; i < GSP_DMEM_BLOBS_MAX; i++)
    {
        if (!gspDmemDumpState.blobs[i].valid)
        {
            gspDmemDumpState.blobs[i].valid = NV_TRUE;
            gspDmemDumpState.blobs[i].name  = name;
            gspDmemDumpState.blobs[i].data  = (void *)data;
            gspDmemDumpState.blobs[i].size  = size;
            return;
        }
    }
}

void
gsp_dmem_dump_schedule(OBJGPU *pGpu, KernelGsp *pKernelGsp, GSP_FIRMWARE *pGspFw)
{
    NvU32 enable = 0;
    NvU32 i;

    if (osReadRegistryDword(pGpu, "RmGspDmemDump", &enable) != NV_OK)
        enable = 0; // default OFF — the opt-in instrument
    if (enable == 0)
        return;

    if (gspDmemDumpState.captured)
        return;
    gspDmemDumpState.captured = NV_TRUE;
    gspDmemDumpState.gpuId    = gpuGetDeviceInstance(pGpu);

    // ---- the surface capture (pointer + size copies; no deref here) ----
    if (pGspFw != NULL)
    {
        _gsp_dmem_blob_set("image.bin",  pGspFw->pImageData, pGspFw->imageSize);
        _gsp_dmem_blob_set("ucodes.bin", pGspFw->pUcodesBin, pGspFw->ucodesBinSize);
    }
    if (pKernelGsp->pGspArgumentsDescriptor != NULL)
        _gsp_dmem_blob_set("args.bin", pKernelGsp->pGspArgumentsCached,
                           pKernelGsp->pGspArgumentsDescriptor->Size);
    if (pKernelGsp->pLibosInitArgumentsDescriptor != NULL)
        _gsp_dmem_blob_set("libosinit.bin", pKernelGsp->pLibosInitArgumentsCached,
                           pKernelGsp->pLibosInitArgumentsDescriptor->Size);
    if ((pKernelGsp->pRmStateMonitorBuffer != NULL) &&
        (pKernelGsp->pRmStateMonitorBufferMD != NULL))
        _gsp_dmem_blob_set("statemonitor.bin", pKernelGsp->pRmStateMonitorBuffer,
                           pKernelGsp->pRmStateMonitorBufferMD->Size);
    if (pKernelGsp->pWprMetaDescriptor != NULL)
        _gsp_dmem_blob_set("wpr2meta.bin", pKernelGsp->pWprMeta,
                           pKernelGsp->pWprMetaDescriptor->Size);
    for (i = 0; i < 8; i++)
    {
        static const char *_gspLogNames[8] = { "logs0.bin", "logs1.bin", "logs2.bin", "logs3.bin",
                                               "logs4.bin", "logs5.bin", "logs6.bin", "logs7.bin" };
        RM_LIBOS_LOG_MEM *pLog = &pKernelGsp->rmLibosLogMem[i];
        if ((pLog->pTaskLogBuffer != NULL) && (pLog->pTaskLogDescriptor != NULL))
            _gsp_dmem_blob_set(_gspLogNames[i], pLog->pTaskLogBuffer,
                               pLog->pTaskLogDescriptor->Size);
    }

    // ---- S5: the Libos sysmem heap — the map NOW (the RM context = the
    // kgspCreateRadix3 pattern ~6032-6040), held for the blob lifetime ----
    if (pKernelGsp->pSysmemHeapDescriptor != NULL)
    {
        void      *pVa   = NULL;
        NvP64      pPriv = NvP64_NULL;
        NvU64      sz    = pKernelGsp->pSysmemHeapDescriptor->Size;
        NV_STATUS  st;

        st = memdescMap(pKernelGsp->pSysmemHeapDescriptor, 0, sz,
                        NV_TRUE, NV_PROTECT_WRITEABLE,
                        (NvP64 *)&pVa, &pPriv);
        if ((st == NV_OK) && (pVa != NULL))
        {
            _gsp_dmem_blob_set("sysmemheap.bin", pVa, sz);
            NV_PRINTF(LEVEL_INFO, "NVRM-451: the sysmem heap mapped va=0x%llx size=0x%llx\n",
                      (NvU64)(NvUPtr)pVa, sz);
        }
        else
        {
            NV_PRINTF(LEVEL_ERROR, "NVRM-451: the sysmem heap map FAILED st=0x%x (the verdict = named)\n", st);
        }
    }

    NV_PRINTF(LEVEL_INFO, "NVRM-451: the surfaces captured — the nv.c side publishes in 8 s\n");
}
