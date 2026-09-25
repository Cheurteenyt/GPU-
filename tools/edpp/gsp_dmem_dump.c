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
    // v3: the sysmem heap = the PHYS capture (no memdescMap, no RM locks —
    // the nv.c side does phys_to_virt, the v9-scanner trick). The RM-side
    // NV_PRINTF = level-gated (the lesson): the nv.c printk = the ledger.
    NvU64         heapPhys;
    NvU64         heapSize;
    // v4: the descriptor = NULL AT THE HOOK (the boot-B proof) — the object
    // pointers = stable, the LATE read = via pLateFn (the FUNCTION POINTER
    // in the shared state: the gc-sections strips the unreferenced globals —
    // the modpost caught it — the live schedule stores the pointer, the nv.c
    // publisher calls through it; NO cross-TU symbol at all)
    void         *pGpuSaved;
    void         *pKernelGspSaved;
    void         (*pLateFn)(void);
} GSP_DMEM_DUMP_STATE;

// non-static: the nv.c (kernel-open) side reads this for the debugfs publish
GSP_DMEM_DUMP_STATE gspDmemDumpState = { 0 };

void gsp_dmem_dump_late(void);   // the forward decl: the schedule stores the pointer below

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
    gspDmemDumpState.pGpuSaved        = (void *)pGpu;
    gspDmemDumpState.pKernelGspSaved  = (void *)pKernelGsp;
    gspDmemDumpState.pLateFn          = gsp_dmem_dump_late;

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

    // ---- S5: the sysmem heap — v4: the descriptor = NULL at this point
    // (the boot-B proof: phys=0x0). The LATE read = gsp_dmem_dump_late()
    // below, called by the nv.c publisher at +8 s (everything = allocated).
    // This early block = kept for the record of the v3 attempt.

    NV_PRINTF(LEVEL_INFO, "NVRM-451: the surfaces captured — the nv.c side publishes in 8 s\n");
}

// THE LATE CAPTURE (the v4): called BY POINTER (the state's pLateFn) from
// the nv.c publisher at +8 s — the descriptor = allocated by then. The pure
// field reads, no locks. (The gc-sections = cannot strip it: the live
// schedule stores this function's pointer into the shared state.)
void
gsp_dmem_dump_late(void)
{
    KernelGsp *pKernelGsp;

    if (!gspDmemDumpState.captured || gspDmemDumpState.heapPhys != 0)
        return; // the not-captured (the regkey off) or the already-late-captured
    pKernelGsp = (KernelGsp *)gspDmemDumpState.pKernelGspSaved;
    if ((pKernelGsp == NULL) || (pKernelGsp->pSysmemHeapDescriptor == NULL))
        return;
    gspDmemDumpState.heapPhys = memdescGetPhysAddr(pKernelGsp->pSysmemHeapDescriptor, AT_CPU, 0);
    gspDmemDumpState.heapSize = pKernelGsp->pSysmemHeapDescriptor->Size;
}

