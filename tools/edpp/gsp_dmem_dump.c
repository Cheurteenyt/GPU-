// gsp_dmem_dump.c — PASS 4.51 TÂCHE A — the GSP memory-surface dump instrument.
//
// The design brief (4.51): expose the GSP-RM state surfaces the loader
// already knows, host-side, after the boot, so the v451a fingerprint
// scanner can answer THE MISSING VERDICT: where do the parsed VBIOS
// timing records live at runtime (the f18-analog lane, 4.47 TÂCHE B).
//
// GROUNDING: every struct member below is verified against the open
// source of the EXACT driver tag 610.57.04
// (https://github.com/NVIDIA/open-gpu-kernel-modules/tree/610.57.04):
//   - src/nvidia/generated/g_kernel_gsp_nvoc.h   (the KernelGsp + GSP_FIRMWARE members)
//   - src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c (the call sites, cited per anchor)
//   - src/nvidia/arch/nvalloc/common/inc/gsp/gsp_fw_wpr_meta.h (GspFwWprMeta)
// The build = the judge (the banked 4.44-machine lesson #4). Minor API
// adaptations against the tree are EXPECTED to be zero-or-trivial; every
// place where a variant may exist carries an ANCHOR NOTE with the exact
// reference site.
//
// THE SURFACES (the reachability matrix):
//   S1 image.bin        pGspFw->pImageData / imageSize        host buffer  CERTAIN
//      (the packed WPR2 image host copy — the STATIC reference; the
//       searcher diffs it against the runtime surfaces)
//   S2 ucodes.bin       pGspFw->pUcodesBin / ucodesBinSize    host buffer  CERTAIN
//   S3 args.bin         pKernelGsp->pGspArgumentsCached       mapped       CERTAIN
//      (GSP_ARGUMENTS_CACHED — the argument block GSP-RM booted with)
//   S4 libosinit.bin    pKernelGsp->pLibosInitArgumentsCached mapped       CERTAIN
//      (LibosMemoryRegionInitArgument[] = THE REGION INVENTORY — the
//       map of every memory region GSP-RM believes it owns; this file
//       alone names the heap segments the 4.51 brief calls
//       "connus du loader kernel_gsp.c")
//   S5 sysmemheap.bin   pKernelGsp->pSysmemHeapDescriptor     memdescMap   CERTAIN
//      (the Libos SYSMEM heap: RPC queues, console, host-shared state;
//       mapped here by the work item — the kgspCreateRadix3 map pattern)
//   S6 statemonitor.bin pKernelGsp->pRmStateMonitorBuffer     mapped       GATED
//      (gated by the RM regkey RMGspStateMonitor — the string is IN OUR
//       BANKED rm-strings.txt; when enabled, NVIDIA maps an RM state
//       export host-side. The regkey boot = the runbook B-day.)
//   S7 logs0..7.bin     pKernelGsp->rmLibosLogMem[i].pTaskLogBuffer mapped CERTAIN
//      (the 8 Libos task-log partitions, pointers already mapped)
//   S8 wpr2meta.bin     pKernelGsp->pWprMetaV1 / pWprMetaHopper  mapped  CERTAIN
//      (THE REVIEW FIX: the exact-tree members = the V1/Hopper pair,
//       g_kernel_gsp_nvoc.h 543-548 — there is NO pWprMeta. Ampere = V1.
//       the WPR2 layout: gspFwWprStart, gspFwHeapOffset, gspFwHeapSize,
//       gspFwOffset, bootBinOffset, frtsOffset, gspFwWprEnd — the WPR2
//       map, zero-read risk)
//
// THE NAMED NEGATIVE (honest, per the 4.51 brief): the falcon-INTERNAL
// DMEM of the GSP RISC-V core is NOT host-reachable while GSP-RM runs.
// The WPR2 FB carveout read (the FW heap proper) = the v2 probe:
// mapping an EXISTING FB range CPU-side needs the memdesc-over-phys API
// of this tree (the candidate anchors live in kernel_gsp.c around
// kgspCreateRadix3, ~5930-6045) and the seal's CPU-read behavior is
// UNDECIDABLE until tried. v1 dumps S1-S8. The verdict classes:
//   HIT in S5/S6       -> the records live host-writable state -> route H
//   HIT in S1/S2 only  -> static copies, no runtime parse found -> dig v2
//   MISS everywhere    -> falcon-internal DMEM or the FB FW heap -> v2/WPR2
//
// INTEGRATION (the ONE hook line — the exact anchor text from
// kernel_gsp.c 610.57.04, inside kgspInitRm_IMPL, success path, after
// the log polling starts):
//     NV_CHECK_OK_OR_GOTO(status, LEVEL_ERROR, kgspStartLogPolling(pGpu, pKernelGsp), done);
//     gsp_dmem_dump_schedule(pGpu, pKernelGsp, pGspFw);   // <-- INSERT THIS
// then #include this file ABOVE kgspInitRm_IMPL in kernel_gsp.c (or link
// it and add the prototype). The instrument is OPT-IN via the registry
// key (read at schedule time):
//     NVreg_RegistryDwords="RmGspDmemDump=1"   (ONE key, ONE boot — the doctrine)
// The delay before the dump = 8 s after the hook (RM finishes its init
// RPCs in the window; the delay is a named constant, change here).
// Output: /sys/kernel/debug/gsp_dmem/gpu<N>/{...}.bin (zero-copy debugfs
// blobs into the live mappings) + one dmesg line per surface (the
// nv_printf lesson: prints reach dmesg — the 4.44-machine lesson #3).
//
// ROLLBACK (runbook-451 §6): this file + the one hook line are the ONLY
// changes; restore = `git checkout --
// src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c` in the DKMS tree + dkms
// build/install + limine-mkinitcpio (the UKI lesson — banked). The
// firmware file is NEVER touched (the sha guard in runbook §0).
//
// SAFETY: read-only on every surface; no GSP-visible byte is written;
// the only new behavior = the CPU-side mappings this file holds. Do not
// unload the driver inside the 8 s window (the work holds pointers; the
// runbook's rollback = full reboot into the reverted driver anyway).

// ---------------------------------------------------------------------------
// Included by kernel_gsp.c — reuses the translation unit's includes.
// The two kernel headers below are new to the TU; both are base kernel
// headers and safe to include after nv-linux.h.
// ---------------------------------------------------------------------------
#include <linux/workqueue.h>
#include <linux/debugfs.h>

typedef struct
{
    NvBool        scheduled;
    NvU32         gpuId;
    OBJGPU       *pGpu;
    KernelGsp    *pKernelGsp;
    // the surface records (pointer copies; the memory is owned by the
    // driver's own allocations, alive for the adapter's lifetime)
    const void   *pImage;        NvU64 imageSize;
    const void   *pUcodes;       NvU32 ucodesSize;
    void         *pArgs;         NvU64 argsSize;
    void         *pLibosInit;    NvU64 libosInitSize;
    void         *pStateMon;     NvU64 stateMonSize;
    void         *pWprMeta;      NvU64 wprMetaSize;
    // S5: the sysmem-heap mapping taken by the work itself
    NvU64         sysHeapSize;
    void         *pSysHeapVa;
    NvP64         sysHeapPriv;
    NvBool        sysHeapMapped;
} GSP_DMEM_DUMP_STATE;

static GSP_DMEM_DUMP_STATE _gspDmemDumpState = { 0 };

static void _gsp_dmem_dump_work(struct work_struct *pWork);
static DECLARE_DELAYED_WORK(_gspDmemDumpWork, _gsp_dmem_dump_work);

// ---- the debugfs publication (zero-copy blobs into the live memory) ----

static struct dentry *_gspDmemDebugfsDir = NULL;
// THE REVIEW FIX: the debugfs = ONE component per create — a '/' in the
// name = the VFS rejects it, the one-shot "gsp_dmem/gpuN" dir = never
// appears. The parent then the child:
static struct dentry *_gspDmemDebugfsParent = NULL;

struct _gsp_dmem_blob_rec
{
    const char                   *name;
    struct debugfs_blob_wrapper   wrapper;
    struct dentry                *dentry;
};

static struct _gsp_dmem_blob_rec _gspDmemBlobs[] =
{
    { "image.bin",        { 0 }, NULL },
    { "ucodes.bin",       { 0 }, NULL },
    { "args.bin",         { 0 }, NULL },
    { "libosinit.bin",    { 0 }, NULL },
    { "sysmemheap.bin",   { 0 }, NULL },
    { "statemonitor.bin", { 0 }, NULL },
    { "wpr2meta.bin",     { 0 }, NULL },
    { "logs0.bin",        { 0 }, NULL },
    { "logs1.bin",        { 0 }, NULL },
    { "logs2.bin",        { 0 }, NULL },
    { "logs3.bin",        { 0 }, NULL },
    { "logs4.bin",        { 0 }, NULL },
    { "logs5.bin",        { 0 }, NULL },
    { "logs6.bin",        { 0 }, NULL },
    { "logs7.bin",        { 0 }, NULL },
};

static void
_gsp_dmem_blob_set(const char *name, const void *data, NvU64 size)
{
    NvU32 i;
    if ((data == NULL) || (size == 0) || (size > 0xFFFFFFFFULL))
        return;
    for (i = 0; i < NV_ARRAY_ELEMENTS(_gspDmemBlobs); i++)
    {
        if (portStringCompare(_gspDmemBlobs[i].name, name, 16) == 0)
        {
            _gspDmemBlobs[i].wrapper.data = (void *)data;
            _gspDmemBlobs[i].wrapper.size = (size_t)size;
            break;
        }
    }
}

static void
gsp_dmem_debugfs_publish(void)
{
    NvU32 i;
    char  dirName[24];

    if (_gspDmemDebugfsDir != NULL)
        return; // already published

    if (_gspDmemDebugfsParent == NULL || IS_ERR(_gspDmemDebugfsParent))
        _gspDmemDebugfsParent = debugfs_create_dir("gsp_dmem", NULL);
    if (IS_ERR_OR_NULL(_gspDmemDebugfsParent))
    {
        NV_PRINTF(LEVEL_ERROR, "NVRM-451: the debugfs parent create failed\n");
        _gspDmemDebugfsParent = NULL;
        return;
    }
    snprintf(dirName, sizeof(dirName), "gpu%u", _gspDmemDumpState.gpuId);
    _gspDmemDebugfsDir = debugfs_create_dir(dirName, _gspDmemDebugfsParent);
    if (IS_ERR_OR_NULL(_gspDmemDebugfsDir))
    {
        NV_PRINTF(LEVEL_ERROR, "NVRM-451: debugfs_create_dir(%s) failed\n", dirName);
        _gspDmemDebugfsDir = NULL;
        return;
    }

    for (i = 0; i < NV_ARRAY_ELEMENTS(_gspDmemBlobs); i++)
    {
        struct _gsp_dmem_blob_rec *pRec = &_gspDmemBlobs[i];
        if (pRec->wrapper.data == NULL)
            continue;
        pRec->dentry = debugfs_create_blob(pRec->name, 0400,
                                           _gspDmemDebugfsDir,
                                           &pRec->wrapper);
        if (IS_ERR_OR_NULL(pRec->dentry))
            pRec->dentry = NULL;
    }
}

// ---- the work item: the map of S5 + the publication + the dmesg ledger ----

static void
_gsp_dmem_dump_surface(const char *name, const void *pVa, NvU64 size)
{
    if ((pVa == NULL) || (size == 0))
    {
        NV_PRINTF(LEVEL_INFO, "NVRM-451: surface %-16s ABSENT (va=NULL or size=0)\n", name);
        return;
    }
    NV_PRINTF(LEVEL_INFO, "NVRM-451: surface %-16s va=0x%llx size=0x%llx\n",
              name, (NvU64)(NvUPtr)pVa, size);
}

static void
_gsp_dmem_dump_work(struct work_struct *pWork)
{
    OBJGPU    *pGpu       = _gspDmemDumpState.pGpu;
    KernelGsp *pKernelGsp = _gspDmemDumpState.pKernelGsp;

    if ((pGpu == NULL) || (pKernelGsp == NULL))
        return;

    // ---- S5: the Libos sysmem heap — map now, hold for the debugfs blob ----
    if (!_gspDmemDumpState.sysHeapMapped &&
        (pKernelGsp->pSysmemHeapDescriptor != NULL))
    {
        void      *pVa   = NULL;
        NvP64      pPriv = NvP64_NULL;
        NvU64      sz    = pKernelGsp->pSysmemHeapDescriptor->Size;
        NV_STATUS  st;

        st = memdescMap(pKernelGsp->pSysmemHeapDescriptor, 0, sz,
                        NV_TRUE, NV_PROTECT_WRITEABLE,
                        (NvP64 *)&pVa, &pPriv);
        // ANCHOR NOTE: the map pattern = kgspCreateRadix3 @kernel_gsp.c
        // ~6032-6040 (memdescMap(..., NV_TRUE, NV_PROTECT_WRITEABLE,
        // &pVaKernel, &pPrivKernel)). WRITEABLE is the proven pattern on
        // this address space; the dump writes nothing — read-only intent
        // through a WRITEABLE map is acceptable for a debug instrument.

        if ((st == NV_OK) && (pVa != NULL))
        {
            _gspDmemDumpState.pSysHeapVa    = pVa;
            _gspDmemDumpState.sysHeapSize   = sz;
            _gspDmemDumpState.sysHeapPriv   = pPriv;
            _gspDmemDumpState.sysHeapMapped = NV_TRUE;
            _gsp_dmem_blob_set("sysmemheap.bin", pVa, sz);
        }
        else
        {
            NV_PRINTF(LEVEL_ERROR,
                      "NVRM-451: sysmem heap map FAILED st=0x%x (the verdict = named)\n", st);
        }
    }

    // ---- the dmesg ledger (the human-readable surface inventory) ----
    _gsp_dmem_dump_surface("image.bin",        _gspDmemDumpState.pImage,      _gspDmemDumpState.imageSize);
    _gsp_dmem_dump_surface("ucodes.bin",       _gspDmemDumpState.pUcodes,     _gspDmemDumpState.ucodesSize);
    _gsp_dmem_dump_surface("args.bin",         _gspDmemDumpState.pArgs,       _gspDmemDumpState.argsSize);
    _gsp_dmem_dump_surface("libosinit.bin",    _gspDmemDumpState.pLibosInit,  _gspDmemDumpState.libosInitSize);
    _gsp_dmem_dump_surface("sysmemheap.bin",   _gspDmemDumpState.pSysHeapVa,  _gspDmemDumpState.sysHeapSize);
    _gsp_dmem_dump_surface("statemonitor.bin", _gspDmemDumpState.pStateMon,   _gspDmemDumpState.stateMonSize);
    _gsp_dmem_dump_surface("wpr2meta.bin",     _gspDmemDumpState.pWprMeta,    _gspDmemDumpState.wprMetaSize);

    // ---- the publication ----
    gsp_dmem_debugfs_publish();
    NV_PRINTF(LEVEL_INFO, "NVRM-451: dump ready at /sys/kernel/debug/gsp_dmem/gpu%u/\n",
              _gspDmemDumpState.gpuId);
}

// ---- the teardown (OPTIONAL hardening — the day's rollback = reboot) ----

void
gsp_dmem_dump_teardown(void)
{
    if (_gspDmemDebugfsDir != NULL)
    {
        debugfs_remove_recursive(_gspDmemDebugfsDir);
        _gspDmemDebugfsDir = NULL;
    }
    if (_gspDmemDumpState.sysHeapMapped &&
        (_gspDmemDumpState.pKernelGsp != NULL) &&
        (_gspDmemDumpState.pKernelGsp->pSysmemHeapDescriptor != NULL))
    {
        // ANCHOR NOTE: the 4-arg unmap = the state-monitor pattern
        // @kernel_gsp.c ~4033 (memdescUnmap(MD, NV_TRUE, pVa, priv)).
        memdescUnmap(_gspDmemDumpState.pKernelGsp->pSysmemHeapDescriptor,
                     NV_TRUE,
                     _gspDmemDumpState.pSysHeapVa,
                     _gspDmemDumpState.sysHeapPriv);
        _gspDmemDumpState.sysHeapMapped = NV_FALSE;
    }
    cancel_delayed_work_sync(&_gspDmemDumpWork);
}

// ---- the SCHEDULER (the hook target) ----

void
gsp_dmem_dump_schedule(OBJGPU *pGpu, KernelGsp *pKernelGsp, GSP_FIRMWARE *pGspFw)
{
    NvU32 enable = 0;
    NvU32 i;

    if (osReadRegistryDword(pGpu, "RmGspDmemDump", &enable) != NV_OK)
        enable = 0; // default OFF — the opt-in instrument
    if (enable == 0)
        return;

    if (_gspDmemDumpState.scheduled)
        return;
    _gspDmemDumpState.scheduled  = NV_TRUE;
    _gspDmemDumpState.pGpu       = pGpu;
    _gspDmemDumpState.pKernelGsp = pKernelGsp;
    _gspDmemDumpState.gpuId      = gpuGetDeviceInstance(pGpu);

    // ---- the surface capture (pointers + sizes; no deref here) ----
    if (pGspFw != NULL)
    {
        _gspDmemDumpState.pImage      = pGspFw->pImageData;
        _gspDmemDumpState.imageSize   = pGspFw->imageSize;
        _gspDmemDumpState.pUcodes     = pGspFw->pUcodesBin;
        _gspDmemDumpState.ucodesSize  = pGspFw->ucodesBinSize;
    }
    if (pKernelGsp->pGspArgumentsDescriptor != NULL)
    {
        _gspDmemDumpState.pArgs    = pKernelGsp->pGspArgumentsCached;
        _gspDmemDumpState.argsSize = pKernelGsp->pGspArgumentsDescriptor->Size;
    }
    if (pKernelGsp->pLibosInitArgumentsDescriptor != NULL)
    {
        _gspDmemDumpState.pLibosInit    = pKernelGsp->pLibosInitArgumentsCached;
        _gspDmemDumpState.libosInitSize = pKernelGsp->pLibosInitArgumentsDescriptor->Size;
    }
    if ((pKernelGsp->pRmStateMonitorBuffer != NULL) &&
        (pKernelGsp->pRmStateMonitorBufferMD != NULL))
    {
        _gspDmemDumpState.pStateMon    = pKernelGsp->pRmStateMonitorBuffer;
        _gspDmemDumpState.stateMonSize = pKernelGsp->pRmStateMonitorBufferMD->Size;
    }
    if (pKernelGsp->pWprMetaV1Descriptor != NULL)
    {
        // THE REVIEW FIX: the 610.57.04 KernelGsp has NO pWprMeta /
        // pWprMetaDescriptor — the real members = the V1/Hopper pair
        // (g_kernel_gsp_nvoc.h 543-548). GA104 = Ampere = the V1 variant.
        _gspDmemDumpState.pWprMeta    = pKernelGsp->pWprMetaV1;
        _gspDmemDumpState.wprMetaSize = pKernelGsp->pWprMetaV1Descriptor->Size;
    }
    if (pKernelGsp->pWprMetaHopperDescriptor != NULL)
    {
        _gspDmemDumpState.pWprMeta    = pKernelGsp->pWprMetaHopper;
        _gspDmemDumpState.wprMetaSize = pKernelGsp->pWprMetaHopperDescriptor->Size;
    }
    for (i = 0; i < 8; i++)
    {
        RM_LIBOS_LOG_MEM *pLog = &pKernelGsp->rmLibosLogMem[i];
        if ((pLog->pTaskLogBuffer != NULL) && (pLog->pTaskLogDescriptor != NULL))
        {
            char name[16];
            snprintf(name, sizeof(name), "logs%u.bin", i);
            _gsp_dmem_blob_set(name, pLog->pTaskLogBuffer,
                               pLog->pTaskLogDescriptor->Size);
        }
    }

    // pre-stage the zero-copy blobs (the work publishes the directory)
    _gsp_dmem_blob_set("image.bin",        _gspDmemDumpState.pImage,      _gspDmemDumpState.imageSize);
    _gsp_dmem_blob_set("ucodes.bin",       _gspDmemDumpState.pUcodes,     _gspDmemDumpState.ucodesSize);
    _gsp_dmem_blob_set("args.bin",         _gspDmemDumpState.pArgs,       _gspDmemDumpState.argsSize);
    _gsp_dmem_blob_set("libosinit.bin",    _gspDmemDumpState.pLibosInit,  _gspDmemDumpState.libosInitSize);
    _gsp_dmem_blob_set("statemonitor.bin", _gspDmemDumpState.pStateMon,   _gspDmemDumpState.stateMonSize);
    _gsp_dmem_blob_set("wpr2meta.bin",     _gspDmemDumpState.pWprMeta,    _gspDmemDumpState.wprMetaSize);

    schedule_delayed_work(&_gspDmemDumpWork, msecs_to_jiffies(8 * 1000));
    NV_PRINTF(LEVEL_INFO, "NVRM-451: gsp_dmem_dump scheduled (+8 s) — the surfaces captured\n");
}
