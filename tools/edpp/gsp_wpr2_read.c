// gsp_wpr2_read.c — PASS 4.62 T2 — ROUTE W, PROBE MD: the memdesc-over-
// phys READ of the GSP-FW heap in WPR2 (the two-sided instrument, the
// 4.51/4.55/4.61 pattern — machine-proven mechanics).
//
// THE GROUNDING (the EXACT tree, open-gpu-kernel-modules @ 610.57.04 —
// re-asserted THIS pass from the fetched tag):
//   - memdescCreateExisting(pMemDesc, pGpu, Size, AddressSpace,
//     CpuCacheAttrib, Flags) @g_mem_desc_nvoc.h:943 — "Initialize a
//     caller supplied memory descriptor for use with memdescDescribe()"
//     (a stack struct, NO allocation);
//   - memdescDescribe(pMemDesc, ADDR_FBMEM, Base, Size) @:1009 — "Fill
//     in a MEMORY_DESCRIPTOR with a description of a preexisting
//     contiguous memory allocation" (Base = the window base from the
//     plan, Size = the window size);
//   - memdescMap(pMemDesc, 0, Size, NV_TRUE, NV_PROTECT_READABLE,
//     &pVa, &pPriv) @:990 — the EXACT call shape of the proven radix3
//     map @kernel_gsp.c:6028 (WRITEABLE there; READABLE here — the
//     4.52 §5 wording);
//   - memdescUnmap @:994 — the 4-arg pattern (banked 4.51, @~4033).
//   THE HONEST MODEL (4.52 §5, banked): the FB FW heap is NEVER
//   CPU-mapped in this driver — the ABSENCE of an in-tree precedent is
//   itself the evidence; THIS probe = the first CPU map of the FB
//   heap, and the seal's CPU-read behavior = the question the day
//   answers (INDECIDABLE-BY-BYTES until it runs).
//
// THE CpuCacheAttrib NOTE: NV_MEMORY_UNCACHED — the FB CPU-access
// attribute family (the radix3 SYSMEM twin = NV_MEMORY_CACHED
// @kernel_gsp.c:6017; FB = the device side, the UC read = no
// cache-staleness question). The attribute preference of the seal =
// INDECIDABLE-BY-BYTES; the real dkms build = the judge (the 4.44
// machine lesson).
//
// THE PLAN (the v462a emission — wpr2_read_plan.h): the windows = the
// STRUCTURAL SURVIVORS of the S8 wpr2meta decode (the WPR2
// containment, the FB bound, the page alignment — the bytes decide,
// never the narrative). The GATED NULL plan = every read refuses
// cleanly. NO plan, NO boot — the runbook-462 §0 gate.
//
// THE GATE: RmGspWpr2Read = the window selector {1..PLAN_N}, ONE
// window per boot (the one-variable-per-transition law). The
// MULTI-KEY LAW (banked twice): the multi-keys = the SEMICOLON.
//
// THE ORDER OF DEFENSE (each layer independent):
//   1. the regkey gate (absent/0 = the file does nothing);
//   2. the selector filter (ONE window per boot);
//   3. the plan gate (the NULL plan = the refusal);
//   4. THE MAP: CreateExisting(stack) + Describe(ADDR_FBMEM) + Map
//      (READABLE) — the MAP-FAIL verdict = THE SEAL NAMED (the
//      negative the mission asks to record, never hidden);
//   5. the COPY: the readLen bytes into the state blob (the
//      debugfs-published surface), the integer primitives (the
//      256-bin histogram, the first u64, distinct, top) — THE C
//      MIRROR of v462a.classify_bytes (the v462b battery proves the
//      two implementations agree on every fixture);
//   6. the plausibility class: SEAL-ZERO / SEAL-FF / SEAL-CONSTANT =
//      THE SEAL ANSWERED (the named negative); WPRMETA-MAGIC /
//      ELF-MAGIC = the window math off by one window (the named
//      lead); HEAP-FREELIST = the heap signature (the POSITIVE);
//      DEGENERATE / LIVE-UNKNOWN = the scan decides;
//   7. the UNMAP (every path);
//   8. the ledger: the state verdicts -> the nv.c printk (the
//      reliable surface — the RM NV_PRINTF = level-gated).
//
// THE SHARED STATE CONTRACT (the layout MIRROR lives in
// patch_nv_462.py — the v462b battery compiles BOTH and asserts the
// sizeof/offsetof agreement member by member; the verdict codes + the
// names tables = compared pairwise):
//   scheduled/executed/gpuId/sel/verdict/plausClass/winClass/fbBase/
//   fbSize/readLen/distinct/firstU64/topVal/topCnt/blob[]/pGpuSaved/
//   pKernelGspSaved/pLateFn
// The RM side WRITES it; the nv.c side READS it, CALLS THROUGH
// pLateFn, publishes blob[] via debugfs_create_blob and computes the
// sha16 in USERSPACE (the runbook §4 — zero crypto in-kernel).
//
// INTEGRATION (kernel_gsp.c, the ONE hook line, next to the
// 4.51/4.52/4.61 instruments):
//     gsp_wpr2_read_schedule(pGpu, pKernelGsp);   // <-- 4.62
// and near the top:  #include "gsp_wpr2_read.c"
// (the plan header beside it: #include "wpr2_read_plan.h").
// BUILD DAY (runbook-462 §3): patch_nv_462.py BEFORE the dkms —
// without it the build passes but the late fn never fires (the
// silent no-op — the runbook REFUSES on the missing Wpr2ReadMarker).
//
// ROLLBACK (runbook-462 §6): this file + the plan header + the ONE
// hook line + the nv.c patch (git checkout) = the ONLY changes; dkms
// remove+install --force + limine-mkinitcpio. The firmware file
// NEVER touched. THE READ ITSELF = passive by construction: one map,
// one copy, one unmap — no write path exists in this file (the
// battery asserts the source stays write-free).
//
// ZERO linux headers HERE (the 4.55 contract; the v455a-class battery
// greps this file for linux/ workqueue/ debugfs/ printk and FAILS if
// the trap ever returns).

// ---------------------------------------------------------------------------
// Included by kernel_gsp.c — reuses the translation unit's includes.
// ---------------------------------------------------------------------------
#include "wpr2_read_plan.h"   // GENERATED — the reviewed read plan

// the verdict codes — THE MIRROR CONTRACT (the nv.c side carries the
// SAME values; the names table lives on the nv.c side, the v462b
// battery compares the two tables element by element)
#define GSP_WPR2_READ_V_OFF            0  // the regkey absent/0
#define GSP_WPR2_READ_V_BAD_SEL        1  // outside {1..PLAN_N}
#define GSP_WPR2_READ_V_NULL_PLAN      2  // the GATED null plan
#define GSP_WPR2_READ_V_NO_GPU         3  // no KernelGsp at +8 s
#define GSP_WPR2_READ_V_MAP_FAIL       4  // THE SEAL NAMED (map refused)
#define GSP_WPR2_READ_V_COPY_SHORT     5  // the VA NULL / the len 0
#define GSP_WPR2_READ_V_READ_DONE      6  // the read ran (the class =
                                          // the plausibility verdict)
#define GSP_WPR2_READ_V_NOT_SCHEDULED  7  // the late call, gate off

// the plausibility classes — THE MIRROR CONTRACT (the integer
// semantics of v462a.classify_bytes, C form; the precedence: the
// seals FIRST, then the magics, then the degeneracy)
#define GSP_WPR2_READ_C_SEAL_ZERO      0
#define GSP_WPR2_READ_C_SEAL_FF        1
#define GSP_WPR2_READ_C_SEAL_CONSTANT  2
#define GSP_WPR2_READ_C_WPRMETA_MAGIC  3
#define GSP_WPR2_READ_C_ELF_MAGIC      4
#define GSP_WPR2_READ_C_HEAP_FREELIST  5
#define GSP_WPR2_READ_C_DEGENERATE     6
#define GSP_WPR2_READ_C_LIVE_UNKNOWN   7

typedef struct
{
    NvBool  scheduled;    // the regkey gate result (the hook ran)
    NvBool  executed;     // the one-shot guard on the late fn
    NvU32   gpuId;
    NvU32   sel;          // the RmGspWpr2Read value THIS boot
    NvU32   verdict;      // GSP_WPR2_READ_V_*
    NvU32   plausClass;   // GSP_WPR2_READ_C_*
    NvU32   winClass;     // the window's class (1=ABS 2=REL 3=S4)
    NvU64   fbBase;       // the window base (the ledger)
    NvU64   fbSize;       // the window size (the ledger)
    NvU32   readLen;      // the bytes copied
    NvU32   distinct;     // the distinct byte values
    NvU64   firstU64;     // the first u64 LE of the window
    NvU32   topVal;       // the top byte value
    NvU32   topCnt;       // the top byte count
    NvU8    blob[GSP_WPR2_READ_MAX_LEN];  // the window (the debugfs
                                          // blob payload)
    void   *pGpuSaved;
    void   *pKernelGspSaved;
    void  (*pLateFn)(void);  // the late read, called BY POINTER (the
                             // gc-sections law — NO cross-TU symbol)
} GSP_WPR2_READ_STATE;

// non-static: the nv.c (kernel-open) side reads this for the ledger,
// the debugfs blob, and calls through pLateFn (the 4.51 v4 pattern,
// machine-proven)
GSP_WPR2_READ_STATE gspWpr2ReadState = { 0 };

void gsp_wpr2_read_late(void);   // the forward decl: the schedule
                                 // stores the pointer below

// ---- the classifier (the C MIRROR of v462a.classify_bytes — the
//      SAME integer semantics: the histogram, the first u64, the top,
//      the distinct; no float, no entropy — the two sides agree on
//      every input by construction, the battery proves it) ----------
static NvU32
_gsp_wpr2_read_classify(const NvU8 *p, NvU32 len, NvU64 *pFirstU64,
                        NvU32 *pDistinct, NvU32 *pTopVal, NvU32 *pTopCnt)
{
    NvU32 hist[256];
    NvU32 i;
    NvU64 first = 0;
    NvU32 distinct = 0;
    NvU32 topVal = 0;
    NvU32 topCnt = 0;

    for (i = 0; i < 256; i++)
        hist[i] = 0;
    for (i = 0; i < len; i++)
        hist[p[i]]++;
    for (i = 0; i < 8; i++)
        first |= ((NvU64)p[i]) << (8 * i);
    for (i = 0; i < 256; i++)
    {
        if (hist[i] == 0)
            continue;
        distinct++;
        if (hist[i] > topCnt)
        {
            topCnt = hist[i];
            topVal = i;
        }
    }
    *pFirstU64 = first;
    *pDistinct = distinct;
    *pTopVal   = topVal;
    *pTopCnt   = topCnt;

    if (hist[0x00] == len)
        return GSP_WPR2_READ_C_SEAL_ZERO;
    if (hist[0xFF] == len)
        return GSP_WPR2_READ_C_SEAL_FF;
    if (((NvU64)topCnt * 256) >= ((NvU64)len * 255))
        return GSP_WPR2_READ_C_SEAL_CONSTANT;
    if (first == 0xDC3AAE21371A60B3ULL)
        return GSP_WPR2_READ_C_WPRMETA_MAGIC;
    if ((p[0] == 0x7f) && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'F'))
        return GSP_WPR2_READ_C_ELF_MAGIC;
    if (first == 0x4845415046524545ULL)
        return GSP_WPR2_READ_C_HEAP_FREELIST;
    if (distinct <= 4)
        return GSP_WPR2_READ_C_DEGENERATE;
    return GSP_WPR2_READ_C_LIVE_UNKNOWN;
}

// ---- the late read (the +8 s body, RM-portable, verdicts recorded) --
// Called BY POINTER (the state's pLateFn) from the nv.c delayed work
// at +8 s after module init (the boot-B proof: the pointers stable).

void
gsp_wpr2_read_late(void)
{
    KernelGsp            *pKernelGsp =
                             (KernelGsp *)gspWpr2ReadState.pKernelGspSaved;
    OBJGPU               *pGpu      = (OBJGPU *)gspWpr2ReadState.pGpuSaved;
    const GSP_WPR2_READ_WINDOW *pWin = NULL;
    NvU32                 sel       = gspWpr2ReadState.sel;
    MEMORY_DESCRIPTOR     desc;      // the CALLER-SUPPLIED descriptor
                                     // (the API comment: a stack
                                     // struct, no allocation)
    NvP64                 pVa        = NvP64_NULL;
    NvP64                 pPriv      = NvP64_NULL;
    volatile NvU8        *pSrc       = NULL;
    NvU32                 i;
    NV_STATUS             st;

    // the one-shot + the gate guard (the double-late defense in depth)
    if (gspWpr2ReadState.executed)
        return;
    if (!gspWpr2ReadState.scheduled)
    {
        gspWpr2ReadState.verdict = GSP_WPR2_READ_V_NOT_SCHEDULED;
        NV_PRINTF(LEVEL_ERROR, "NVRM-462: the late read with the gate "
                               "off (RmGspWpr2Read absent, or the hook "
                               "never ran)\n");
        return;
    }
    gspWpr2ReadState.executed = NV_TRUE;

    if ((pKernelGsp == NULL) || (pGpu == NULL))
    {
        gspWpr2ReadState.verdict = GSP_WPR2_READ_V_NO_GPU;
        NV_PRINTF(LEVEL_ERROR, "NVRM-462: no GPU/KernelGsp at +8 s — "
                               "the read refuses (nothing read)\n");
        return;
    }
    if ((GSP_WPR2_READ_PLAN_N == 0) ||
        (gspWpr2ReadWindows[0].winClass == 0))
    {
        gspWpr2ReadState.verdict = GSP_WPR2_READ_V_NULL_PLAN;
        NV_PRINTF(LEVEL_ERROR, "NVRM-462: the plan is the GATED NULL "
                               "plan — no window survived the v462a "
                               "structural invariants, nothing to read "
                               "(re-decode the S8 dump)\n");
        return;
    }
    if ((sel == 0) || (sel > GSP_WPR2_READ_PLAN_N))
    {
        gspWpr2ReadState.verdict = GSP_WPR2_READ_V_BAD_SEL;
        NV_PRINTF(LEVEL_ERROR, "NVRM-462: sel=%u outside the plan "
                               "{1..%u} (plan meta_sha16=%s) — nothing "
                               "read\n", sel, GSP_WPR2_READ_PLAN_N,
                  GSP_WPR2_READ_PLAN_META_SHA16);
        return;
    }
    pWin = &gspWpr2ReadWindows[sel - 1];
    gspWpr2ReadState.winClass = pWin->winClass;
    gspWpr2ReadState.fbBase   = pWin->base;
    gspWpr2ReadState.fbSize   = pWin->size;
    gspWpr2ReadState.readLen  = pWin->readLen;

    // ---- THE MAP: CreateExisting + Describe(ADDR_FBMEM) + Map ----
    // (the 4.52 §5 anchors, the READABLE variant of the proven radix3
    // call shape @kernel_gsp.c:6028; ONE map, ONE copy, ONE unmap)
    memdescCreateExisting(&desc, pGpu, pWin->size, ADDR_FBMEM,
                          NV_MEMORY_UNCACHED, MEMDESC_FLAGS_NONE);
    memdescDescribe(&desc, ADDR_FBMEM, pWin->base, pWin->size);
    st = memdescMap(&desc, 0, pWin->readLen, NV_TRUE,
                    NV_PROTECT_READABLE, &pVa, &pPriv);
    if ((st != NV_OK) || (pVa == NvP64_NULL))
    {
        gspWpr2ReadState.verdict = GSP_WPR2_READ_V_MAP_FAIL;
        gspWpr2ReadState.plausClass = GSP_WPR2_READ_C_SEAL_ZERO;
        NV_PRINTF(LEVEL_ERROR, "NVRM-462: the FB heap map FAILED "
                               "st=0x%x base=0x%llx len=%u — THE SEAL "
                               "ANSWERED (the named negative, nothing "
                               "read) meta_sha16=%s\n", st, pWin->base,
                  pWin->readLen, GSP_WPR2_READ_PLAN_META_SHA16);
        return;
    }
    pSrc = (volatile NvU8 *)KERNEL_POINTER_FROM_NvP64(NvU8 *, pVa);

    // ---- the COPY (one pass, the bytes into the state blob) ----
    {
        NvU32 len = pWin->readLen;
        if (len > GSP_WPR2_READ_MAX_LEN)
            len = GSP_WPR2_READ_MAX_LEN;
        for (i = 0; i < len; i++)
            gspWpr2ReadState.blob[i] = pSrc[i];
        gspWpr2ReadState.readLen = len;

        gspWpr2ReadState.plausClass =
            _gsp_wpr2_read_classify(gspWpr2ReadState.blob, len,
                                    &gspWpr2ReadState.firstU64,
                                    &gspWpr2ReadState.distinct,
                                    &gspWpr2ReadState.topVal,
                                    &gspWpr2ReadState.topCnt);
        gspWpr2ReadState.verdict = GSP_WPR2_READ_V_READ_DONE;
        NV_PRINTF(LEVEL_INFO, "NVRM-462: read sel=%u class=%u "
                              "base=0x%llx len=%u first=0x%llx "
                              "distinct=%u meta_sha16=%s\n",
                  sel, gspWpr2ReadState.plausClass, pWin->base, len,
                  gspWpr2ReadState.firstU64, gspWpr2ReadState.distinct,
                  GSP_WPR2_READ_PLAN_META_SHA16);
    }

    // ---- the unmap (every path above the map-fail returns early) ----
    memdescUnmap(&desc, NV_TRUE, pVa, pPriv);
}

// ---- the scheduler (the hook target — NO workqueue here) ----

void
gsp_wpr2_read_schedule(OBJGPU *pGpu, KernelGsp *pKernelGsp)
{
    NvU32 sel = 0;

    if (osReadRegistryDword(pGpu, "RmGspWpr2Read", &sel) != NV_OK)
        sel = 0; // default OFF — the opt-in reader, SEPARATE from the
                 // 4.51 dump / 4.52 poke / 4.61 write keys (all coexist)
    if (sel == 0)
        return;  // the silent OFF (the instrument absent — no verdict,
                 // no ledger noise; the nv.c side prints the honest
                 // "off or the hook never ran" line at +8 s)

    // the PLAN GATE at arm time (the second layer — the runbook §0
    // = the first): the GATED NULL plan refuses BEFORE the selector,
    // nothing arms, nothing reads
    if ((GSP_WPR2_READ_PLAN_N == 0) ||
        (gspWpr2ReadWindows[0].winClass == 0))
    {
        gspWpr2ReadState.verdict = GSP_WPR2_READ_V_NULL_PLAN;
        NV_PRINTF(LEVEL_ERROR, "NVRM-462: the plan = the GATED NULL "
                               "plan — no window survived the v462a "
                               "structural invariants; RmGspWpr2Read=%u "
                               "refused at arm time (nothing reads)\n",
                  sel);
        return;
    }
    if (sel > GSP_WPR2_READ_PLAN_N)
    {
        gspWpr2ReadState.verdict = GSP_WPR2_READ_V_BAD_SEL;
        NV_PRINTF(LEVEL_ERROR, "NVRM-462: RmGspWpr2Read=%u outside "
                               "the plan {1..%u} — OFF\n", sel,
                                  GSP_WPR2_READ_PLAN_N);
        return;
    }

    if (gspWpr2ReadState.scheduled)
        return;
    gspWpr2ReadState.scheduled       = NV_TRUE;
    gspWpr2ReadState.gpuId           = gpuGetDeviceInstance(pGpu);
    gspWpr2ReadState.sel             = sel;  // the late fn reads THE
                                             // boot's window from it
    gspWpr2ReadState.pGpuSaved       = (void *)pGpu;
    gspWpr2ReadState.pKernelGspSaved = (void *)pKernelGsp;
    gspWpr2ReadState.pLateFn         = gsp_wpr2_read_late; // the
                                           // gc-sections law: the
                                           // pointer keeps the fn alive

    // NO schedule_delayed_work HERE — the workqueue = the nv.c side's
    // (patch_nv_462.py armed it at module init, +8 s). This hook ONLY
    // fills the state (the 4.51 v4 pattern).
    NV_PRINTF(LEVEL_INFO, "NVRM-462: gsp_wpr2_read armed sel=%u ONE "
                          "window read this boot meta_sha16=%s — the "
                          "nv.c side fires at +8 s\n", sel,
              GSP_WPR2_READ_PLAN_META_SHA16);
}
