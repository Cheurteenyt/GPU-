// gsp_dmem_write.c — PASS 4.61 T2 — LE OUTIL D'ÉCRITURE (the DMEM-tail
// write lane, the µW-base target). THE TWO-SIDED PORT of the 4.55
// gsp_hpoke.c (machine-proven: 4 boots 0 Xid on the dump twin, the
// same pLateFn mechanics).
//
// THE PORT CONTRACT (the 4.55 pattern, UNCHANGED mechanics):
//   THIS file (the RM TU, included by kernel_gsp.c): the regkey gate
//     (osReadRegistryDword RmGspDMemWrite), the selector filter
//     (sel = the group k+1, {1..4}), the plan table
//     (gsp_dmem_write_plan.h — the v461a emission), the surface
//     resolver (the KernelGsp members the 4.51 dump instrument itself
//     read), the PRE-VERIFY (THE MARKER CHECK — the mission law: read
//     the current base, verify 0x0EE6B280, THEN write), the u64-pair
//     write ({0x10B07600, 0} — the 4.44 payload law), the
//     POST-VERIFY, the unmap. ALL RM-portable, ZERO linux headers —
//     the v455a-class battery greps this file for linux/ workqueue/
//     debugfs/ printk and FAILS if the trap ever returns.
//   the nv.c side (kernel-open/nvidia/nv.c, the linux TU): the delayed
//     work (8 s) calls through pLateFn, then prints the LEDGER =
//     patch_nv_461.py (the DmemWriteMarker, idempotent, coexists with
//     the 4.51 DmemDumpMarker and the 4.52 HpokeMarker).
//
// GROUNDING (the EXACT tree, open-gpu-kernel-modules @ 610.57.04):
//   - the surface members = g_kernel_gsp_nvoc.h (the 4.51 §1 banked
//     list, ALL PRESENT): pGspArgumentsCached + pGspArgumentsDescriptor,
//     pLibosInitArgumentsCached + descriptor, pRmStateMonitorBuffer +
//     pRmStateMonitorBufferMD, pWprMeta + pWprMetaDescriptor,
//     pSysmemHeapDescriptor;
//   - the sizes = memdescGetSize(the descriptor) — the RM API the
//     driver uses on these very members;
//   - the heap path = the radix3 WRITEABLE map @kernel_gsp.c:6028 (the
//     4.52-proven pattern, byte-for-byte);
//   - the unmap = the 4-arg pattern @~4033 (banked 4.51);
//   - the regkey pattern @kernel_gsp.c:312 (the 4.51/4.52 instruments).
//   THE HONEST MODEL (findings-4.61 §1): the banked evidence says the
//   object 0x6d0 = the RM heap (FB/WPR2, the 4.51 verdict 1) — the
//   surfaces this writer can reach = the host-reachable set S1-S8.
//   The plan = the v461a scan verdict: a plan EXISTS only where the
//   marker bytes were FOUND in a dump (the targeting proof). No hit ->
//   the GATED NULL plan -> every write request refuses cleanly. The
//   day decides; the instrument never guesses.
//
// THE GATE (the mission, verbatim): the key = RmGspDMemWrite, ONE
// write per boot. The VALUE selects the group:
//     NVreg_RegistryDwords="RmGspDMemWrite=1"  -> sel 1 = base[0] (k=0)
//     RmGspDMemWrite=2                          -> sel 2 = base[1]
//     (3 = base[2], 4 = base[3]; absent/0 = OFF; >4 = the refusal)
// THE MULTI-KEY LAW (the 4.51 lesson, banked twice): multiple regkeys
// = the SEMICOLON: "RmGspDmemDump=1;RmGspDMemWrite=1" — the space
// form = never parsed (the conf = the capture OFF).
//
// THE ORDER OF DEFENSE (each layer independent, the 4.52 law):
//   1. the regkey gate (absent/0 = the file does nothing);
//   2. the selector filter (ONE entry; the others untouched);
//   3. the surface resolver (the plan's surface id -> the pointer +
//      the size; the unknown id = BAD_SURFACE, nothing written);
//   4. the bounds check (the entry offset+len vs the surface size);
//   5. THE PRE-VERIFY = THE MARKER CHECK: the runtime bytes must
//      equal the plan's old bytes (0x0EE6B280 + the found neighbor) —
//      the targeting proof, the mission law; a moved/rewritten base
//      (or the recompute racing us) aborts BEFORE any write
//      (the STALE-PLAN verdict);
//   6. the write: the u64 pair {0x10B07600, 0} (len 8, the 4.44
//      payload law — the zero half = the DOCUMENTED side effect);
//   7. the POST-VERIFY: the readback must equal the new bytes (the
//      VERIFY-FAIL verdict is recorded, never retried, never hidden);
//   8. the ledger: the state verdicts -> the nv.c printk (the
//      reliable surface) + the RM NV_PRINTF kept (the bonus).
//
// THE SHARED STATE CONTRACT (the layout MIRROR lives in
// patch_nv_461.py — the v461b battery compiles BOTH and asserts the
// sizeof/offsetof agreement member by member; the verdict codes +
// the names table = compared (name, value) pairwise):
//   scheduled/executed/gpuId/sel/verdict/verifyOk/surfOffset/surface/
//   group/len/fieldName/hex*/sha16/pGpuSaved/pKernelGspSaved/pLateFn
// The RM side WRITES it; the nv.c side READS it and CALLS THROUGH
// pLateFn. Nothing else (the 4.55 cross-side law).
//
// INTEGRATION (kernel_gsp.c, the ONE hook line, next to the 4.51/4.52
// instruments, same anchor, the success path after the log polling):
//     gsp_dmem_dump_schedule(pGpu, pKernelGsp, pGspFw);   // (4.51)
//     gsp_hpoke_schedule(pGpu, pKernelGsp);               // (4.52/4.55)
//     gsp_dmem_write_schedule(pGpu, pKernelGsp);          // <-- 4.61
// and near the top:  #include "gsp_dmem_write.c"
// (the plan header lives beside it: #include "gsp_dmem_write_plan.h").
// BUILD DAY (the runbook-461 §1): apply patch_nv_461.py BEFORE the
// dkms — without it the build passes but the late fn never fires (the
// silent no-op — the runbook REFUSES on the missing DmemWriteMarker).
//
// ROLLBACK (runbook-461): this file + the plan header + the ONE hook
// line + the nv.c patch (git checkout -- kernel-open/nvidia/nv.c) =
// the ONLY changes; dkms remove+install --force + limine-mkinitcpio
// (the banked ritual). The firmware file NEVER touched (the §0 sha
// guard). THE WRITE ITSELF = REVERSIBLE BY CONSTRUCTION per the
// mission: the pre-verify carries the old bytes — the stock value
// {0x0EE6B280, 0} is in the plan JSON; the restore = the same
// instrument with the reverted plan (or the driver-only rollback).
//
// SAFETY: the write happens ONCE per boot, into the surface the
// reviewed plan names, at the offset the dump proved, at the u64
// width the 4.44 payload law defines. No MMIO write, no firmware
// file write, no falcon mailbox, no ROP — the plain-store pattern the
// driver itself uses on these surfaces (kgspSetupLibosInitArgs).

// ---------------------------------------------------------------------------
// Included by kernel_gsp.c — reuses the translation unit's includes.
// ZERO linux headers HERE (the 4.55 contract).
// ---------------------------------------------------------------------------
#include "gsp_dmem_write_plan.h"   // GENERATED — the reviewed write plan

// the verdict codes — THE MIRROR CONTRACT (the nv.c side carries the
// SAME values; the names table lives on the nv.c side, the v461b
// battery compares the two tables element by element)
#define GSP_DMEM_WRITE_V_OFF             0  // the regkey absent/0
#define GSP_DMEM_WRITE_V_BAD_SEL         1  // outside {1..4}
#define GSP_DMEM_WRITE_V_NO_SURF_PTR     2  // the surface pointer NULL
#define GSP_DMEM_WRITE_V_NULL_PLAN       3  // the GATED null plan
#define GSP_DMEM_WRITE_V_SEL_NOT_IN_PLAN 4  // the selector has no entry
#define GSP_DMEM_WRITE_V_BOUNDS          5  // the offset beyond the size
#define GSP_DMEM_WRITE_V_MAP_FAIL        6  // the heap map failed
#define GSP_DMEM_WRITE_V_STALE_PLAN      7  // THE MARKER MISMATCH — ABORT
#define GSP_DMEM_WRITE_V_WRITE_DONE      8  // the write ran (verifyOk)
#define GSP_DMEM_WRITE_V_NOT_SCHEDULED   9  // the late call, gate off
#define GSP_DMEM_WRITE_V_BAD_SURFACE    10  // the id outside the resolver

#define GSP_DMEM_WRITE_SURF_ARGS        1
#define GSP_DMEM_WRITE_SURF_LIBOSINIT   2
#define GSP_DMEM_WRITE_SURF_STATEMON    3
#define GSP_DMEM_WRITE_SURF_WPRMETA     4
#define GSP_DMEM_WRITE_SURF_SYSMEMHEAP  5

typedef struct
{
    NvBool     scheduled;      // the regkey gate result (the hook ran)
    NvBool     executed;       // the one-shot guard on the late fn
    NvU32      gpuId;
    NvU32      sel;            // the RmGspDMemWrite value THIS boot
    NvU32      verdict;        // GSP_DMEM_WRITE_V_*
    NvU32      verifyOk;       // 1 = the post-verify matched
    NvU64      surfOffset;     // the entry's offset (the ledger)
    NvU32      surface;        // the surface id (the ledger)
    NvU32      group;          // k (the ledger)
    NvU32      len;            // the write width (8 = the u64 pair)
    char       fieldName[8];   // "base0".."base3" (the ledger)
    char       hexSeen[24];    // the pre-verify runtime bytes (rendered)
    char       hexWant[24];    // the plan old bytes (rendered)
    char       hexNew[24];     // the post-write bytes (rendered)
    char       sha16[20];      // the GSP_DMEM_WRITE_PLAN_SHA16 copy (17 max)
    void      *pGpuSaved;
    void      *pKernelGspSaved;
    void     (*pLateFn)(void); // the late write, called BY POINTER (the
                              // gc-sections law — NO cross-TU symbol)
} GSP_DMEM_WRITE_STATE;

// non-static: the nv.c (kernel-open) side reads this for the ledger
// and calls through pLateFn (the 4.51 v4 pattern, machine-proven)
GSP_DMEM_WRITE_STATE gspDmemWriteState = { 0 };

void gsp_dmem_write_late(void);   // the forward decl: the schedule stores
                                  // the pointer below

static const char *
_gsp_dmem_write_field_name(NvU32 sel)
{
    switch (sel)
    {
        case 1: return "base0";
        case 2: return "base1";
        case 3: return "base2";
        case 4: return "base3";
        default: return "?";
    }
}

static void
_gsp_dmem_write_hex(const NvU8 *p, NvU32 len, char *out, NvU32 outLen)
{
    NvU32 i;
    NvU32 n = 0;
    for (i = 0; (i < len) && ((n + 3) < outLen); i++)
    {
        out[n++] = "0123456789abcdef"[p[i] >> 4];
        out[n++] = "0123456789abcdef"[p[i] & 0xf];
    }
    out[n] = '\0';
}

// ---- the surface resolver: the plan's surface id -> {base, size} ----
// The direct-pointer surfaces = the driver's own allocations (the 4.51
// dump instrument read them through these very pointers); the size =
// memdescGetSize(the descriptor). The heap = the 4.52 map path.
static NvBool
_gsp_dmem_write_resolve(KernelGsp *pKernelGsp, NvU32 surface,
                        volatile NvU8 **ppBase, NvU64 *pSize,
                        NvBool *pMapped)
{
    *ppBase   = NULL;
    *pSize    = 0;
    *pMapped  = NV_FALSE;

    switch (surface)
    {
        case GSP_DMEM_WRITE_SURF_ARGS:
            if ((pKernelGsp->pGspArgumentsCached == NULL) ||
                (pKernelGsp->pGspArgumentsDescriptor == NULL))
                return NV_FALSE;
            *ppBase = (volatile NvU8 *)pKernelGsp->pGspArgumentsCached;
            *pSize  = memdescGetSize(pKernelGsp->pGspArgumentsDescriptor);
            return NV_TRUE;
        case GSP_DMEM_WRITE_SURF_LIBOSINIT:
            if ((pKernelGsp->pLibosInitArgumentsCached == NULL) ||
                (pKernelGsp->pLibosInitArgumentsDescriptor == NULL))
                return NV_FALSE;
            *ppBase =
                (volatile NvU8 *)pKernelGsp->pLibosInitArgumentsCached;
            *pSize =
                memdescGetSize(pKernelGsp->pLibosInitArgumentsDescriptor);
            return NV_TRUE;
        case GSP_DMEM_WRITE_SURF_STATEMON:
            if ((pKernelGsp->pRmStateMonitorBuffer == NULL) ||
                (pKernelGsp->pRmStateMonitorBufferMD == NULL))
                return NV_FALSE;
            *ppBase = (volatile NvU8 *)pKernelGsp->pRmStateMonitorBuffer;
            *pSize  =
                memdescGetSize(pKernelGsp->pRmStateMonitorBufferMD);
            return NV_TRUE;
        case GSP_DMEM_WRITE_SURF_WPRMETA:
            if ((pKernelGsp->pWprMeta == NULL) ||
                (pKernelGsp->pWprMetaDescriptor == NULL))
                return NV_FALSE;
            *ppBase = (volatile NvU8 *)pKernelGsp->pWprMeta;
            *pSize  = memdescGetSize(pKernelGsp->pWprMetaDescriptor);
            return NV_TRUE;
        default:
            return NV_FALSE;   // BAD_SURFACE (the heap = handled by the
                               // caller: the map path)
    }
}

// ---- the late write (the +8 s body, RM-portable, verdicts recorded) --
// Called BY POINTER (the state's pLateFn) from the nv.c delayed work at
// +8 s after module init (the boot-B proof: the pointers = stable).

void
gsp_dmem_write_late(void)
{
    KernelGsp                   *pKernelGsp =
                                    (KernelGsp *)gspDmemWriteState.pKernelGspSaved;
    const GSP_DMEM_WRITE_ENTRY  *pEntry     = NULL;
    NvU32                        sel        = gspDmemWriteState.sel;
    NvU32                        i;
    volatile NvU8               *pSurf      = NULL;
    NvU64                        sz         = 0;
    NvBool                       mapped     = NV_FALSE;
    NvBool                       isHeap     = NV_FALSE;
    void                        *pVa        = NULL;
    NvP64                        pPriv      = NvP64_NULL;
    NV_STATUS                    st;

    // the one-shot + the gate guard (the double-late defense in depth)
    if (gspDmemWriteState.executed)
        return;
    if (!gspDmemWriteState.scheduled)
    {
        gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_NOT_SCHEDULED;
        NV_PRINTF(LEVEL_ERROR, "NVRM-461: the late write with the gate "
                               "off (RmGspDMemWrite absent, or the hook "
                               "never ran)\n");
        return;
    }
    gspDmemWriteState.executed = NV_TRUE;

    if (pKernelGsp == NULL)
    {
        gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_NO_SURF_PTR;
        NV_PRINTF(LEVEL_ERROR, "NVRM-461: no KernelGsp at +8 s — the "
                               "write refuses (nothing written)\n");
        return;
    }
    if ((GSP_DMEM_WRITE_PLAN_N == 0) || (gspDmemWritePlan[0].sel == 0))
    {
        gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_NULL_PLAN;
        NV_PRINTF(LEVEL_ERROR, "NVRM-461: the plan is the GATED NULL "
                               "plan — the dumps carry no base-marker "
                               "hit, nothing to write (re-run v461a on "
                               "fresh dumps)\n");
        return;
    }

    // ---- the ONE entry for THIS boot (the selector filter) ----
    for (i = 0; i < GSP_DMEM_WRITE_PLAN_N; i++)
    {
        if (gspDmemWritePlan[i].sel == sel)
        {
            pEntry = &gspDmemWritePlan[i];
            break;
        }
    }
    if (pEntry == NULL)
    {
        gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_SEL_NOT_IN_PLAN;
        NV_PRINTF(LEVEL_ERROR, "NVRM-461: sel=%u (%s) not in the plan "
                               "(plan_sha16=%s) — nothing written\n",
                  sel, _gsp_dmem_write_field_name(sel),
                  GSP_DMEM_WRITE_PLAN_SHA16);
        return;
    }
    gspDmemWriteState.surfOffset = pEntry->offset;
    gspDmemWriteState.surface    = pEntry->surface;
    gspDmemWriteState.group      = pEntry->group;
    gspDmemWriteState.len        = pEntry->len;

    // ---- the surface resolver ----
    isHeap = (pEntry->surface == GSP_DMEM_WRITE_SURF_SYSMEMHEAP);
    if (isHeap)
    {
        // the 4.52 heap path: the descriptor map (WRITEABLE)
        if (pKernelGsp->pSysmemHeapDescriptor == NULL)
        {
            gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_NO_SURF_PTR;
            NV_PRINTF(LEVEL_ERROR, "NVRM-461: no sysmem heap descriptor "
                                   "at +8 s — the write refuses\n");
            return;
        }
        sz = pKernelGsp->pSysmemHeapDescriptor->Size;
        if (pEntry->offset + pEntry->len > sz)
        {
            gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_BOUNDS;
            NV_PRINTF(LEVEL_ERROR, "NVRM-461: plan offset 0x%llx beyond "
                                   "the heap (0x%llx) — nothing "
                                   "written\n", pEntry->offset, sz);
            return;
        }
        st = memdescMap(pKernelGsp->pSysmemHeapDescriptor, 0, sz,
                        NV_TRUE, NV_PROTECT_WRITEABLE,
                        (NvP64 *)&pVa, &pPriv);
        if ((st != NV_OK) || (pVa == NULL))
        {
            gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_MAP_FAIL;
            NV_PRINTF(LEVEL_ERROR, "NVRM-461: the heap map FAILED "
                                   "st=0x%x — nothing written\n", st);
            return;
        }
        pSurf = (volatile NvU8 *)KERNEL_POINTER_FROM_NvP64(NvU8 *, pVa);
        mapped = NV_TRUE;
    }
    else
    {
        // the direct-pointer surfaces (the driver's own allocations)
        if (!_gsp_dmem_write_resolve(pKernelGsp, pEntry->surface,
                                     &pSurf, &sz, &mapped))
        {
            gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_BAD_SURFACE;
            NV_PRINTF(LEVEL_ERROR, "NVRM-461: surface=%u outside the "
                                   "resolver or the pointer NULL — "
                                   "nothing written\n", pEntry->surface);
            return;
        }
        if (pEntry->offset + pEntry->len > sz)
        {
            gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_BOUNDS;
            NV_PRINTF(LEVEL_ERROR, "NVRM-461: plan offset 0x%llx beyond "
                                   "the surface (0x%llx) — nothing "
                                   "written\n", pEntry->offset, sz);
            return;
        }
    }

    // ---- THE PRE-VERIFY = THE MARKER CHECK (the mission law) ----
    {
        NvU8 oldSeen[8] = { 0 };
        char hexOld[24]  = { 0 };   // zero-init: the state copy publishes
        char hexWant[24] = { 0 };   // these bytes — no stack garbage in
                                    // the shared ledger

        for (i = 0; i < pEntry->len; i++)
            oldSeen[i] = pSurf[pEntry->offset + i];
        _gsp_dmem_write_hex(oldSeen, pEntry->len, hexOld, sizeof(hexOld));
        _gsp_dmem_write_hex(pEntry->old, pEntry->len, hexWant,
                            sizeof(hexWant));
        // the ledger copies (the state = the reliable surface)
        for (i = 0; i < sizeof(gspDmemWriteState.hexSeen); i++)
            gspDmemWriteState.hexSeen[i] = hexOld[i];
        for (i = 0; i < sizeof(gspDmemWriteState.hexWant); i++)
            gspDmemWriteState.hexWant[i] = hexWant[i];

        for (i = 0; i < pEntry->len; i++)
        {
            if (oldSeen[i] != pEntry->old[i])
            {
                gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_STALE_PLAN;
                NV_PRINTF(LEVEL_ERROR,
                          "NVRM-461: STALE-PLAN sel=%u (%s) surf=%u "
                          "off=0x%llx seen=%s want=%s plan_sha16=%s — "
                          "the marker 0x0EE6B280 did not hold (the "
                          "recompute raced, or the base moved) — "
                          "ABORT, nothing written\n",
                          sel, _gsp_dmem_write_field_name(sel),
                          pEntry->surface, pEntry->offset, hexOld,
                          hexWant, GSP_DMEM_WRITE_PLAN_SHA16);
                if (mapped)
                    memdescUnmap(pKernelGsp->pSysmemHeapDescriptor,
                                 NV_TRUE, pVa, pPriv);
                return;
            }
        }
        NV_PRINTF(LEVEL_INFO, "NVRM-461: pre-verify OK sel=%u (%s) "
                              "surf=%u off=0x%llx seen=%s "
                              "plan_sha16=%s\n",
                  sel, _gsp_dmem_write_field_name(sel), pEntry->surface,
                  pEntry->offset, hexOld, GSP_DMEM_WRITE_PLAN_SHA16);
    }

    // ---- the WRITE (the u64 pair {0x10B07600, 0}, one, no retry) ----
    for (i = 0; i < pEntry->len; i++)
        pSurf[pEntry->offset + i] = pEntry->nw[i];

    // ---- the POST-VERIFY: the readback must equal the new bytes ----
    {
        NvU8 newSeen[8] = { 0 };
        NvBool ok = NV_TRUE;
        char hexNew[24] = { 0 };    // zero-init (the published ledger)

        for (i = 0; i < pEntry->len; i++)
            newSeen[i] = pSurf[pEntry->offset + i];
        for (i = 0; i < pEntry->len; i++)
            ok = ok && (newSeen[i] == pEntry->nw[i]);
        _gsp_dmem_write_hex(newSeen, pEntry->len, hexNew, sizeof(hexNew));
        for (i = 0; i < sizeof(gspDmemWriteState.hexNew); i++)
            gspDmemWriteState.hexNew[i] = hexNew[i];

        gspDmemWriteState.verdict  = GSP_DMEM_WRITE_V_WRITE_DONE;
        gspDmemWriteState.verifyOk = ok ? 1 : 0;
        NV_PRINTF(ok ? LEVEL_INFO : LEVEL_ERROR,
                  "NVRM-461: write sel=%u (%s) surf=%u off=0x%llx "
                  "new=%s verify=%s plan_sha16=%s\n",
                  sel, _gsp_dmem_write_field_name(sel), pEntry->surface,
                  pEntry->offset, hexNew, ok ? "OK" : "FAIL",
                  GSP_DMEM_WRITE_PLAN_SHA16);
    }

    // ---- the unmap (the heap path only; the 4-arg pattern) ----
    if (mapped)
        memdescUnmap(pKernelGsp->pSysmemHeapDescriptor, NV_TRUE, pVa,
                     pPriv);
}

// ---- the scheduler (the hook target — NO workqueue here) ----

void
gsp_dmem_write_schedule(OBJGPU *pGpu, KernelGsp *pKernelGsp)
{
    NvU32 sel = 0;

    if (osReadRegistryDword(pGpu, "RmGspDMemWrite", &sel) != NV_OK)
        sel = 0; // default OFF — the opt-in writer, SEPARATE from the
                 // 4.51 dump and 4.52 poke keys (the three coexist)
    if ((sel == 0) || (sel > 4))
    {
        if (sel > 4)
        {
            gspDmemWriteState.verdict = GSP_DMEM_WRITE_V_BAD_SEL;
            NV_PRINTF(LEVEL_ERROR, "NVRM-461: RmGspDMemWrite=%u outside "
                                   "the group domain {1..4} — OFF\n",
                                  sel);
        }
        // sel == 0: the silent OFF (the instrument absent — no verdict,
        // no ledger noise; the nv.c side prints the honest "off or the
        // hook never ran" line at +8 s)
        return;
    }

    if (gspDmemWriteState.scheduled)
        return;
    gspDmemWriteState.scheduled       = NV_TRUE;
    gspDmemWriteState.gpuId           = gpuGetDeviceInstance(pGpu);
    gspDmemWriteState.sel             = sel;   // the late fn reads THE
                                               // boot's selector from it
    gspDmemWriteState.pGpuSaved       = (void *)pGpu;
    gspDmemWriteState.pKernelGspSaved = (void *)pKernelGsp;
    gspDmemWriteState.pLateFn         = gsp_dmem_write_late; // the
                                             // gc-sections law: the
                                             // pointer keeps the fn alive
    {
        const char *fn = _gsp_dmem_write_field_name(sel);
        NvU32 i;
        for (i = 0; (i < 7) && fn[i]; i++)
            gspDmemWriteState.fieldName[i] = fn[i];
        gspDmemWriteState.fieldName[i] = '\0';
    }
    {
        const char *sha = GSP_DMEM_WRITE_PLAN_SHA16;
        NvU32 i;
        for (i = 0; (i < 19) && sha[i]; i++)
            gspDmemWriteState.sha16[i] = sha[i];
        gspDmemWriteState.sha16[i] = '\0';
    }

    // NO schedule_delayed_work HERE — the workqueue = the nv.c side's
    // (patch_nv_461.py armed it at module init, +8 s). This hook ONLY
    // fills the state (the 4.51 v4 pattern).
    NV_PRINTF(LEVEL_INFO, "NVRM-461: gsp_dmem_write armed sel=%u (%s) "
                          "ONE u64 pair this boot plan_sha16=%s — the "
                          "nv.c side fires at +8 s\n",
              sel, _gsp_dmem_write_field_name(sel),
              GSP_DMEM_WRITE_PLAN_SHA16);
}
