#!/usr/bin/env python3
"""patch_nv_461.py — the 4.61 nv.c (kernel-open) side of the two-sided
DMEM write lane: the delayed work (8 s) calls the RM-side late function
THROUGH the shared state's pLateFn (the gc-sections law — no cross-TU
symbol), then prints the dmesg LEDGER from the state's verdict fields
(the 4.51 lesson: the RM NV_PRINTF = level-gated, the nv.c printk =
the reliable surface). The v9-scanner patch pattern (the exact anchors:
nvidia_init_module + nv_memdbg_init). Idempotent (DmemWriteMarker).
Coexists with the 4.51 DmemDumpMarker AND the 4.52 HpokeMarker (either
application order — the anchor nv_memdbg_init() stays unique: the
insertions APPEND after it, never duplicate it).
Run as root, BEFORE the dkms (the runbook-461 §1 — without it the
build passes but the write never fires: the silent no-op)."""
import os
import sys

# the tree path — overridable for the v461b fixture dry-run (the selftest
# never touches the real tree; the default = the machine-day target)
P = os.environ.get('NV_C_461_PATH',
                   '/usr/src/nvidia-610.57.04/kernel-open/nvidia/nv.c')
s = open(P).read()

if 'DmemWriteMarker' in s:
    print('already patched (idempotent)')
    sys.exit(0)

# ---- 1. the declarations (the layout MIRROR) before nvidia_init_module --
anchor = 'static int __init nvidia_init_module(void)'
assert s.count(anchor) == 1, 'the init anchor absent or duplicated'
s = s.replace(anchor, '''/* DmemWriteMarker — the 4.61 two-sided DMEM write lane (the linux
 * side; the RM side = gsp_dmem_write.c in kernel_gsp.c: the gate, the
 * selector, the surface resolver, the marker pre-verify, the u64-pair
 * write, the post-verify). The verdict codes + the state struct = the
 * EXACT mirrors of the RM side (the v461b battery compiles BOTH and
 * asserts the sizeof/offsetof agreement member by member — the mirror
 * drift = the lab fail, never the machine day). */
#define GSP_DMEM_WRITE_V_OFF             0
#define GSP_DMEM_WRITE_V_BAD_SEL         1
#define GSP_DMEM_WRITE_V_NO_SURF_PTR     2
#define GSP_DMEM_WRITE_V_NULL_PLAN       3
#define GSP_DMEM_WRITE_V_SEL_NOT_IN_PLAN 4
#define GSP_DMEM_WRITE_V_BOUNDS          5
#define GSP_DMEM_WRITE_V_MAP_FAIL        6
#define GSP_DMEM_WRITE_V_STALE_PLAN      7
#define GSP_DMEM_WRITE_V_WRITE_DONE      8
#define GSP_DMEM_WRITE_V_NOT_SCHEDULED   9
#define GSP_DMEM_WRITE_V_BAD_SURFACE    10

typedef struct
{
    NvBool     scheduled;      /* the regkey gate result */
    NvBool     executed;       /* the one-shot guard */
    NvU32      gpuId;
    NvU32      sel;
    NvU32      verdict;
    NvU32      verifyOk;
    NvU64      surfOffset;
    NvU32      surface;
    NvU32      group;
    NvU32      len;
    char       fieldName[8];
    char       hexSeen[24];
    char       hexWant[24];
    char       hexNew[24];
    char       sha16[20];
    void      *pGpuSaved;
    void      *pKernelGspSaved;
    void     (*pLateFn)(void);  /* the late write, called BY POINTER */
} GSP_DMEM_WRITE_STATE;   /* the layout MIRROR of the RM-side struct */

extern GSP_DMEM_WRITE_STATE gspDmemWriteState;  /* the RM = non-static */
static struct delayed_work gsp_dmem_write_work;
static void gsp_dmem_write_worker(struct work_struct *w);

static int __init nvidia_init_module(void)''', 1)

# ---- 2. the arm inside the init (the anchor = robust to the 4.51/4.52
# patch orders: nv_memdbg_init() appears exactly once pre- or post-both) --
anchor2 = 'nv_memdbg_init();'
assert s.count(anchor2) == 1, 'the nv_memdbg anchor absent or duplicated'
s = s.replace(anchor2, '''nv_memdbg_init();

    {
        static NvBool dmem_write_armed = NV_FALSE;
        if (!dmem_write_armed)
        {
            dmem_write_armed = NV_TRUE;
            INIT_DELAYED_WORK(&gsp_dmem_write_work,
                              gsp_dmem_write_worker);
            schedule_delayed_work(&gsp_dmem_write_work,
                                  msecs_to_jiffies(8000));
            printk(KERN_ERR "NVRM-461: the DMEM write work armed (the "
                            "late fn fires in 8 s if RmGspDMemWrite "
                            "opted in)\\n");
        }
    }''', 1)

# ---- 3. the worker (AFTER the declarations, BEFORE the init function —
# the first occurrence of the anchor = the decl block's trailing line;
# the banked 4.51 lesson: the worker AFTER its declarations) ----
worker = '''static const char *gsp_dmem_write_verdict_names_nv[11] = {
    "OFF", "BAD-SEL", "NO-SURF-PTR", "NULL-PLAN", "SEL-NOT-IN-PLAN",
    "BOUNDS", "MAP-FAIL", "STALE-PLAN", "WRITE-DONE", "NOT-SCHEDULED",
    "BAD-SURFACE"
};

static void gsp_dmem_write_worker(struct work_struct *w)
{
    void (*latefn)(void) = gspDmemWriteState.pLateFn;
    const char *vn;

    if (latefn)
        latefn();   /* the RM-side write fills the state's verdicts */

    vn = (gspDmemWriteState.verdict < 11)
           ? gsp_dmem_write_verdict_names_nv[gspDmemWriteState.verdict]
           : "?";
    if (!gspDmemWriteState.scheduled)
    {
        printk(KERN_ERR "NVRM-461: the write not scheduled (RmGspDMem"
                        "Write absent/0, or the kernel_gsp.c hook never "
                        "ran — verdict=%s)\\n", vn);
        return;
    }
    printk(KERN_ERR "NVRM-461: write sel=%u (%s) surf=%u group=%u "
                    "off=0x%llx len=%u verdict=%s verify=%s seen=%s "
                    "want=%s new=%s sha16=%s\\n",
           gspDmemWriteState.sel, gspDmemWriteState.fieldName,
           gspDmemWriteState.surface, gspDmemWriteState.group,
           gspDmemWriteState.surfOffset, gspDmemWriteState.len, vn,
           (gspDmemWriteState.verdict == GSP_DMEM_WRITE_V_WRITE_DONE)
              ? (gspDmemWriteState.verifyOk ? "OK" : "FAIL") : "n/a",
           gspDmemWriteState.hexSeen, gspDmemWriteState.hexWant,
           gspDmemWriteState.hexNew, gspDmemWriteState.sha16);
}

'''
marker = 'static int __init nvidia_init_module(void)'
idx = s.index(marker)
s = s[:idx] + worker + s[idx:]

open(P, 'w').write(s)
print('PATCH OK: nv.c = the DMEM write worker + the arm '
      '(the DmemWriteMarker)')
