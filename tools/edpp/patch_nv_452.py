#!/usr/bin/env python3
"""patch_nv_452.py — the 4.55 nv.c (kernel-open) side of the two-sided
hpoke writer: the delayed work (8 s) calls the RM-side late function
THROUGH the shared state's pLateFn (the gc-sections law — no cross-TU
symbol), then prints the dmesg LEDGER from the state's verdict fields
(the 4.51 lesson: the RM NV_PRINTF = level-gated, the nv.c printk =
the reliable surface). The v9-scanner patch pattern (the exact anchors:
nvidia_init_module + nv_memdbg_init). Idempotent (HpokeMarker).
Coexists with the 4.51 DmemDumpMarker (either application order).
Run as root, BEFORE the dkms (the runbook-452 §4 — without it the
build passes but the poke never fires: the silent no-op)."""
import os
import sys

# the tree path — overridable for the v455a fixture dry-run (the selftest
# never touches the real tree; the default = the machine-day target)
P = os.environ.get('NV_C_452_PATH',
                   '/usr/src/nvidia-610.57.04/kernel-open/nvidia/nv.c')
s = open(P).read()

if 'HpokeMarker' in s:
    print('already patched (idempotent)')
    sys.exit(0)

# ---- 1. the declarations (the layout MIRROR) before nvidia_init_module ----
anchor = 'static int __init nvidia_init_module(void)'
assert s.count(anchor) == 1, 'the init anchor absent or duplicated'
s = s.replace(anchor, '''/* HpokeMarker — the 4.55 two-sided hpoke writer (the linux side; the RM
 * side = gsp_hpoke.c in kernel_gsp.c: the gate, the plan filter, the
 * radix3 WRITEABLE map, the pre/post verify, the byte-lane write).
 * The verdict codes + the state struct = the EXACT mirrors of the RM
 * side (the v455a selftest compiles BOTH and asserts the sizeof/
 * offsetof agreement member by member — the mirror drift = the lab
 * fail, never the machine day). */
#define GSP_HPOKE_V_OFF             0
#define GSP_HPOKE_V_BAD_SEL         1
#define GSP_HPOKE_V_NO_HEAP_DESC    2
#define GSP_HPOKE_V_NULL_PLAN       3
#define GSP_HPOKE_V_SEL_NOT_IN_PLAN 4
#define GSP_HPOKE_V_BOUNDS          5
#define GSP_HPOKE_V_MAP_FAIL        6
#define GSP_HPOKE_V_STALE_PLAN      7
#define GSP_HPOKE_V_WRITE_DONE      8
#define GSP_HPOKE_V_NOT_SCHEDULED   9

typedef struct
{
    NvBool     scheduled;      /* the regkey gate result */
    NvBool     executed;       /* the one-shot guard */
    NvU32      gpuId;
    NvU32      sel;
    NvU32      verdict;
    NvU32      verifyOk;
    NvU64      heapOffset;
    NvU32      len;
    char       fieldName[8];
    char       hexSeen[24];
    char       hexWant[24];
    char       hexNew[24];
    char       sha16[20];
    void      *pGpuSaved;
    void      *pKernelGspSaved;
    void     (*pLateFn)(void);  /* the late poke, called BY POINTER */
} GSP_HPOKE_STATE;   /* the layout MIRROR of the RM-side struct */

extern GSP_HPOKE_STATE gspHpokeState;   /* the RM side = non-static */
static struct delayed_work gsp_hpoke_work;
static void gsp_hpoke_worker(struct work_struct *w);

static int __init nvidia_init_module(void)''', 1)

# ---- 2. the arm inside the init (the anchor = robust to the 4.51 patch
# order: nv_memdbg_init() appears exactly once pre- or post-DmemDump) ----
anchor2 = 'nv_memdbg_init();'
assert s.count(anchor2) == 1, 'the nv_memdbg anchor absent or duplicated'
s = s.replace(anchor2, '''nv_memdbg_init();

    {
        static NvBool hpoke_armed = NV_FALSE;
        if (!hpoke_armed)
        {
            hpoke_armed = NV_TRUE;
            INIT_DELAYED_WORK(&gsp_hpoke_work, gsp_hpoke_worker);
            schedule_delayed_work(&gsp_hpoke_work, msecs_to_jiffies(8000));
            printk(KERN_ERR "NVRM-452: the poke work armed (the late fn "
                            "fires in 8 s if RmGspHPoke opted in)\\n");
        }
    }''', 1)

# ---- 3. the worker (AFTER the declarations, BEFORE the init function —
# the first occurrence of the anchor = the decl block's trailing line;
# the banked 4.51 lesson: the worker AFTER its declarations) ----
worker = '''static const char *gsp_hpoke_verdict_names_nv[10] = {
    "OFF", "BAD-SEL", "NO-HEAP-DESC", "NULL-PLAN", "SEL-NOT-IN-PLAN",
    "BOUNDS", "MAP-FAIL", "STALE-PLAN", "WRITE-DONE", "NOT-SCHEDULED"
};

static void gsp_hpoke_worker(struct work_struct *w)
{
    void (*latefn)(void) = gspHpokeState.pLateFn;
    const char *vn;

    if (latefn)
        latefn();   /* the RM-side poke fills the state's verdicts */

    vn = (gspHpokeState.verdict < 10)
           ? gsp_hpoke_verdict_names_nv[gspHpokeState.verdict] : "?";
    if (!gspHpokeState.scheduled)
    {
        printk(KERN_ERR "NVRM-452: the poke not scheduled (RmGspHPoke "
                        "absent/0, or the kernel_gsp.c hook never ran — "
                        "verdict=%s)\\n", vn);
        return;
    }
    printk(KERN_ERR "NVRM-452: poke sel=%u (%s) off=0x%llx len=%u "
                    "verdict=%s verify=%s seen=%s want=%s new=%s "
                    "sha16=%s\\n",
           gspHpokeState.sel, gspHpokeState.fieldName,
           gspHpokeState.heapOffset, gspHpokeState.len, vn,
           (gspHpokeState.verdict == GSP_HPOKE_V_WRITE_DONE)
              ? (gspHpokeState.verifyOk ? "OK" : "FAIL") : "n/a",
           gspHpokeState.hexSeen, gspHpokeState.hexWant,
           gspHpokeState.hexNew, gspHpokeState.sha16);
}

'''
marker = 'static int __init nvidia_init_module(void)'
idx = s.index(marker)
s = s[:idx] + worker + s[idx:]

open(P, 'w').write(s)
print('PATCH OK: nv.c = the hpoke worker + the arm (the HpokeMarker)')
