#!/usr/bin/env python3
"""patch_nv_462.py — the 4.62 nv.c (kernel-open) side of the two-sided
ROUTE W read probe: the delayed work (8 s) calls the RM-side late
function THROUGH the shared state's pLateFn (the gc-sections law — no
cross-TU symbol), then prints the dmesg LEDGER from the state's verdict
fields (the 4.51 lesson: the RM NV_PRINTF = level-gated, the nv.c
printk = the reliable surface) and publishes the read window as a
debugfs blob (the 4.51 dump pattern — the sha16 = computed in
USERSPACE from the blob, zero crypto in-kernel; the runbook-462 §4).
The v9-scanner patch pattern (the exact anchors: nvidia_init_module +
nv_memdbg_init). Idempotent (Wpr2ReadMarker). Coexists with the 4.51
DmemDumpMarker, the 4.52 HpokeMarker AND the 4.61 DmemWriteMarker
(either application order — the anchor nv_memdbg_init() stays unique:
the insertions APPEND after it, never duplicate it).
Run as root, BEFORE the dkms (the runbook-462 §3 — without it the
build passes but the read never fires: the silent no-op)."""
import os
import sys

# the tree path — overridable for the v462b fixture dry-run (the selftest
# never touches the real tree; the default = the machine-day target)
P = os.environ.get('NV_C_462_PATH',
                   '/usr/src/nvidia-610.57.04/kernel-open/nvidia/nv.c')
s = open(P).read()

if 'Wpr2ReadMarker' in s:
    print('already patched (idempotent)')
    sys.exit(0)

# ---- 0. the debugfs include (the 4.51 publisher pattern; nv.c lacks
#         it — added ONCE, next to the 4.51 line when present) ----
if '#include <linux/debugfs.h>' not in s:
    anchor_inc = '#include <linux/miscdevice.h>'
    if anchor_inc not in s:
        anchor_inc = '#include <linux/io.h>'
    assert anchor_inc in s, 'the include anchor absent'
    s = s.replace(anchor_inc,
                  anchor_inc + '\n#include <linux/debugfs.h>   /* the 4.62 publisher */',
                  1)

# ---- 1. the declarations (the layout MIRROR) before nvidia_init_module --
anchor = 'static int __init nvidia_init_module(void)'
assert s.count(anchor) == 1, 'the init anchor absent or duplicated'
s = s.replace(anchor, '''/* Wpr2ReadMarker — the 4.62 two-sided ROUTE W read probe (the linux
 * side; the RM side = gsp_wpr2_read.c in kernel_gsp.c: the gate, the
 * window selector, the plan gate, memdescCreateExisting +
 * memdescDescribe(ADDR_FBMEM) + memdescMap READABLE, the integer
 * classifier, the unmap). The verdict codes + the classes + the state
 * struct = the EXACT mirrors of the RM side (the v462b battery
 * compiles BOTH and asserts the sizeof/offsetof agreement member by
 * member — the mirror drift = the lab fail, never the machine day). */
#define GSP_WPR2_READ_V_OFF            0
#define GSP_WPR2_READ_V_BAD_SEL        1
#define GSP_WPR2_READ_V_NULL_PLAN      2
#define GSP_WPR2_READ_V_NO_GPU         3
#define GSP_WPR2_READ_V_MAP_FAIL       4
#define GSP_WPR2_READ_V_COPY_SHORT     5
#define GSP_WPR2_READ_V_READ_DONE      6
#define GSP_WPR2_READ_V_NOT_SCHEDULED  7

#define GSP_WPR2_READ_C_SEAL_ZERO      0
#define GSP_WPR2_READ_C_SEAL_FF        1
#define GSP_WPR2_READ_C_SEAL_CONSTANT  2
#define GSP_WPR2_READ_C_WPRMETA_MAGIC  3
#define GSP_WPR2_READ_C_ELF_MAGIC      4
#define GSP_WPR2_READ_C_HEAP_FREELIST  5
#define GSP_WPR2_READ_C_DEGENERATE     6
#define GSP_WPR2_READ_C_LIVE_UNKNOWN   7

#define GSP_WPR2_READ_MAX_LEN_NV       (1u << 20)

typedef struct
{
    NvBool  scheduled;    /* the regkey gate result */
    NvBool  executed;     /* the one-shot guard */
    NvU32   gpuId;
    NvU32   sel;
    NvU32   verdict;
    NvU32   plausClass;
    NvU32   winClass;
    NvU64   fbBase;
    NvU64   fbSize;
    NvU32   readLen;
    NvU32   distinct;
    NvU64   firstU64;
    NvU32   topVal;
    NvU32   topCnt;
    NvU8    blob[GSP_WPR2_READ_MAX_LEN_NV];  /* the layout MIRROR — the
                              instance lives in the RM TU (extern) */
    void   *pGpuSaved;
    void   *pKernelGspSaved;
    void  (*pLateFn)(void);  /* the late read, called BY POINTER */
} GSP_WPR2_READ_STATE;   /* the layout MIRROR of the RM-side struct */

extern GSP_WPR2_READ_STATE gspWpr2ReadState;  /* the RM = non-static */
static struct delayed_work gsp_wpr2_read_work;
static void gsp_wpr2_read_worker(struct work_struct *w);

static int __init nvidia_init_module(void)''', 1)

# ---- 2. the arm inside the init (the anchor = robust to the
#         4.51/4.52/4.61 patch orders: nv_memdbg_init() appears exactly
#         once pre- or post-all) --
anchor2 = 'nv_memdbg_init();'
assert s.count(anchor2) == 1, 'the nv_memdbg anchor absent or duplicated'
s = s.replace(anchor2, '''nv_memdbg_init();

    {
        static NvBool wpr2_read_armed = NV_FALSE;
        if (!wpr2_read_armed)
        {
            wpr2_read_armed = NV_TRUE;
            INIT_DELAYED_WORK(&gsp_wpr2_read_work,
                              gsp_wpr2_read_worker);
            schedule_delayed_work(&gsp_wpr2_read_work,
                                  msecs_to_jiffies(8000));
            printk(KERN_ERR "NVRM-462: the ROUTE W read work armed (the "
                            "late fn fires in 8 s if RmGspWpr2Read "
                            "opted in)\\n");
        }
    }''', 1)

# ---- 3. the worker (AFTER the declarations, BEFORE the init function —
# the first occurrence of the anchor = the decl block's trailing line;
# the banked 4.51 lesson, TWICE repeated: the worker AFTER its
# declarations) ----
worker = '''static const char *gsp_wpr2_read_verdict_names_nv[8] = {
    "OFF", "BAD-SEL", "NULL-PLAN", "NO-GPU", "MAP-FAIL", "COPY-SHORT",
    "READ-DONE", "NOT-SCHEDULED"
};

static const char *gsp_wpr2_read_class_names_nv[8] = {
    "SEAL-ZERO", "SEAL-FF", "SEAL-CONSTANT", "WPRMETA-MAGIC",
    "ELF-MAGIC", "HEAP-FREELIST", "DEGENERATE", "LIVE-UNKNOWN"
};

static void gsp_wpr2_read_worker(struct work_struct *w)
{
    void (*latefn)(void) = gspWpr2ReadState.pLateFn;
    const char *vn;
    const char *cn;
    static struct debugfs_blob_wrapper wpr2_wrappers[4];
    static NvBool wpr2_published = NV_FALSE;
    struct dentry *parent;
    struct dentry *child;
    char name[32];

    if (latefn)
        latefn();   /* the RM-side read fills the state's verdicts */

    vn = (gspWpr2ReadState.verdict < 8)
           ? gsp_wpr2_read_verdict_names_nv[gspWpr2ReadState.verdict]
           : "?";
    cn = (gspWpr2ReadState.plausClass < 8)
           ? gsp_wpr2_read_class_names_nv[gspWpr2ReadState.plausClass]
           : "?";

    if (!gspWpr2ReadState.scheduled)
    {
        printk(KERN_ERR "NVRM-462: the read not scheduled (RmGspWpr2"
                        "Read absent/0, or the kernel_gsp.c hook never "
                        "ran — verdict=%s)\\n", vn);
        return;
    }
    if ((gspWpr2ReadState.verdict == GSP_WPR2_READ_V_READ_DONE) &&
        !wpr2_published && (gspWpr2ReadState.readLen > 0) &&
        (gspWpr2ReadState.sel <= 4))
    {
        parent = debugfs_create_dir("gsp_wpr2_read", NULL);
        if (parent)
        {
            child = debugfs_create_dir("win", parent);
            if (child)
            {
                scnprintf(name, sizeof(name), "window%u.bin",
                          gspWpr2ReadState.sel);
                wpr2_wrappers[gspWpr2ReadState.sel - 1].data =
                    gspWpr2ReadState.blob;
                wpr2_wrappers[gspWpr2ReadState.sel - 1].size =
                    (size_t)gspWpr2ReadState.readLen;
                debugfs_create_blob(name, 0400, child,
                                    &wpr2_wrappers[gspWpr2ReadState.sel - 1]);
                wpr2_published = NV_TRUE;
                printk(KERN_ERR "NVRM-462: the window blob published "
                                "(/sys/kernel/debug/gsp_wpr2_read/win/"
                                "%s — the sha16 = USERSPACE computes "
                                "it)\\n", name);
            }
        }
    }
    printk(KERN_ERR "NVRM-462: read sel=%u win=%u base=0x%llx size=%llu "
                    "len=%u verdict=%s class=%s first=0x%llx "
                    "distinct=%u top=%u/%u\\n",
           gspWpr2ReadState.sel, gspWpr2ReadState.winClass,
           gspWpr2ReadState.fbBase, gspWpr2ReadState.fbSize,
           gspWpr2ReadState.readLen, vn, cn, gspWpr2ReadState.firstU64,
           gspWpr2ReadState.distinct, gspWpr2ReadState.topVal,
           gspWpr2ReadState.topCnt);
}

'''
marker = 'static int __init nvidia_init_module(void)'
idx = s.index(marker)
s = s[:idx] + worker + s[idx:]

open(P, 'w').write(s)
print('PATCH OK: nv.c = the ROUTE W read worker + the arm '
      '(the Wpr2ReadMarker)')
