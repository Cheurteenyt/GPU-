#!/usr/bin/env python3
"""patch_nv_451.py — the 4.51 nv.c (kernel-open) side of the two-sided
DMEM instrument: the delayed work (8 s) publishes the RM-captured blobs
via debugfs + the dmesg ledger. The v9-scanner patch pattern (the exact
anchors: nvidia_init_module + nv_memdbg_init). Idempotent
(DmemDumpMarker). Run as root."""
import sys

P = '/usr/src/nvidia-610.57.04/kernel-open/nvidia/nv.c'
s = open(P).read()

if 'DmemDumpMarker' in s:
    print('already patched (idempotent)')
    sys.exit(0)

# ---- 0. the debugfs include (nv.c = lacks it) ----
anchor_inc = '#include "nv-linux.h"'
assert s.count(anchor_inc) == 1, 'the nv-linux.h include absent or duplicated'
s = s.replace(anchor_inc, anchor_inc + '\n#include <linux/debugfs.h>   /* the 4.51 publisher */', 1)

# ---- 1. the declarations before nvidia_init_module ----
anchor = 'static int __init nvidia_init_module(void)'
assert s.count(anchor) == 1, 'the init anchor absent or duplicated'
s = s.replace(anchor, '''/* DmemDumpMarker — the 4.51 TÂCHE A: the GSP surface publication (the linux
 * side of the two-sided instrument; the RM side = gsp_dmem_dump.c in
 * kernel_gsp.c captures the pointers + maps the sysmem heap). */
#define GSP_DMEM_BLOBS_MAX_NV 16
typedef struct {
    NvBool        valid;
    const char   *name;
    void         *data;
    NvU64         size;
} GSP_DMEM_BLOB_REC_NV;   /* the layout MIRROR of the RM-side GSP_DMEM_BLOB_REC */

typedef struct {
    NvBool        captured;
    NvU32         gpuId;
    GSP_DMEM_BLOB_REC_NV blobs[GSP_DMEM_BLOBS_MAX_NV];
} GSP_DMEM_DUMP_STATE_NV;   /* the layout MIRROR of the RM-side GSP_DMEM_DUMP_STATE */

extern GSP_DMEM_DUMP_STATE_NV gspDmemDumpState;   /* the RM side = non-static */
static struct delayed_work gsp_dmem_work;
static void gsp_dmem_publisher(struct work_struct *w);

static int __init nvidia_init_module(void)''', 1)

# ---- 2. the schedule inside the init ----
anchor2 = '''    nv_memdbg_init();

    rc = nv_procfs_init();'''
assert s.count(anchor2) == 1, 'the nv_memdbg anchor absent or duplicated'
s = s.replace(anchor2, '''    nv_memdbg_init();

    {
        static NvBool dmem_scheduled = NV_FALSE;
        if (!dmem_scheduled)
        {
            dmem_scheduled = NV_TRUE;
            INIT_DELAYED_WORK(&gsp_dmem_work, gsp_dmem_publisher);
            schedule_delayed_work(&gsp_dmem_work, msecs_to_jiffies(8000));
            printk(KERN_ERR "NVRM-451: the publisher armed (the debugfs in 8 s)\\n");
        }
    }

    rc = nv_procfs_init();''', 1)

# ---- 3. the publisher (AFTER the declarations, BEFORE the init function —
# the first occurrence of the anchor = the decl block's trailing line) ----
worker = '''
static void gsp_dmem_publisher(struct work_struct *w)
{
    static struct debugfs_blob_wrapper wrappers[GSP_DMEM_BLOBS_MAX_NV];
    struct dentry *parent, *child;
    char dir[24];
    int i, published = 0;

    if (!gspDmemDumpState.captured)
    {
        printk(KERN_ERR "NVRM-451: the surfaces not captured (RmGspDmemDump off)\\n");
        return;
    }
    parent = debugfs_create_dir("gsp_dmem", NULL);
    if (IS_ERR_OR_NULL(parent))
    {
        printk(KERN_ERR "NVRM-451: the debugfs parent create failed\\n");
        return;
    }
    snprintf(dir, sizeof(dir), "gpu%u", gspDmemDumpState.gpuId);
    child = debugfs_create_dir(dir, parent);
    if (IS_ERR_OR_NULL(child))
    {
        printk(KERN_ERR "NVRM-451: the debugfs child create failed\\n");
        return;
    }
    for (i = 0; i < GSP_DMEM_BLOBS_MAX_NV; i++)
    {
        if (!gspDmemDumpState.blobs[i].valid)
            continue;
        wrappers[i].data = gspDmemDumpState.blobs[i].data;
        wrappers[i].size = (size_t)gspDmemDumpState.blobs[i].size;
        debugfs_create_blob(gspDmemDumpState.blobs[i].name, 0400, child, &wrappers[i]);
        printk(KERN_ERR "NVRM-451: surface %-16s va=0x%llx size=0x%llx\\n",
               gspDmemDumpState.blobs[i].name,
               (NvU64)(NvUPtr)gspDmemDumpState.blobs[i].data,
               gspDmemDumpState.blobs[i].size);
        published++;
    }
    printk(KERN_ERR "NVRM-451: the dump ready at /sys/kernel/debug/gsp_dmem/%s/ (%d surfaces)\\n",
           dir, published);
}

'''
marker = 'static int __init nvidia_init_module(void)'
idx = s.index(marker)
s = s[:idx] + worker + s[idx:]

open(P, 'w').write(s)
print('PATCH OK: nv.c = the publisher + the schedule (the DmemDumpMarker)')
