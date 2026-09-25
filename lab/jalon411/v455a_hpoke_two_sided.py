#!/usr/bin/env python3
"""v455a_hpoke_two_sided.py — PASS 4.55 selftest: the two-sided
conversion of the gsp_hpoke debt (the trap = the 3rd occurrence, the
pattern = the 4.51 v2 proof). The battery:

  G1  the header-hygiene guard — the RM TU carries ZERO linux headers
      (the trap's own test: workqueue/delayed_work/printk/debugfs in
      gsp_hpoke.c = the battery FAILS, the debt can never return
      silently)
  G2  the mirror CONTRACT text — the verdict codes (name, value) and
      the verdict names table agree BETWEEN the RM file and
      patch_nv_452.py
  G3  the stub-compile + the logic battery — the RM TU compiles
      against the stub surface (plan_ok + plan_null variants) and
      EVERY verdict path executes on the host (the off gate, the bad
      selector, the happy path byte-exact, the one-shot, the
      STALE-PLAN abort (nothing written), the selector miss, the
      bounds, the map fail, the null descriptor, the pre-executed
      guard) — the late call exercised THROUGH the state's pLateFn
      pointer (the gc-sections contract itself)
  G4  the layout mirror — sizeof/offsetof for EVERY member computed
      on BOTH sides (the RM struct vs the patcher's mirror text,
      compiled with the same gcc) — the drift = a named member
  G5  the patcher dry-run — the fixture nv.c (the anchor twin) patched,
      the idempotency, the worker AFTER the declarations, the patched
      file = gcc -Wall -fsyntax-only CLEAN (the format strings checked
      via the printf attribute — the 4.51 \\n-in-C-string lesson
      executed)
  G6  the cross-side contract — the patched nv.c carries NO RM
      primitive (memdescMap/osReadRegistryDword/the plan), the RM TU
      carries NO linux machinery; + the 2-TU LINK proof: the driver
      compiled against the PATCHER's mirror struct reads the state
      the RM TU wrote (the extern contract at link level)

Run: python3 v455a_hpoke_two_sided.py   (self-contained, host-only,
nothing touches a GPU or the real tree)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
RM_FILE = os.path.join(REPO, "tools", "edpp", "gsp_hpoke.c")
PATCHER = os.path.join(REPO, "tools", "edpp", "patch_nv_452.py")

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL") + " " + name + ((" — " + detail) if (detail and not cond) else ""))
    return bool(cond)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# ---------------------------------------------------------------- the fixtures

STUB_H = r"""
#ifndef GSP_HPOKE_STUB_H
#define GSP_HPOKE_STUB_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char      NvU8;
typedef unsigned int       NvU32;
typedef unsigned long long NvU64;
typedef unsigned char      NvBool;
typedef void              *NvP64;
typedef unsigned int       NV_STATUS;
typedef enum { LEVEL_ERROR = 1, LEVEL_INFO = 2 } NV_LEVEL;
#define NV_OK 0u
#define NV_TRUE 1
#define NV_FALSE 0
#define NvP64_NULL ((void *)0)
#define NV_PROTECT_WRITEABLE 0x2
#define NV_PRINTF(lvl, fmt, ...) fprintf(stderr, "[RM] " fmt, ##__VA_ARGS__)
#define KERNEL_POINTER_FROM_NvP64(type, p) ((type)(p))
typedef struct { NvU64 Size; } STUB_MEMDESC;
typedef struct { int _gpu; } OBJGPU;
typedef struct { STUB_MEMDESC *pSysmemHeapDescriptor; } KernelGsp;
/* the mocks — defined in the driver TU, declared here */
extern NvU32 g_stub_regval;
extern int   g_stub_regpresent;
extern NvU8 *g_stub_heap;
extern NvU64 g_stub_heapsize;
extern STUB_MEMDESC *g_stub_desc;
extern int g_stub_mapcount, g_stub_unmapcount, g_stub_mapfail;
extern int g_stub_gpuinst;
NV_STATUS osReadRegistryDword(OBJGPU *p, const char *k, NvU32 *v);
NV_STATUS memdescMap(STUB_MEMDESC *d, NvU64 off, NvU64 sz, NvBool wr,
                     NvU32 prot, NvP64 *pVa, NvP64 *pPriv);
void memdescUnmap(STUB_MEMDESC *d, NvBool f, NvP64 pVa, NvP64 pPriv);
NvU32 gpuGetDeviceInstance(OBJGPU *p);
#endif
"""

MOCKS_C = r"""
/* the mock surface — the smallest twin of the RM primitives the file
 * uses; the map = a host buffer, the registry = a pair of globals */
NvU32 g_stub_regval = 0;
int   g_stub_regpresent = 0;
NvU8 *g_stub_heap = 0;
NvU64 g_stub_heapsize = 0;
STUB_MEMDESC *g_stub_desc = 0;
int g_stub_mapcount = 0, g_stub_unmapcount = 0, g_stub_mapfail = 0;
int g_stub_gpuinst = 42;

NV_STATUS osReadRegistryDword(OBJGPU *p, const char *k, NvU32 *v)
{
    (void)p; (void)k;
    if (!g_stub_regpresent) return 1u;   /* any non-OK = the key absent */
    *v = g_stub_regval;
    return NV_OK;
}
NV_STATUS memdescMap(STUB_MEMDESC *d, NvU64 off, NvU64 sz, NvBool wr,
                     NvU32 prot, NvP64 *pVa, NvP64 *pPriv)
{
    (void)d; (void)off; (void)wr; (void)prot;
    if (g_stub_mapfail) return 0x55u;
    *pVa = (NvP64)g_stub_heap;
    *pPriv = NvP64_NULL;
    g_stub_mapcount++;
    (void)sz;
    return NV_OK;
}
void memdescUnmap(STUB_MEMDESC *d, NvBool f, NvP64 pVa, NvP64 pPriv)
{
    (void)d; (void)f; (void)pVa; (void)pPriv;
    g_stub_unmapcount++;
}
NvU32 gpuGetDeviceInstance(OBJGPU *p) { (void)p; return (NvU32)g_stub_gpuinst; }
"""

PLAN_OK_H = r"""/* gsp_hpoke_plan.h — the v455a FIXTURE (the format twin of the v452c
 * emission; the REAL plan header = generated by v452c_hpatch_build.py
 * on the machine day — this fixture exercises the mechanics only) */
#define GSP_HPOKE_PLAN_SHA16 "0123456789abcdef"
#define GSP_HPOKE_PLAN_N 2

typedef struct
{
    NvU32 sel;          /* the RmGspHPoke value that selects it */
    NvU64 heapOffset;   /* the ABSOLUTE offset in the sysmem heap */
    NvU8  len;          /* the byte-lane width (1/2/4) */
    NvU8  old[8];       /* the pre-verify bytes (the runtime truth) */
    NvU8  nw[8];        /* the new bytes (the v451b LHR values) */
} GSP_HPOKE_ENTRY;

static const GSP_HPOKE_ENTRY gspHpokePlan[GSP_HPOKE_PLAN_N > 0
    ? GSP_HPOKE_PLAN_N : 1] =
{
    /* sel=1 rc @0x40 verify-after */
    { 1, 0x0000000000000040ULL, 2, { 0xde, 0xad }, { 0xbe, 0xef } },
    /* sel=2 rfc @0x80 verify-after */
    { 2, 0x0000000000000080ULL, 4, { 0x01, 0x02, 0x03, 0x04 },
                                    { 0x05, 0x06, 0x07, 0x08 } },
};
"""

PLAN_NULL_H = r"""/* gsp_hpoke_plan.h — the v455a FIXTURE (the GATED null plan) */
#define GSP_HPOKE_PLAN_SHA16 "ffffffffffffffff"
#define GSP_HPOKE_PLAN_N 0

typedef struct
{
    NvU32 sel;
    NvU64 heapOffset;
    NvU8  len;
    NvU8  old[8];
    NvU8  nw[8];
} GSP_HPOKE_ENTRY;

static const GSP_HPOKE_ENTRY gspHpokePlan[GSP_HPOKE_PLAN_N > 0
    ? GSP_HPOKE_PLAN_N : 1] =
{
    { 0, 0, 0, {0}, {0} }, /* the GATED null plan (no eligible candidate) */
};
"""

DRIVER_COMMON = r"""
#include "gsp_hpoke_stub.h"
""" + MOCKS_C + r"""
#include "gsp_hpoke.c"   /* the TU under test (the stub = the includes) */

static int g_fails = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS %s\n", name); \
    else { printf("FAIL %s\n", name); g_fails++; } } while (0)

static STUB_MEMDESC the_desc = { 0 };
static OBJGPU the_gpu;
static KernelGsp the_kgsp;

static void reset_all(int prefill)
{
    memset(&gspHpokeState, 0, sizeof(gspHpokeState));
    g_stub_regpresent = 0; g_stub_regval = 0;
    g_stub_mapcount = 0; g_stub_unmapcount = 0; g_stub_mapfail = 0;
    g_stub_heapsize = 0x1000;
    memset(g_stub_heap, 0xA5, 0x1000);          /* the NOT-the-plan fill */
    if (prefill)                                 /* the plan's old bytes */
    {
        memcpy(g_stub_heap + 0x40, (const NvU8 *)"\xde\xad", 2);
        memcpy(g_stub_heap + 0x80, (const NvU8 *)"\x01\x02\x03\x04", 4);
    }
    g_stub_desc = &the_desc;
    the_desc.Size = g_stub_heapsize;
    the_kgsp.pSysmemHeapDescriptor = g_stub_desc;  /* the WIRING the mock
                                                     needs (the v455a 1st
                                                     run caught its lack) */
}

/* the nv.c worker's guard, verbatim — the driver = the nv.c twin */
static void call_late(void)
{
    if (gspHpokeState.pLateFn)
        gspHpokeState.pLateFn();
}

int main(void)
{
    g_stub_heap = (NvU8 *)malloc(0x1000);
"""

DRIVER_OK_BODY = r"""
    /* ---- 1. the gate OFF (the key absent) ---- */
    reset_all(1);
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    CHECK(gspHpokeState.scheduled == NV_FALSE, "off: the schedule stays cold");
    call_late();   /* the pointer path (the nv.c contract, guard included) */
    CHECK(gspHpokeState.verdict == 0 /* OFF: the guard skipped the NULL fn */,
          "off: the guard skips the NULL fn, the verdict stays OFF");
    CHECK(gspHpokeState.executed == NV_FALSE, "off: the one-shot NOT armed");
    CHECK(g_stub_heap[0x40] == 0xde && g_stub_heap[0x41] == 0xad,
          "off: the heap untouched (the prefill intact)");

    /* the defense-in-depth branch: pLateFn SET but the gate cold */
    g_stub_regpresent = 1; g_stub_regval = 1;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    gspHpokeState.scheduled = NV_FALSE;   /* the impossible state, forced */
    call_late();
    CHECK(gspHpokeState.verdict == 9 /* NOT_SCHEDULED */,
          "defense: the late fn self-refuses when the gate is cold");

    /* ---- 2. the selector out of the domain ---- */
    reset_all(1);
    g_stub_regpresent = 1; g_stub_regval = 7;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    CHECK(gspHpokeState.verdict == 1 /* BAD_SEL */ &&
          gspHpokeState.scheduled == NV_FALSE,
          "bad-sel: 7 = recorded, still cold");

    /* ---- 3. the happy path sel=1 (the bytes, the counters, the ledger) ---- */
    reset_all(1);
    g_stub_regpresent = 1; g_stub_regval = 1;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    CHECK(gspHpokeState.scheduled == NV_TRUE && gspHpokeState.sel == 1,
          "happy: scheduled with sel=1");
    CHECK(strcmp(gspHpokeState.fieldName, "rc") == 0, "happy: fieldName=rc");
    CHECK(strcmp(gspHpokeState.sha16, "0123456789abcdef") == 0,
          "happy: the sha16 copy");
    CHECK(gspHpokeState.gpuId == 42, "happy: the gpuId captured");
    CHECK(gspHpokeState.pLateFn != NULL, "happy: the pLateFn stored");
    CHECK(gspHpokeState.pLateFn == gsp_hpoke_late,
          "happy: the pointer = the late fn");
    call_late();
    CHECK(gspHpokeState.verdict == 8 /* WRITE_DONE */ &&
          gspHpokeState.verifyOk == 1,
          "happy: WRITE_DONE + verify OK");
    CHECK(g_stub_heap[0x40] == 0xbe && g_stub_heap[0x41] == 0xef,
          "happy: the bytes written byte-exact");
    CHECK(g_stub_heap[0x80] == 0x01 && g_stub_heap[0x81] == 0x02 &&
          g_stub_heap[0x82] == 0x03 && g_stub_heap[0x83] == 0x04,
          "happy: the OTHER entry untouched (one field per boot)");
    CHECK(g_stub_mapcount == 1 && g_stub_unmapcount == 1,
          "happy: the map/unmap pair");
    CHECK(strcmp(gspHpokeState.hexSeen, "dead") == 0 &&
          strcmp(gspHpokeState.hexWant, "dead") == 0 &&
          strcmp(gspHpokeState.hexNew, "beef") == 0,
          "happy: the ledger hex rendered");
    call_late();
    CHECK(g_stub_mapcount == 1 && gspHpokeState.verdict == 8,
          "one-shot: the second late call refuses");

    /* ---- 4. STALE-PLAN (the runtime moved — ABORT, nothing written) ---- */
    reset_all(0);   /* the heap = all-0xA5, NOT the entry-2 old bytes */
    g_stub_regpresent = 1; g_stub_regval = 2;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    call_late();
    CHECK(gspHpokeState.verdict == 7 /* STALE_PLAN */,
          "stale: the verdict recorded");
    CHECK(g_stub_heap[0x80] == 0xA5 && g_stub_heap[0x81] == 0xA5,
          "stale: NOTHING written (the id-19 landmine guard)");
    CHECK(g_stub_mapcount == 1 && g_stub_unmapcount == 1,
          "stale: the map unheld cleanly");

    /* ---- 5. the selector miss (sel=3 not in the plan) ---- */
    reset_all(1);
    g_stub_regpresent = 1; g_stub_regval = 3;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    call_late();
    CHECK(gspHpokeState.verdict == 4 /* SEL_NOT_IN_PLAN */ &&
          g_stub_mapcount == 0,
          "sel-miss: refused BEFORE any map");

    /* ---- 6. the bounds (the plan beyond the heap) ---- */
    reset_all(1);
    g_stub_regpresent = 1; g_stub_regval = 2;
    the_desc.Size = 0x60;   /* the entry-2 @0x80 = beyond */
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    call_late();
    CHECK(gspHpokeState.verdict == 5 /* BOUNDS */ && g_stub_mapcount == 0,
          "bounds: the plan-for-another-heap guard");

    /* ---- 7. the map fail ---- */
    reset_all(1);
    g_stub_regpresent = 1; g_stub_regval = 1; g_stub_mapfail = 1;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    call_late();
    CHECK(gspHpokeState.verdict == 6 /* MAP_FAIL */ &&
          g_stub_unmapcount == 0,
          "map-fail: recorded, no unmap of a failed map");

    /* ---- 8. the null descriptor (the boot-B shape) ---- */
    reset_all(1);
    g_stub_regpresent = 1; g_stub_regval = 1;
    g_stub_desc = NULL;
    the_kgsp.pSysmemHeapDescriptor = NULL;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    call_late();
    CHECK(gspHpokeState.verdict == 2 /* NO_HEAP_DESC */,
          "no-desc: the +8 s honest refusal");

    /* ---- 9. the pre-executed guard (the defense in depth) ---- */
    reset_all(1);
    g_stub_regpresent = 1; g_stub_regval = 1;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    gspHpokeState.executed = NV_TRUE;   /* the hostile/double late call */
    call_late();
    CHECK(gspHpokeState.verdict == 0 /* OFF (untouched) */ &&
          g_stub_mapcount == 0,
          "pre-executed: the double-call refuses silently");

    printf("BATTERY_OK fails=%d\n", g_fails);
    return g_fails ? 1 : 0;
}
"""

DRIVER_NULL_BODY = r"""
    /* the GATED null plan: the schedule arms, the late refuses cleanly */
    reset_all(1);
    g_stub_regpresent = 1; g_stub_regval = 1;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    CHECK(gspHpokeState.scheduled == NV_TRUE &&
          strcmp(gspHpokeState.sha16, "ffffffffffffffff") == 0,
          "null: the sha16 = the null plan's");
    call_late();
    CHECK(gspHpokeState.verdict == 3 /* NULL_PLAN */ &&
          g_stub_mapcount == 0,
          "null: the gated plan refuses before the map");
    printf("BATTERY_OK fails=%d\n", g_fails);
    return g_fails ? 1 : 0;
}
"""

# ---------------------------------------------------------------- the checks

def strip_c_comments(src):
    """the code, not the prose — the G1 greps run on the STRIPPED text
    (the 4.54 lesson: the check that greps its own documentation = the
    auto-reference bug; the comments MAY discuss the forbidden words,
    the CODE may never carry them)."""
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)
    return src


def g1_rm_hygiene():
    """G1 — the RM TU carries ZERO linux headers (the trap's own test)."""
    src = strip_c_comments(open(RM_FILE).read())
    for bad in [r"#include\s*<linux/", r"workqueue", r"delayed_work",
                r"msecs_to_jiffies", r"\bprintk\b", r"debugfs",
                r"INIT_DELAYED_WORK"]:
        check("G1 rm-hygiene no /" + bad.strip(),
              re.search(bad, src) is None, "the trap found in gsp_hpoke.c")
    for need in ["pLateFn", "gsp_hpoke_late", "osReadRegistryDword",
                 "memdescMap", "GSP_HPOKE_V_"]:
        check("G1 rm requires " + need, need in src)
    # the state = non-static (the extern contract with the nv.c side)
    check("G1 the state non-static",
          re.search(r"^static\s+GSP_HPOKE_STATE\s+gspHpokeState", src, re.M)
          is None and "GSP_HPOKE_STATE gspHpokeState" in src)


def extract_struct(text):
    """the GSP_HPOKE_STATE struct text (no nested braces in either side)."""
    m = re.search(r"typedef struct\s*\{[^}]*\}\s*GSP_HPOKE_STATE;", text,
                  re.S)
    return m.group(0) if m else None


def extract_verdicts(text):
    """[(name, value)] from the #define GSP_HPOKE_V_* lines."""
    out = re.findall(r"#define\s+GSP_HPOKE_V_(\w+)\s+(\d+)", text)
    return [(n, int(v)) for n, v in out]


def g2_mirror_text():
    """G2 — the verdict codes + the names table agree RM <-> patcher."""
    rm = open(RM_FILE).read()
    pa = open(PATCHER).read()
    rv = extract_verdicts(rm)
    nv = extract_verdicts(pa)
    check("G2 the verdict codes present x10",
          len(rv) == 10 and len(nv) == 10,
          f"rm={len(rv)} nv={len(nv)}")
    check("G2 the verdict codes identical", sorted(rv) == sorted(nv),
          f"rm={rv} nv={nv}")
    # the names table on the nv side = the RM names by value, _ -> -
    m = re.search(r"gsp_hpoke_verdict_names_nv\[10\]\s*=\s*\{(.*?)\};", pa,
                  re.S)
    check("G2 the names table present", m is not None)
    if m:
        names = re.findall(r'"([A-Z\-]+)"', m.group(1))
        want = [n.replace("_", "-") for n, _ in sorted(rv, key=lambda x: x[1])]
        check("G2 the names table order", names == want,
              f"nv={names} want={want}")
    check("G2 the mirror struct present on both sides",
          extract_struct(rm) is not None and extract_struct(pa) is not None)
    # the patcher adds NO include (workqueue comes via nv-linux.h)
    check("G2 the patcher adds no linux include",
          re.search(r"#include\s*<linux/", pa) is None)


MEMBERS = ["scheduled", "executed", "gpuId", "sel", "verdict", "verifyOk",
           "heapOffset", "len", "fieldName", "hexSeen", "hexWant",
           "hexNew", "sha16", "pGpuSaved", "pKernelGspSaved", "pLateFn"]


def offsetof_prog(struct_text):
    pre = """
#include <stdio.h>
#include <stddef.h>
typedef unsigned char      NvU8;
typedef unsigned int       NvU32;
typedef unsigned long long NvU64;
typedef unsigned char      NvBool;
typedef void              *NvP64;
"""
    body = "int main(void) {\n"
    body += '  printf("{\\"sizeof\\":%zu", sizeof(GSP_HPOKE_STATE));\n'
    for mem in MEMBERS:
        body += ('  printf(",\\"%s\\":%%zu", offsetof(GSP_HPOKE_STATE, %s));\n'
                 % (mem, mem))
    body += '  printf("}\\n");\n  return 0;\n}\n'
    return pre + struct_text + "\n" + body


def g4_layout(build):
    """G4 — the sizeof/offsetof mirror, compiled BOTH sides, same gcc."""
    rm = open(RM_FILE).read()
    pa = open(PATCHER).read()
    s_rm, s_nv = extract_struct(rm), extract_struct(pa)
    outs = {}
    for tag, txt in (("rm", s_rm), ("nv", s_nv)):
        c = os.path.join(build, f"layout_{tag}.c")
        open(c, "w").write(offsetof_prog(txt))
        exe = os.path.join(build, f"layout_{tag}")
        r = run(["gcc", "-Wall", "-Werror", c, "-o", exe])
        if not check(f"G4 the {tag} struct compiles", r.returncode == 0,
                     r.stderr[-300:]):
            return
        r = run([exe])
        outs[tag] = r.stdout.strip()
    check("G4 the layout mirrors byte-for-byte", outs["rm"] == outs["nv"],
          f"rm={outs.get('rm')} nv={outs.get('nv')}")


FIXTURE_STUB_H = r"""
#ifndef NV_FIXTURE_STUB_H
#define NV_FIXTURE_STUB_H
/* the minimal linux/nv twin — JUST enough for the patched fixture to
 * compile (gcc -fsyntax-only, -Wall) so the patch text's C = judged by
 * the compiler, not the eye (the 4.51 backslash-n-in-C-string lesson) */
#include <stdio.h>
#include <string.h>
typedef unsigned char      NvBool;
typedef unsigned int       NvU32;
typedef unsigned long long NvU64;
#define NV_FALSE 0
#define NV_TRUE 1
#define KERN_ERR ""
int printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#define __init
struct work_struct { int _x; };
struct delayed_work { struct work_struct work; };
#define INIT_DELAYED_WORK(w, fn) do { (void)(w); (void)(fn); } while (0)
#define schedule_delayed_work(w, d) do { (void)(w); (void)(d); } while (0)
#define msecs_to_jiffies(ms) (ms)
static inline void nv_memdbg_init(void) {}
static inline int  nv_procfs_init(void) { return 0; }
#endif
"""

FIXTURE_NV_C = r"""
/* nv.c — the FIXTURE: the anchor twin of the real kernel-open/nvidia/nv.c
 * (the two anchors the patcher needs, nothing else — the dry-run target) */
#include "nv_fixture_stub.h"

static int __init nvidia_init_module(void)
{
    int rc;
    nv_memdbg_init();

    rc = nv_procfs_init();
    return rc;
}
"""


def g5_patcher_dry_run(build):
    """G5 — the patcher against the fixture: the anchors, the idempotency,
    the worker order, the gcc -Wall syntax judgment."""
    fx = os.path.join(build, "fixture")
    os.makedirs(fx, exist_ok=True)
    open(os.path.join(fx, "nv_fixture_stub.h"), "w").write(FIXTURE_STUB_H)
    nv_c = os.path.join(fx, "nv.c")
    open(nv_c, "w").write(FIXTURE_NV_C)

    env = dict(os.environ, NV_C_452_PATH=nv_c)
    r = run([sys.executable, PATCHER], env=env)
    if not check("G5 the patcher runs", r.returncode == 0 and
                 "PATCH OK" in r.stdout, r.stdout + r.stderr[-300:]):
        return
    s = open(nv_c).read()
    check("G5 the marker present", "HpokeMarker" in s)
    anchor = "static int __init nvidia_init_module(void)"
    check("G5 the init anchor stays unique", s.count(anchor) == 1)
    check("G5 the arm after nv_memdbg_init",
          s.find("nv_memdbg_init();") < s.find("INIT_DELAYED_WORK"))
    worker_pos = s.find("static void gsp_hpoke_worker(struct work_struct *w)\n{")
    decls_pos = s.find("static struct delayed_work gsp_hpoke_work;")
    init_pos = s.index(anchor)
    check("G5 the worker body AFTER its declarations",
          0 < decls_pos < worker_pos < init_pos,
          f"decls={decls_pos} worker={worker_pos} init={init_pos}")
    check("G5 the names table before the worker body",
          0 < s.find("gsp_hpoke_verdict_names_nv") < worker_pos)

    # the idempotency
    r2 = run([sys.executable, PATCHER], env=env)
    check("G5 the second run = idempotent",
          r2.returncode == 0 and "already patched" in r2.stdout)
    check("G5 the idempotent run = no double patch",
          open(nv_c).read() == s)

    # the compiler judgment (the format strings included)
    r3 = run(["gcc", "-Wall", "-Werror=format", "-fsyntax-only", nv_c],
             cwd=fx)
    check("G5 gcc -Wall -fsyntax-only the patched fixture",
          r3.returncode == 0, r3.stderr[-400:])


def g6_cross_side_and_link(build):
    """G6 — the cross-side contract + the 2-TU link proof (the driver
    compiled against the PATCHER's mirror struct reads the state the
    RM TU wrote — the extern contract at link level)."""
    pa = open(PATCHER).read()
    mirror = extract_struct(pa)
    check("G6 the mirror extractable", mirror is not None)

    d_ok = os.path.join(build, "ok")
    os.makedirs(d_ok, exist_ok=True)
    open(os.path.join(d_ok, "gsp_hpoke_stub.h"), "w").write(STUB_H)
    open(os.path.join(d_ok, "gsp_hpoke_plan.h"), "w").write(PLAN_OK_H)
    shutil.copy(RM_FILE, os.path.join(d_ok, "gsp_hpoke.c"))
    open(os.path.join(d_ok, "gsp_hpoke_tu.c"), "w").write(
        '#include "gsp_hpoke_stub.h"\n' + MOCKS_C +
        '\n#include "gsp_hpoke.c"\n')

    tu2 = r"""
#include "gsp_hpoke_stub.h"
""" + mirror + r"""

/* the extern = the patch's own line (the mirror typedef carries no
 * variable — the v455a run caught its absence in the test TU) */
extern GSP_HPOKE_STATE gspHpokeState;

static int g_fails = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS %s\n", name); \
    else { printf("FAIL %s\n", name); g_fails++; } } while (0)

extern NvU32 g_stub_regval;
extern int   g_stub_regpresent;
extern NvU8 *g_stub_heap;
extern STUB_MEMDESC *g_stub_desc;
extern void gsp_hpoke_schedule(OBJGPU *, KernelGsp *);
static STUB_MEMDESC the_desc = { 0x1000 };
static OBJGPU the_gpu;
static KernelGsp the_kgsp;

int main(void)
{
    /* the same happy path as G3 — driven from the OTHER side of the
     * extern contract (the mirror reads what the RM wrote) */
    g_stub_heap = (NvU8 *)malloc(0x1000);
    memset(g_stub_heap, 0xA5, 0x1000);
    g_stub_heap[0x40] = 0xde; g_stub_heap[0x41] = 0xad;
    g_stub_desc = &the_desc;
    the_kgsp.pSysmemHeapDescriptor = &the_desc;   /* the same wiring G3 taught */
    g_stub_regpresent = 1; g_stub_regval = 1;
    gsp_hpoke_schedule(&the_gpu, &the_kgsp);
    CHECK(gspHpokeState.scheduled == NV_TRUE, "link: the state visible");
    CHECK(gspHpokeState.pLateFn != NULL, "link: the fn pointer crosses");
    if (gspHpokeState.pLateFn)
        gspHpokeState.pLateFn();   /* the worker's guard, verbatim */
    CHECK(gspHpokeState.verdict == 8 && gspHpokeState.verifyOk == 1,
          "link: the verdict crosses the mirror");
    CHECK(gspHpokeState.heapOffset == 0x40 && gspHpokeState.len == 2,
          "link: the entry fields cross");
    CHECK(strcmp(gspHpokeState.fieldName, "rc") == 0 &&
          strcmp(gspHpokeState.sha16, "0123456789abcdef") == 0,
          "link: the strings cross");
    CHECK(g_stub_heap[0x40] == 0xbe && g_stub_heap[0x41] == 0xef,
          "link: the write happened (seen from TU2)");
    printf("LINK_OK fails=%d\n", g_fails);
    return g_fails ? 1 : 0;
}
"""
    open(os.path.join(d_ok, "tu2_mirror.c"), "w").write(tu2)

    # the one-TU logic batteries
    for tag, plan_h, body in (("battery_ok", PLAN_OK_H, DRIVER_OK_BODY),
                              ("battery_null", PLAN_NULL_H,
                               DRIVER_NULL_BODY)):
        d = os.path.join(build, tag)
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "gsp_hpoke_stub.h"), "w").write(STUB_H)
        open(os.path.join(d, "gsp_hpoke_plan.h"), "w").write(plan_h)
        shutil.copy(RM_FILE, os.path.join(d, "gsp_hpoke.c"))
        open(os.path.join(d, "main.c"), "w").write(DRIVER_COMMON + body)
        r = run(["gcc", "-Wall", "-Werror=format",
                 os.path.join(d, "main.c"), "-o",
                 os.path.join(d, "battery")])
        if not check(f"G3 the {tag} compiles", r.returncode == 0,
                     r.stderr[-400:]):
            continue
        r = run([os.path.join(d, "battery")])
        check(f"G3 the {tag} battery green", r.returncode == 0,
              r.stdout[-600:] + r.stderr[-300:])

    # the 2-TU link (the extern/mirror contract at the linker level)
    r = run(["gcc", "-Wall", "-c", os.path.join(d_ok, "gsp_hpoke_tu.c"),
             "-o", os.path.join(d_ok, "tu1.o")])
    if check("G6 the TU1 (the RM side) compiles", r.returncode == 0,
             r.stderr[-400:]):
        r2 = run(["gcc", "-Wall", "-Werror=format",
                  os.path.join(d_ok, "tu2_mirror.c"),
                  os.path.join(d_ok, "tu1.o"), "-o",
                  os.path.join(d_ok, "mirror_link")])
        if check("G6 the TU2 (the patcher mirror) links",
                 r2.returncode == 0, r2.stderr[-400:]):
            r3 = run([os.path.join(d_ok, "mirror_link")])
            check("G6 the link battery green", r3.returncode == 0,
                  r3.stdout[-600:] + r3.stderr[-300:])

    # the cross-side greps (against the PATCHED fixture = the artifact)
    fx_nv = os.path.join(build, "fixture", "nv.c")
    if os.path.exists(fx_nv):
        s = open(fx_nv).read()
        for bad in ["memdescMap", "memdescUnmap", "osReadRegistryDword",
                    "gspHpokePlan", "gsp_hpoke_plan.h"]:
            check("G6 the nv side carries no / " + bad, bad not in s)


def main():
    print("=== v455a: the two-sided hpoke battery ===")
    build = tempfile.mkdtemp(prefix="v455a_")
    try:
        g1_rm_hygiene()
        g2_mirror_text()
        g5_patcher_dry_run(build)
        g6_cross_side_and_link(build)
        g4_layout(build)
    finally:
        shutil.rmtree(build, ignore_errors=True)
    total = len(RESULTS)
    fails = sum(1 for _, ok, _ in RESULTS if not ok)
    print(f"=== TOTAL {total} checks, {total - fails} PASS, {fails} FAIL ===")
    print(json.dumps({"total": total, "pass": total - fails, "fail": fails}))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
