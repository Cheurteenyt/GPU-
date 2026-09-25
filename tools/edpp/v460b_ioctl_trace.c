/*
 * v460b_ioctl_trace.c — l'instrument de capture 4.60 (le « strace qui
 * montre les payloads » au niveau userspace→kernel).
 *
 * Principe : un shim LD_PRELOAD qui intercepte ioctl() et décharge
 * CHAQUE appel RM (NV_ESC_RM_* sur /dev/nvidiactl) avec la struct
 * COMPLÈTE + l'hexdump des params (avant = IN, après = IN+OUT).
 * L'analogue exact du RPCDUMP76 de 4.23, mais AU-DESSUS du kernel :
 * on voit la séquence ioctl complète de nvidia-smi -pl (le version
 * check, les allocs, le fetch des limites, le check NVML, le SET).
 *
 * Usage (le runbook-460 §1) :
 *   gcc -shared -fPIC -O2 -o v460b_ioctl_trace.so v460b_ioctl_trace.c -ldl
 *   sudo LD_PRELOAD=$PWD/v460b_ioctl_trace.so NV460_TRACE=/tmp/v460-pl250.log \
 *        nvidia-smi -pl 250
 *   (attention : /tmp = VOLATILE — copier le log hors de /tmp après)
 *
 * Le format des lignes (grep-able, la loi RPCDUMP76) :
 *   460TRACE op=... fd=... nr=0x.. ... params=<hex>   (IN, avant l'appel)
 *   460TRACE op=... ... status=... params=<hex>       (OUT, après l'appel)
 *
 * Zéro patch driver, zéro boot. La capture = passive (on ne modifie
 * aucun champ — le dump seule).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>

/* ── les définitions de l'arbre 610.57.04 (byte-exact, voir imports/) ── */
typedef unsigned int   NvU32;
typedef int            NvS32;
typedef unsigned long long NvU64;

#define NV_ESC_RM_FREE        0x29
#define NV_ESC_RM_CONTROL     0x2A
#define NV_ESC_RM_ALLOC       0x2B
#define NV_IOCTL_BASE         200
#define NV_ESC_CARD_INFO      (NV_IOCTL_BASE + 0)
#define NV_ESC_REGISTER_FD    (NV_IOCTL_BASE + 1)
#define NV_ESC_CHECK_VERSION_STR (NV_IOCTL_BASE + 10)

typedef struct {            /* nvos.h 610.57.04 — 32 B */
    NvU32 hClient;          /* 0x00 */
    NvU32 hObject;          /* 0x04 */
    NvU32 cmd;              /* 0x08 */
    NvU32 flags;            /* 0x0C */
    NvU64 params;           /* 0x10 (NvP64) */
    NvU32 paramsSize;       /* 0x18 */
    NvU32 status;           /* 0x1C */
} NVOS54_T;

typedef struct {            /* nvos.h 610.57.04 — sizeof = 48 (pad 4) */
    NvU32 hRoot;            /* 0x00 */
    NvU32 hObjectParent;    /* 0x04 */
    NvU32 hObjectNew;       /* 0x08 */
    NvU32 hClass;           /* 0x0C */
    NvU64 pAllocParms;      /* 0x10 */
    NvU64 pRightsRequested; /* 0x18 */
    NvU32 paramsSize;       /* 0x20 */
    NvU32 flags;            /* 0x24 */
    NvU32 status;           /* 0x28 */
} NVOS64_T;

typedef struct {            /* nvos.h — 12 B */
    NvU32 hRoot;            /* 0x00 */
    NvU32 hObjectOld;       /* 0x04 */
    NvU32 status;           /* 0x08 */
} NVOS00_T;

typedef struct {            /* nv-ioctl.h — 72 B */
    NvU32 cmd;
    NvU32 reply;
    char  versionString[64];
} RM_API_VER_T;

/* ── le moteur de trace ── */
static int (*real_ioctl)(int, unsigned long, ...) = NULL;
static FILE *trace_fp = NULL;
static int trace_fd_gate = -1;   /* -1 = trace tout ; >=0 = seulement ce fd */

static void hexdump(const unsigned char *p, unsigned int n, char *out, unsigned int cap)
{
    unsigned int i, w = 0;
    if (!p || n == 0) { snprintf(out, cap, "(null)"); return; }
    if (n > 4096) n = 4096; /* le garde-fou du ledger */
    for (i = 0; i < n && w < cap - 4; i++) {
        w += (unsigned int)snprintf(out + w, cap - w, "%02x", p[i]);
    }
    out[w] = 0;
}

static void trace_open(void)
{
    const char *path = getenv("NV460_TRACE");
    const char *fdgate = getenv("NV460_TRACE_FD");
    if (!getenv("NV460_TRACE")) return;      /* inactif sans la clé */
    if (trace_fp) return;
    if (path && path[0]) {
        trace_fp = fopen(path, "a");
        if (!trace_fp) trace_fp = stderr;
    } else {
        trace_fp = stderr;
    }
    if (fdgate) trace_fd_gate = atoi(fdgate);
    setvbuf(trace_fp, NULL, _IOLBF, 0);
}

static void fdpath(int fd, char *out, unsigned int cap)
{
    char lnk[64];
    ssize_t r;
    snprintf(lnk, sizeof(lnk), "/proc/self/fd/%d", fd);
    r = readlink(lnk, out, cap - 1);
    if (r > 0) out[r] = 0; else snprintf(out, cap, "(fd%d)", fd);
}

static void emit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(trace_fp, fmt, ap);
    va_end(ap);
    fputc('\n', trace_fp);
    fflush(trace_fp);
}

int ioctl(int fd, unsigned long req, ...)
{
    void *arg;
    va_list ap;
    unsigned int nr = (unsigned int)(req & 0xFF);

    va_start(ap, req);
    arg = va_arg(ap, void *);
    va_end(ap);

    if (!real_ioctl) real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    trace_open();

    /* RM_Control */
    if (nr == NV_ESC_RM_CONTROL && arg) {
        NVOS54_T *p = (NVOS54_T *)arg;
        char hx[9000], pth[128];
        if ((trace_fd_gate < 0 || fd == trace_fd_gate) && p->paramsSize <= 4096) {
            hexdump((const unsigned char *)(unsigned long)p->params, p->paramsSize, hx, sizeof(hx));
            fdpath(fd, pth, sizeof(pth));
            emit("460TRACE op=CONTROL fd=%d dev=%s hClient=0x%08x hObject=0x%08x cmd=0x%08x flags=0x%x paramsSize=%u params=%s",
                 fd, pth, p->hClient, p->hObject, p->cmd, p->flags, p->paramsSize, hx);
        }
        int r = real_ioctl(fd, req, arg);
        int e = errno;
        if ((trace_fd_gate < 0 || fd == trace_fd_gate) && p->paramsSize <= 4096) {
            hexdump((const unsigned char *)(unsigned long)p->params, p->paramsSize, hx, sizeof(hx));
            emit("460TRACE op=CONTROL_RET cmd=0x%08x status=0x%08x errno=%d rc=%d params=%s",
                 p->cmd, p->status, r < 0 ? e : 0, r, hx);
        }
        return r;
    }

    /* RM_Alloc */
    if (nr == NV_ESC_RM_ALLOC && arg) {
        NVOS64_T *p = (NVOS64_T *)arg;
        char hx[9000], pth[128];
        if ((trace_fd_gate < 0 || fd == trace_fd_gate) && p->paramsSize <= 4096) {
            hexdump((const unsigned char *)(unsigned long)p->pAllocParms, p->paramsSize, hx, sizeof(hx));
            fdpath(fd, pth, sizeof(pth));
            emit("460TRACE op=ALLOC fd=%d dev=%s hRoot=0x%08x hParent=0x%08x hNew=0x%08x hClass=0x%08x paramsSize=%u flags=0x%x params=%s",
                 fd, pth, p->hRoot, p->hObjectParent, p->hObjectNew, p->hClass, p->paramsSize, p->flags, hx);
        }
        int r = real_ioctl(fd, req, arg);
        if ((trace_fd_gate < 0 || fd == trace_fd_gate)) {
            emit("460TRACE op=ALLOC_RET hClass=0x%08x hNew=0x%08x status=0x%08x",
                 p->hClass, p->hObjectNew, p->status);
        }
        return r;
    }

    /* RM_Free */
    if (nr == NV_ESC_RM_FREE && arg) {
        NVOS00_T *p = (NVOS00_T *)arg;
        int r = real_ioctl(fd, req, arg);
        if (trace_fd_gate < 0 || fd == trace_fd_gate)
            emit("460TRACE op=FREE hRoot=0x%08x hObjectOld=0x%08x status=0x%08x",
                 p->hRoot, p->hObjectOld, p->status);
        return r;
    }

    /* le version check (les 200+) */
    if (nr == NV_ESC_CHECK_VERSION_STR && arg) {
        RM_API_VER_T *p = (RM_API_VER_T *)arg;
        int r = real_ioctl(fd, req, arg);
        if (trace_fd_gate < 0 || fd == trace_fd_gate)
            emit("460TRACE op=VERSION cmd=%u reply=%u version=\"%.64s\" rc=%d",
                 p->cmd, p->reply, p->versionString, r);
        return r;
    }

    return real_ioctl(fd, req, arg);
}
