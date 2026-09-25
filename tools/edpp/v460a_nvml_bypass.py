#!/usr/bin/env python3
"""v460a_nvml_bypass.py — LE BYPASS NVML 4.60 : le contrôle direct par ioctl.

La reproduction userspace pure de la séquence SET de `nvidia-smi -pl`,
SANS le fetch/check de la NVML : ctypes + /dev/nvidiactl, les structures
byte-exact de l'arbre 610.57.04 (imports/open-gpu-kernel-modules-610.57.04/).

Le contrat (mission 4.60) :
  T2  la séquence = celle du strace du -pl 250 (qui a réussi) avec la
      valeur 280000 — via la table de décode de v460b_analyze.py ;
  T3  le GSP = le juge final : la lecture avant/après = l'observable
      binaire ; zéro écriture firmware, zéro patch driver, la
      réversibilité totale (un ioctl = un appel, --restore) ;
  T4  la contingence : le code d'erreur exact = la localisation du mur
      (kernel-reject / accepté-non-appliqué = le mur GSP / appliqué = le
      break).

LA SÉQUENCE (le frame PROUVÉ sur l'arbre — escape.c 610.57.04) :
  1. open /dev/nvidiactl (+ /dev/nvidiaN + REGISTER_FD, la fidélité NVML)
  2. NV_ESC_CHECK_VERSION_STR (210, 'F', 72 B)   — la porte du RM API
  3. NV_ESC_RM_ALLOC (0x2B, NVOS64=48 B)         — NV01_ROOT     (hClient)
  4. NV_ESC_RM_ALLOC                             — NV01_DEVICE_0 (hDevice)
  5. NV_ESC_RM_ALLOC                             — NV20_SUBDEVICE_0 (hSub)
  6. NV_ESC_RM_CONTROL (0x2A, NVOS54=32 B)       — le GET des limites (si table)
  7. NV_ESC_RM_CONTROL                           — le SET 280000 (--arm)
  8. le GET relise + nvidia-smi -q -d POWER      — le verdict binaire
  9. les FREE en ordre inverse                   — le cleanup

DISCIPLINE : le SET n'existe pas sans --arm (le gate ACK de la maison) ;
le dry-run par défaut = tout le chemin, l'écriture seule sautée.

Usage :
  sudo python3 v460a_nvml_bypass.py --selftest
  sudo python3 v460a_nvml_bypass.py                       # le dry-run
  sudo python3 v460a_nvml_bypass.py --table v460-decode.json --mw 280000 --arm
  sudo python3 v460a_nvml_bypass.py --table v460-decode.json --restore 250000 --arm
"""
import argparse
import ctypes
import ctypes.util
import json
import os
import re
import struct
import subprocess
import sys
import time

# ══════════════════════════════════════════════════════════════════════
# Les constantes de l'arbre 610.57.04 (chaque valeur = citée du header)
# ══════════════════════════════════════════════════════════════════════

# nv-ioctl-numbers.h (kernel-open/common/inc) + nv_escape.h (unix/include)
NV_IOCTL_MAGIC = 0x46          # 'F'  (les 200+)
RM_IOCTL_TYPE = 0x55           # 'U'  (les NV_ESC_RM_*)
NV_ESC_CARD_INFO = 200
NV_ESC_REGISTER_FD = 201
NV_ESC_CHECK_VERSION_STR = 210
NV_ESC_RM_FREE = 0x29
NV_ESC_RM_CONTROL = 0x2A
NV_ESC_RM_ALLOC = 0x2B

# les classes (cl0000.h / cl0080.h / cl2080.h)
NV01_ROOT = 0x0
NV01_DEVICE_0 = 0x80
NV20_SUBDEVICE_0 = 0x2080

# les versions RM API (nv-ioctl.h)
NV_RM_API_VERSION_CMD_STRICT = 0
NV_RM_API_VERSION_CMD_RELAXED = 0x31   # '1'
NV_RM_API_VERSION_REPLY_RECOGNIZED = 1

# ctrl2080perf.h — la famille publique RatedTdp (résolue dans NOTRE rm.elf,
# handler 0x163c42c — le pass 4.21) : la sonde de lisibilité
NV2080_CTRL_CMD_PERF_RATED_TDP_GET_CONTROL = 0x2080206E
NV2080_CTRL_CMD_PERF_RATED_TDP_SET_CONTROL = 0x2080206F

# nvstatuscodes.h — les codes du verdict T4
NVSTATUS = {
    0x00000000: "NV_OK",
    0x0000001B: "NV_ERR_INSUFFICIENT_PERMISSIONS",
    0x0000001F: "NV_ERR_INVALID_ARGUMENT",
    0x00000023: "NV_ERR_INVALID_CLIENT",
    0x00000026: "NV_ERR_INVALID_DEVICE",
    0x00000029: "NV_ERR_INVALID_FLAGS",
    0x0000002E: "NV_ERR_INVALID_LIMIT",
    0x00000031: "NV_ERR_INVALID_OBJECT",
    0x00000033: "NV_ERR_INVALID_OBJECT_HANDLE",
    0x00000036: "NV_ERR_INVALID_OBJECT_PARENT",
    0x0000003B: "NV_ERR_INVALID_PARAMETER",
    0x00000056: "NV_ERR_NOT_SUPPORTED",
    0x00000063: "NV_ERR_STATE_IN_USE",
    0x0000FFFF: "NV_ERR_GENERIC",
}

# les tailles de struct attendues par la validation kernel
# (nv.c nv_validate_ioctl_data + osapi.c RmValidateIoctl — lues du source)
SZ_NVOS54 = 32    # CONTROL
SZ_NVOS64 = 48    # ALLOC (le chemin rights/FINN — avec le pad final)
SZ_NVOS21 = 32    # ALLOC (l'ancien chemin — même ESC, la taille décide)
SZ_NVOS00 = 12    # FREE
SZ_VERCHK = 72    # CHECK_VERSION_STR


def iowr(typ, nr, size):
    """l'encodage _IOWR du kernel Linux — nv.c décode _IOC_NR + _IOC_SIZE."""
    return (3 << 30) | ((size & 0x3FFF) << 16) | ((typ & 0xFF) << 8) | (nr & 0xFF)


IOCTL_RM_CONTROL = iowr(RM_IOCTL_TYPE, NV_ESC_RM_CONTROL, SZ_NVOS54)   # 0xC020552A
IOCTL_RM_ALLOC = iowr(RM_IOCTL_TYPE, NV_ESC_RM_ALLOC, SZ_NVOS64)       # 0xC030552B
IOCTL_RM_FREE = iowr(RM_IOCTL_TYPE, NV_ESC_RM_FREE, SZ_NVOS00)         # 0xC00C5529
IOCTL_VERCHK = iowr(NV_IOCTL_MAGIC, NV_ESC_CHECK_VERSION_STR, SZ_VERCHK)  # 0xC04846D2
IOCTL_REGISTER_FD = iowr(NV_IOCTL_MAGIC, NV_ESC_REGISTER_FD, 4)

# ══════════════════════════════════════════════════════════════════════
# Les structs ctypes — chaque offset = la définition du header
# ══════════════════════════════════════════════════════════════════════


class NVOS54_PARAMETERS(ctypes.Structure):
    _fields_ = [("hClient", ctypes.c_uint32),      # 0x00
                ("hObject", ctypes.c_uint32),      # 0x04
                ("cmd", ctypes.c_uint32),          # 0x08
                ("flags", ctypes.c_uint32),        # 0x0C
                ("params", ctypes.c_uint64),       # 0x10 (NvP64)
                ("paramsSize", ctypes.c_uint32),   # 0x18
                ("status", ctypes.c_uint32)]       # 0x1C


class NVOS64_PARAMETERS(ctypes.Structure):
    _fields_ = [("hRoot", ctypes.c_uint32),        # 0x00
                ("hObjectParent", ctypes.c_uint32),  # 0x04
                ("hObjectNew", ctypes.c_uint32),   # 0x08 [in/out]
                ("hClass", ctypes.c_uint32),       # 0x0C
                ("pAllocParms", ctypes.c_uint64),  # 0x10
                ("pRightsRequested", ctypes.c_uint64),  # 0x18
                ("paramsSize", ctypes.c_uint32),   # 0x20
                ("flags", ctypes.c_uint32),        # 0x24
                ("status", ctypes.c_uint32)]       # 0x28


class NVOS00_PARAMETERS(ctypes.Structure):
    _fields_ = [("hRoot", ctypes.c_uint32),
                ("hObjectOld", ctypes.c_uint32),
                ("status", ctypes.c_uint32)]


class nv_ioctl_rm_api_version_t(ctypes.Structure):
    _fields_ = [("cmd", ctypes.c_uint32),
                ("reply", ctypes.c_uint32),
                ("versionString", ctypes.c_char * 64)]


NV_PROC_NAME_MAX_LENGTH = 100   # nvlimits.h


class NV0000_ALLOC_PARAMETERS(ctypes.Structure):
    _fields_ = [("hClient", ctypes.c_uint32),
                ("processID", ctypes.c_uint32),
                ("processName", ctypes.c_char * NV_PROC_NAME_MAX_LENGTH),
                ("pOsPidInfo", ctypes.c_uint64)]


class NV0080_ALLOC_PARAMETERS(ctypes.Structure):
    _fields_ = [("deviceId", ctypes.c_uint32),      # 0x00
                ("hClientShare", ctypes.c_uint32),  # 0x04
                ("hTargetClient", ctypes.c_uint32),  # 0x08
                ("hTargetDevice", ctypes.c_uint32),  # 0x0C
                ("flags", ctypes.c_uint32),         # 0x10
                ("vaSpaceSize", ctypes.c_uint64),   # 0x18 (aligned 8)
                ("vaStartInternal", ctypes.c_uint64),  # 0x20
                ("vaLimitInternal", ctypes.c_uint64),  # 0x28
                ("vaMode", ctypes.c_uint32)]        # 0x30


class NV2080_ALLOC_PARAMETERS(ctypes.Structure):
    _fields_ = [("subDeviceId", ctypes.c_uint32)]


class NV2080_CTRL_PERF_RATED_TDP_CONTROL_PARAMS(ctypes.Structure):
    _fields_ = [("client", ctypes.c_uint32),
                ("input", ctypes.c_uint32),
                ("vPstateType", ctypes.c_uint32)]


# ══════════════════════════════════════════════════════════════════════
# Le moteur
# ══════════════════════════════════════════════════════════════════════

libc = None


def _libc():
    global libc
    if libc is None:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    return libc


def do_ioctl(fd, cmd, structp):
    r = _libc().ioctl(ctypes.c_int(fd), ctypes.c_ulong(cmd), structp)
    return r


def st_name(st):
    return "%s (0x%08X)" % (NVSTATUS.get(st, "NV_STATUS_INCONNU"), st)


class Ledger:
    def __init__(self):
        self.steps = []

    def add(self, **kw):
        kw["t"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.steps.append(kw)
        return kw

    def save(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.steps, f, indent=1, ensure_ascii=False)


def read_driver_version():
    """la version du module live (la chaîne pour le version check STRICT)."""
    for path in ("/proc/driver/nvidia/version",):
        try:
            txt = open(path).read()
        except OSError:
            continue
        m = re.search(r"NVRM version:\s+NVIDIA UNIX \S+\s+Kernel\s+Module\s+(\d+\.\d+\.\d+)", txt)
        if m:
            return m.group(1)
    return None


def hexof(buf):
    return bytes(bytearray(buf)).hex()


class NvmlBypass:
    def __init__(self, gpu=0, ledger=None, log=print):
        self.gpu = gpu
        self.ledger = ledger or Ledger()
        self.log = log
        self.ctl_fd = None
        self.gpu_fd = None
        self.hClient = 0
        self.hDevice = 0
        self.hSubdevice = 0

    # ── la séquence (le frame) ────────────────────────────────────────
    def open_devices(self):
        self.ctl_fd = os.open("/dev/nvidiactl", os.O_RDWR | os.O_CLOEXEC)
        self.ledger.add(step="open", path="/dev/nvidiactl", fd=self.ctl_fd)
        gpath = "/dev/nvidia%d" % self.gpu
        try:
            self.gpu_fd = os.open(gpath, os.O_RDWR | os.O_CLOEXEC)
            self.ledger.add(step="open", path=gpath, fd=self.gpu_fd)
            reg = ctypes.c_int32(self.ctl_fd)   # nv_ioctl_register_fd_t
            r = do_ioctl(self.gpu_fd, IOCTL_REGISTER_FD, ctypes.byref(reg))
            self.ledger.add(step="register_fd", ctl_fd=self.ctl_fd,
                            rc=r, errno=ctypes.get_errno())
        except OSError as e:
            self.ledger.add(step="open", path=gpath, error=str(e))
            self.log(f"[!] {gpath} : {e} (on continue sur le ctl seul — "
                     f"le CONTROL n'exige pas le fd GPU : escape.c "
                     f"RmGetDeviceFd = gate NV00FD/NV00E0 seulement)")

    def version_check(self):
        want = read_driver_version() or "610.57.04"
        for cmd_mode, label in ((NV_RM_API_VERSION_CMD_STRICT, "STRICT"),
                                (NV_RM_API_VERSION_CMD_RELAXED, "RELAXED")):
            v = nv_ioctl_rm_api_version_t()
            v.cmd = cmd_mode
            v.reply = 0
            v.versionString = want.encode()
            r = do_ioctl(self.ctl_fd, IOCTL_VERCHK, ctypes.byref(v))
            self.ledger.add(step="version_check", mode=label, want=want,
                            reply=v.reply, rc=r, errno=ctypes.get_errno())
            if v.reply == NV_RM_API_VERSION_REPLY_RECOGNIZED:
                self.log(f"[ok] le version check {label} reconnu (\"{want}\")")
                return True
        self.log(f"[!] version NON reconnue par le driver (want \"{want}\") "
                 f"— l'ABI peut diverger ; on s'arrête (l'honnêteté > l'audace)")
        return False

    def _alloc(self, hClass, hParent, params, paramsSize, name):
        a = NVOS64_PARAMETERS()
        a.hRoot = self.hClient
        a.hObjectParent = hParent
        a.hObjectNew = 0
        a.hClass = hClass
        a.pAllocParms = ctypes.cast(ctypes.byref(params), ctypes.c_void_p).value or 0
        a.pRightsRequested = 0
        a.paramsSize = paramsSize
        a.flags = 0
        r = do_ioctl(self.ctl_fd, IOCTL_RM_ALLOC, ctypes.byref(a))
        rec = self.ledger.add(step="alloc", name=name, hClass=hClass,
                              hParent=hParent, paramsSize=paramsSize,
                              params_hex=hexof(params), hObjectNew=a.hObjectNew,
                              status=a.status, rc=r, errno=ctypes.get_errno())
        nm = {NV01_ROOT: "NV01_ROOT", NV01_DEVICE_0: "NV01_DEVICE_0",
              NV20_SUBDEVICE_0: "NV20_SUBDEVICE_0"}.get(hClass, hex(hClass))
        if a.status != 0 or r != 0:
            self.log(f"[!] alloc {nm} : rc={r} errno={ctypes.get_errno()} "
                     f"status={st_name(a.status)}")
            return None
        self.log(f"[ok] alloc {nm} -> h=0x{a.hObjectNew:08x}")
        rec["handle"] = a.hObjectNew
        return a.hObjectNew

    def alloc_chain(self):
        cl = NV0000_ALLOC_PARAMETERS()
        cl.hClient = 0
        cl.processID = os.getpid()
        cl.processName = b"v460a"
        cl.pOsPidInfo = 0
        self.hClient = self._alloc(NV01_ROOT, 0, cl, ctypes.sizeof(cl), "NV01_ROOT")
        if not self.hClient:
            return False

        dv = NV0080_ALLOC_PARAMETERS()
        dv.deviceId = self.gpu
        dv.hClientShare = self.hClient
        dv.hTargetClient = self.hClient
        dv.hTargetDevice = 0
        dv.flags = 0
        dv.vaSpaceSize = 0
        dv.vaStartInternal = 0
        dv.vaLimitInternal = 0
        dv.vaMode = 0
        self.hDevice = self._alloc(NV01_DEVICE_0, self.hClient, dv,
                                   ctypes.sizeof(dv), "NV01_DEVICE_0")
        if not self.hDevice:
            return False

        sb = NV2080_ALLOC_PARAMETERS()
        sb.subDeviceId = 1
        self.hSubdevice = self._alloc(NV20_SUBDEVICE_0, self.hDevice, sb,
                                      ctypes.sizeof(sb), "NV20_SUBDEVICE_0")
        return bool(self.hSubdevice)

    def control(self, hobject, cmd, params_buf, flags=0):
        c = NVOS54_PARAMETERS()
        c.hClient = self.hClient
        c.hObject = hobject
        c.cmd = cmd
        c.flags = flags
        c.params = ctypes.cast(params_buf, ctypes.c_void_p).value or 0
        c.paramsSize = ctypes.sizeof(params_buf)
        c.status = 0xFFFFFFFF
        r = do_ioctl(self.ctl_fd, IOCTL_RM_CONTROL, ctypes.byref(c))
        # le buffer params = IN/OUT (le pointeur partagé) : le hexdump
        # d'APRÈS l'appel = les OUT (la loi du GET)
        self.ledger.add(step="control", cmd=cmd, hObject=hobject, flags=flags,
                        paramsSize=c.paramsSize, params_after=hexof(params_buf),
                        status=c.status, rc=r, errno=ctypes.get_errno())
        return c.status, r

    def control_raw(self, hobject, cmd, raw_bytes, flags=0):
        buf = (ctypes.c_char * max(1, len(raw_bytes))).from_buffer_copy(
            raw_bytes or b"\x00")
        return self.control(hobject, cmd, buf, flags)

    def free_all(self):
        for h, nm in ((self.hSubdevice, "SUBDEVICE"), (self.hDevice, "DEVICE"),
                      (self.hClient, "ROOT")):
            if not h:
                continue
            f = NVOS00_PARAMETERS()
            f.hRoot = self.hClient if nm != "ROOT" else 0
            f.hObjectOld = h
            r = do_ioctl(self.ctl_fd, IOCTL_RM_FREE, ctypes.byref(f))
            self.ledger.add(step="free", name=nm, hObjectOld=h,
                            status=f.status, rc=r)
            if f.status == 0:
                self.log(f"[ok] free {nm} 0x{h:08x}")
            else:
                self.log(f"[!] free {nm} : {st_name(f.status)}")

    def close(self):
        for fdattr in ("gpu_fd", "ctl_fd"):
            fd = getattr(self, fdattr, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fdattr, None)

    # ── les phases 4.60 ───────────────────────────────────────────────
    def probe_ratedtdp(self):
        """la sonde PUBLIQUE (le struct 12 B de ctrl2080perf.h) : la
        lisibilité du sous-device + l'état de l'arbitrage RatedTdp."""
        p = NV2080_CTRL_PERF_RATED_TDP_CONTROL_PARAMS()
        p.client, p.input, p.vPstateType = 0, 0, 0
        st, r = self.control(self.hSubdevice,
                             NV2080_CTRL_CMD_PERF_RATED_TDP_GET_CONTROL, p)
        self.log(f"[*] RatedTdp GET 0x{NV2080_CTRL_CMD_PERF_RATED_TDP_GET_CONTROL:x} "
                 f"-> {st_name(st)} params={hexof(p)}")
        return st == 0


def load_table(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def patch_mw(raw, offsets, mw):
    b = bytearray(raw)
    for off in offsets:
        if off + 4 <= len(b):
            struct.pack_into("<I", b, off, mw)
    return bytes(b)


def read_nvidia_smi_power():
    """l'observable croisée (T3) : le champ Power Limit de nvidia-smi."""
    try:
        out = subprocess.run(["nvidia-smi", "-q", "-d", "POWER"],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception as e:
        return None, str(e)
    cur = None
    for ln in out.splitlines():
        m = re.search(r"Power Limit\s*:\s*([\d.]+)\s*W", ln)
        if m and cur is None:
            cur = float(m.group(1))
    return cur, out


def main():
    ap = argparse.ArgumentParser(
        description="le bypass NVML 4.60 — le SET direct par ioctl")
    ap.add_argument("--selftest", action="store_true",
                    help="les checks offline (zéro device) — l'exiger d'abord")
    ap.add_argument("--table", help="la table de décode v460b (JSON)")
    ap.add_argument("--mw", type=int, default=280000,
                    help="la valeur SET en mW (280000 par défaut)")
    ap.add_argument("--gpu", type=int, default=0)
    ap.add_argument("--arm", action="store_true",
                    help="LE GATE : sans ça, zéro écriture (dry-run)")
    ap.add_argument("--restore", type=int, metavar="MW",
                    help="remettre la limite à MW (le retour en arrière)")
    ap.add_argument("--probe-ratedtdp", action="store_true",
                    help="la sonde publique RatedTdp (lecture seule)")
    ap.add_argument("--set-cmd", type=lambda x: int(x, 0), default=None,
                    help="le mode manuel : la cmd SET brute (ex. 0x2080xxxx) "
                         "sans la table")
    ap.add_argument("--set-size", type=int, default=None,
                    help="le mode manuel : la taille du buffer params")
    ap.add_argument("--set-offsets", type=lambda x: int(x, 0), nargs="*",
                    default=None,
                    help="le mode manuel : les offsets du/des champs mW dans "
                         "les params")
    ap.add_argument("--set-hobject", type=lambda x: int(x, 0), default=None,
                    help="le mode manuel : l'hObject cible (défaut = hDevice)")
    ap.add_argument("--ledger", default="v460a-ledger.json")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    led = Ledger()
    log = lambda s: print(s, flush=True)

    table = load_table(args.table) if args.table else None
    if table and not (table.get("set") or args.restore):
        log("[!] la table n'a pas de 'set' — relancer v460b_analyze avec "
            "--pl correct, ou fournir --set-cmd")

    mw = args.restore if args.restore else args.mw
    armed = args.arm or bool(args.restore)
    if args.restore and not args.arm:
        log("[*] --restore implique --arm (le retour en arrière voulu)")

    log(f"== v460a : mw={mw} gpu={args.gpu} ARMÉ={armed} table={'oui' if table else 'non'} ==")

    b = NvmlBypass(gpu=args.gpu, ledger=led, log=log)
    verdict = "INCOMPLET"
    try:
        b.open_devices()
        if not b.version_check():
            verdict = "ABORT_VERSION"
            return 2
        if not b.alloc_chain():
            verdict = "ABORT_ALLOC"
            return 2
        log(f"[*] handles : client=0x{b.hClient:08x} device=0x{b.hDevice:08x} "
            f"subdevice=0x{b.hSubdevice:08x}")

        if args.probe_ratedtdp:
            b.probe_ratedtdp()

        # le GET avant (T3 : l'observable binaire AVANT)
        before = None
        if table and table.get("get"):
            g = table["get"]
            st, r = b.control_raw(g.get("hObject") or b.hDevice,
                                  g["cmd"],
                                  bytes.fromhex(g.get("template_hex") or ""),
                                  g.get("flags", 0))
            ret = next((s for s in reversed(led.steps)
                        if s.get("step") == "control" and s.get("cmd") == g["cmd"]), {})
            params_out = bytes.fromhex(ret.get("params_after", "") or "")
            before = [struct.unpack_from("<I", params_out, o)[0]
                      for o in range(0, max(0, len(params_out) - 3), 4)
                      if 1000 <= struct.unpack_from("<I", params_out, o)[0] <= 600000]
            log(f"[*] GET 0x{g['cmd']:x} -> {st_name(st)} ; les mW-class vus: {before}")
            led.add(step="get_before", cmd=g["cmd"], status=st, mw_class=before)

        # le SET (T2 : la séquence capturée, la valeur patchée)
        set_st = None
        if armed and table and table.get("set"):
            s = table["set"]
            raw = bytes.fromhex(s.get("template_hex") or "")
            offs = s.get("value_offsets") or []
            patched = patch_mw(raw, offs, mw)
            log(f"[*] SET cmd=0x{s['cmd']:x} size={s.get('paramsSize')} "
                f"offsets={offs} -> {mw} mW (template {len(raw)} B)")
            set_st, r = b.control_raw(s.get("hObject") or b.hDevice,
                                      s["cmd"], patched, s.get("flags", 0))
            led.add(step="set", mode="table", cmd=s["cmd"], mw=mw, offsets=offs,
                    status=set_st, status_name=NVSTATUS.get(set_st, "INCONNU"))
            log(f"[*] SET -> {st_name(set_st)}")
        elif armed and args.set_cmd is not None:
            size = args.set_size or 4
            offs = args.set_offsets if args.set_offsets is not None else [0]
            raw = bytearray(size)
            patched = patch_mw(bytes(raw), offs, mw)
            log(f"[*] SET (manuel) cmd=0x{args.set_cmd:x} size={size} "
                f"offsets={offs} -> {mw} mW")
            set_st, r = b.control_raw(args.set_hobject or b.hDevice,
                                      args.set_cmd, patched, 0)
            led.add(step="set", mode="manuel", cmd=args.set_cmd, mw=mw,
                    offsets=offs, status=set_st,
                    status_name=NVSTATUS.get(set_st, "INCONNU"))
            log(f"[*] SET -> {st_name(set_st)}")
        elif armed:
            log("[!] armé SANS table ni --set-cmd : zéro écriture faite.")
        else:
            log("[*] DRY-RUN : le SET sauté (le gate --arm absent) — la "
                "séquence jusqu'au GET = validée, zéro écriture")

        # le GET après + l'observable croisée (T3/T4)
        after = None
        if table and table.get("get"):
            g = table["get"]
            st3, _ = b.control_raw(g.get("hObject") or b.hDevice, g["cmd"],
                                   bytes.fromhex(g.get("template_hex") or ""),
                                   g.get("flags", 0))
            ret = next((s for s in reversed(led.steps)
                        if s.get("step") == "control" and s.get("cmd") == g["cmd"]), {})
            params_out = bytes.fromhex(ret.get("params_after", "") or "")
            after = [struct.unpack_from("<I", params_out, o)[0]
                     for o in range(0, max(0, len(params_out) - 3), 4)
                     if 1000 <= struct.unpack_from("<I", params_out, o)[0] <= 600000]
            log(f"[*] GET après -> {st_name(st3)} ; les mW-class: {after}")
            led.add(step="get_after", cmd=g["cmd"], status=st3, mw_class=after)

        smi_w, smi_raw = read_nvidia_smi_power()
        if smi_w is not None:
            log(f"[*] nvidia-smi Power Limit = {smi_w} W")
        else:
            log(f"[*] nvidia-smi illisible : {smi_raw}")

        # LE VERDICT (T3/T4 — la matrice de la mission)
        if not armed:
            verdict = "DRY_RUN (zéro écriture — la séquence = verte jusqu'au GET)"
        elif set_st is None:
            verdict = "PAS_DE_SET (la table manquante — cf. ci-dessus)"
        elif set_st != 0:
            verdict = (f"MUR_KERNEL/X86-RM : le SET rejeté par le kernel "
                       f"({st_name(set_st)}) — le mur = AVANT le GSP, nommé")
        else:
            applied = bool(after) and any(
                abs(v - mw) <= 500 for v in (after or []))
            if applied or (smi_w is not None and abs(smi_w * 1000 - mw) <= 500):
                verdict = "LE BREAK : le SET accepté ET appliqué (le GET/smi = 280)"
            else:
                verdict = ("MUR_GSP : le SET accepté mais NON appliqué "
                           "(le GET/nvidia-smi inchangés) — le check effectif "
                           "= firmware-side, le négatif définitif")
        log(f"\n== LE VERDICT : {verdict} ==")
        led.add(step="verdict", verdict=verdict)
        return 0
    finally:
        b.free_all()
        b.close()
        led.save(args.ledger)
        log(f"[*] le ledger : {args.ledger}")


# ══════════════════════════════════════════════════════════════════════
# Le selftest offline (zéro device — la discipline byte-exact de la maison)
# ══════════════════════════════════════════════════════════════════════

def selftest():
    fails = []

    def chk(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
        if not cond:
            fails.append(name)

    # les tailles (la validation kernel exige EXACTEMENT ça)
    chk("sizeof(NVOS54)==32", ctypes.sizeof(NVOS54_PARAMETERS) == 32,
        str(ctypes.sizeof(NVOS54_PARAMETERS)))
    chk("sizeof(NVOS64)==48", ctypes.sizeof(NVOS64_PARAMETERS) == 48,
        str(ctypes.sizeof(NVOS64_PARAMETERS)))
    chk("sizeof(NVOS00)==12", ctypes.sizeof(NVOS00_PARAMETERS) == 12)
    chk("sizeof(verchk)==72", ctypes.sizeof(nv_ioctl_rm_api_version_t) == 72)
    chk("sizeof(NV0000_ALLOC)==120",
        ctypes.sizeof(NV0000_ALLOC_PARAMETERS) == 120,
        str(ctypes.sizeof(NV0000_ALLOC_PARAMETERS)))
    chk("sizeof(NV0080_ALLOC)==56",
        ctypes.sizeof(NV0080_ALLOC_PARAMETERS) == 56,
        str(ctypes.sizeof(NV0080_ALLOC_PARAMETERS)))
    chk("sizeof(NV2080_ALLOC)==4",
        ctypes.sizeof(NV2080_ALLOC_PARAMETERS) == 4)

    # les offsets NVOS54 (la carte du 4.24/escape.c)
    chk("NVOS54.cmd@8", NVOS54_PARAMETERS.cmd.offset == 8)
    chk("NVOS54.params@0x10", NVOS54_PARAMETERS.params.offset == 0x10)
    chk("NVOS54.paramsSize@0x18", NVOS54_PARAMETERS.paramsSize.offset == 0x18)
    chk("NVOS54.status@0x1C", NVOS54_PARAMETERS.status.offset == 0x1C)
    chk("NVOS64.pAllocParms@0x10", NVOS64_PARAMETERS.pAllocParms.offset == 0x10)
    chk("NVOS64.paramsSize@0x20", NVOS64_PARAMETERS.paramsSize.offset == 0x20)

    # les encodages ioctl (les constantes classiques des straces publics)
    chk("iowr CONTROL==0xC020552A", IOCTL_RM_CONTROL == 0xC020552A,
        hex(IOCTL_RM_CONTROL))
    chk("iowr ALLOC(NVOS64)==0xC030552B", IOCTL_RM_ALLOC == 0xC030552B,
        hex(IOCTL_RM_ALLOC))
    chk("iowr FREE==0xC00C5529", IOCTL_RM_FREE == 0xC00C5529, hex(IOCTL_RM_FREE))
    chk("iowr VERCHK==0xC04846D2", IOCTL_VERCHK == 0xC04846D2, hex(IOCTL_VERCHK))

    # le patch mW (le cœur du replay T2)
    raw = bytes.fromhex("0011" + "a0860100" + "2233")   # 250000 @2
    p = patch_mw(raw, [2], 280000)
    chk("patch_mw 250000->280000@2",
        struct.unpack_from("<I", p, 2)[0] == 280000 and p[:2] == b"\x00\x11"
        and p[6:] == b"\x22\x33")

    # les RatedTdp publics (4.21)
    chk("RATED_TDP_GET==0x2080206e",
        NV2080_CTRL_CMD_PERF_RATED_TDP_GET_CONTROL == 0x2080206E)
    chk("RATED_TDP_SET==0x2080206f",
        NV2080_CTRL_CMD_PERF_RATED_TDP_SET_CONTROL == 0x2080206F)
    chk("sizeof(RatedTdpParams)==12",
        ctypes.sizeof(NV2080_CTRL_PERF_RATED_TDP_CONTROL_PARAMS) == 12)

    # les NVstatus du verdict T4
    chk("NV_ERR_INVALID_LIMIT==0x2E", NVSTATUS[0x2E] == "NV_ERR_INVALID_LIMIT")
    chk("NV_ERR_NOT_SUPPORTED==0x56", NVSTATUS[0x56] == "NV_ERR_NOT_SUPPORTED")

    # la lecture de version (offline-safe)
    v = read_driver_version()
    chk("read_driver_version (si /proc présent)", True, str(v))

    print(f"\n{'TOUT VERT' if not fails else f'{len(fails)} FAIL'} : "
          f"{len(fails)} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
