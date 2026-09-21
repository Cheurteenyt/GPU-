#!/usr/bin/env python3
"""cert20-brom-dump.py — the SEC2 Boot ROM dump attempt via the Falcon XFER ports (READ-ONLY).

The gadget addresses (0xcbd-0x7f2f) live in the SEC2 Boot ROM (the masked
IMEM @0x0-0x8000). The envytools falcon documentation (xfer.rst) defines the
XFER engine MMIO ports:

  XFER_EXT_BASE        falcon+0x110  (I[0x04400])
  XFER_LOCAL_ADDRESS   falcon+0x114  (I[0x04500])
  XFER_CTRL            falcon+0x118  (I[0x04600])  — bit0: start, bit2: dir?
  XFER_STATUS          falcon+0x120  (I[0x04800])

The SEC2 falcon block = BAR0 0x840000 (NV_PSEC, dev_sec_pri.h). This tool
attempts a passive readback of IMEM 0x0-0x8000 (the BROM) through the XFER
ports: program the transfer local->ext into a scratch sysmem, then read it.

READ-ONLY from the host's perspective (XFER programming = the documented
debug mechanism). If the ports are locked post-boot (likely), the DENIED
reads = the documented answer too.

Run from a TTY with the driver unloaded:
    sudo python3 cert20-brom-dump.py
"""
import os
import struct
import subprocess
import sys
import time

PCI_FULL = "0000:07:00.0"
RESOURCE0 = f"/sys/bus/pci/devices/{PCI_FULL}/resource0"

SEC2 = 0x00840000
XFER_EXT_BASE = SEC2 + 0x110
XFER_LOCAL = SEC2 + 0x114
XFER_CTRL = SEC2 + 0x118
XFER_EXT_OFF = SEC2 + 0x11C
XFER_STATUS = SEC2 + 0x120
DMEM_WINDOW = SEC2 + 0x1000  # the falcon DMEM data window (per the falcon docs)

LOG = []



def log(msg):
    print(msg)
    LOG.append(msg)


def rd32(fd, off):
    return struct.unpack("<I", os.pread(fd, 4, off))[0]


def wr32(fd, off, val):
    os.pwrite(fd, struct.pack("<I", val & 0xFFFFFFFF), off)


def try_rd(fd, off, name):
    try:
        v = rd32(fd, off)
        log(f"  {name:22s} @0x{off:08x} = 0x{v:08x}")
        return v
    except OSError as e:
        log(f"  {name:22s} @0x{off:08x} = DENIED (errno {e.errno})")
        return None


def main():
    log("=== the SEC2 Boot ROM dump attempt via the Falcon XFER ports ===")
    log("=== (read-only, the documented debug mechanism per envytools xfer.rst) ===")

    fd = os.open(RESOURCE0, os.O_RDWR | os.O_SYNC)

    # 1. l'état des registres XFER avant toute manipulation
    log("--- the XFER port state ---")
    ext_base = try_rd(fd, XFER_EXT_BASE, "XFER_EXT_BASE")
    local = try_rd(fd, XFER_LOCAL, "XFER_LOCAL_ADDRESS")
    ctrl = try_rd(fd, XFER_CTRL, "XFER_CTRL")
    status = try_rd(fd, XFER_STATUS, "XFER_STATUS")

    # 2. la fenêtre DMEM directe (le data window @+0x1000 par la doc falcon)
    log("--- the DMEM window probe (the direct data window) ---")
    dmem_vals = {}
    for off in (DMEM_WINDOW, DMEM_WINDOW + 4, SEC2 + 0x0):
        try:
            v = rd32(fd, off)
            dmem_vals[off] = v
            log(f"  DMEM window @0x{off:08x} = 0x{v:08x}")
        except OSError as e:
            log(f"  DMEM window @0x{off:08x} = DENIED (errno {e.errno})")
            break

    # 3. la tentative XFER local->ext : IMEM 0x0 (la BROM) vers la fenêtre
    if ctrl is not None:
        log("--- the XFER attempt: IMEM 0x0 -> the window ---")
        try:
            # la cible externe = la fenêtre DMEM (le mécanisme le plus simple)
            wr32(fd, XFER_LOCAL, 0x00000000)  # IMEM offset 0 (la BROM start)
            wr32(fd, XFER_EXT_OFF, 0x00000000)
            wr32(fd, XFER_CTRL, 0x00000006)  # start + la direction local->ext
            time.sleep(0.05)
            st = rd32(fd, XFER_STATUS)
            log(f"  XFER_STATUS après = 0x{st:08x} (0x0 = done?)")
            # la lecture de la fenêtre après le transfer
            for i in range(4):
                try:
                    v = rd32(fd, DMEM_WINDOW + i * 4)
                    log(f"  fenêtre[{i}] = 0x{v:08x}")
                except OSError:
                    log(f"  fenêtre[{i}] = DENIED")
                    break
        except OSError as e:
            log(f"  XFER write DENIED (errno {e.errno}) — les ports = verrouillés post-boot")

    # 4. la tentative DMEM directe : la fenêtre = le DMEM visible du host
    log("--- le dump DMEM direct (la fenêtre @+0x1000, 256 octets) ---")
    dump = []
    try:
        for i in range(64):
            dump.append(rd32(fd, DMEM_WINDOW + i * 4))
        log(f"  {len(dump)} dwords lus — les premiers:")
        for i in range(0, min(16, len(dump)), 4):
            row = " ".join(f"{v:08x}" for v in dump[i:i+4])
            log(f"  +0x{i*4:04x}: {row}")
    except OSError as e:
        log(f"  DMEM direct DENIED (errno {e.errno})")

    os.close(fd)
    out = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/day0/cert20-brom-dump.log"
    with open(out, "a") as f:
        f.write("\n".join(LOG) + "\n")
    log(f"=== le log: {out} ===")


if __name__ == "__main__":
    main()
