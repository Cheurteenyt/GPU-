#!/usr/bin/env python3
"""amd-spi-bypass — set the FCH SPI host-access bits, dump the BIOS, restore.

Run:  sudo python3 tools/amd-spi-bypass.py

The wall (measured): SPI_CNTRL0 bits 22 (SpiAccessMacRomEn) and 23
(SpiHostAccessRomEn) are CLEAR — flashrom refuses and the ROM window is
unreachable. The bypass: set both bits via /dev/mem (iomem=relaxed is
active), run the double flashrom read, then RESTORE the original
register value. The flash chip itself is only ever read.

Every step is logged to day0/spi-bypass-log.txt on the data drive.
"""

import mmap
import os
import struct
import subprocess
import sys

LAB = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/BIOS-"
LOG = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/day0/spi-bypass-log.txt"
DEST1 = LAB + "/nw-3644-read1.rom"
DEST2 = LAB + "/nw-3644-read2.rom"

logf = open(LOG, "a")


def log(msg):
    line = str(msg)
    print(line, flush=True)
    logf.write(line + "\n")
    logf.flush()


def main():
    log(f"=== AMD SPI bypass attempt {__import__('datetime').datetime.now().isoformat()} ===")
    bar_raw = int(subprocess.check_output(["setpci", "-s", "00:14.3", "0xA0.L"]).strip(), 16)
    base = bar_raw & 0xFFFFFFE0
    log(f"SPI base: {base:#x}")

    fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
    mm = mmap.mmap(fd, 0x1000, offset=base & ~0xFFF)
    off = base & 0xFFF
    original = struct.unpack_from("<I", mm, off)[0]
    log(f"SPI_CNTRL0 original: {original:#010x} (bits22/23 = {(original >> 22) & 1}/{(original >> 23) & 1})")

    target = original | 0xC00000  # set bits 22|23
    struct.pack_into("<I", mm, off, target)
    readback = struct.unpack_from("<I", mm, off)[0]
    log(f"SPI_CNTRL0 after write: {readback:#010x}")
    if (readback & 0xC00000) != 0xC00000:
        log("VERDICT: the write did NOT stick — the register is SMU/EC-locked.")
        log("The software bypass is impossible on this board; the hardware programmer is the path.")
        mm.close()
        os.close(fd)
        logf.close()
        return 1
    log("VERDICT: bits set — the host ROM access is open.")

    ok = 0
    try:
        for dest in (DEST1, DEST2):
            log(f"--- flashrom read -> {dest}")
            r = subprocess.run(
                ["flashrom", "-p", "internal", "-r", dest],
                capture_output=True, text=True, timeout=300,
            )
            tail = (r.stdout + r.stderr).strip().splitlines()[-6:]
            for line in tail:
                log("  | " + line)
            if r.returncode == 0 and os.path.exists(dest):
                ok += 1
    except subprocess.TimeoutExpired:
        log("flashrom TIMED OUT")

    log(f"reads admitted: {ok}/2")
    if ok == 2:
        import hashlib
        for dest in (DEST1, DEST2):
            h = hashlib.sha256(open(dest, "rb").read()).hexdigest()
            log(f"sha256 {os.path.basename(dest)}: {h}")

    struct.pack_into("<I", mm, off, original)
    readback = struct.unpack_from("<I", mm, off)[0]
    log(f"SPI_CNTRL0 restored: {readback:#010x} (matches original: {readback == original})")
    mm.close()
    os.close(fd)
    logf.close()
    return 0 if ok == 2 else 1


if __name__ == "__main__":
    sys.exit(main())
