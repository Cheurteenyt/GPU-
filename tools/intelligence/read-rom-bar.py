#!/usr/bin/env python3
"""read-rom-bar — read the GA104 expansion-ROM BAR through /dev/mem.

Run as root:  sudo python3 tools/read-rom-bar.py

v2: the assignment address is now chosen from /proc/iomem's REAL free
holes (v1 guessed 0xfd000000 and read another device's memory — the
lesson is structural: never assign from a guess). The BAR is restored
to 0 afterwards; the card's flash is never written.
"""

import mmap
import os
import re
import sys
from pathlib import Path

DEV = "/sys/bus/pci/devices/0000:07:00.0"
OUT = Path(__file__).resolve().parent.parent / "day0" / "rom-bar-window.bin"
READ_SIZE = 0x80000  # the kernel-sized ROM resource of 0000:07:00.0 (512 KiB)
ALIGN = 0x1000000     # the ROM BAR decodes up to 16 MiB → 16 MiB alignment


def read_rom_bar() -> tuple[int, bool]:
    cfg = open(DEV + "/config", "rb").read(0x34)
    raw = int.from_bytes(cfg[0x30:0x34], "little")
    return raw & ~1, bool(raw & 1)


def write_rom_bar(value: int) -> None:
    with open(DEV + "/config", "r+b") as f:
        f.seek(0x30)
        f.write(value.to_bytes(4, "little"))
        f.flush()


def occupied_real() -> list[tuple[int, int, str]]:
    """Real reservations only: /proc/iomem's 'PCI Bus n' lines are the
    hierarchy itself and cover everything — they don't occupy."""
    out = []
    for line in open("/proc/iomem"):
        m = re.match(r"\s*([0-9a-f]+)-([0-9a-f]+) : (.+)", line)
        if m and "PCI Bus" not in m.group(3):
            out.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3).strip()))
    return out


def probe_window(fd: int, addr: int) -> bytes:
    mm = mmap.mmap(fd, 0x1000, offset=addr)
    data = mm[:]
    mm.close()
    return data


def classify(probe: bytes) -> str:
    if probe[:2] == b"\x55\xaa":
        return "ROM (55AA)"
    if probe[:4] == b"NVGI":
        return "ROM (NVGI)"
    if probe.count(0xFF) == len(probe):
        return "erased"
    if probe.count(0x00) == len(probe):
        return "zero"
    return "other-device-memory"


def main() -> int:
    """v3.1: the address is not guessed — it is the card's own
    firmware-assigned ROM window, 0xfc000000, whose decode was proven by
    the v2 probe (55 aa 7f eb 4b 37 34 30 30 = this board's header).
    Scratch holes outside the upstream bridges' decode ranges
    master-abort to all-FF: that is the v1/v2 lesson."""
    addr = 0xFC000000
    occ = [(s2, e2, n2) for s2, e2, n2 in occupied_real()
           if s2 < addr + READ_SIZE and e2 > addr]
    print("reservations overlapping the window:", occ or "none")
    bad = [o for o in occ if "0000:07:00.0" not in o[2]]  # own resource is fine
    if bad:
        print("VERDICT: window overlaps another device — refusing"); return 1

    write_rom_bar(addr | 1)
    back = read_rom_bar()
    print(f"BAR written, readback: {back[0]:#x} enabled={back[1]}")
    if not back[1]:
        print("VERDICT: BAR refused the assignment"); return 1

    data = b""
    fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
    try:
        probe = probe_window(fd, addr)
        v = classify(probe)
        print(f"probe -> {v} (head: {probe[:16].hex(' ')})")
        if not v.startswith("ROM"):
            print("VERDICT: window does not decode the ROM"); return 1
        print(f"reading {READ_SIZE:#x} bytes at {addr:#x}")
        mm = mmap.mmap(fd, READ_SIZE, offset=addr)
        data = mm[:]
        mm.close()
    finally:
        os.close(fd)
        write_rom_bar(0)
        cfg = open(DEV + "/config", "rb").read(0x34)
        print(f"ROM BAR after restore: {hex(int.from_bytes(cfg[0x30:0x34], 'little'))}")

    OUT.write_bytes(data)
    print(f"saved: {OUT} ({len(data)} bytes)")
    ff = data.count(0xFF) / len(data)
    print(f"ff_share: {ff:.4f}")
    print("head 0x40:", data[:0x40].hex(" "))
    chip = Path(OUT).parent / "rom-read-20260917" / "vbios-sysfs.rom"
    if chip.exists():
        ref = chip.read_bytes()
        n = min(len(ref), len(data))
        print(f"prefix match vs sysfs chain dump ({n} B): {data[:n] == ref[:n]}")
    for name, off in [("power_budget", 551240), ("fan_cooler", 554029), ("fan_policy", 554087)]:
        print(f"{name} @ {off}: {data[off:off+8].hex(' ')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
