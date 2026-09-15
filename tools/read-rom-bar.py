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
READ_SIZE = 0x100000  # the SPI chip fits in 1 MiB (TPU image = 0xF4000)
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
    addr, enabled = read_rom_bar()
    print(f"ROM BAR as found: {addr:#x} enabled={enabled}")
    if addr != 0:
        candidates = [addr]
    else:
        occupied = occupied_real()
        candidates = [
            c
            for c in (0xFC000000, 0xFDF00000, 0xFE000000, 0xFB000000, 0xF4000000, 0xE8000000)
            if not any(s < c + READ_SIZE and e > c for s, e, _ in occupied)
        ]
        print("candidates (conflict-checked):", [hex(c) for c in candidates])

    fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
    chosen, verdict = None, None
    for cand in candidates:
        write_rom_bar(cand | 1)
        back = read_rom_bar()
        if not back[1]:
            print(f"  {cand:#x}: BAR refused the assignment")
            continue
        try:
            probe = probe_window(fd, cand)
        except (PermissionError, OSError) as e:
            print(f"  {cand:#x}: probe failed: {e}")
            write_rom_bar(0)
            continue
        v = classify(probe)
        print(f"  {cand:#x}: probe -> {v} (head: {probe[:16].hex(' ')})")
        if v.startswith("ROM"):
            chosen, verdict = cand, v
            break
        write_rom_bar(0)

    if chosen is None:
        print("VERDICT: no candidate decodes a ROM — the expansion-ROM BAR on this "
              "card does not serve the SPI to the host this way. The full-flash "
              "path is the live USB (nvflash without the loaded driver).")
        return 1

    print(f"ROM decodes at {chosen:#x} — reading {READ_SIZE:#x} bytes")
    mm = mmap.mmap(fd, READ_SIZE, offset=chosen)
    data = mm[:]
    mm.close()
    fd.close()
    write_rom_bar(0)
    print("BAR restored to 0 — no trace left.")

    OUT.write_bytes(data)
    print(f"saved: {OUT} ({len(data)} bytes)")
    ff = data.count(0xFF) / len(data)
    print(f"ff_share: {ff:.4f}")
    print("head 0x40:", data[:0x40].hex(" "))
    for pat, name in [(b"\x55\xaa", "55AA"), (b"NVGI", "NVGI")]:
        offs = [m.start() for m in re.finditer(re.escape(pat), data)][:12]
        print(f"{name} hits:", [hex(o) for o in offs])
    runs, cur = [], None
    for i in range(0, len(data), 0x1000):
        w = data[i : i + 0x1000]
        if w.count(0xFF) / len(w) < 0.99:
            if cur is None:
                cur = [i, i]
            else:
                cur[1] = i
        else:
            if cur:
                runs.append(cur)
                cur = None
    if cur:
        runs.append(cur)
    print("non-erased 4K runs:", [(hex(a), hex(b)) for a, b in runs][:10])
    m = re.search(rb"\d{2}\.\d{2}\.\d{2}\.\d{2}\.[0-9A-Z]{2}", data)
    print("version string:", m.group().decode() if m else "NOT FOUND",
          "@", hex(m.start()) if m else "-")
    return 0


if __name__ == "__main__":
    sys.exit(main())
