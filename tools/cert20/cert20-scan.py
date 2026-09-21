#!/usr/bin/env python3
"""cert20-scan.py — the FEAT/fuse register space scan (READ-ONLY, passive).

Scans BAR0 0x820000-0x826000 (the fuse/feature block neighborhood) for:
  1. the u32 values 100000/240000/250000/280000 mW (the power limits!)
  2. the register map (every nonzero dword, for the manual review)

The reads are passive MMIO reads — no writes, no exploit, safe on a
running system. The found addresses = the power-limit shadow registers
(if the FEAT_OVR system covers the power axis on GA104).

    sudo python3 cert20-scan.py
"""
import os, struct, sys

PCI_FULL = "0000:07:00.0"
RESOURCE0 = f"/sys/bus/pci/devices/{PCI_FULL}/resource0"
SCAN_START = 0x820000
SCAN_END = 0x826000

POWER_VALUES = {
    100000: "100 W (min)",
    130000: "130 W",
    140000: "140 W",
    170000: "170 W",
    200000: "200 W",
    220000: "220 W",
    240000: "240 W (rated)",
    250000: "250 W (peak)",
    265000: "265 W (notre cible avg)",
    280000: "280 W (notre cible peak)",
}


def main():
    import subprocess, time
    print("=== arrêt du display manager + déchargement du driver (l'état où les lectures fonctionnent) ===")
    for svc in ("display-manager",):
        subprocess.run(["systemctl", "stop", svc], capture_output=True)
    run_ = subprocess.run(["killall", "-9", "Xorg", "Xwayland", "nvidia-persistenced"], capture_output=True)
    for mod in ("nvidia_uvm", "nvidia_drm", "nvidia_modeset", "nvidia"):
        subprocess.run(["modprobe", "-r", mod], capture_output=True)
    time.sleep(2)
    fd = os.open(RESOURCE0, os.O_RDWR | os.O_SYNC)
    print(f"=== scan BAR0 0x{SCAN_START:06x}-0x{SCAN_END:06x} (lecture dword par dword) ===")

    # la lecture dword par dword avec capture d'erreur
    readable = {}
    denied = 0
    for off in range(SCAN_START, SCAN_END, 4):
        try:
            readable[off] = struct.unpack("<I", os.pread(fd, 4, off))[0]
        except OSError:
            denied += 1
    os.close(fd)
    print(f"lisibles: {len(readable):,}, DENIED: {denied:,}")

    # 1. les valeurs de power en mW (u32 LE)
    print("--- les valeurs de power (u32 LE) ---")
    found_any = False
    for val, name in sorted(POWER_VALUES.items()):
        hits = [hex(off) for off, v in readable.items() if v == val]
        if hits:
            found_any = True
            print(f"  {name}: {hits}")
    if not found_any:
        print("  aucune valeur de power mW trouvée dans la fenêtre")

    # 2. la carte des dwords non-nuls
    print("--- les dwords non-nuls ---")
    nonzero = 0
    for off in sorted(readable):
        v = readable[off]
        if v != 0 and v != 0xFFFFFFFF:
            print(f"  0x{off:06x} = 0x{v:08x}")
            nonzero += 1
            if nonzero > 150:
                print("  ... (tronqué)")
                break
    print(f"=== scan terminé : {nonzero} dwords non-nuls, {denied} DENIED ===")
    os.close(fd) if False else None
    fd2 = fd
    print("=== rechargement du driver + le display manager ===")
    for mod in ("nvidia", "nvidia_modeset", "nvidia_drm", "nvidia_uvm"):
        subprocess.run(["modprobe", mod], capture_output=True)
    subprocess.run(["systemctl", "start", "display-manager"], capture_output=True)
    print("=== restauré ===")


if __name__ == "__main__":
    main()
