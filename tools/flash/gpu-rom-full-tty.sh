#!/bin/bash
# gpu-rom-full-tty.sh (v4) — FULL 976 KiB VBIOS read via nvflash, detached.
#
# WHY: the fan policy, fan cooler, power budget and vP-state tables live at
# ~551-563 KiB (proven by the pointer resolution cross-checked on the TPU
# reference dumps) — beyond the GPU's 512 KiB ROM BAR window that gx20/gx21
# already read in-session. nvflash pages the SPI beyond the window, but it
# refuses to run while the kernel driver is loaded. Under the nomodeset boot
# the console sits on simpledrm, so the driver IS unloadable once the desktop
# stack is stopped — this script does exactly that, detached.
#
# HOW TO RUN (from a terminal, ON the "Omarchy nomodeset (maintenance GPU)"
# boot — the /proc/cmdline check below refuses anything else):
#
#   sudo systemd-run --unit=romfull --collect \
#     bash "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/tools/gpu-rom-full-tty.sh"
#
# The screen WILL go black (the desktop must die to release the driver —
# ZCode and terminals die with it). Wait ~2 minutes: the script reloads the
# driver and restarts the login screen by itself. Log back in, reopen ZCode.
#
# READ-ONLY: nvflash --save never writes to the GPU. Doctrine: never flash to read.

set -u
OUT="/root/rom-full-$(date +%Y%m%d-%H%M%S)"
LOG="/root/rom-full-log.txt"

mkdir -p "$OUT"
exec > >(tee -a "$LOG") 2>&1
echo "=== full rom read $(date -Is) ==="

[ "$(id -u)" = 0 ] || { echo "ERROR: run as root (systemd-run does this)"; exit 1; }
grep -o nomodeset /proc/cmdline > /dev/null || { echo "ERROR: not on the nomodeset maintenance boot"; exit 1; }
command -v nvflash > /dev/null || { echo "ERROR: nvflash not at /usr/local/bin/nvflash"; exit 1; }

restore() {
  echo "[restore] reloading driver and desktop"
  modprobe nvidia_drm 2>/dev/null
  modprobe nvidia_uvm 2>/dev/null
  systemctl start lactd coolercontrold 2>/dev/null
  systemctl start sddm 2>/dev/null
  echo "[restore] done"
}
trap restore EXIT

echo "[1/6] stopping the desktop stack"
systemctl stop sddm lactd coolercontrold 2>/dev/null
sleep 3

echo "[2/6] unloading the NVIDIA driver (console is on simpledrm)"
for i in $(seq 1 10); do
  lsmod | grep -q '^nvidia' || break
  modprobe -r nvidia_drm nvidia_uvm nvidia_modeset nvidia 2>/dev/null
  sleep 2
done
if lsmod | grep -q '^nvidia'; then
  echo "ERROR: driver still pinned:"
  lsmod | grep '^nvidia'
  lsof /dev/nvidia* 2>/dev/null | head -10
  exit 1
fi
echo "  driver fully unloaded"

echo "[3/6] nvflash board info"
nvflash --version 2>&1 | head -4 || true

echo "[4/6] nvflash full save (expect ~999424 bytes)"
nvflash --save "$OUT/rom-full.rom" || { echo "ERROR: nvflash --save failed"; exit 1; }

echo "[5/6] verifying"
stat -c '  size: %s bytes' "$OUT/rom-full.rom"
sha256sum "$OUT/rom-full.rom"
python3 - "$OUT/rom-full.rom" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
print("  head:", d[:16].hex(" "))
print("  55aa header:", d[:2] == b"\x55\xaa")
for name, off, sig in [("power_budget", 551240, 0x30), ("fan_cooler", 554029, 0x10), ("fan_policy", 554087, 0x20)]:
    print(f"  {name} @ {off}: {d[off:off+4].hex(' ')} (expected version {sig:#04x})" if off < len(d) else f"  {name}: beyond file")
hits = [i for i in range(len(d) - 3) if d[i] == 0x20 and d[i + 1] == 0x15 and d[i + 2] == 0x01]
print("  vP-state candidates:", [hex(h) for h in hits[:6]])
PY

echo "[6/6] success — artifacts in $OUT (the trap restores the desktop)"
