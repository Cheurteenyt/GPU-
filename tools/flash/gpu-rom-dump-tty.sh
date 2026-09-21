#!/bin/bash
# gpu-rom-dump-tty.sh (v2) — full GPU ROM READ, 100% PC, via the nomodeset boot entry.
#
# HOW TO USE (from the maintenance boot):
#   1. Reboot, pick "Omarchy nomodeset (maintenance GPU)" in the Limine menu.
#   2. Log in on the TTY it lands on.
#   3. Run:  sudo bash "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/tools/gpu-rom-dump-tty.sh"
#   4. Reboot normally afterwards (the entry is non-destructive).
#
# v2: nothing on the data drive is needed — nvflash now lives at
# /usr/local/bin/nvflash (on the always-mounted root fs) and all artifacts
# are written under /root/gpu-rom-read-<date>/. The data drive is NOT
# auto-mounted in maintenance mode (no desktop session), which is exactly
# why v1 failed with "No such file or directory".
#
# READ-ONLY: this script never writes to the GPU. Doctrine: never flash to read.
# Two independent reads (kernel sysfs expansion-ROM path + nvflash) are compared
# byte-for-byte over their common prefix; a mismatch means STOP and report.

set -u
NVFLASH=""
for c in /usr/local/bin/nvflash \
         "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/tools/nvflash-5.867/x64/nvflash"; do
  [ -x "$c" ] && NVFLASH="$c" && break
done
OUT="/root/gpu-rom-read-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUT"
exec > >(tee -a "$OUT/log.txt") 2>&1
echo "=== gpu rom read $(date -Is) ==="

[ "$(id -u)" = 0 ] || { echo "ERROR: run with sudo"; exit 1; }
[ -n "$NVFLASH" ] || { echo "ERROR: nvflash not found"; exit 1; }

echo "[1/5] boot parameters"
grep -o nomodeset /proc/cmdline > /dev/null || { echo "ERROR: not booted with nomodeset — pick the maintenance entry"; exit 1; }
echo "  nomodeset confirmed: $(cat /proc/cmdline)"

echo "[2/5] NVIDIA driver must be absent"
if lsmod | grep -q '^nvidia'; then echo "ERROR: nvidia driver is loaded — you are not on the maintenance entry"; exit 1; fi
echo "  ok, no driver holding the card"

echo "[3/5] quiet the desktop stack (may already be inactive under nomodeset)"
systemctl stop sddm lactd coolercontrold 2>/dev/null || true
lspci -d 10de: -nn | sed 's/^/  gpu: /'

DEV=""
for d in /sys/bus/pci/devices/*; do
  [ "$(cat "$d/vendor" 2>/dev/null)" = "0x10de" ] && DEV="$d" && break
done
[ -n "$DEV" ] || { echo "ERROR: no NVIDIA PCI device found"; exit 1; }
echo "  device: $DEV"

echo "[4/5] read 1 of 2: kernel sysfs expansion-ROM path"
SYS_OK=no
if echo 1 > "$DEV/rom" 2>/dev/null; then
  if cat "$DEV/rom" > "$OUT/vbios-sysfs.rom" 2>/dev/null; then
    SYS_OK=yes
  fi
  echo 0 > "$DEV/rom" 2>/dev/null || true
fi
if [ "$SYS_OK" = yes ]; then
  echo "  sysfs: $(stat -c%s "$OUT/vbios-sysfs.rom") bytes, sha256 $(sha256sum "$OUT/vbios-sysfs.rom" | cut -d' ' -f1)"
else
  echo "  sysfs ROM read unavailable on this card — continuing with nvflash only"
fi

echo "[5/5] read 2 of 2: nvflash"
if "$NVFLASH" --save "$OUT/vbios-nvflash.rom"; then
  echo "  nvflash: $(stat -c%s "$OUT/vbios-nvflash.rom") bytes, sha256 $(sha256sum "$OUT/vbios-nvflash.rom" | cut -d' ' -f1)"
else
  echo "ERROR: nvflash --save failed — full log above; report back"
  exit 1
fi

echo "=== cross-check ==="
if [ "$SYS_OK" = yes ]; then
  A="$OUT/vbios-sysfs.rom"; B="$OUT/vbios-nvflash.rom"
  SA=$(stat -c%s "$A"); SB=$(stat -c%s "$B")
  N=$(( SA < SB ? SA : SB ))
  if cmp -s -n "$N" "$A" "$B"; then
    echo "  MATCH over common prefix of $N bytes (sizes: sysfs $SA / nvflash $SB)"
  else
    echo "  MISMATCH over the first $N bytes — STOP, do not proceed to any write, report back"
    exit 1
  fi
else
  echo "  single-source read (nvflash) — sysfs unavailable, keep the file as-is"
fi
echo "done. artifacts in $OUT (nothing was written to the GPU)"
echo "you can reboot normally now"
