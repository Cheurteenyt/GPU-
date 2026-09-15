#!/bin/bash
# full-flash-tty.sh — the full-SPI read, in-session (the TTY route).
#
# Run from a TTY (Ctrl+Alt+F3), NOT from the graphical terminal:
#   sudo bash "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/tools/full-flash-tty.sh"
#
# The screen goes dark for about a minute (the display manager stops,
# the NVIDIA driver unloads, nvflash reads, everything is restored).
# Even if nvflash fails, the driver and the session are restored.

set -u
LAB="/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab"
DEST="$LAB/day0/vbios-full-flash.rom"
DM=sddm

if [ "$(id -u)" != "0" ]; then echo "ERROR: run with sudo"; exit 1; fi
if [ ! -d "$LAB" ]; then echo "ERROR: the gpu-lab drive is not mounted"; exit 1; fi
if [ -f "$DEST" ]; then
  echo "WARNING: $DEST already exists — moving it aside"
  mv "$DEST" "$DEST.bak.$(date +%s)"
fi

echo "[1/5] stopping $DM (screen goes dark now)"
systemctl stop "$DM"

echo "[2/5] unloading the NVIDIA driver"
modprobe -r i2c_nvidia_gpu nvidia_drm nvidia_uvm nvidia_modeset nvidia 2>/dev/null \
  || rmmod i2c_nvidia_gpu nvidia_drm nvidia_uvm nvidia_modeset nvidia 2>/dev/null || true

echo "[3/5] nvflash --save (read-only, the card is never written)"
cd "$LAB"
if ./tools/x64/nvflash --save "$DEST"; then
  echo "READ OK"
else
  echo "NVFLASH FAILED — the ROM file may be missing or partial"
fi

echo "[4/5] reloading the NVIDIA driver"
modprobe nvidia_modeset 2>/dev/null || true
modprobe nvidia_drm 2>/dev/null || true
modprobe nvidia_uvm 2>/dev/null || true
modprobe nvidia 2>/dev/null || true

echo "[5/5] restarting $DM"
systemctl start "$DM"

if [ -f "$DEST" ]; then
  echo "=== result ==="
  ls -la "$DEST"
  sha256sum "$DEST"
else
  echo "no ROM file was produced — nothing to hash"
fi
echo "done. the desktop should be back; log in again."
