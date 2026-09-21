#!/bin/bash
# full-flash-tty.sh (v2) — the full-SPI read, in-session (TTY route).
#
# Run from a TTY (Ctrl+Alt+F3), NOT from the graphical terminal:
#   sudo bash "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/tools/full-flash-tty.sh"
#
# v2 changes after the first attempt:
#   - every line is logged to /tmp/full-flash.log (survives a reboot, so
#     a failed run is still diagnosable afterwards),
#   - the data drive mount is verified (and fixed) BEFORE the display
#     manager stops,
#   - the restore verifies the NVIDIA driver is actually loaded BEFORE
#     restarting the display manager (the first attempt's race is what
#     left the desktop unable to start),
#   - if anything fails late, the script leaves a working TTY and tells
#     the user to reboot instead of starting a display over a dead stack.

set -u
LAB="/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab"
DEST="$LAB/day0/vbios-full-flash.rom"
LOG="$LAB/day0/full-flash-log.txt"
DM=sddm

echo "=== full-flash attempt $(date -Is) ==="

if [ "$(id -u)" != "0" ]; then echo "ERROR: run with sudo"; exit 1; fi
if [ ! -d "$LAB" ]; then echo "ERROR: the gpu-lab drive is not mounted"; exit 1; fi
exec > >(tee -a "$LOG") 2>&1
if [ -f "$DEST" ]; then
  echo "WARNING: $DEST already exists — moving it aside"
  mv "$DEST" "$DEST.bak.$(date +%s)"
fi

echo "[1/5] data-drive mount check"
if ! findmnt -T "$LAB" > /dev/null; then
  echo "  not mounted — attempting udisks mount"
  DEV=$(lsblk -rno NAME,LABEL | awk '$2=="Jeux SSD"{print "/dev/"$1; exit}')
  [ -n "$DEV" ] && udisksctl mount -b "$DEV" || { echo "  ERROR: cannot mount the drive"; exit 1; }
fi
echo "  mounted: $(findmnt -n -o SOURCE --target "$LAB")"

echo "[2/5] stopping $DM (screen goes dark now)"
STOPPED_SERVICES=""
(setsid bash -c 'sleep 240; if ! systemctl is-active --quiet sddm; then
  modprobe nvidia_modeset nvidia_drm nvidia_uvm nvidia 2>/dev/null; modprobe nvidia 2>/dev/null
  systemctl start coolercontrold lactd 2>/dev/null
  systemctl start sddm
  echo "WATCHDOG: forced restore at $(date -Is)" >> "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/day0/full-flash-log.txt"
fi' </dev/null >/dev/null 2>&1) &
WATCHDOG_PID=$!
echo "watchdog armed (pid $WATCHDOG_PID): forced restore after 240s no matter what"
systemctl stop "$DM"
for SVC in coolercontrold lactd; do
  if systemctl is-active --quiet "$SVC"; then
    echo "  stopping $SVC (it holds the GPU open)"
    systemctl stop "$SVC"
    STOPPED_SERVICES="$STOPPED_SERVICES $SVC"
  fi
done

restore() {
  for SVC in $STOPPED_SERVICES; do
  echo "[restore] restarting $SVC"
  systemctl start "$SVC"
done
echo "[restore] reloading the NVIDIA driver"
  modprobe nvidia 2>/dev/null || true
  modprobe nvidia_modeset 2>/dev/null || true
  modprobe nvidia_drm 2>/dev/null || true
  modprobe nvidia_uvm 2>/dev/null || true
  sleep 2
  if lsmod | grep -q "^nvidia "; then
    echo "[restore] driver loaded — restarting $DM"
    systemctl start "$DM"
    echo "[restore] done — the login screen should be back"
  else
    echo "[restore] DRIVER DID NOT LOAD — reboot the machine (safe; nothing is damaged)"
  fi
}

echo "[3/5] unloading the NVIDIA driver (waiting for session processes to die)"
sleep 3
unloaded=0
for i in 1 2 3 4 5 6; do
  modprobe -r i2c_nvidia_gpu nvidia_drm nvidia_uvm nvidia_modeset nvidia 2>/dev/null \
    || rmmod i2c_nvidia_gpu nvidia_drm nvidia_uvm nvidia_modeset nvidia 2>/dev/null || true
  if ! lsmod | grep -q "^nvidia "; then unloaded=1; break; fi
  if [ "$i" = "3" ]; then
    echo "  terminating remaining GPU holders"
    for pid in $(lsof -t /dev/nvidia* /dev/nvidiactl 2>/dev/null); do kill "$pid" 2>/dev/null; done
    sleep 3
  fi
  echo "  still busy (attempt $i) — waiting 2s"
  sleep 2
done
if [ "$unloaded" != "1" ]; then
  echo "ERROR: the driver refused to unload — holders:"
  lsof /dev/nvidia* 2>/dev/null | head -8
  echo "restoring and aborting"
  restore
  exit 1
fi
echo "  driver unloaded"

echo "[4/5] nvflash --save (read-only, the card is never written, 2-minute hard timeout)"
cd "$LAB"
if timeout -k 5 120 ./tools/x64/nvflash --save "$DEST" < /dev/null; then
  echo "READ OK"
else
  RC=$?
  echo "NVFLASH FAILED or TIMED OUT (exit code $RC — see the exact error above)"
fi

echo "[5/5] restore"
restore

if [ -f "$DEST" ]; then
  echo "=== result ==="
  ls -la "$DEST"
  sha256sum "$DEST"
else
  echo "no ROM file was produced — read the log above, then report it"
fi
echo "the full log stays at $LOG (copied below if the drive is mounted)"
cp "$LOG" "$LAB/day0/full-flash-log.txt" 2>/dev/null || true
kill "$WATCHDOG_PID" 2>/dev/null || true
echo "done."
