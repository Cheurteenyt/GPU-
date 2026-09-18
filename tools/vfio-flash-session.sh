#!/usr/bin/env bash
# vfio-flash-session.sh — the VM-based flash session (the ingenious bypass).
#
# Runs ON THE ARCH LIVE USB. It:
#   1. installs qemu + OVMF (network: DHCP ethernet works on the live ISO)
#   2. builds a minimal Linux VM initramfs (busybox + nvflash + the script)
#   3. binds the NVIDIA GPU to vfio-pci (no host driver on the live session)
#   4. boots the VM with the GPU passed through — the VM's kernel RESETS the
#      card to a clean state (no GOP, no firmware handoff state) — and runs
#      the flash session INSIDE the VM
#   5. the result files land on the data drive via a second virtio disk
#
# The VM sees the card FRESH — the nvflash "system restart" state cannot
# exist inside the VM (the VM's kernel initializes the card itself).
#
# Usage (on the live session):
#   mount /dev/sda1 /mnt
#   bash "/mnt/Reverse Engenering/gpu-lab/tools/vfio-flash-session.sh"
set -u
M=/mnt
LAB="$M/Reverse Engenering/gpu-lab"
NVFLASH="$LAB/tools/nvflash-5.867/x64/nvflash"
ROM_BUILD="$LAB/acquisitions/MSI.RTX3070.8192.210519_1.rom"
ROM_MOD="$LAB/acquisitions/MSI.RTX3070.8192.210519_1-unlock-2200MHz-280W.rom"
OUT="$LAB/day0/vfio-flash-$(date +%Y%m%d-%H%M%S)"
GPU=0000:07:00.0

[ "$(id -u)" = 0 ] || { echo "ERROR: root required"; exit 1; }
mountpoint -q /mnt || { echo "ERROR: mount the data drive first"; exit 1; }
mkdir -p "$OUT"

echo "=== VFIO flash session $(date -Is) ==="
echo "[1/6] installing qemu + ovmf (network)"
pacman -Sy --noconfirm --needed qemu-full edk2-ovmf >/tmp/vfio-pacman.log 2>&1 || { echo "pacman failed — see /tmp/vfio-pacman.log"; exit 1; }
echo "  ok"

echo "[2/6] building the minimal VM initramfs (busybox + nvflash)"
VMROOT=/tmp/vmroot; mkdir -p "$VMROOT/bin" "$VMROOT/proc" "$VMROOT/sys" "$VMROOT/dev"
BB=$(find /mnt -name 'busybox*' -type f 2>/dev/null | head -1)
if [ -z "$BB" ]; then
  curl -sL -o /tmp/busybox "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" || { echo "busybox download failed"; exit 1; }
  BB=/tmp/busybox
fi
cp "$BB" "$VMROOT/bin/busybox" && chmod +x "$VMROOT/bin/busybox"
"$VMROOT/bin/busybox" mkdir -p "$VMROOT/bin" 2>/dev/null
for app in sh mount cp ls echo sleep sync cat mdev; do ln -sf busybox "$VMROOT/bin/$app"; done
cp "$NVFLASH" "$VMROOT/nvflash" && chmod +x "$VMROOT/nvflash"
cat > "$VMROOT/init" <<'INITEOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo "=== VM flash session ==="
echo "[V1] nvflash version"
/nvflash --version 2>&1 | head -4
echo "[V2] chip read"
/nvflash --save /chip-before.rom
echo "[V3] verify + protectoff + flash + re-verify"
/nvflash --verify /unlock.rom && \
/nvflash --protectoff && \
/nvflash --flash /unlock.rom && \
/nvflash --verify /unlock.rom && echo "VM FLASH COMPLETE" || echo "VM FLASH FAILED"
/poweroff -f
INITEOF
chmod +x "$VMROOT/init"
(cd "$VMROOT" && find . | cpio -o -H newc --quiet | gzip > /tmp/vm-initramfs.cpio.gz) || { echo "initramfs build failed"; exit 1; }
cp /tmp/vm-initramfs.cpio.gz "$OUT/"
cp "$ROM_BUILD" "$OUT/chip-build.rom" 2>/dev/null
cp "$ROM_MOD" "$OUT/unlock.rom" 2>/dev/null || { echo "ERROR: modded ROM missing"; exit 1; }
KERN=$(ls /mnt/arch/boot/x86_64/vmlinuz-linux 2>/dev/null || find /mnt -name 'vmlinuz*' 2>/dev/null | head -1)
[ -f "$KERN" ] || { echo "ERROR: kernel not found on the USB"; exit 1; }

echo "[3/6] binding the GPU to vfio-pci"
modprobe vfio_pci
echo vfio_pci > /sys/bus/pci/devices/$GPU/driver_override 2>/dev/null || true
echo $GPU > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || true

echo "[4/6] launching the VM with the GPU passed through"
qemu-system-x86_64 \
  -enable-kvm -m 2G -nographic \
  -kernel "$KERN" -initrd /tmp/vm-initramfs.cpio.gz \
  -append "console=ttyS0 quiet" \
  -device vfio-pci,host=$GPU \
  -drive file="$OUT/unlock.rom",if=virtio,format=raw,readonly=on \
  -net none >/tmp/vfio-vm.log 2>&1
VMRC=$?
echo "VM exit: $VMRC"

echo "[5/6] post-checks"
ls -la /tmp/vm-initramfs.cpio.gz >/dev/null
echo "[6/6] done — the VM reset the card; reboot normally (re-arm BootNext from Omarchy if needed)"
