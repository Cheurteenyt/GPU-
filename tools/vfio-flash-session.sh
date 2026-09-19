#!/usr/bin/env bash
# vfio-flash-session.sh — the VM-based flash session (the ingenious bypass).
#
# v2 — fixes from the 2026-09-18 failed run (VM exit: 1, zero progress):
#   F1. kvm module was NOT loaded on the live session -> "Could not access
#       KVM kernel module" -> the VM never booted. Now modprobe'd, with a
#       hard gate on /dev/kvm.
#   F2. the guest kernel lives at /run/archiso/airootfs/usr/lib/modules/*/
#       on current ISOs, not on the USB partition (manual cp workaround on
#       the failed run). Searched there first now.
#   F3. the initramfs NEVER mounted the virtio ROM disk — /unlock.rom did
#       not exist inside the VM, so even a booted VM could not flash.
#       Now: dd from /dev/vda before the flash step.
#   F4. no trace survived (VM console -> /tmp on the live USB). Now the
#       console lands in $OUT/vm-console.log on the DATA DRIVE, plus an
#       explicit verdict line and the chip-before backup via a writable
#       second virtio disk.
#   F5. guest cmdline lacked iomem=relaxed — nvflash would have hit
#       STRICT_DEVMEM inside the VM too. Added.
#
# Runs ON THE ARCH LIVE USB. It:
#   1. installs qemu (network: DHCP ethernet works on the live ISO)
#   2. builds a minimal Linux VM initramfs (busybox + nvflash + the script)
#   3. binds the NVIDIA GPU to vfio-pci (no host driver on the live session)
#   4. boots the VM with the GPU passed through — the VM's kernel RESETS the
#      card to a clean state (no GOP, no firmware handoff state) — and runs
#      the flash session INSIDE the VM
#   5. the verdict, the console log and chip-before.rom land on the data drive
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
NVFLASH="$LAB/tools/nvflash-5.867/x64/nvflash-patched"
K4FLASH="$LAB/tools/nvflash-5.792-k4/nvflash-k4-vv"
ROM_BUILD="$LAB/acquisitions/MSI.RTX3070.8192.210519_1.rom"
ROM_MOD="$LAB/acquisitions/MSI.RTX3070.8192.210519_1-unlock-v2-REALCHIP-2200MHz-280W.rom"
OUT="$LAB/day0/vfio-flash-$(date +%Y%m%d-%H%M%S)"
GPU=0000:07:00.0
ROMSZ=999424   # 1952 sectors — the chip size, exact fit for the virtio return disk

[ "$(id -u)" = 0 ] || { echo "ERROR: root required"; exit 1; }
mountpoint -q /mnt || { echo "ERROR: mount the data drive first"; exit 1; }
[ -f "$ROM_MOD" ] || { echo "ERROR: modded ROM missing: $ROM_MOD"; exit 1; }
[ -f "$NVFLASH" ] || { echo "ERROR: nvflash missing: $NVFLASH"; exit 1; }
[ -f "$K4FLASH" ] || { echo "ERROR: k4 nvflash missing: $K4FLASH"; exit 1; }
mkdir -p "$OUT"
# every line from here on lands on the data drive too — the live console dies
# as soon as the GPU is unbound, so the disk is the only reliable record
exec > >(tee "$OUT/session.log") 2>&1

echo "=== VFIO flash session $(date -Is) ==="
echo "[1/6] kvm + qemu + cpio"
modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || modprobe kvm 2>/dev/null || true
[ -e /dev/kvm ] || { echo "ERROR: /dev/kvm absent even after modprobe — enable SVM (AMD) / VT-x (Intel) in the firmware, or this kernel has no KVM"; exit 1; }
mount -o remount,size=6G /run/archiso/cowspace 2>/dev/null || echo "  (cowspace remount skipped)"
pacman -Sy --noconfirm --needed qemu-system-x86 cpio efibootmgr strace >/tmp/vfio-pacman.log 2>&1 || { echo "pacman failed — see /tmp/vfio-pacman.log"; exit 1; }
echo "  ok"

echo "[2/6] building the minimal VM initramfs (busybox + nvflash)"
VMROOT=/tmp/vmroot; rm -rf "$VMROOT"; mkdir -p "$VMROOT/bin" "$VMROOT/proc" "$VMROOT/sys" "$VMROOT/dev"
BB=$(find /mnt -maxdepth 4 -name 'busybox*' -type f 2>/dev/null | head -1)
if [ -z "$BB" ]; then
  curl -sL -o /tmp/busybox "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" || { echo "busybox download failed"; exit 1; }
  BB=/tmp/busybox
fi
cp "$BB" "$VMROOT/bin/busybox" && chmod +x "$VMROOT/bin/busybox"
for app in sh mount cp ls echo sleep sync cat mdev dd wc grep tail head poweroff reboot lsmod; do ln -sf busybox "$VMROOT/bin/$app"; done
cp "$NVFLASH" "$VMROOT/nvflash" && chmod +x "$VMROOT/nvflash"
cp "$K4FLASH" "$VMROOT/nvflash-k4-vv" && chmod +x "$VMROOT/nvflash-k4-vv"
# nvflash is a DYNAMIC ELF — without its loader it fails with the misleading
# "/nvflash: not found" (the kernel cannot find the INTERPRETER, not the file)
mkdir -p "$VMROOT/lib64" "$VMROOT/usr/lib"
cp -L /lib64/ld-linux-x86-64.so.2 "$VMROOT/lib64/" 2>/dev/null || cp -L /usr/lib64/ld-linux-x86-64.so.2 "$VMROOT/lib64/" || { echo "ERROR: ELF loader not found on the live session"; exit 1; }
for lib in libdl.so.2 libm.so.6 libpthread.so.0 libc.so.6 libgcc_s.so.1; do
  cp -L "/usr/lib/$lib" "$VMROOT/usr/lib/" 2>/dev/null || echo "  (note: $lib absent — stub on this glibc)"
done
# prove it before building the archive: the version banner must print.
# NOTE: nvflash's EXIT CODE is useless here — it returns 2 when no NVIDIA
# adapter is visible (true in any chroot); the banner is the execution proof
CHROOTOUT=$(chroot "$VMROOT" /nvflash --version 2>&1 || true)
echo "$CHROOTOUT" | grep -q "Firmware Update Utility" || { echo "ERROR: nvflash did not execute in the chroot (no banner) — loader/libs problem:"; echo "$CHROOTOUT" | head -5; exit 1; }
echo "  nvflash executable check: OK ($(echo "$CHROOTOUT" | head -1 | tr -d '\r'))"
K4OUT=$(chroot "$VMROOT" /nvflash-k4-vv --version 2>&1 || true)
echo "$K4OUT" | grep -q "Firmware Update Utility" || { echo "ERROR: k4 nvflash did not execute in the chroot:"; echo "$K4OUT" | head -5; exit 1; }
echo "  k4 nvflash executable check: OK"
cat > "$VMROOT/init" <<'INITEOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo "=== VM flash session ==="
echo "[V0] staging unlock.rom from the virtio disk"
dd if=/dev/vda of=/unlock.rom 2>/dev/null
echo "  staged: $(wc -c </unlock.rom) bytes (expect 999424)"
[ "$(wc -c </unlock.rom)" = "999424" ] || { echo "VM FLASH FAILED (staging size mismatch)"; poweroff -f; }
echo "[V1] nvflash version"
/nvflash --version 2>&1 | head -4
echo "[V2] chip read (gate: the dump must succeed before any write)"
/nvflash --save /chip-before.rom
if [ -s /chip-before.rom ]; then
  dd if=/chip-before.rom of=/dev/vdb 2>/dev/null && sync
  echo "  chip-before.rom: $(wc -c </chip-before.rom) bytes -> returned to host"
else
  echo "  chip read FAILED — aborting before any write"
fi
[ -s /chip-before.rom ] || { echo "VM FLASH FAILED (chip read failed)"; poweroff -f; }
echo "[V3] TGP power policy: limitRated -> 280000 mW (reversible: --delpp TGP limitRated)"
setsid -c sh -c 'exec /nvflash --listpp </dev/console >/dev/console 2>&1'
setsid -c sh -c 'exec /nvflash-k4-vv --addpp TGP limitRated 280000 </dev/console >/dev/console 2>&1'
setsid -c sh -c 'exec /nvflash --listpp </dev/console >/dev/console 2>&1'
echo "VM POLICY UPDATE DONE (read the policy state above)"
[ -f /nvflash.log ] && dd if=/nvflash.log of=/dev/vdb seek=1952 2>/dev/null && sync
poweroff -f
INITEOF
chmod +x "$VMROOT/init"
# the pipeline's exit status lies when cpio is missing (gzip still returns 0),
# so the size gate below is the real check (empty cpio = ~20 bytes)
(cd "$VMROOT" && find . | cpio -o -H newc --quiet | gzip > /tmp/vm-initramfs.cpio.gz) || true
ISZ=$(stat -c%s /tmp/vm-initramfs.cpio.gz 2>/dev/null || echo 0)
[ "$ISZ" -lt 3000000 ] && { echo "ERROR: initramfs is only $ISZ bytes (cpio missing?) — aborting, GPU untouched"; exit 1; }
cp /tmp/vm-initramfs.cpio.gz "$OUT/"
cp "$ROM_BUILD" "$OUT/chip-build.rom" 2>/dev/null
cp "$ROM_MOD" "$OUT/unlock.rom"
truncate -s 3145728 "$OUT/chip-before.rom"   # VM writes the chip dump (999424 B) + the nvflash log after it
KERN=$(ls /run/archiso/airootfs/usr/lib/modules/*/vmlinuz 2>/dev/null | head -1 \
    || ls /mnt/arch/boot/x86_64/vmlinuz-linux 2>/dev/null \
    || find /mnt -maxdepth 5 -name 'vmlinuz*' 2>/dev/null | head -1)
[ -f "$KERN" ] || { echo "ERROR: guest kernel not found (airootfs nor USB)"; exit 1; }
echo "  ok (kernel: $KERN)"

echo "[3/6] binding the GPU group to vfio-pci"
modprobe vfio_pci
GRP=$(basename "$(readlink /sys/bus/pci/devices/$GPU/iommu_group)" 2>/dev/null || true)
bind_one() {
  d=$1
  [ -L /sys/bus/pci/devices/$d/driver ] && echo $d > /sys/bus/pci/devices/$d/driver/unbind 2>/dev/null || true
  # the override MUST be the driver name "vfio-pci" (dash) — "vfio_pci" never
  # matches and the bind fails silently, leaving the group non-viable
  echo vfio-pci > /sys/bus/pci/devices/$d/driver_override 2>/dev/null || true
  echo $d > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null
  cur=$(basename "$(readlink /sys/bus/pci/devices/$d/driver)" 2>/dev/null || echo "UNBOUND")
  echo "  $d -> $cur"
}
if [ -n "$GRP" ]; then
  echo "  IOMMU group $GRP members: $(ls /sys/kernel/iommu_groups/$GRP/devices/ 2>/dev/null | tr '\n' ' ')"
  echo "  >>> the screen goes BLACK from here (the live console runs on this card) —"
  echo "  >>> everything continues in $OUT/session.log and the machine reboots itself at the end"
  for dev in /sys/kernel/iommu_groups/$GRP/devices/*; do bind_one "$(basename "$dev")"; done
else
  echo "  no IOMMU group visible — enabling unsafe no-IOMMU vfio mode (fine for this dedicated flash session)"
  echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null || true
  bind_one "$GPU"
fi
# NO exit beyond this point: the console is already dead — any further problem
# must land in the logs, and [6/6] reboots back to safety
VFIONODE=""
for i in $(seq 1 20); do
  VFIONODE=$(find /dev/vfio -maxdepth 1 -type c -name '[0-9]*' 2>/dev/null | head -1)
  [ -e "$VFIONODE" ] && break
  sleep 0.5
done
if [ -e "$VFIONODE" ]; then echo "  vfio node ready: $VFIONODE"; else echo "  WARNING: no vfio node appeared — QEMU will report the precise reason in its log"; fi

echo "[4/6] launching the VM with the GPU passed through (6 min max per attempt)"
QARGS=(-m 2G -nographic
  -kernel "$KERN" -initrd /tmp/vm-initramfs.cpio.gz
  -append "console=ttyS0,115200n8 iomem=relaxed"
  -device vfio-pci,host=$GPU,rombar=0
  -drive file="$OUT/unlock.rom",if=virtio,format=raw,readonly=on
  -drive file="$OUT/chip-before.rom",if=virtio,format=raw
  -net none -D "$OUT/qemu.log")
echo "  attempt 1: KVM"
# </dev/null is THE fix: with a real tty on stdin, a background-pgrp process
# (timeout's child) gets SIGTTOU'd and suspended forever on its first
# tcsetattr — the VM never started in ALL previous runs because of this
( while sleep 2; do printf 'y\n'; done ) | timeout 360 qemu-system-x86_64 -enable-kvm "${QARGS[@]}" >"$OUT/vm-console.log" 2>&1
VMRC=$?
VMLOG="$OUT/vm-console.log"
if [ "$VMRC" = 124 ]; then
  echo "  KVM: no exit in 6 min — retry with TCG (no KVM) under strace (fallback + diagnostic)"
  ( while sleep 2; do printf 'y\n'; done ) | timeout 600 strace -f -tt -o "$OUT/qemu-strace.log" qemu-system-x86_64 -accel tcg "${QARGS[@]}" >"$OUT/vm-console-tcg.log" 2>&1
  VMRC=$?
  VMLOG="$OUT/vm-console-tcg.log"
fi
echo "VM exit: $VMRC"

dd if="$OUT/chip-before.rom" bs=512 skip=1952 2>/dev/null | tr -d '\0' > "$OUT/nvflash-guest.log"
echo "[5/6] verdict + console tail + guest nvflash log"
tail -20 "$VMLOG" 2>/dev/null
dmesg | tail -80 > "$OUT/host-dmesg.log" 2>/dev/null
Z=$(head -c 999424 /dev/zero | sha256sum | cut -c1-16)
C=$(sha256sum "$OUT/chip-before.rom" 2>/dev/null | cut -c1-16)
[ "$C" = "$Z" ] && echo "  (chip-before.rom is still all zeros — the guest never reached its flash stage)" || echo "  (chip-before.rom holds a REAL chip dump — the guest ran its session)"
echo
if grep -q "VM FLASH COMPLETE" "$OUT/vm-console.log" "$OUT/vm-console-tcg.log" 2>/dev/null; then
  echo "VERDICT: FLASH COMPLETE — reboot normally, then check 2200 MHz / 280 W in LACT (rollback: dual-BIOS switch pos 2)"
elif grep -q "VM FLASH FAILED" "$OUT/vm-console.log" "$OUT/vm-console-tcg.log" 2>/dev/null; then
  echo "VERDICT: FLASH FAILED — the exact nvflash error is in the tail above and in $VMLOG"
else
  echo "VERDICT: the VM did not reach the flash step — full console in $VMLOG"
fi
efibootmgr -N >/dev/null 2>&1 || true   # clear any pending BootNext: the post-flash reboot goes to Limine, not back here
echo "[6/6] done — logs + chip-before.rom saved on the data drive in $OUT"
echo "      verdict lines are in $OUT/session.log and $OUT/vm-console.log"
sync
sleep 3
echo "rebooting now — read the verdict on the data drive after Omarchy is back"
systemctl reboot -f 2>/dev/null || reboot -f
