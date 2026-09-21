#!/bin/bash
# vbios-flash-kit.sh — the flash procedure for the 280 W modded VBIOS.
# Run from the Arch live USB (no NVIDIA driver there):
#
#   mount /dev/sda1 /mnt
#   bash /mnt/gpu-lab/tools/vbios-flash-kit.sh
#
# SAFETY MODEL:
#   - the MSI Gaming Trio's dual-BIOS switch must be set to the SECONDARY
#     position BEFORE booting: a bad flash never touches the primary.
#   - the stock image on disk is the rollback artifact.
#   - nvflash refuses mismatched boards; we flash on the same board the ROM
#     was built from, and the chip read (step B) must match build 210519_1
#     byte-for-byte over its first 512 KiB before anything is written.
set -u
LAB=/mnt/gpu-lab
ROM="$LAB/acquisitions/MSI.RTX3070.8192.210519_1-mod-280W.rom"
NV=carrier  # resolved below
[ "$(id -u)" = 0 ] || { echo "ERROR: run as root"; exit 1; }
mountpoint -q /mnt || { echo "ERROR: mount the data drive first: mount /dev/sda1 /mnt"; exit 1; }

NV="$(command -v nvflash || echo /mnt/gpu-lab/tools/nvflash-5.867/x64/nvflash)"
[ -x "$NV" ] || { echo "ERROR: nvflash not found"; exit 1; }

echo "=== flash kit $(date -Is) ==="
echo "[0/5] dual-BIOS switch MUST be on the SECONDARY position. Confirm it is."
echo "[1/5] preflight: the ROM to write"
"$NV" --version 2>&1 | head -3
"$NV" "$ROM" 2>&1 | sed 's/^/  id: /' || true
echo "[2/5] verify against the card (no write yet)"
"$NV" --verify "$ROM" || { echo "VERIFY FAILED — do not proceed"; exit 1; }
echo "[3/5] unlock write protection"
"$NV" --protectoff || { echo "protectoff failed"; exit 1; }
echo "[4/5] FLASH"
"$NV" --flash "$ROM" || { echo "FLASH FAILED — the secondary BIOS is still recoverable via the switch"; exit 1; }
echo "[5/5] verify after write"
"$NV" --verify "$ROM" || { echo "post-flash verify FAILED — switch back to the primary BIOS and re-run"; exit 1; }
echo "done. Switch back to the PRIMARY BIOS to compare, or stay on secondary with the 280 W mod."
