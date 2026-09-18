#!/bin/bash
# usb-flash-session.sh — the complete mod session from the Arch live USB:
#   STEP B: read the REAL 976 KiB chip content (nvflash)
#   GATE  : verify the chip matches build 210519_1 byte-for-byte over the
#           first 512 KiB (the build the mod was derived from)
#   STEP C: flash the 280 W modded image on the card (--verify before AND
#           after) — with the dual-BIOS switch on SECONDARY as the net
#
# Run on the live session:
#   mount /dev/sda1 /mnt
#   bash /mnt/gpu-lab/tools/usb-flash-session.sh
#
# The flash targets the SAME card the build came from. Doctrine: verify
# everything, write once, verify again. The stock image stays on disk for
# instant rollback, and the primary BIOS is untouched by the switch.

set -u
M=/mnt
LAB="$M/Reverse Engenering/gpu-lab"
NV=$LAB/tools/nvflash-5.867/x64/nvflash
ROM_BUILD=$LAB/acquisitions/MSI.RTX3070.8192.210519_1.rom
ROM_MOD=$LAB/acquisitions/MSI.RTX3070.8192.210519_1-unlock-2200MHz-280W.rom
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$LAB/day0/flash-session-$STAMP

[ "$(id -u)" = 0 ] || { echo "ERROR: run as root (the live session is root)"; exit 1; }
mountpoint -q /mnt || { echo "ERROR: mount the data drive first: mount /dev/sda1 /mnt"; exit 1; }
[ -x "$NV" ] || { echo "ERROR: nvflash missing"; exit 1; }
[ -f "$ROM_MOD" ] || { echo "ERROR: modded ROM missing"; exit 1; }
if lsmod | grep -q '^nvidia'; then echo "ERROR: nvidia driver loaded?!"; exit 1; fi
mkdir -p "$OUT"

echo "=== flash session $(date -Is) ==="
echo "[0/6] shrinking the ReBAR aperture (nvflash 5.867 conflicts with 8GiB BAR1)"
GPUPCI=$(lspci -Dnn | grep -i 'nvidia' | grep -iE 'VGA|3D' | head -1 | cut -d' ' -f1)
[ -z "$GPUPCI" ] && { echo "ERROR: GPU not found on PCI"; exit 1; }
DEV=/sys/bus/pci/devices/$GPUPCI
echo "  GPU at $GPUPCI; BAR1 before: $(sed -n 2p $DEV/resource)"
if [ -f $DEV/resource_resize ]; then
  echo "1 256M" > $DEV/resource_resize 2>/dev/null || echo "1 268435456" > $DEV/resource_resize
  echo "  BAR1 after:  $(sed -n 2p $DEV/resource)"
else
  echo "  resource_resize unavailable — continuing (iommu=pt may suffice)"
fi
echo "[B/1] reading the REAL chip content (~999424 B expected)"
"$NV" --version 2>&1 | head -3 || true
"$NV" --save "$OUT/chip-full.rom" || { echo "ERROR: chip read failed"; exit 1; }
stat -c '  size: %s bytes' "$OUT/chip-full.rom"
sha256sum "$OUT/chip-full.rom" | tee "$OUT/chip-full.rom.sha256"

echo "[B/2] identity gate: chip vs build 210519_1 (first 512 KiB)"
if python3 - "$OUT/chip-full.rom" "$ROM_BUILD" <<'PY'
import sys, hashlib
chip = open(sys.argv[1], "rb").read()
build = open(sys.argv[2], "rb").read()
n = min(len(build), len(chip))
same = chip[:n] == build[:n]
print(f"  chip {len(chip):,} B vs build {len(build):,} B over {n:,} B prefix -> {'MATCH' if same else 'MISMATCH'}")
sys.exit(0 if same else 1)
PY
then
  echo "  identity confirmed — the mod was derived from THIS content"
else
  echo "  IDENTITY MISMATCH — the chip is not the build the mod was derived from."
  echo "  NOTHING was flashed. The full chip read is saved for analysis."
  exit 1
fi

echo "[C/1] verify the modded image against the card (no write yet)"
"$NV" --verify "$ROM_MOD" || { echo "VERIFY FAILED — nothing flashed"; exit 1; }
echo "[C/2] removing write protection"
"$NV" --protectoff || { echo "protectoff failed"; exit 1; }
echo "[C/3] FLASHING the 280 W modded image"
"$NV" --flash "$ROM_MOD" || { echo "FLASH FAILED — the dual-BIOS switch restores the primary"; exit 1; }
echo "[C/4] post-flash verification"
"$NV" --verify "$ROM_MOD" || { echo "post-flash verify FAILED — switch to the primary BIOS"; exit 1; }

echo "copy of the pre-flash chip read retained: $OUT/chip-full.rom"
echo "SESSION COMPLETE — reboot normally. On the secondary BIOS you are at 280 W."
echo "rollback at any time: flip the dual-BIOS switch back to the primary position."
