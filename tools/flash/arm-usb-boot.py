#!/usr/bin/env python3
"""arm-usb-boot — set BootNext to the HWTruthUSB NVRAM entry (the key can
be plugged later — the NVRAM entry persists)."""
import subprocess, sys
r = subprocess.run(["efibootmgr"], capture_output=True, text=True)
entry = None
for line in r.stdout.splitlines():
    if "HWTruthUSB" in line and "*" in line:
        entry = line.split("Boot")[1].split("*")[0].strip()
        break
if not entry:
    print("ERROR: HWTruthUSB entry not found in NVRAM")
    sys.exit(1)
r = subprocess.run(["efibootmgr", "-b", entry, "-n", entry], capture_output=True, text=True)
print(r.stdout.strip())
verify = subprocess.run(["efibootmgr"], capture_output=True, text=True).stdout
for line in verify.splitlines():
    if "BootNext" in line:
        print(line.strip())
print(f"ARMED: BootNext={entry} — branche la clé avant le reboot")
