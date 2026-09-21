#!/usr/bin/env python3
"""patch-usb-entries — add iomem=relaxed to the Arch ISO's boot entries on
the USB key, so nvflash can map the GPU registers on the live session.
(The Arch ISO kernel lacks this flag; without it nvflash dies with
"system restart might be required" — ring 31 root cause.)
Usage: sudo -n python3 /home/cheurteen/hwlab-tools/patch-usb-entries.py
"""
import glob
import os
import subprocess
import sys

MNT = "/tmp/usb-esp"

if not os.path.ismount(MNT):
    os.makedirs(MNT, exist_ok=True)
    r = subprocess.run(["mount", "/dev/sdb2", MNT], capture_output=True, text=True)
    if r.returncode != 0:
        print("mount failed:", r.stderr.strip())
        sys.exit(1)

patched = []
for conf in sorted(glob.glob(MNT + "/loader/entries/*.conf")):
    text = open(conf).read()
    if "iomem=relaxed" in text:
        print(f"already patched: {conf}")
        continue
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("options "):
            lines[i] = line + " iomem=relaxed"
            patched.append(conf)
            break
    open(conf, "w").write("\n".join(lines) + "\n")

print("patched entries:")
for conf in patched:
    for line in open(conf).read().splitlines():
        if line.startswith("options "):
            print(f"  {conf}: {line}")
if not patched:
    print("nothing needed patching")
