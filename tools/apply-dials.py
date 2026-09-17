#!/usr/bin/env python3
"""apply-dials — write the RM registry-dial test config and refresh initramfs.

Ring 31 protocol: ONE dial per reboot. The dial is appended to
/etc/modprobe.d/hwtruth-dials.conf (previous lines preserved, so a history
of tested dials accumulates visibly). mkinitcpio -P regenerates the
initramfs because the nvidia modules load from there.

Usage: sudo -n python3 /home/cheurteen/hwlab-tools/apply-dials.py <dial=value> [...]
"""
import subprocess
import sys
from pathlib import Path

CONF = Path("/etc/modprobe.d/hwtruth-dials.conf")
ALLOWED_PREFIXES = ("Rm", "RM")  # only RM registry keys, no NVreg overrides


def main():
    dials = sys.argv[1:]
    if not dials:
        print("usage: apply-dials.py RmSomeDial=1 [RmOtherDial=2 ...]")
        return 1
    for dial in dials:
        name, _, value = dial.partition("=")
        if not name.startswith(ALLOWED_PREFIXES) or not value:
            print(f"REFUSED: {dial!r} — only Rm*/RM* keys with an explicit value")
            return 1
    joined = ";".join(dials)
    # single-line semantics: the new invocation REPLACES previous dials
    new_line = f"options nvidia NVreg_RegistryDwords={joined}"
    lines = [new_line]
    CONF.write_text(
        "# hwtruth dial tests — one dial per reboot (ring 31 protocol)\n"
        + "\n".join(lines) + "\n"
    )
    print(f"written {CONF}:")
    print(CONF.read_text())
    print("regenerating initramfs (mkinitcpio -P)…")
    r = subprocess.run(["mkinitcpio", "-P"], capture_output=True, text=True)
    ok = all(f"-> preset '{p}': success" in r.stderr + r.stdout or "success" in (r.stderr + r.stdout) for p in ("linux-omarchy",)) or r.returncode == 0
    tail = (r.stderr + r.stdout).strip().splitlines()[-3:]
    for l in tail:
        print("  " + l)
    if r.returncode != 0:
        print("WARNING: mkinitcpio reported an error — check before rebooting")
        return 1
    print("OK — reboot to apply, then report back for verification")
    return 0


if __name__ == "__main__":
    sys.exit(main())
