#!/usr/bin/env python3
"""in-session-flash.py — flash the 280W mod WITHOUT any reboot.

The no-reboot pipeline, assembled from every ring lesson:
  ring 22: the console pin — solved AT RUNTIME by unbinding vtconsole
  ring 31: nvflash vs ReBAR — solved by shrinking BAR1 via sysfs
  ring 23: the chip identity — gate before any write
  ring 26: the mod itself — six bytes, verified twice

Detached by design: run with setsid+nohup. It kills the desktop (Zcode
included — by design), flashes, then restores the driver and the desktop.
Log: <lab>/day0/in-session-flash-log.txt
Verdict: <lab>/day0/in-session-flash-status.json
"""
import json
import subprocess
import sys
import time
from pathlib import Path

LAB = Path("/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab")
NV = "/usr/local/bin/nvflash"
BUILD = LAB / "acquisitions/MSI.RTX3070.8192.210519_1.rom"
MOD = LAB / "acquisitions/MSI.RTX3070.8192.210519_1-mod-280W.rom"
OUT = LAB / f"day0/in-session-{time.strftime('%Y%m%d-%H%M%S')}"
LOG = LAB / "day0/in-session-flash-log.txt"
STATUS = LAB / "day0/in-session-flash-status.json"
GPU_SYS = Path("/sys/bus/pci/devices/0000:07:00.0")
steps = {}


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def save_status():
    STATUS.write_text(json.dumps(steps, indent=1))


def sh(cmd, shell=False):
    r = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
    log(f"$ {' '.join(cmd) if isinstance(cmd, list) else cmd}\n{r.stdout.strip()}{r.stderr.strip()}"[:1500])
    return r.returncode


def restore_driver():
    log("RESTORE: reloading the driver and the desktop")
    try:
        sh("echo '1 8G' > " + str(GPU_SYS / "resource_resize"), shell=True)
    except Exception:
        pass
    sh(["modprobe", "nvidia_drm"])
    time.sleep(3)
    for vt in Path("/sys/class/vtconsole").glob("vtcon*"):
        try:
            sh(f"echo 1 > {vt}/bind", shell=True)
        except Exception:
            pass
    sh(["systemctl", "start", "lactd"])
    sh(["systemctl", "start", "coolercontrold"])
    sh(["systemctl", "start", "sddm"])
    steps["restored"] = True
    save_status()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    log(f"=== in-session flash — grace period 60 s (close your apps if you want) ===")
    time.sleep(60)
    try:
        # 1. release the framebuffer console (the ring-22 pin, at runtime)
        fbcon = None
        for vt in Path("/sys/class/vtconsole").glob("vtcon*"):
            name = (vt / "name").read_text()
            if "frame buffer device" in name:
                fbcon = vt
                sh(f"echo 0 > {vt}/bind", shell=True)
        log(f"console released: {fbcon}")
        steps["console_released"] = str(fbcon)

        # 2. stop the desktop stack
        for svc in ("sddm", "lactd", "coolercontrold"):
            sh(["systemctl", "stop", svc])
        time.sleep(3)
        steps["stack_stopped"] = True
        save_status()

        # 3. kill every GPU holder (Zcode dies here — by design, detached survives)
        sh("fuser -k -9 /dev/nvidia0 /dev/nvidiactl /dev/nvidia-modeset /dev/nvidia-uvm /dev/nvidia-uvm-tools 2>/dev/null", shell=True)
        time.sleep(3)

        # 4. unload the driver
        for i in range(15):
            rc = sh(["modprobe", "-r", "nvidia_drm", "nvidia_uvm", "nvidia_modeset", "nvidia"])
            loaded = subprocess.run("lsmod | grep -c '^nvidia'", shell=True, capture_output=True, text=True).stdout.strip()
            if loaded == "0":
                break
            time.sleep(2)
        loaded = subprocess.run("lsmod | grep -c '^nvidia'", shell=True, capture_output=True, text=True).stdout.strip()
        if loaded != "0":
            log("ERROR: driver still pinned — restoring, no flash attempted")
            steps["error"] = "driver pinned"
            restore_driver()
            return 1
        log("driver fully unloaded — the card is ours")
        steps["driver_unloaded"] = True
        save_status()

        # 5. shrink BAR1 (ReBAR conflicts with nvflash 5.867)
        sh(f"echo '1 256M' > {GPU_SYS}/resource_resize", shell=True)
        bar1 = (GPU_SYS / "resource").read_text().splitlines()[1]
        log(f"BAR1 now: {bar1}")
        steps["bar1"] = bar1
        save_status()

        # 6. read the real chip
        rc = sh([NV, "--save", str(OUT / "chip-before.rom")])
        chip = (OUT / "chip-before.rom").read_bytes() if rc == 0 else b""
        if rc != 0 or len(chip) < 900000:
            log("chip read failed — restoring, nothing flashed")
            steps["error"] = "chip read failed"
            restore_driver()
            return 1
        log(f"chip read: {len(chip):,} bytes")
        steps["chip_read_bytes"] = len(chip)
        save_status()

        # 7. identity gate (ring 23: chip[:512K] == build[0x9200:])
        build = BUILD.read_bytes()
        if chip[:524288] != build[0x9200:0x9200 + 524288]:
            log("IDENTITY MISMATCH — restoring, nothing flashed")
            steps["error"] = "identity mismatch"
            restore_driver()
            return 1
        log("identity confirmed: this chip is build 210519_1")
        steps["identity"] = True
        save_status()

        # 8. flash the mod (yes-piped for the confirmation prompts)
        sh("yes | " + NV + " --protectoff", shell=True)
        time.sleep(2)
        rc = sh("yes | " + NV + " --flash '" + str(MOD) + "'", shell=True)
        steps["flash_rc"] = rc
        save_status()
        if rc != 0:
            log("FLASH FAILED — restoring. The stock image may still be intact; verify at next boot.")
            restore_driver()
            return 1
        log("flash reported success")

        # 9. verify by re-reading the whole chip
        time.sleep(3)
        rc = sh([NV, "--save", str(OUT / "chip-after.rom")])
        if rc == 0:
            after = (OUT / "chip-after.rom").read_bytes()
            match = after == MOD.read_bytes()
            log(f"post-flash re-read: {len(after):,} B — byte-identical to the mod: {match}")
            steps["verified"] = match
        save_status()

        restore_driver()
        log("DONE — check nvidia-smi power limit for the 280 W verdict")
        steps["done"] = True
        save_status()
        return 0
    except Exception as e:
        log(f"EXCEPTION: {e}")
        steps["error"] = str(e)
        restore_driver()
        return 1


if __name__ == "__main__":
    sys.exit(main())
