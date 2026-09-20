#!/usr/bin/env python3
"""cert20-verify.py — the post-boot PLM verification (read-only).

After the patched-driver module load (the ROP fires during the GSP boot),
read the FEAT PLM register and the SEC2 state. Read-only, safe anytime.

    sudo python3 cert20-verify.py
"""
import os, struct, sys

PCI_FULL = "0000:07:00.0"
RESOURCE0 = f"/sys/bus/pci/devices/{PCI_FULL}/resource0"
PLM_FEAT = 0x00823804

SEC2_REGS = {
    0x008403c0: "ENGINE",
    0x00840804: "MAILBOX0",
    0x00840808: "MAILBOX1",
    0x0084080c: "MAILBOX2",
    0x00840810: "MAILBOX3",
    0x00840814: "MAILBOX4",
}


def rd32(fd, off):
    return struct.unpack("<I", os.pread(fd, 4, off))[0]


def main():
    fd = os.open(RESOURCE0, os.O_RDWR | os.O_SYNC)
    plm = rd32(fd, PLM_FEAT)
    print(f"PLM FEAT @0x{PLM_FEAT:08x} = 0x{plm:08x}")
    if plm & 0x70 == 0x70:
        print(">>> bits 4-6 SET — the PLM is OPEN (the ROP executed!) <<<")
        print(">>> next: the power-limit register hunt in the FEAT_OVR space <<<")
    else:
        print(f">>> bits 4-6 clear — the PLM state = the locked baseline (0x...8f) <<<")
    print("--- the SEC2 state ---")
    for off, name in sorted(SEC2_REGS.items()):
        print(f"  {name:10s} @0x{off:08x} = 0x{rd32(fd, off):08x}")
    os.close(fd)


if __name__ == "__main__":
    main()
