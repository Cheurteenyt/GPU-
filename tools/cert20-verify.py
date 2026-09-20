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
    def safe_rd(off):
        try:
            return f"0x{rd32(fd, off):08x}"
        except OSError as e:
            return f"DENIED (errno {e.errno})"
    plm = safe_rd(PLM_FEAT)
    print(f"PLM FEAT @0x{PLM_FEAT:08x} = {plm}")
    if "DENIED" in plm:
        print(">>> READ-DENIED: the register protection is ACTIVE — consistent")
        print(">>> with the ROP having written and the PLM having re-locked <<<")
    elif "0xffffff8f" in plm:
        print(">>> the locked baseline — the ROP did not reach the write <<<")
    print("--- the SEC2 state (the DENIED entries = the protected registers) ---")
    for off, name in sorted(SEC2_REGS.items()):
        print(f"  {name:10s} @0x{off:08x} = {safe_rd(off)}")
    os.close(fd)


if __name__ == "__main__":
    main()
