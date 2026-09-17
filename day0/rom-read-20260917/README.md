# gpu-lab/day0/rom-read-20260917 — the founder's chip, read whole

Date: 2026-09-17, during the nomodeset maintenance boot (but the read itself
worked with the NVIDIA driver loaded — the kernel PCI core serves the sysfs
ROM attribute independently of the driver).

- Method: `echo 1 > /sys/bus/pci/devices/0000:07:00.0/rom; cat rom`, twice.
- vbios-sysfs.rom / vbios-sysfs-2.rom: 157,696 bytes each,
  sha256 `135b215313fa4d1e…` — **byte-identical double read**.
- Chain parsed by the chip's own PCI structures:
  - image 0: x86 legacy, code type 0x00, 65,024 B at 0x0 (PCIR 0x170)
  - image 1: EFI, code type 0x03, 92,672 B at 0xFE00, indicator 0x80 (last)
  - total 157,696 B == file size → **complete ROM, self-consistent**
- PCIR: vendor 10de, device 2488 (RTX 3070 LHR), version string
  `94.04.46.00.EB` present.
- **The previously used reference `day0/vbios-94.04.46.00.EB.rom`
  (62,464 B) does NOT match the chip** — its 62,464-byte prefix differs from
  this dump despite the identical version string. It was partial AND not the
  board's build. All future decodes must use this chip dump.
- GPU health after the reads: P2, 37 °C, zero NVRM Xid in the journal.
