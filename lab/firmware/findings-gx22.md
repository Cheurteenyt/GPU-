# findings-gx22 — the in-session full-read closure: every seal, measured

Date: 2026-09-17. Subject: the founder asked for an ingenious no-reboot route
to the full 976 KiB image. Every in-session route was tried and is now closed
with measurements; the negative space is mapped as carefully as the positive.

## Seals proven this ring

1. **sysfs `rom`**: the kernel caps the attribute at the PCI image-chain
   length (157,696 B here) — `pci_get_rom_size` walks PCIR and stops at the
   last image. Not a bug; a design decision upstream.
2. **ROM BAR window**: hardware decodes exactly 512 KiB (0xFC000000-0xFC07FFFF,
   audio function immediately after). The 512 KiB read through /dev/mem is
   byte-identical to the sysfs dump — two paths, same truth.
3. **SPI aliasing**: rejected. The 999,424-byte TPU dumps show ~3 % self-
   similarity at period 0x80000 (noise level) and the fan-policy header does
   not appear at aliased offsets. The upper half of the chip is unique data.
4. **BAR1 (VRAM aperture) scan**: blocked while the driver is bound — sysfs
   `resource1` pread → EIO at every offset, mmap → EPERM (flaky once, stable
   when re-probed). The driver's exclusive claim wins over iomem=relaxed for
   PCI mmap in practice.
5. **System RAM scan** (GSP/RM could cache the image in a sysmem heap):
   /dev/mem pread of any System RAM range → EPERM. STRICT_DEVMEM beats
   `iomem=relaxed` for RAM on this kernel; only Reserved/MMIO ranges read.
6. **nvflash with driver loaded**: hard refusal; its own hint names the
   module list (`rmmod i2c_nvidia_gpu nvidia_drm nvidia_uvm nvidia_modeset
   nvidia`) and its strings show the real access path — "Access SPI Flash
   through SES target" plus AP0 SPI size/protect registers — a dedicated
   engine, not the ROM BAR. Reversing and replaying that MMIO under the live
   driver is the only remaining in-session idea, and it risks the running
   session for a read.
7. **nvflashk** (community fork): Windows-oriented, certificate-bypass only;
   no Linux driver-check relaxation. RM SDK headers (open-gpu-kernel-modules
   ctrl2080bios.h): metadata commands only, no image-read control.

## Also proven (boot side)

8. The proprietary driver **ignores `nomodeset`**: with the maintenance boot
   active, /proc/fb still showed `nvidia-drmdrmfb` — the driver's fbdev held
   the console and the unload failed with a kernel-side refcount (the ring-13
   wall, reproduced). Fix applied to the maintenance entry:
   `nvidia_drm.modeset=0 nvidia_drm.fbdev=0` (backup limine.conf.bak-gx21).
9. The v4 detached flow (systemd-run) works mechanically: log to /root,
   stop stack, unload attempt, verify, restore-and-restart — it failed only
   at the unload step, which item 8 fixes. Note: the data drive is NOT
   visible to system units (session mount namespace) — scripts must live on
   the root fs; /root is the right artifact home.

## Verdict

In-session full read: closed, with receipts. One reboot into the fixed
maintenance entry runs `gpu-rom-full-tty.sh` (romfull3) and delivers the
full image to /root; the same reboot also re-trains the display link from
POST, which the founder's current black-screen symptom wants anyway.

## Unknown / next (gx23)

- Execute the fixed maintenance flow; verify the tail tables
  (power_budget @551240 `30 2c …`, fan_cooler @554029 `10 06 1a 02`,
  fan_policy @554087 `20 04 33 08`, vP-state headers) directly in the
  pulled image; then decode and cross with the live machine.
