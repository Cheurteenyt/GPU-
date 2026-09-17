# findings-gx24 — gsp.bin unpacked: the GSP's anatomy, mapped

Date: 2026-09-17. Subject: the last unexplored firmware layer of the GPU —
the GSP firmware package the driver loads into the card's RISC-V processor.

## The container, peeled

1. `/usr/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin` (84,310,882 B for our
   GA104) is an **ELF64** whose single real section `.fwimage`
   (84,258,816 B) is the actual firmware package. Extracted to
   `tools/gsp-extract/fwimage.bin`.
2. `.fwimage` layout:
   - `0x0-0x6d000`: **RISC-V bootloader**, raw code (jal/ret idioms), plus
     the **section directory** at 0x6d000-0x6e000: 13 named entries —
     `kernel_ga10x.elf`, `kernel_gh100.elf`, `kernel_gb10x.elf`,
     `kernel_gb10y.elf`, `kernel_gb20x.elf`, `kernel_gb20y.elf`,
     `kernel_gr10x.elf` (one GSP kernel per chip family), `debug.elf`,
     `init.elf`, `rm.elf`, `vgpu.elf`, `mnoc.elf`, `rm.bindata.bin`.
   - Twelve embedded ELF64 images found at 0x6e000-0x12d0270: the 7
     ~160 KiB kernels, a 41 KiB watchdog image (`handleWdtEvent` → PMU),
     a 725 KiB and a 58 KiB component, and the giant —
     **`rm.elf`, 17,236,632 B** (GSP-RM, the Resource Manager).
   - `0x12d0270` to end (64,531,856 B): **`rm.bindata.bin`**, entropy 8.00
     throughout, no gzip/zstd/xz/lz4 frames — compressed by the
     bootloader's proprietary algorithm.
3. Directory entries are signed-section descriptors: GSP carveout addresses
   (`0xffffffff92fff000`, `0xffffffffa3000000`), file offsets, sizes, type
   tags (5=code, 6=data), and signature/hash record offsets (e.g. 0x170,
   0x188, 0x1f8) — the firmware is authenticated per section.
4. **The SES question closed**: nvflash's "Access SPI Flash through SES
   target" cannot be re-read out of this package in the clear — only two
   byte-triples spelling SES exist in fwimage, both inside the compressed
   bindata (coincidences). The SPI engine code lives in the compressed RM
   bindata; reaching it means beating the bootloader's LZ first (ring 25).

## Honesty ledger

- Proven: the container layout above, every offset quoted, reproducible
  from `fwimage.bin`.
- Inferred: `rm.elf` = the 17,236,632-byte image (size and content class);
  per-entry name-to-image mapping needs the directory fields decoded
  properly (stride is not the naive 0x60 used here — it drifts, the parse
  must anchor on the name-offset field).
- Unknown: the bindata compression algorithm; the exact WPR address map.

## Productive next (ring 25)

- Anchor the directory parse on the name-offset field, extract `rm.elf`
  and `vgpu.elf` by table, then attack the bindata LZ (the bootloader at
  0x0-0x6d000 contains the decompressor — a bounded RISC-V RE target).
- Payoff: the SES/SPI engine code, the RM's power-policy tables, and the
  GSP-side logging strings — the last firmware layer between us and the
  metal.

## Addendum (same session): the directory record format, read

The directory is a chain of variable records anchored around 0x6d020
(`kernel_ga10x.elf` first). Each record: leading u64 offsets (0xb8, 0xd0,
0xe8, 0x158 — links within the directory region), then the inline name,
then N section descriptors:

    u64 VA (0xffffffff92fff000 — GSP carveout 1)
    u64 0
    u64 align (0x1000)
    u64 size (e.g. 0xd000 for kernel_ga10x code)
    u64 base/offset (0xd000)
    u64 type (5 = code, 6 = data)
    u64 sig/hash record offset
    … second descriptor with VA 0xffffffffa3000000 (carveout 2) …

So each kernel ships as TWO signed sections (code + data) with their own
carveout VAs and signature records — the firmware is per-section
authenticated. Remaining for ring 25: the absolute-base question (the
descriptor offsets are relative to a base the bootloader holds), then the
bindata LZ. `tools/gsp-extract/parse-gfw-directory.py` holds the first
attempt; the hexdump-anchored record walk above supersedes it.
