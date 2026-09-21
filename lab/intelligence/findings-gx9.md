# findings-gx9 — the ninth ring: recon of the last territory (GSP-RM)

Scope: the installed GSP firmware (`/lib/firmware/nvidia/610.57.04/
gsp_ga10x.bin`, 84 310 168 B — the exact driver the founder's card runs),
a GitHub hunt for existing extraction tools, and the open driver's loader
source. Zero hardware interaction.

## What is measured

**The container.** `gsp_ga10x.bin` is an ELF64 for **RISC-V** (the GSP
processor's ISA), machine 0xF3, whose own symbol table is a 4-entry
`_binary__dvs_p4_...` stub — a `ld -b binary` wrapper. Inside it, **14
embedded ELF images** (`\x7fELF` at 0x6e040, 0x94040, … 0x19f040), the
nameplate strings naming them: `kernel_ga10x.elf`, `kernel_gh100.elf`,
`kernel_gb10x.elf` — one per chip family, the GA10x one being the ~16 MiB
image at 0x19f040.

**The plaintext layer is the libos microkernel.** Readable runs carry
source paths (`/gpu_drv/uproc/os/libos-v3.1.0/src/kernel/...`),
assertion strings (memorypool, objectpool, DMA, IPI, pagestate, the
scheduler ports) and the task machinery (RM partition, VGPU partition,
the in-firmware debugger: watchpoints, memory read, instruction read).
GSP-RM runs a microkernel with tasks, and its libos layer ships in
clear.

**The RM payload is packed.** Every target string — perf table, vP-state,
PowerCapping, topology, fan cooler, MemClock, bitEntry — has **zero
plaintext hits** across all 84 MB. The VBIOS-table parsers live in the
packed GSP-RM image, unreachable by strings.

**No public extractor.** The GitHub hunt (airlied/gsp-parse = a RPC
binding generator from the open headers, not an extractor; NVIDIA's
`extract-firmware-nouveau.py` = a copy/binhex tool; vmlinux-to-elf = a
compressed-kernel ELF rebuilder with no GSP support) yields no ready
tool. The LZ4-frame magic does not appear — the packing is the
bootloader's own scheme.

## The verdict

The route to the PERF v0x60 records and the vP-state v0x20 entries
through GSP-RM is a **decompression project of its own**: unpack the
packed RM task image (reverse the bootloader's scheme or lift it from
the open loader's expectations), then re-run this lab's string and
symbol hunts on the unpacked image. The groundwork is now on file: the
container layout, the embedded-ELF map, the libos layer identified, the
task architecture named. The sibling lab's ring-24 playbook (build what
cannot be downloaded) applies; the cmp170hx history shows such hunts
succeed with patience.

## Honesty ledger

- Proven: the container structure (ELF/RISC-V, 14 embedded images, the
  nameplate strings); the libos layer in clear; zero plaintext table
  names; no public extractor.
- Inferred: that the packed image contains the table parsers (their
  function is documented by the RPC architecture; their code is what is
  missing).
- Unknown: the packing scheme; whether the packed image is signed as a
  whole (the WPR boot path suggests yes); the libos version's lifetime
  across driver versions.
