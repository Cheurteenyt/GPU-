# PROVENANCE — `nv-kernel.o_binary` (the closed x86 host RM)

| field | value |
|---|---|
| file | `tools/analysis/x86-rm/binaries/nv-kernel.o_binary` |
| size | 19,233,368 bytes |
| sha256 | `48096db025a439328592250b1c79e7f27943b37b733583778407f3cf46bca251` |
| identity | ELF64 (class 2), little-endian (data 1), **ET_REL (type 1)**, **EM_X86_64 (machine 62)**, 13 sections, symtab present |
| source package | `NVIDIA-Linux-x86_64-610.57.04.run` (official NVIDIA download, us.download.nvidia.com) |
| package size | 463,025,450 bytes |
| package sha256 | `b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d` (full value in the campaign acquisition register; the `.run` itself is not committed) |
| in-package path | `kernel-open/nvidia/nv-kernel.o_binary` |
| extraction | makeself `--extract` of the official `.run` (no modification), file copied verbatim |
| acquisition date | 2026-09-22 (campaign pass 4.27 acquired the package; pass 4.28 landed this file) |

## The pass-4.28 userspace extension substrates (same package, same law)

All extracted verbatim from the same verified package; package sha256
re-verified on the 4.28 downloads (waves 3 and 4, independently).

| file | size | sha256 | in-package path |
|---|---|---|---|
| `binaries/libnvidia-ml.so.610.57.04` | 2,654,168 | `50feda0f0d2712bd3b82d1c2f8c5083b9169607d5db481ebc278ec76582068a0` | `libnvidia-ml.so.610.57.04` |
| `binaries/libnvidia-eglcore.so.610.57.04` | 39,091,248 | `afd79b7f6e708cb2521aeb852d26d0768d694ae1394f0e213c61300f25bd3246` | `libnvidia-eglcore.so.610.57.04` |
| `binaries/nvidia_drv.so` | 3,627,376 | `28ae0bf0e4097c611d99e39cb3afc1eaaa6013019a3cc609a669042b0c69229c` | `nvidia_drv.so` |

- `libnvidia-ml.so` — the wave-3 decisive artifact (the issuer of the
  captured RPC: the only package binary carrying the `0x2080d031` cmd
  besides the GSP firmware images and the closed core's table row);
  wave 4 named its two sending functions (nvmlDeviceSetMClkVfOffset /
  nvmlDeviceSetGpcClkVfOffset).
- `nvidia_drv.so` — the wave-4 decisive artifact: the Xorg driver's twin
  of the same marshal, whose response-echo decode closed the naming.
- `libnvidia-eglcore.so` — needle-scanned (d031 = 0; 250000 x5 `.text`,
  240000 x4 `.rodata`, 100000 x6 — banked uninterpreted in the wave-4
  register); committed for scan reproducibility.

## The package's OTHER core (hash-documented, NOT committed — over the 100-MB limit)

`kernel/nvidia/nv-kernel.o_binary` — **120,980,872 bytes**, sha256
`c90f58d59e8fef44fa07d057bd9ffb1e1b5ee38d3c51b35df71e05e0ad268cbf`,
ELF64 ET_REL EM_X86_64 (the CLOSED driver's core — a different build from
the committed kernel-open one). It holds the host dispatch table in
`.rodata` (stride-0x20 rows {cmd, tag, 0, 0x44}; the 0x2080d031 row at
file 0x666b110). Reproduce from the same `.run`:
`sh NVIDIA-Linux-x86_64-610.57.04.run --extract-only` then
`sha256sum <target>/kernel/nvidia/nv-kernel.o_binary`.

## What this file is

`nv-kernel.o_binary` is NVIDIA's pre-linked closed-source x86-64 relocatable
object: the host-side Resource Manager core that the open kernel shim
(`kernel-open/nvidia/*.c`) links against to produce `nvidia.ko`. It is the
substrate the 4.25 x86-marshal pass (PR #10) declared **absent from the
repo** — the absence that held the five captured values of the 1544-B
`0x2080d031` params struct at HYPOTHESIS. This pass lands it (AGENTS.md law 1:
sha256 + provenance; the repo already commits analysis binaries of comparable
size — `tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin`).

It is a **read-only analysis artifact**: nothing here writes to a card
(law 2), nothing here mutates the running machine (law 3).

## Reproduction recipe

```bash
curl -O https://us.download.nvidia.com/XFree86/Linux-x86_64/610.57.04/NVIDIA-Linux-x86_64-610.57.04.run
sha256sum NVIDIA-Linux-x86_64-610.57.04.run        # verify against the acquisition register
sh NVIDIA-Linux-x86_64-610.57.04.run --extract-only
sha256sum extracted/kernel-open/nvidia/nv-kernel.o_binary   # must match the sha256 above
```

## The pass-4.30 extension: the GSP firmware files INSIDE the .run (byte-exact)

The two GSP firmware files of the package, located in the makeself
payload and re-extracted byte-exact (instrument:
`lab/jalon411/v430_run_provenance.py`, register:
`lab/jalon411/v430_run_provenance.json` — every number below is
re-derived by its selftest, exit 2 on drift):

| field | value |
|---|---|
| package | `NVIDIA-Linux-x86_64-610.57.04.run`, 463,025,450 B, sha256 `b2e935c6…eb116d` (re-verified streaming in-instrument) |
| packaging | makeself 1.6.0-nv9; header `skip=1022`; the wrapper's own extraction line (verbatim): `tail -n +$skip $0 \| zstd -d \| UnTAR` |
| payload start | **byte offset 160,635 (0x2737b)** — `tail -n +1022` starts at LINE 1022 (1-based); the zstd frame magic `28 b5 2f fd` is byte-checked there |
| payload end | EOF (one zstd stream to the end of the file) |
| decompressed | POSIX tar, 1,808,865,280 B, 1,189 members walked (name/size/mtime/mode/header-offset each) |
| honest framing | per-member plain offsets DO NOT exist in the .run coordinate (one zstd stream — compression rewrites everything after 0x2737b); the member offsets below are in the DECOMPRESSED-tar coordinate, which is byte-stable |

| in-tar member | size | sha256 | tar data offset (decompressed coordinate) |
|---|---|---|---|
| `./firmware/gsp_ga10x.bin` | 84,310,168 | `c0156954f3e048d56011524e0c2ae2881bb6db8173b53f9b2f4eb94197f02999` | 0x400 |
| `./firmware/gsp_tu10x.bin` | 29,381,504 | `d157e3b7dd5da2ca8d1ccb6ca98958f9e35d10a9ef7326277ebac133e4b0d1a7` | 0x5068000 |

Both re-extracted from the payload and compared byte-exact against the
makeself reference extraction (`--extract-only`) — sha256 equality on
both files (the same hashes findings-4.27 §1 banked). Reproduce:

```bash
sha256sum NVIDIA-Linux-x86_64-610.57.04.run   # b2e935c6…
python3 lab/jalon411/v430_run_provenance.py   # re-derives the table above in-situ
```
