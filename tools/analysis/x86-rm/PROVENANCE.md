# PROVENANCE — `nv-kernel.o_binary` (the closed x86 host RM)

| field | value |
|---|---|
| file | `tools/analysis/x86-rm/binaries/nv-kernel.o_binary` |
| size | 19,233,368 bytes |
| sha256 | `48096db025a439328592250b1c79e7f27943b37b733583778407f3cf46bca251` |
| identity | ELF64 (class 2), little-endian (data 1), **ET_REL (type 1)**, **EM_X86_64 (machine 62)**, 13 sections, symtab present |
| source package | `NVIDIA-Linux-x86_64-610.57.04.run` (official NVIDIA download, us.download.nvidia.com) |
| package size | 463,025,450 bytes |
| package sha256 | `b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d` |
| in-package path | `kernel-open/nvidia/nv-kernel.o_binary` |
| extraction | makeself `--extract` of the official `.run` (no modification), file copied verbatim |
| acquisition date | 2026-09-22 (campaign pass 4.27 acquired the package; pass 4.28 landed this file) |

## Companion artifact — `libnvidia-ml.so.610.57.04`

| field | value |
|---|---|
| file | `tools/analysis/x86-rm/binaries/libnvidia-ml.so.610.57.04` |
| size | 2,654,168 bytes |
| sha256 | `50feda0f0d27…` (full value in `lab/jalon411/v428f_nvvm_sites.json`) |
| identity | ELF64, ET_DYN, x86-64, stripped |
| in-package path | `libnvidia-ml.so.610.57.04` |
| role | the 4.28 wave-3 decisive artifact: the ONLY binary of the package carrying the `0x2080d031` cmd (2 sites, each paired with the `0x608` params-size immediate) — the issuer of the captured RPC |
| note | `libnvidia-eglcore.so.610.57.04` (39,091,248 B, sha256 `afd79b7f…`) was needle-scanned but NOT committed (no decisive evidence; hash recorded in the register) |

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
