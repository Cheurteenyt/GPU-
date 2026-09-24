#!/usr/bin/env python3
"""pillarB-sysmem.py — PASS 4.51 TÂCHE C — the sysmem-side battery.

The judge for the RML2MaxWaysSysmem A/B (the 4.49 store: u32 ->
config+0x3D84, consumed @0x1318d4a -> L2 partition reg 0x2AC ways<<8;
value domain {0} U {7}; 0 = the sysmem ways released, 7 = the default).

THE PHYSICS (named before the first run):
  - the GPU reading SYSMEM (host RAM) traffic goes over PCIe
    (~25-32 GB/s raw on PCIe4 x16) — never the 448 GB/s DRAM ceiling;
  - BUT the reads still pass through the L2: with sysmem ways >= 1, a
    REPEATED read of the same small pinned buffer can be served from
    the L2 (the warm case) — measured speed can EXCEED PCIe massively;
    with ways = 0 every read re-crosses PCIe (the cold case always);
  - THE VERDICT = the warm:cold ratio of the device-side sysmem read
    (ratio ~1 = ways released; ratio >> 1 = sysmem caching live), plus
    the device-warm control (the same kernel on a device buffer = the
    L2 reference — the 1004 GB/s @4 MB night number, banked).

The battery (all medians of 3, the 4.47 §1 discipline):
  device_warm_gbs   the kernel on a 2 MiB DEVICE buffer, 200 launches
                    (the L2-resident reference — always cacheable)
  sysmem_warm_gbs   the kernel on a 2 MiB PINNED buffer, 200 launches
                    (UVA: the device dereferences the host pointer —
                    cacheable ONLY if the sysmem ways serve it)
  sysmem_cold_gbs   the kernel rotating over 1.25 GiB of pinned slices,
                    20 launches (every read re-crosses PCIe)
  h2d_gbs / d2h_gbs the pinned copy paths (torch), 2 GiB
  d2d_gbs           the device copy control (the 448-scale battery)

FALLBACK (honest): the inline CUDA extension needs nvcc (the pillarB.cu
precedent). If the build fails, the battery emits the copy paths only +
"kernel_read": "INDECIDABLE" — the A/B stays decidable on the copies
(the DMA traffic surface) but the CACHE verdict needs the kernel.

The run-pair protocol (runbook-451 §5-§6): run x2 per boot state
(ways=0 boot C, the revert boot D); the card rule: a delta beyond the
run-to-run noise + zero Xid + the named mechanism, or NO-EFFECT/UNPROVEN.
"""
import json
import statistics
import sys
import time

CEILING_NOTE = ("sysmem reads are PCIe-bound (~25-32 GB/s raw on PCIe4 x16); "
                "the device-warm row is the L2 reference (~1000 GB/s @4 MB, "
                "the banked night); the warm:cold ratio = the ways verdict")

KERNEL_SRC = r"""
#include <torch/extension.h>
#include <cuda_runtime.h>

__global__ void bw_read_kernel(const float* __restrict__ p, float* __restrict__ out, size_t n)
{
    size_t i = (size_t)threadIdx.x + (size_t)blockIdx.x * blockDim.x;
    const size_t stride = (size_t)gridDim.x * blockDim.x;
    float s = 0.f;
    for (; i < n; i += stride) s += p[i];
    size_t o = (size_t)threadIdx.x + (size_t)blockIdx.x * blockDim.x;
    if (o < stride) out[o] = s;   // one float per thread, no atomics
}

static float* g_out = nullptr;
static size_t g_out_n = 0;

void bw_read(int64_t ptr, int64_t n_floats, int64_t grid, int64_t block, at::Tensor out)
{
    const float* p = reinterpret_cast<const float*>(ptr);
    bw_read_kernel<<<(int)grid, (int)block>>>(p, out.data_ptr<float>(), (size_t)n_floats);
}
"""


def _timed(fn, reps=3):
    out = []
    for _ in range(reps):
        torch.cuda.synchronize()
        t0 = time.perf_counter()
        fn()
        torch.cuda.synchronize()
        out.append(time.perf_counter() - t0)
    return statistics.median(out)


def main():
    try:
        import torch
    except ImportError:
        print(json.dumps({"harness": "NONE",
                          "note": "no torch — INDECIDABLE (install torch)"}))
        return 2

    res = {"pass": "4.51", "harness": "torch+inline-cuda", "ceiling_note": CEILING_NOTE}
    dev = "cuda:0"
    torch.cuda.init()

    GIB = 1024 ** 3
    F2B = 4

    # ---- the copy controls (always available) ----
    n = 2 * GIB // F2B
    x = torch.randn(n, device=dev)
    y = torch.empty_like(x)
    xp = x.cpu().pin_memory()
    yp = torch.empty_like(xp)
    BYTES = 2 * GIB
    t = _timed(lambda: y.copy_(x));            res["d2d_gbs"] = round(BYTES / t / 1e9, 1)
    t = _timed(lambda: yp.copy_(xp, non_blocking=True)); res["h2d_gbs"] = round(BYTES / t / 1e9, 1)
    t = _timed(lambda: xp.copy_(yp, non_blocking=True)); res["d2h_gbs"] = round(BYTES / t / 1e9, 1)

    # ---- the kernel-read battery (the cache verdict) ----
    try:
        from torch.utils.cpp_extension import load_inline
        mod = load_inline(
            name="pillarB_sysmem_451",
            cpp_sources="void bw_read(int64_t,int64_t,int64_t,int64_t,at::Tensor);",
            cuda_sources=KERNEL_SRC,
            functions=["bw_read"], verbose=False)
        GRID, BLOCK = 1024, 256
        out = torch.zeros(GRID * BLOCK, device=dev, dtype=torch.float32)

        def launch(ptr, nf):
            mod.bw_read(ptr, nf, GRID, BLOCK, out)

        # device-warm: 2 MiB device buffer, 200 launches (the L2 reference)
        n_dev = (2 << 20) // F2B
        xdev = torch.randn(n_dev, device=dev)
        torch.cuda.synchronize(); t0 = time.perf_counter()
        for _ in range(200):
            launch(xdev.data_ptr(), n_dev)
        torch.cuda.synchronize()
        res["device_warm_gbs"] = round(200 * (2 << 20) / (time.perf_counter() - t0) / 1e9, 1)

        # sysmem-warm: the same on a 2 MiB pinned buffer (UVA direct deref)
        warm = torch.zeros(n_dev, dtype=torch.float32).pin_memory()
        torch.cuda.synchronize(); t0 = time.perf_counter()
        for _ in range(200):
            launch(warm.data_ptr(), n_dev)
        torch.cuda.synchronize()
        res["sysmem_warm_gbs"] = round(200 * (2 << 20) / (time.perf_counter() - t0) / 1e9, 1)

        # sysmem-cold: rotate over 1.25 GiB of pinned slices, 20 launches
        big = torch.zeros(1250 * (1 << 20) // F2B, dtype=torch.float32).pin_memory()
        slice_n = (64 << 20) // F2B
        stride = slice_n
        torch.cuda.synchronize(); t0 = time.perf_counter()
        for i in range(20):
            off = (i * stride) % (big.numel() - slice_n)
            launch(big.data_ptr() + off * F2B, slice_n)
        torch.cuda.synchronize()
        res["sysmem_cold_gbs"] = round(20 * (64 << 20) / (time.perf_counter() - t0) / 1e9, 1)

        cw = res["sysmem_cold_gbs"]
        res["ways_verdict_ratio"] = round(res["sysmem_warm_gbs"] / cw, 2) if cw else None
        res["kernel_read"] = "MEASURED"
        res["verdict_rule"] = ("ratio ~1 = the sysmem ways serve nothing (released); "
                               "ratio >> 1 (approaching device_warm) = sysmem caching live; "
                               "compare boot C (ways=0) vs boot D (default) — the A/B decides")
    except Exception as e:  # noqa: BLE001 — the honest fallback
        res["kernel_read"] = "INDECIDABLE"
        res["kernel_error"] = str(e)[:200]
        res["note"] = ("the copy paths still A/B (the DMA surface); the CACHE "
                       "verdict needs the kernel — fix nvcc/extension and re-run")

    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
