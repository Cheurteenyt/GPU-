// pillarB.cu — the Pillar B battery, the 0xSero method (pass 4.50).
//
// The reference: 555/608 GB/s = 91.3% of the ceiling by STREAM-class
// kernels. This battery measures AND CHASES that % on the RTX 3070
// (448 GB/s theoretical stock; CEILING env overrides).
//
// Modes (argv[1]):
//   copy|read|write      the plain float4 kernels (grid-stride, unroll 8)
//   copy-cs|read-cs      the streaming-hint variants (__ldcs/__stcs,
//                        evict-first — the D2D L2-thrash fix)
//   ce                   the copy-engine path (cudaMemcpy D2D)
//   overlap              the CE + SM overlap on separate streams
//   persist <bytes>      the L2-resident read loop with a persisting
//                        accessPolicyWindow (the M3 lane — the honest
//                        "600+" for footprints that fit ~4 MB L2)
//
// Output: one JSON line per run:
//   {"mode":..., "gbs":..., "pct_ceiling":..., "bytes":..., "ms":...}
//
// Build: nvcc -O3 -arch=sm_86 -o pillarB pillarB.cu
// (the driver pillarB-driver.sh probes the arch from nvidia-smi)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cuda_runtime.h>

static double CEILING = 448.0;   // GB/s, overridden by $CEILING

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "CUDA error %s @%d: %s\n", #x, __LINE__, \
            cudaGetErrorString(e_)); exit(1); } } while (0)

__global__ void k_copy(const float4 *__restrict__ src,
                       float4 *__restrict__ dst, size_t n4) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    const size_t stride = gridDim.x * (size_t)blockDim.x;
    for (; i < n4; i += stride) {
        float4 a = src[i], b = src[i + stride / 2 < n4 ? i + stride / 2 : i];
        float4 c = src[i + stride < n4 ? i + stride : i];
        dst[i] = make_float4(a.x + b.x + c.x, a.y, a.z, a.w); // keep 3 loads
    }
}

__global__ void k_copy_cs(const float4 *__restrict__ src,
                          float4 *__restrict__ dst, size_t n4) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    const size_t stride = gridDim.x * (size_t)blockDim.x;
    for (; i < n4; i += stride) {
        float4 a = __ldcs(&src[i]);
        float4 b = __ldcs(&src[i + stride / 2 < n4 ? i + stride / 2 : i]);
        float4 c = __ldcs(&src[i + stride < n4 ? i + stride : i]);
        __stcs(&dst[i], make_float4(a.x + b.x + c.x, a.y, a.z, a.w));
    }
}

__global__ void k_read(const float4 *__restrict__ src, float *__restrict__ sink,
                       size_t n4) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    const size_t stride = gridDim.x * (size_t)blockDim.x;
    float acc = 0.f;
    for (; i < n4; i += stride) {
        float4 a = src[i], b = src[i + stride / 2 < n4 ? i + stride / 2 : i];
        acc += a.x + a.y + a.z + a.w + b.x + b.y + b.z + b.w;
    }
    if (acc == 1234.5678f) *sink = acc;   // never true; defeats DCE
}

__global__ void k_read_cs(const float4 *__restrict__ src,
                          float *__restrict__ sink, size_t n4) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    const size_t stride = gridDim.x * (size_t)blockDim.x;
    float acc = 0.f;
    for (; i < n4; i += stride) {
        float4 a = __ldcs(&src[i]);
        float4 b = __ldcs(&src[i + stride / 2 < n4 ? i + stride / 2 : i]);
        acc += a.x + a.y + a.z + a.w + b.x + b.y + b.z + b.w;
    }
    if (acc == 1234.5678f) *sink = acc;
}

__global__ void k_write(float4 *__restrict__ dst, size_t n4) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    const size_t stride = gridDim.x * (size_t)blockDim.x;
    const float4 v = make_float4(1.f, 2.f, 3.f, 4.f);
    for (; i < n4; i += stride) dst[i] = v;
}

__global__ void k_write_cs(float4 *__restrict__ dst, size_t n4) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    const size_t stride = gridDim.x * (size_t)blockDim.x;
    const float4 v = make_float4(1.f, 2.f, 3.f, 4.f);
    for (; i < n4; i += stride) __stcs(&dst[i], v);
}

__global__ void k_read_persist(const float4 *__restrict__ src,
                               float *__restrict__ sink, size_t n4) {
    // the L2-resident read loop: same kernel as k_read (the persisting
    // policy comes from the accessPolicyWindow, not the kernel)
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    const size_t stride = gridDim.x * (size_t)blockDim.x;
    float acc = 0.f;
    for (; i < n4; i += stride) {
        float4 a = src[i];
        acc += a.x + a.y + a.z + a.w;
    }
    if (acc == 1234.5678f) *sink = acc;
}

static void report(const char *mode, double bytes, float ms) {
    double gbs = bytes / (ms / 1000.0) / 1e9;
    printf("{\"mode\":\"%s\",\"gbs\":%.1f,\"pct_ceiling\":%.1f,"
           "\"bytes\":%.0f,\"ms\":%.2f}\n",
           mode, gbs, 100.0 * gbs / CEILING, bytes, ms);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: pillarB <mode> [persist_bytes]\n"); return 2; }
    const char *env = getenv("CEILING");
    if (env) CEILING = atof(env);
    const char *mode = argv[1];
    int dev = 0;
    CK(cudaSetDevice(dev));
    cudaDeviceProp prop;
    CK(cudaGetDeviceProperties(&prop, dev));
    int sms = prop.multiProcessorCount;
    size_t bytes = (argc > 2 && !strcmp(mode, "persist"))
                       ? (size_t)atoll(argv[2])
                       : (size_t)2 * 1024 * 1024 * 1024;  // 2 GiB
    size_t n4 = bytes / sizeof(float4);
    float4 *src, *dst;
    CK(cudaMalloc(&src, bytes));
    CK(cudaMalloc(&dst, bytes));
    CK(cudaMemset(src, 1, bytes));
    float *sink;
    CK(cudaMalloc(&sink, 4));
    int threads = 256;
    // ~4 waves of blocks; the grid-stride loop handles the rest
    int blocks = sms * 8;
    cudaEvent_t t0, t1;
    CK(cudaEventCreate(&t0));
    CK(cudaEventCreate(&t1));
    const int REPS = 3;
    float best = -1.f;

    if (!strcmp(mode, "copy") || !strcmp(mode, "copy-cs")) {
        int cs = !strcmp(mode, "copy-cs");
        for (int r = 0; r < REPS; r++) {
            CK(cudaEventRecord(t0));
            if (cs) k_copy_cs<<<blocks, threads>>>(src, dst, n4);
            else k_copy<<<blocks, threads>>>(src, dst, n4);
            CK(cudaEventRecord(t1));
            CK(cudaEventSynchronize(t1));
            float ms; CK(cudaEventElapsedTime(&ms, t0, t1));
            if (best < 0 || ms < best) best = ms;
        }
        // D2D copy traffic = 2x bytes (read + write)
        report(mode, 2.0 * (double)bytes, best);
    } else if (!strcmp(mode, "read") || !strcmp(mode, "read-cs")) {
        int cs = !strcmp(mode, "read-cs");
        for (int r = 0; r < REPS; r++) {
            CK(cudaEventRecord(t0));
            if (cs) k_read_cs<<<blocks, threads>>>(src, sink, n4);
            else k_read<<<blocks, threads>>>(src, sink, n4);
            CK(cudaEventRecord(t1));
            CK(cudaEventSynchronize(t1));
            float ms; CK(cudaEventElapsedTime(&ms, t0, t1));
            if (best < 0 || ms < best) best = ms;
        }
        report(mode, (double)bytes, best);
    } else if (!strcmp(mode, "write") || !strcmp(mode, "write-cs")) {
        int cs = !strcmp(mode, "write-cs");
        for (int r = 0; r < REPS; r++) {
            CK(cudaEventRecord(t0));
            if (cs) k_write_cs<<<blocks, threads>>>(dst, n4);
            else k_write<<<blocks, threads>>>(dst, n4);
            CK(cudaEventRecord(t1));
            CK(cudaEventSynchronize(t1));
            float ms; CK(cudaEventElapsedTime(&ms, t0, t1));
            if (best < 0 || ms < best) best = ms;
        }
        report(mode, (double)bytes, best);
    } else if (!strcmp(mode, "ce")) {
        for (int r = 0; r < REPS; r++) {
            CK(cudaEventRecord(t0));
            CK(cudaMemcpy(dst, src, bytes, cudaMemcpyDeviceToDevice));
            CK(cudaEventRecord(t1));
            CK(cudaEventSynchronize(t1));
            float ms; CK(cudaEventElapsedTime(&ms, t0, t1));
            if (best < 0 || ms < best) best = ms;
        }
        report(mode, 2.0 * (double)bytes, best);
    } else if (!strcmp(mode, "overlap")) {
        // 2 CE copies + 1 SM kernel on 3 streams, N rounds
        cudaStream_t s1, s2, s3;
        CK(cudaStreamCreate(&s1)); CK(cudaStreamCreate(&s2));
        CK(cudaStreamCreate(&s3));
        size_t chunk = bytes / 8;
        CK(cudaEventRecord(t0));
        for (int r = 0; r < 4; r++) {
            CK(cudaMemcpyAsync(dst, src, chunk, cudaMemcpyDeviceToDevice, s1));
            CK(cudaMemcpyAsync((char *)dst + bytes - chunk,
                               (char *)src + bytes - chunk, chunk,
                               cudaMemcpyDeviceToDevice, s2));
            k_read<<<blocks, threads, 0, s3>>>(src, sink, n4 / 2);
        }
        CK(cudaEventRecord(t1));
        CK(cudaGetLastError());
        CK(cudaEventSynchronize(t1));
        float ms; CK(cudaEventElapsedTime(&ms, t0, t1));
        // traffic: 2 CE copies x chunk x 2(R+W) x 4 rounds + SM read bytes/2
        double traffic = 2.0 * (double)chunk * 2.0 * 4.0
                       + 0.5 * (double)bytes;
        report(mode, traffic, ms);
        CK(cudaStreamDestroy(s1)); CK(cudaStreamDestroy(s2));
        CK(cudaStreamDestroy(s3));
    } else if (!strcmp(mode, "persist")) {
        // the M3 lane: a persisting window over the WHOLE buffer, then
        // repeated read passes — the L2 hits dominate once resident
        size_t win = bytes;   // the caller sizes the footprint
        if (win > (size_t)prop.l2CacheSize) win = prop.l2CacheSize;
        cudaStreamAttrValue attr = {};
        attr.accessPolicyWindow.base_ptr = src;
        attr.accessPolicyWindow.num_bytes = win;
        attr.accessPolicyWindow.hitRatio = 1.0f;
        attr.accessPolicyWindow.hitProp = cudaAccessPropertyPersisting;
        attr.accessPolicyWindow.missProp = cudaAccessPropertyStreaming;
        CK(cudaStreamSetAttribute(0, cudaStreamAttributeAccessPolicyWindow,
                                  &attr));
        size_t n4w = win / sizeof(float4);
        // warm pass (the residency fill), then measure 5 passes
        k_read_persist<<<blocks, threads>>>(src, sink, n4w);
        CK(cudaDeviceSynchronize());
        CK(cudaEventRecord(t0));
        for (int r = 0; r < 5; r++)
            k_read_persist<<<blocks, threads>>>(src, sink, n4w);
        CK(cudaEventRecord(t1));
        CK(cudaGetLastError());
        CK(cudaEventSynchronize(t1));
        float ms; CK(cudaEventElapsedTime(&ms, t0, t1));
        report("persist", 5.0 * (double)win, ms);
        // the reset (the persisting lines must not leak into other runs)
        CK(cudaCtxResetPersistingL2Cache());
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    return 0;
}
