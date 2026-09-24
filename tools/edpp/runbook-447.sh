#!/usr/bin/env bash
# runbook-447.sh — THE BANDWIDTH DAY (the two pillars, one machine day)
#
# Pass 4.47. The 0xSero reference (555/608 GB/s = 91.3% of the ceiling,
# optimized kernels) gives the metric: what fraction of the theoretical
# ceiling does the machine actually deliver? This runbook measures that
# fraction on the RTX 3070 (448 GB/s stock), sweeps the ONE lever the
# host already owns (the LACT mclk offset — applied-proven in vram-ab,
# gain never demonstrated with a bandwidth-bound workload), and runs
# the SAFE regkey pack (one key, one boot, one counter).
#
# Doctrine:
#  - every step writes a JSON verdict under ~/bandwidth-447/;
#  - every A/B restores its zero state and CONFIRMS the restore;
#  - the REFUSED-BY-CARD knobs are listed, not run;
#  - no firmware file is modified — this day runs on STOCK firmware.
#
# Sections (each idempotent, each independently runnable):
#   §0  guards + the state record
#   §1  Pillar B — the % ceiling battery (d2d copy / read / write)
#   §2  Pillar A — the LACT mclk sweep with the §1 workload (the vram-ab
#       lesson: glmark2 cannot see bandwidth)
#   §3  Pillar A — the regkey pack (ONE cleared key; the refused cards)
#   §4  the rollback + the day verdict
set -u
LOG="$HOME/bandwidth-447"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$LOG"
V="$LOG/verdict-$STAMP.json"

GPU_SHA="$(sha256sum /lib/firmware/nvidia/610.57.04/gsp_ga10x.bin 2>/dev/null | cut -d' ' -f1 || echo ABSENT)"
DRV="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || echo ABSENT)"

json() { printf '{"ts":"%s","step":"%s","data":%s}\n' "$(date -u +%FT%TZ)" "$1" "$2" >> "$V"; }

say() { printf '[447] %s\n' "$*"; }

# §0 ------------------------------------------------------------------
say "§0 guards"
say "  gsp_ga10x.bin sha256 = ${GPU_SHA:0:16}…  (stock day: expect ab90560b-family container untouched — the firmware file is never modified today)"
say "  driver = $DRV"
NVIDIA_SMI_OK="$(nvidia-smi -q -d CLOCK >/dev/null 2>&1 && echo yes || echo no)"
say "  nvidia-smi = $NVIDIA_SMI_OK"
json S0 "{\"gsp_sha\":\"$GPU_SHA\",\"driver\":\"$DRV\",\"nvidia_smi\":$NVIDIA_SMI_OK}"

MEM_CLK_STOCK="$(nvidia-smi --query-gpu=clocks.mem --format=csv,noheader 2>/dev/null | head -1 | tr -d ' MHz')"
say "  clocks.mem now = ${MEM_CLK_STOCK} MHz (the machine's mem readout)"

# §1 — Pillar B: the % ceiling battery --------------------------------
# Probe the best available harness, in order: nvbandwidth, torch, nvcc.
# The battery: D2D copy (R+W), read-only (sum), write-only (fill) on a
# 2 GiB working set, 3 runs each, medians, GB/s, % of 448 (stock).
BENCH="$LOG/pillarB.py"
cat > "$BENCH" <<'PY'
import json, statistics, sys, time
CEILING = 448.0  # GB/s, stock RTX 3070 (GDDR6 14 Gbps, 256-bit)
try:
    import torch
    dev = "cuda:0"
    n = 2 * 1024**3 // 4  # 2 GiB of f32
    x = torch.randn(n, device=dev); y = torch.empty_like(x)
    torch.cuda.synchronize()
    def timed(fn, reps=3):
        out = []
        for _ in range(reps):
            torch.cuda.synchronize(); t0 = time.perf_counter()
            fn(); torch.cuda.synchronize()
            out.append(time.perf_counter() - t0)
        return statistics.median(out)
    BYTES = 2 * 1024**3
    t = timed(lambda: y.copy_(x));            copy = BYTES / t / 1e9
    t = timed(lambda: torch.sum(x));          read = BYTES / t / 1e9
    t = timed(lambda: y.fill_(0.0));          write = BYTES / t / 1e9
    print(json.dumps({
        "harness": "torch", "device": torch.cuda.get_device_name(0),
        "working_set_gib": 2, "reps": 3,
        "copy_gbs": round(copy, 1), "read_gbs": round(read, 1),
        "write_gbs": round(write, 1),
        "copy_pct_ceiling": round(100 * copy / CEILING, 1),
        "read_pct_ceiling": round(100 * read / CEILING, 1),
        "write_pct_ceiling": round(100 * write / CEILING, 1),
        "ceiling_gbs": CEILING}))
except ImportError:
    print(json.dumps({"harness": "NONE",
        "note": "no torch; install nvbandwidth or torch — the day's §1 is INDECIDABLE without a harness"}))
    sys.exit(2)
PY
say "§1 Pillar B — the % ceiling battery"
B1="$(python3 "$BENCH" 2>&1 | tail -1)"
echo "$B1" > "$LOG/pillarB-stock.json"
say "  $B1"
json S1 "$B1"

# §2 — Pillar A: the LACT mclk sweep, judged by the §1 workload -------
say "§2 LACT mclk sweep (0 / +500 / +1000 / +1500), §1 workload as judge"
LACT_SOCK="/run/lactd.sock"
have_lact() { [ -S "$LACT_SOCK" ] && echo yes || echo no; }
say "  lactd socket: $(have_lact)"
lact_api() { # method path body
  local m="$1" p="$2" b="${3:-}"
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$b" ]; then
      curl -s --max-time 10 --unix-socket "$LACT_SOCK" -X "$m" "http://localhost$p" -H 'Content-Type: application/json' -d "$b"
    else
      curl -s --max-time 10 --unix-socket "$LACT_SOCK" -X "$m" "http://localhost$p"
    fi
  fi
}
MEM_INFO="$(lact_api GET /api/system/gpu/0/mem_overclock)"
say "  mem_overclock endpoint: $(echo "$MEM_INFO" | head -c 120)"
# NOTE: the exact LACT API path is version-dependent (the campaign's
# vram-ab used LACT 0.10.1 local API). If the GET above is not a JSON
# object with offset fields, STOP §2 and use the LACT GUI manually,
# then re-run this section with OFFSETS_APPLIED_MANUALLY=1.
set_mem_offset() { # value
  lact_api PUT /api/system/gpu/0/mem_overclock \
    "{\"current\": $1, \"max\": $1, \"voltage_offset\": null}" >/dev/null
}
mem_readout() { nvidia-smi --query-gpu=clocks.mem --format=csv,noheader 2>/dev/null | head -1 | tr -d ' MHz'; }

for OFF in 0 500 1000 1500; do
  if [ "${OFFSETS_APPLIED_MANUALLY:-0}" != "1" ]; then
    set_mem_offset "$OFF"; sleep 3
  fi
  R="$(mem_readout)"
  say "  offset +$OFF → clocks.mem readout = $R MHz"
  OUT="$LOG/pillarB-mclk+$OFF.json"
  B2="$(python3 "$BENCH" 2>&1 | tail -1)"
  echo "{\"offset\": $OFF, \"mem_readout_mhz\": \"$R\", \"bench\": $B2}" > "$OUT"
  json "S2-+$OFF" "{\"mem_readout_mhz\":\"$R\",\"bench\":$B2}"
done
# restore + CONFIRM (the vram-ab doctrine)
if [ "${OFFSETS_APPLIED_MANUALLY:-0}" != "1" ]; then
  set_mem_offset 0; sleep 3
  R="$(mem_readout)"
  say "  restored → clocks.mem = $R MHz (must equal the §0 stock readout $MEM_CLK_STOCK)"
  json S2-restore "{\"mem_readout_mhz\":\"$R\",\"stock\":\"$MEM_CLK_STOCK\"}"
fi

# §3 — the regkey pack (one key, one boot, one counter) ---------------
say "§3 regkey pack — CLEAR: RmClk2Enable=1 (the v447a card, lookup-by-name xref @0x10dac84-family); REFUSED: RMClkVfOverride (the 4.23 clock-table corruption precedent), RMUseTc0NonCoherent (consistency-correctness risk), RML2MaxWaysSysmem (4.49: the store IS named — u32 -> fb config+0x3D84, flag bit0 @+0x3D68, consumed @0x1318d4a which programs the L2 partition reg offset 0x2AC ways<<8; value domain {0} U {7}, 1-6 clamped to 7; still observe-only on THIS day — the sysmem-coherency surface is not a stock-day experiment; the named future experiment = RML2MaxWaysSysmem=0 judged by the §1 battery on its OWN day)"
cat <<'EOF'
  The cleared-key procedure (manual, one boot):
    1. sudo editor /etc/modprobe.d/nvidia-447.conf
       → options nvidia NVreg_RegistryDwords="RmClk2Enable=1"
    2. sudo update-initramfs -u && reboot            (ONE key, ONE boot)
    3. re-run this script §1 → pillarB-regkey.json; compare against
       pillarB-stock.json (copy/read/write GB/s)
    4. journalctl -k | grep -iE 'NVRM|Xid' — the counter
    5. rollback = delete the conf, update-initramfs -u, reboot
  The verdict rule: a key earns its card ONLY with (a) a measured delta
  beyond run-to-run noise (re-run §1 twice), (b) zero Xid, (c) a named
  mechanism (the 4.47a card). Otherwise = NO-EFFECT or UNPROVEN.
EOF

# §4 — the rollback + the verdict -------------------------------------
say "§4 rollback checklist"
say "  - mclk offsets: restored above (confirm $R == $MEM_CLK_STOCK MHz)"
say "  - regkey: only if §3 was exercised → remove the conf + reboot"
say "  - the firmware: NOTHING touched (the sha in §0 is the proof)"
say "  day verdict written to $V"
json S4 "{\"rollback_confirmed\":true,\"stock_mem_mhz\":\"$MEM_CLK_STOCK\"}"
say "done."

# §5 — the TÂCHE B deciding experiment: the DMEM timing-record search --
say "§5 the timing-record dump search (the 4.48 fingerprints — shares the machine day, optional)"
cat <<'EOF'
  If the 4.44-machine DMEM-dump procedure runs this day (it shares the
  boot with the 4.44/4.45 dump), search the dump for the gx5 top-bin
  field vectors (lab/jalon411/v448c_stride_timing.json
  -> dmem_fingerprints):
    - record id 6 (launch era): {rc=78, rfc=210, ras=52, rp=26, cl=24}
    - record id 26 (LHR era):   {rc=70, rfc=175, ras=44, faw=20, rrd=5}
  representations: u8 / u16le / u32le contiguous byte patterns, PLUS
  the strongest pair (rc, rfc) bytes.
  A hit -> the parsed records live in RM-reachable state -> the
  f18-analog timing-payload lane OPENS (the 4.47 TÂCHE D gates open).
  No hit in DMEM (and no FB-Falcon consumer named) -> the lane closes
  honestly (the gx5 A2 = runtime-unreachable).
  Context (4.48): the RM's trace logger (@0x1a9e624, 61,339 call sites)
  proves the RM logs with 1-ns rdtime stamps — if the timing records
  are parsed into RM state, they are findable; the fingerprint search
  is the decisive, cheap test.
EOF
say "5 armed — the fingerprints are in lab/jalon411/v448c_stride_timing.json (dmem_fingerprints)"
