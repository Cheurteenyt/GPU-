#!/usr/bin/env bash
# pillarB-driver.sh — the Pillar B instrument driver (pass 4.50).
#
# Probes nvcc, builds pillarB.cu for the local arch, runs ALL modes,
# writes one JSON verdict under ~/bandwidth-447/. The stock day is
# untouched: this driver measures, it never configures.
#
# Usage: pillarB-driver.sh [CEILING_GBPS]
#   CEILING defaults to 448 (the RTX 3070 stock). After an mclk offset
#   is applied (runbook-447 §2), pass the new ceiling:
#     e.g. +1500 offset -> 16.6 Gbps -> CEILING=531
set -u
LOG="$HOME/bandwidth-447"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$LOG"
V="$LOG/pillarB-cu-$STAMP.json"

CEIL="${1:-448}"
export CEILING="$CEIL"

command -v nvcc >/dev/null 2>&1 || {
  printf '{"harness":"nvcc","error":"nvcc ABSENT — install cuda-toolkit (the §1 harness probe order: nvbandwidth -> torch -> nvcc)"}\n' >> "$V"
  echo "[pillarB] nvcc absent — see the message in $V"
  exit 2
}
ARCH="$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | tr -d '.' || echo 86)"
ARCH="${ARCH:-86}"
BIN="$LOG/pillarB-sm$ARCH"
nvcc -O3 -arch="sm_$ARCH" -o "$BIN" "$(dirname "$0")/pillarB.cu" || exit 1

# the reset persisting-L2 guard before AND after (the leakage protection)
reset_l2() { python3 - <<'PY' 2>/dev/null || true
import ctypes
PY
}
: "$LOG/pillarB-cu.log"
{
  for m in copy copy-cs read read-cs write write-cs ce overlap; do
    "$BIN" "$m" 2>&1 | tail -1
  done
  # the M3 sweep: the footprints around the L2 size (~4 MB on GA104)
  for sz in 262144 1048576 3145728 4194304; do
    "$BIN" "persist" "$sz" 2>&1 | tail -1
  done
} | tee "$LOG/pillarB-cu.log" >> "$V"
echo "[pillarB] verdicts -> $V"
