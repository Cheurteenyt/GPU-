#!/usr/bin/env bash
# runbook-452.sh — THE WRITE-LANE DAY (pass 4.52)
#
# The 4.52 tasks on ONE gated day, one variable per boot transition
# (the doctrine):
#   §1  the PCIe CALIBRATION (T5)  -> the honest cold baseline BEFORE
#       anything else (the ways verdict and the timing verdict both
#       read it — a 25%-of-nominal baseline poisons every A/B)
#   §2  the S4/S5 PARSE (T1+T2)    -> the 451-day blobs become the
#       region map + the route-H candidates
#   §3  the PLAN (T3)              -> v452c builds the signed write
#       plan + the C table (byte-exact vs python)
#   §4  the POKE boot              -> RmGspHPoke=<sel>, ONE field, the
#       pre/post-verify ledger + the judge battery x2
#   §5  the REVERT boot            -> the key removed, the battery x2,
#       the A/B closes
#   §6  the ledger + the rollback  -> DRIVER ONLY (the ritual, ~10 min)
#
# Doctrine (unchanged):
#  - the firmware file is NEVER touched (the §0 sha guard);
#  - EVERYTHING depends on the 451-day dump: no blobs -> §2 REFUSES and
#    the day stops at the calibration + the parse gate (the v451b
#    pattern: the targets stay null until the bytes decide);
#  - the write instrument is OPT-IN via RmGspHPoke=<sel>, SEPARATE from
#    the 4.51 dump key — absent/0 = the file does nothing;
#  - the rollback = the driver revert ONLY (git checkout + dkms +
#    limine-mkinitcpio — the banked UKI lesson);
#  - every step writes JSON under ~/write-lane-452/.
#
# Usage: sudo bash runbook-452.sh <section>
set -u
LOG="$HOME/write-lane-452"
REPO="${REPO:-$HOME/Projects/GPU-}"
SRC="${NVSRC:-/usr/src/nvidia-610.57.04}"
KGSP="$SRC/src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
DUMP451="${DUMP451:-$HOME/dmem-451}"   # the 451-day blob dir
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$LOG"
V="$LOG/verdict-452.json"

json() { printf '{"ts":"%s","step":"%s","data":%s}\n' "$(date -u +%FT%TZ)" "$1" "$2" >> "$V"; }
say()  { printf '[452] %s\n' "$*"; }
sha16() { sha256sum "$1" 2>/dev/null | cut -c1-16; }

case "${1:-}" in
# §0 ------------------------------------------------------------------
prereq)
  say "§0 guards + the banked counts (the reproduction FIRST)"
  say "  gsp_ga10x.bin sha16 = $(sha16 "$FW") (the STOCK guard)"
  say "  driver = $(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)"
  [ -f "$KGSP" ] || { say "  REFUSÉ: kernel_gsp.c absent at $KGSP"; exit 1; }

  # the anchor greps — the 610.57.04 members the write lane uses
  n=0
  for sym in "pSysmemHeapDescriptor" "kgspStartLogPolling" \
             "memdescMap" "memdescUnmap" "osReadRegistryDword" \
             "kgspSetupLibosInitArgs"; do
    if grep -q "$sym" "$KGSP"; then
      say "    anchor OK: $sym"; n=$((n+1))
    else
      say "    anchor MISSING: $sym — the instrument needs adaptation"
    fi
  done
  [ "$n" -ge 5 ] || { say "  REFUSÉ: fewer than 5/6 anchors"; exit 1; }
  say "  [1/4] anchors $n/6 (the grounding: the tag 610.57.04)"

  # the banked counts (the 4.52 rule: REPRODUCED FIRST)
  python3 "$REPO/tools/booter_emu.py" --selftest 2>&1 | tail -1
  python3 "$REPO/tools/booter_emu.py" --test-transfer 2>&1 | tail -1
  python3 "$REPO/tools/booter_emu.py" --test-timings 2>&1 | tail -1
  python3 "$REPO/tools/edpp/build_timing_payload.py" 2>&1 | head -1
  python3 "$REPO/lab/jalon411/v451a_dmem_scan.py" --selftest 2>&1 | tail -1
  python3 "$REPO/lab/jalon411/v452a_libos_walk.py" --selftest 2>&1 | tail -1
  python3 "$REPO/lab/jalon411/v452b_heap_scan.py" --selftest 2>&1 | tail -1
  python3 "$REPO/lab/jalon411/v452c_hpatch_build.py" --selftest 2>&1 | tail -1
  python3 "$REPO/tools/edpp/pillarB-sysmem.py" --selftest 2>&1 | tail -1
  say "  [2/4] the instrument batteries above (ALL must PASS)"

  [ -f "$LOG/gsp_hpoke_plan.h" ] && say "  [3/4] the plan header present (§3 done)" \
    || say "  [3/4] the plan header ABSENT (§4 refuses until §3 passes)"
  say "  [4/4] the module is BUILT FRESH after any patch (§4) — the UKI lesson"
  json S0 "{\"anchors\":\"$n/6\"}"
  ;;

# §1 — T5: the honest cold baseline ------------------------------------
calib)
  say "§1 the PCIe calibration (T5) — BEFORE any A/B"
  say "  the machine state (the diagnosis inputs, recorded as-is):"
  nvidia-smi --query-gpu=pcie.link.width.current,pcie.link.width.max,pcie.link.gen.current,pcie.link.gen.max,clocks.sm,clocks.mem,pstate --format=csv > "$LOG/link-state.txt" 2>/dev/null || true
  cat "$LOG/link-state.txt" || true
  (lspci -vvv 2>/dev/null | grep -EA12 "VGA|3D" | grep -E "LnkSta|LnkCtl|ASPM|Speed|Width" | head -8) > "$LOG/lnksta.txt" || true
  cat "$LOG/lnksta.txt" || true
  cat /sys/module/pcie_aspm/parameters/policy > "$LOG/aspm-policy.txt" 2>/dev/null || true
  say "  aspm policy = $(cat "$LOG/aspm-policy.txt" 2>/dev/null || echo unknown)"
  say "  the battery (run 1 — the AS-IS baseline, the honest number):"
  python3 "$REPO/tools/edpp/pillarB-sysmem.py" | tee "$LOG/pillarB-asis-1.json" | python3 -c "import json,sys; d=json.load(sys.stdin); print('  h2d=%s d2h=%s d2d=%s device_warm=%s cold=%s ratio=%s' % (d.get('h2d_gbs'),d.get('d2h_gbs'),d.get('d2d_gbs'),d.get('device_warm_gbs'),d.get('sysmem_cold_gbs'),d.get('ways_verdict_ratio')))" || true
  say "  the battery (run 2 — the repeatability):"
  python3 "$REPO/tools/edpp/pillarB-sysmem.py" | tee "$LOG/pillarB-asis-2.json" > /dev/null || true
  say "  THE CALIBRATION VERDICT (read the JSON 'calibration' block):"
  say "   h2d/d2h >= ~60% of the PCIe4 x16 nominal -> the baseline is HONEST"
  say "   below -> the named cause (the width, the gen, the ASPM, the P-state)"
  say "   fix the ENVIRONMENT (the clock lock, the ASPM policy), re-run —"
  say "   the A/B days (the ways, the timing) read the FINAL baseline only"
  json S1 "{\"calibration\":\"see pillarB-asis-*.json + link-state.txt\"}"
  ;;

# §2 — T1+T2: the parse of the 451-day blobs ----------------------------
parse)
  say "§2 the S4/S5 parse (gated on the 451-day dump)"
  S4="$(ls "$DUMP451"/*libosinit.bin 2>/dev/null | head -1)"
  S5="$(ls "$DUMP451"/*sysmemheap.bin 2>/dev/null | head -1)"
  S1="$(ls "$DUMP451"/*image.bin 2>/dev/null | head -1)"
  S2="$(ls "$DUMP451"/*ucodes.bin 2>/dev/null | head -1)"
  if [ -z "$S4" ] || [ -z "$S5" ]; then
    say "  REFUSÉ: the 451-day blobs absent at $DUMP451 (libosinit/sysmemheap)"
    say "  THE GATE HOLDS: no dump -> no map, no candidates, no plan."
    say "  Run runbook-451 §2-§3 first (boot A), then come back."
    json S2 "{\"gate\":\"REFUSED — no dump\"}"
    exit 2
  fi
  say "  S4=$S4"
  python3 "$REPO/lab/jalon411/v452a_libos_walk.py" --s4 "$S4" ${S5:+--s5 "$S5"} \
    --out "$LOG/v452a.json" | tee "$LOG/v452a.log"
  say "  S5=$S5"
  python3 "$REPO/lab/jalon411/v452b_heap_scan.py" --heap "$S5" \
    ${S1:+--static "$S1:image"} ${S2:+--static "$S2:ucodes"} \
    --out "$LOG/v452b.json" | tee "$LOG/v452b.log"
  json S2 "{\"parse\":\"v452a + v452b done — see the logs\"}"
  say "  THE DECISION TREE:"
  say "   plan-eligible candidates -> §3 builds the plan"
  say "   none -> the v451b table holds (the WPR2 v2 probe / falcon-internal)"
  ;;

# §3 — T3: the signed plan ----------------------------------------------
plan)
  say "§3 the route-H write plan (v452c)"
  [ -f "$LOG/v452b.json" ] || { say "  REFUSÉ: run §2 first"; exit 2; }
  python3 "$REPO/lab/jalon411/v452c_hpatch_build.py" --v452b "$LOG/v452b.json" \
    --plan "$LOG/v452c-plan.json" --emit-c "$LOG/gsp_hpoke_plan.h" \
    | tee "$LOG/v452c.log"
  grep -q "C byte-exact vs python: PASS" "$LOG/v452c.log" \
    || { say "  REFUSÉ: the C emission is NOT byte-exact — the plan is not installed"; exit 1; }
  [ -s "$LOG/gsp_hpoke_plan.h" ] || { say "  REFUSÉ: no plan header"; exit 1; }
  say "  the plan header: $LOG/gsp_hpoke_plan.h"
  say "  THE HUMAN REVIEW (the doctrine): read v452c-plan.json — the entries,"
  say "  the named nulls (ras/faw/rrd INDECIDABLE on this route), the refusals."
  say "  A selector collision = re-run §3 with --pick <pattern> after the review."
  say "  THEN: copy the header into the source tree at §4."
  json S3 "{\"plan\":\"built — plan_sha16 in v452c-plan.json\"}"
  ;;

# §4 — the poke boot ------------------------------------------------------
patch)
  say "§4 the drop-in + the plan + the hook line"
  SEL="${2:-}"
  [ -n "$SEL" ] || { say "  usage: $0 patch <sel 1..5>  (1=rc 2=rfc 3=ras 4=faw 5=rrd)"; exit 1; }
  [ -f "$LOG/gsp_hpoke_plan.h" ] || { say "  REFUSÉ: run §3 first"; exit 2; }
  cp "$REPO/tools/edpp/gsp_hpoke.c" "$SRC/src/nvidia/src/kernel/gpu/gsp/" \
    || { say "  REFUSÉ: the copy failed"; exit 1; }
  cp "$LOG/gsp_hpoke_plan.h" "$SRC/src/nvidia/src/kernel/gpu/gsp/" \
    || { say "  REFUSÉ: the plan copy failed"; exit 1; }
  # ---- the 4.55 addition: the nv.c side (the two-sided conversion) ----
  # the RM TU = clean since 4.55 (zero linux headers); the delayed work
  # + the dmesg ledger live in kernel-open/nvidia/nv.c. WITHOUT this
  # patch the dkms build STILL PASSES but the late fn is never called
  # (the silent no-op — worse than a build fail), so the marker = a
  # HARD REFUSAL below.
  NVC="$SRC/kernel-open/nvidia/nv.c"
  [ -f "$NVC" ] || { say "  REFUSÉ: $NVC absent"; exit 1; }
  if grep -q "HpokeMarker" "$NVC"; then
    say "  the nv.c side ALREADY patched (idempotent re-run)"
  else
    say "  applying patch_nv_452.py (the HpokeMarker — coexists with the"
    say "  4.51 DmemDumpMarker, either order):"
    sudo python3 "$REPO/tools/edpp/patch_nv_452.py" \
      || { say "  REFUSÉ: the nv.c patch failed"; exit 1; }
  fi
  grep -q "HpokeMarker" "$NVC" \
    || { say "  REFUSÉ: the HpokeMarker ABSENT from nv.c — the poke would be a"; say "         silent no-op; apply patch_nv_452.py before the dkms"; exit 1; }
  if grep -q "gsp_hpoke_schedule" "$KGSP"; then
    say "  the hook line ALREADY present (idempotent re-run)"
  else
    say "  MANUAL STEP (the exact anchor — insert in kgspInitRm_IMPL, success"
    say "  path, immediately AFTER the kgspStartLogPolling line — next to the"
    say "  4.51 instrument's hook if present):"
    say "    gsp_hpoke_schedule(pGpu, pKernelGsp);"
    say "  and near the top of kernel_gsp.c (after the local includes):"
    say '    #include "gsp_hpoke.c"'
    exit 1
  fi
  say "  dkms build/install + the UKI rebuild (the OLD module = the silent"
  say "  false negative — the banked lesson):"
  say "    sudo dkms build -m nvidia -v 610.57.04 && sudo dkms install -m nvidia -v 610.57.04"
  say "    sudo limine-mkinitcpio"
  say "  THEN edit /etc/modprobe.d/nvidia-452-poke.conf (ONE key ONE boot):"
  say '    options nvidia NVreg_RegistryDwords="RmGspHPoke='"$SEL"'"'
  say "  (keep RmGspDmemDump=1 on the same boot if the dump is wanted — the"
  say "   keys are SEPARATE instruments)"
  say "  sudo update-initramfs -u && reboot"
  say "  AFTER the boot: sudo bash $0 verify"
  json S4 "{\"patch\":\"installed for sel=$SEL\"}"
  ;;

verify)
  say "§4 the post-boot verification (the poke ledger + the judge)"
  dmesg | grep "NVRM-452" | tee "$LOG/dmesg-452.txt"
  grep -q "verify=OK" "$LOG/dmesg-452.txt" \
    || say "  WARN: no verify=OK line — read the ledger (STALE-PLAN = the plan"
  say "         is behind the runtime; verify=FAIL = the write did not hold)"
  for i in 1 2; do
    python3 "$REPO/tools/edpp/pillarB-sysmem.py" > "$LOG/pillarB-poke-$i.json"
  done
  nvidia-smi -q -d CLOCK > "$LOG/clocks-poke.txt"
  dmesg | grep -iE "Xid" | tail -10 > "$LOG/xid-poke.txt" || true
  [ -s "$LOG/xid-poke.txt" ] && say "  XID PRESENT — the experiment STOPS here, revert (§5)" \
    || say "  zero Xid"
  say "  the judge battery x2 done — compare vs $LOG/pillarB-asis-*.json"
  json S4 "{\"verify\":\"dmesg ledger + battery x2 recorded\"}"
  say "  then: §5 (the revert boot — the proof, not just a cleanup)"
  ;;

# §5 — the revert boot ----------------------------------------------------
revert)
  say "§5 the REVERT boot (the A-side proof)"
  say "  1. rm /etc/modprobe.d/nvidia-452-poke.conf"
  say "  2. sudo update-initramfs -u && reboot"
  say "  3. after the boot: sudo bash $0 verify-revert"
  ;;
verify-revert)
  for i in 1 2; do
    python3 "$REPO/tools/edpp/pillarB-sysmem.py" > "$LOG/pillarB-revert-$i.json"
  done
  nvidia-smi -q -d CLOCK > "$LOG/clocks-revert.txt"
  dmesg | grep "NVRM-452" | tail -5 > "$LOG/dmesg-revert.txt" || true
  [ -s "$LOG/dmesg-revert.txt" ] && say "  WARN: NVRM-452 lines on the reverted boot (the key should be gone)" || say "  no poke activity (the key gone = the instrument inert)"
  json S5 "{\"revert\":\"battery x2 — the A/B table closes\"}"
  say "  the verdict rule (the 4.47 doctrine): a delta beyond the run-to-run"
  say "  noise (x2 per side) + zero Xid + the named mechanism (the plan sha,"
  say "  the pre/post-verify) — otherwise NO-EFFECT or UNPROVEN"
  ;;

# §6 — the ledger + the rollback ------------------------------------------
verdict|rollback)
  say "§6 the rollback checklist (the DRIVER ONLY)"
  say "  git -C $SRC checkout -- src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
  say "  git -C $SRC checkout -- kernel-open/nvidia/nv.c   # the 4.55 HpokeMarker (and the 4.51 DmemDumpMarker) leave together"
  say "  rm -f $SRC/src/nvidia/src/kernel/gpu/gsp/gsp_hpoke.c"
  say "  rm -f $SRC/src/nvidia/src/kernel/gpu/gsp/gsp_hpoke_plan.h"
  say "  rm -f $SRC/src/nvidia/src/kernel/gpu/gsp/gsp_dmem_dump.c   # if 4.51 also reverts"
  say "  sudo dkms build -m nvidia -v 610.57.04 && sudo dkms install -m nvidia -v 610.57.04"
  say "  sudo limine-mkinitcpio   (the UKI lesson)"
  say "  rm -f /etc/modprobe.d/nvidia-452-poke.conf && sudo update-initramfs -u && reboot"
  say "  the firmware: NOTHING touched (the §0 sha = the proof)"
  say "  the full rollback cycle ~= 10 min (PROVEN, the 4.44-machine ledger)"
  json S6 "{\"rollback\":\"checklist printed\"}"
  ;;
*)
  echo "usage: $0 {prereq|calib|parse|plan|patch <sel>|verify|revert|verify-revert|verdict}"; exit 1 ;;
esac
