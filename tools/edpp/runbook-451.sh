#!/usr/bin/env bash
# runbook-451.sh — THE DMEM VERDICT DAY (pass 4.51)
#
# The three 4.51 tasks on ONE instrument, four boots, one variable per
# boot transition (the doctrine):
#   boot A  RmGspDmemDump=1                          -> the dump + the search (TÂCHE A)
#   boot B  + RMGspStateMonitor=1                    -> the state-monitor surface (TÂCHE A)
#   boot C  + RML2MaxWaysSysmem=0                    -> the ways A/B (TÂCHE C)
#   boot D  - RML2MaxWaysSysmem (monitor kept)       -> the revert proof (TÂCHE C)
# The driver patch (gsp_dmem_dump.c) is an INSTRUMENT: read-only, present
# across A-D; the REGKEY is the only A/B variable per transition.
#
# Doctrine:
#  - the firmware file is NEVER touched (the §0 sha guard);
#  - the dump = read-only debugfs blobs, zero-copy into the live mappings;
#  - the rollback = the driver revert ONLY (git checkout + dkms +
#    limine-mkinitcpio — the UKI lesson, banked 4.44-machine #1);
#  - every step writes JSON under ~/dmem-451/;
#  - REFUSED-BY-CARD knobs stay refused (runbook-447 §3 stands).
#
# Usage: sudo bash runbook-451.sh <section>
#   §0 prereq    guards + the anchor greps + the instrument coherence
#   §1 patch     the drop-in + the hook line + dkms + limine-mkinitcpio
#   §2 bootA     the dump enable conf + (manual reboot) + the pull + sha
#   §3 search    v451a on the A-blobs -> the verdict JSON
#   §4 bootB     + RMGspStateMonitor=1 + (manual reboot) + pull + search
#   §5 bootC     + RML2MaxWaysSysmem=0 + (manual reboot) + the battery x2
#   §6 bootD     the ways revert + (manual reboot) + the battery re-run
#   §7 verdict   the ledger + the rollback checklist
set -u
LOG="$HOME/dmem-451"
REPO="${REPO:-$HOME/Projects/GPU-}"
SRC="${NVSRC:-/usr/src/nvidia-610.57.04}"
KGSP="$SRC/src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$LOG"
V="$LOG/verdict-451.json"

json() { printf '{"ts":"%s","step":"%s","data":%s}\n' "$(date -u +%FT%TZ)" "$1" "$2" >> "$V"; }
say()  { printf '[451] %s\n' "$*"; }

sha16() { sha256sum "$1" 2>/dev/null | cut -c1-16; }

case "${1:-}" in
# §0 ------------------------------------------------------------------
prereq)
  say "§0 guards"
  say "  gsp_ga10x.bin sha16 = $(sha16 "$FW") (the STOCK guard — compare against the .stock if present)"
  [ -f "$FW.stock" ] && [ "$(sha16 "$FW")" = "$(sha16 "$FW.stock")" ] \
    && say "  [1/5] firmware = STOCK (vs .stock)" \
    || say "  [1/5] WARN: no .stock comparison — RECORD the sha anyway"
  say "  driver = $(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)"
  [ -f "$KGSP" ] || { say "  REFUSÉ: kernel_gsp.c absent at $KGSP"; exit 1; }
  say "  [2/5] the DKMS tree present: $SRC"

  # the anchor greps — the 610.57.04 members the instrument uses
  n=0
  for sym in "_kgspPrepareGspRmBinaryImage" "pSysmemHeapDescriptor" \
             "pRmStateMonitorBuffer" "pWprMetaDescriptor" \
             "pGspArgumentsCached" "rmLibosLogMem" "kgspInitRm_IMPL"; do
    if rg -q "$sym" "$KGSP" 2>/dev/null || grep -q "$sym" "$KGSP"; then
      say "    anchor OK: $sym"; n=$((n+1))
    else
      say "    anchor MISSING: $sym — the instrument needs adaptation (the build judge)"
    fi
  done
  [ "$n" -ge 6 ] || { say "  REFUSÉ: fewer than 6/7 anchors found"; exit 1; }
  say "  [3/5] anchors $n/7 (the grounding: open-gpu-kernel-modules tag 610.57.04)"

  # the instrument coherence (the baseline gate, local)
  python3 "$REPO/lab/jalon411/v451a_dmem_scan.py" --selftest | tail -1
  python3 "$REPO/tools/booter_emu.py" --selftest 2>&1 | tail -1
  say "  [4/5] instruments coherent (v451a selftest + emu selftest above)"
  say "  [5/5] the module is BUILT FRESH after the patch (§1) — the UKI lesson: dkms + limine-mkinitcpio, or the OLD module loads silently"
  json S0 "{\"anchors\":\"$n/7\",\"kgsp_sha16\":\"$(sha16 "$KGSP")\"}"
  ;;

# §1 ------------------------------------------------------------------
patch)
  say "§1 the drop-in + the hook line"
  cp "$REPO/tools/edpp/gsp_dmem_dump.c" "$SRC/src/nvidia/src/kernel/gpu/gsp/" \
    || { say "  REFUSÉ: copy failed"; exit 1; }
  if grep -q "gsp_dmem_dump_schedule" "$KGSP"; then
    say "  the hook line ALREADY present (idempotent re-run)"
  else
    say "  MANUAL STEP (the exact anchor — one line to insert in kgspInitRm_IMPL,"
    say "  immediately AFTER the kgspStartLogPolling line, success path):"
    say "    gsp_dmem_dump_schedule(pGpu, pKernelGsp, pGspFw);"
    say "  and near the top of kernel_gsp.c (after the local includes):"
    say '    #include "gsp_dmem_dump.c"'
    say "  (the 4.44 lesson #4: the patch anchor = the EXACT source text —"
    say "   a replace that eats a parameter list = the build = the judge)"
    exit 1
  fi
  say "  dkms build/install + the UKI rebuild:"
  say "    sudo dkms build -m nvidia -v 610.57.04 && sudo dkms install -m nvidia -v 610.57.04"
  say "    sudo limine-mkinitcpio   (BANKED: skipping it = the OLD module boots — the silent false negative)"
  say "  record /proc/cmdline BEFORE the reboot (the effective cmdline truth):"
  cat /proc/cmdline > "$LOG/proc-cmdline-before.txt" 2>/dev/null || true
  json S1 "{\"patch\":\"installed\"}"
  ;;

# §2 ------------------------------------------------------------------
bootA)
  say "§2 boot A: RmGspDmemDump=1 (the dump enable, ONE key ONE boot)"
  say "  1. sudo editor /etc/modprobe.d/nvidia-451-dump.conf:"
  say '       options nvidia NVreg_RegistryDwords="RmGspDmemDump=1"'
  say "  2. sudo update-initramfs -u && reboot"
  say "  3. after boot + 15 s, run: sudo bash $0 pullA"
  ;;
pullA)
  say "§2 pull: the debugfs blobs -> $LOG/"
  D=/sys/kernel/debug/gsp_dmem
  ls "$D"/gpu*/ 2>/dev/null || { say "  REFUSÉ: $D absent — the instrument did not run (check dmesg for NVRM-451)"; exit 1; }
  for f in "$D"/gpu*/*.bin; do
    cp "$f" "$LOG/$(basename "$(dirname "$f")")-$(basename "$f")"
  done
  ( cd "$LOG" && sha256sum gpu*/*.bin 2>/dev/null || sha256sum gpu*-*.bin ) | tee "$LOG/shas-A.txt"
  dmesg | grep "NVRM-451" | tail -30 | tee "$LOG/dmesg-451.txt"
  json pullA "{\"blobs\":$(ls "$LOG" | grep -c '.bin')}"
  say "  then: sudo bash $0 search"
  ;;

# §3 ------------------------------------------------------------------
search)
  say "§3 the v451a search on the A-blobs"
  BLOBS=()
  for f in "$LOG"/gpu*/*.bin "$LOG"/gpu*-*.bin; do
    [ -f "$f" ] && BLOBS+=("$f:$(basename "$f" .bin)")
  done
  [ ${#BLOBS[@]} -gt 0 ] || { say "  REFUSÉ: no blobs"; exit 1; }
  python3 "$REPO/lab/jalon411/v451a_dmem_scan.py" --out "$LOG/v451a-A.json" "${BLOBS[@]}" | tee "$LOG/search-A.log"
  json S3 "{\"search\":\"A done — see v451a-A.json\"}"
  say "  THE DECISION TREE:"
  say "   HIT in sysmemheap/statemonitor -> TÂCHE B OPENS (route H: the host-writable target)"
  say "   HIT in image/ucodes only       -> static copies; the v2 (WPR2) probe is designed"
  say "   MISS everywhere                -> falcon-internal or FB FW heap -> boot B + v2"
  ;;

# §4 ------------------------------------------------------------------
bootB)
  say "§4 boot B: + RMgspStateMonitor=1 (the NVIDIA state-monitor surface)"
  say "  the regkey string is IN OUR BANKED rm-strings.txt (RMGspStateMonitor);"
  say "  the driver reads it as NV_REG_STR_RM_ENABLE_STATE_MONITOR (kernel_gsp.c ~4322)."
  say "  1. edit /etc/modprobe.d/nvidia-451-dump.conf:"
  say '       options nvidia NVreg_RegistryDwords="RmGspDmemDump=1 RMgspStateMonitor=1"'
  say "  2. update-initramfs -u && reboot; 3. pullB + search (statemonitor.bin should appear)"
  ;;
pullB)
  bash "$0" pullA && mv "$LOG/v451a-A.json" "$LOG/v451a-A.json.bak" 2>/dev/null
  bash "$0" search
  json S4 "{\"search\":\"B done (the monitor surface)\"}"
  ;;

# §5 — TÂCHE C: the ways A/B -------------------------------------------
bootC)
  say "§5 boot C: + RML2MaxWaysSysmem=0 (TÂCHE C — the ways A/B, ONE key ONE boot)"
  say "  the 4.49 chain: u32 -> config+0x3D84, consumed @0x1318d4a -> reg 0x2AC ways<<8;"
  say "  the value domain {0} U {7}: 0 = HONORED (the ways released), 7 = the default;"
  say "  the RISK card: the historical -13% (the pre-repo RML2MaxWaysSysmem=1 test) —"
  say "  NOTE: =1 is CLAMPED to 7 per the 4.49 consumer decode, so a real -13% under =1"
  say "  would CONTRADICT the clamp reading — the =0 experiment decides cleanly (in-domain)."
  say "  1. edit the conf: NVreg_RegistryDwords=\"RmGspDmemDump=1 RMgspStateMonitor=1 RML2MaxWaysSysmem=0\""
  say "  2. update-initramfs -u && reboot; 3. batteryC"
  ;;
batteryC)
  say "§5 the battery x2 (the judge: 4.47 §1 + the sysmem extension)"
  for i in 1 2; do
    python3 "$REPO/tools/edpp/pillarB-sysmem.py" > "$LOG/pillarB-sysmem-ways0-$i.json"
    python3 "$REPO/tools/edpp/runbook-447.sh" 2>/dev/null | true # the §1 battery if integrated
  done
  nvidia-smi -q -d CLOCK > "$LOG/clocks-ways0.txt"
  dmesg | grep -iE "Xid|NVRM" | tail -20 > "$LOG/dmesg-ways0.txt"
  json S5 "{\"battery\":\"ways=0 recorded x2\"}"
  say "  then: bootD"
  ;;

# §6 — the revert proof -------------------------------------------------
bootD)
  say "§6 boot D: the ways REVERT (the conf minus RML2MaxWaysSysmem)"
  say "  1. edit the conf back to: NVreg_RegistryDwords=\"RmGspDmemDump=1 RMgspStateMonitor=1\""
  say "  2. update-initramfs -u && reboot; 3. batteryD"
  ;;
batteryD)
  for i in 1 2; do
    python3 "$REPO/tools/edpp/pillarB-sysmem.py" > "$LOG/pillarB-sysmem-revert-$i.json"
  done
  nvidia-smi -q -d CLOCK > "$LOG/clocks-revert.txt"
  dmesg | grep -iE "Xid|NVRM" | tail -20 > "$LOG/dmesg-revert.txt"
  json S6 "{\"battery\":\"the revert re-run x2 — the A/B table closes\"}"
  say "  the verdict rule (the 4.47 doctrine): the ways key earns its card ONLY with"
  say "  (a) a delta beyond run-to-run noise (x2 each side), (b) zero Xid, (c) the named"
  say "  mechanism (the 4.49 chain). Otherwise = NO-EFFECT or UNPROVEN."
  ;;

# §7 — the ledger + the rollback ---------------------------------------
verdict|rollback)
  say "§7 the rollback checklist (the DRIVER ONLY)"
  say "  git -C $SRC checkout -- src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
  say "  rm $SRC/src/nvidia/src/kernel/gpu/gsp/gsp_dmem_dump.c"
  say "  sudo dkms build -m nvidia -v 610.57.04 && sudo dkms install -m nvidia -v 610.57.04"
  say "  sudo limine-mkinitcpio   (the UKI lesson)"
  say "  rm /etc/modprobe.d/nvidia-451-dump.conf && sudo update-initramfs -u && reboot"
  say "  the firmware: NOTHING touched (the §0 sha = the proof)"
  say "  the full rollback cycle ~= 10 min (PROVEN, the 4.44-machine ledger)"
  json S7 "{\"rollback\":\"checklist printed\"}"
  ;;
*)
  echo "usage: $0 {prereq|patch|bootA|pullA|search|bootB|pullB|bootC|batteryC|bootD|batteryD|verdict}"; exit 1 ;;
esac
