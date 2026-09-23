#!/usr/bin/env bash
# RUNBOOK 280 W — la journée du break, scriptée de bout en bout.
# Usage : sudo bash runbook-280.sh <étape>
#   swap      : installe le gsp.bin patché (le stock = backupé)
#   restore   : le rollback complet (le stock revient)
#   verify    : la vérification post-boot (le limit, le GSP, la santé)
#   validate  : la suite complète de validation de charge (Solar Bay + Q2RTX + memtest)
#   capture   : les dumps du transport (les recv/send) pour l'analyse
set -e
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
BENCH=/home/cheurteen/Projects/compute-lab/bench
PATCHED=/home/cheurteen/gsp_ga10x_patched.bin   # le firmware patché (le sha 6a3c1a06…)

case "$1" in
  swap)
    [ -f "$PATCHED" ] || { echo "ABSENT: $PATCHED — reproduire avec gspbuild.py patchrm (le registre v430)"; exit 1; }
    [ -f "$FW.stock" ] || cp "$FW" "$FW.stock"
    sha256sum "$FW.stock" | cut -c1-16
    cp "$PATCHED" "$FW"
    echo "gsp.bin patché installé. Reboot maintenant."
    echo "Si le boot échoue : Ctrl+Alt+F3 → sudo cp $FW.stock $FW && reboot"
    ;;
  restore)
    [ -f "$FW.stock" ] && cp "$FW.stock" "$FW" && echo "stock restauré ✓"
    ;;
  verify)
    nvidia-smi --query-gpu=power.limit,power.max_limit,power.min_limit --format=csv,noheader
    nvidia-smi -pl 280 2>&1 | tail -1
    nvidia-smi --query-gpu=power.limit --format=csv,noheader
    ;;
  validate)
    echo "=== 1. la stabilité : memtest_vulkan (2 min) ==="
    timeout 120 "/run/media/cheurteen/Jeux SSD/Reverse Engenering/memtest-vulkan/memtest_vulkan" 2>&1 | tail -2
    echo "=== 2. le ring C1 : la bande passante ==="
    $BENCH/bandwidth 2>&1 | tail -1
    echo "=== 3. Solar Bay (le score officiel, le RT moderne) ==="
    cd /home/cheurteen/.local/share/3dmark 2>/dev/null || true
    echo "(lancer Solar Bay via l'app 3DMark ou steam — le score à comparer : 58522 stock / 62107 +500mem)"
    echo "=== 4. Q2RTX (le path tracing réel) ==="
    echo "(MangoHud log déjà configuré dans les options de lancement Steam)"
    echo "=== 5. les Xid ==="
    dmesg | grep -c xid || echo "0 xid ✓"
    ;;
  capture)
    journalctl -b -k | grep -E "RPCRECV76|RPCRECVLARGE76|RPCDUMP76|EDPPSCAN|V10SURGICAL" > /tmp/capture-280.txt
    wc -l /tmp/capture-280.txt
    echo "l'analyse : les tools/edpp/ + les parseurs du lab"
    ;;
  *) echo "usage : $0 {swap|restore|verify|validate|capture}"; exit 1 ;;
esac
