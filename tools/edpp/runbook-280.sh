#!/usr/bin/env bash
# RUNBOOK 280 W — la journée du break, scriptée de bout en bout.
#
# ── VERDICT 4.34 (lire avant tout swap) ─────────────────────────────────
# La passe 4.32 a PROUVÉ par les octets que les 7 sites 250000 du rm.elf
# sont de la logique TEMPORELLE (la bande d'hystérésis [250000,500000] us
# du moteur de requête 0x4F0), PAS une politique de puissance. Tourner
# ces sites ne peut PAS donner 280 W. Le container 4.30 (6a3c1a06…) est
# de plus 6/7 INCOHÉRENT (le 7e site split-form garde 250000) — NE JAMAIS
# LE BOOTER. Le patch 7/7 complet (fwimage sha 5962342b…) existe comme
# preuve de complétude (v434a), PAS comme recommandation de boot.
# La voie 280 W reste le FEED HÔTE (l'objet EDPp est rempli au runtime
# via vtable — les limites viennent du CPU, pas des octets rm.elf).
# `swap` refuse le 6/7 ; `swap77` exige RUNBOOK_77_ACK=1 (opt-in).
# ────────────────────────────────────────────────────────────────────────
#
# Usage : sudo bash runbook-280.sh <étape>
#   swap      : installe le gsp.bin patché (le stock = backupé)
#               — REFUSE le 6/7 incohérent, exige RUNBOOK_77_ACK=1 pour le 7/7
#   restore   : le rollback complet (le stock revient)
#   verify    : la vérification post-boot (le limit, le GSP, la santé)
#   validate  : la suite complète de validation de charge (Solar Bay + Q2RTX + memtest)
#   capture   : les dumps du transport (les recv/send) pour l'analyse
set -e
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
BENCH=/home/cheurteen/Projects/compute-lab/bench
PATCHED=/home/cheurteen/gsp_ga10x_patched.bin   # le firmware patché (le sha 6a3c1a06…)
PATCHED77=/home/cheurteen/gsp_ga10x_patched77.bin  # le 7/7 complet (v434a)

sha16() { sha256sum "$1" | cut -c1-16; }

case "$1" in
  swap)
    [ -f "$PATCHED" ] || { echo "ABSENT: $PATCHED — reproduire avec gspbuild.py patchrm (le registre v430)"; exit 1; }
    H=$(sha16 "$PATCHED")
    if [ -f "$PATCHED77" ]; then
      H77=$(sha16 "$PATCHED77")
      # le 7/7 : opt-in explicite obligatoire (sémantique TIME, pas puissance — 4.32)
      [ "$RUNBOOK_77_ACK" = "1" ] || {
        echo "REFUSÉ: le 7/7 ($PATCHED77, sha $H77…) est la preuve de complétude, pas un boot recommandé.";
        echo "        4.32: les 7 sites 250000 = logique TEMPORELLE — ce patch ne donnera PAS 280 W.";
        echo "        Pour l'expérience quand même: RUNBOOK_77_ACK=1 sudo -E bash $0 swap";
        exit 1; }
      [ "$H77" = "$(sha16 "$PATCHED77")" ] && PATCHED="$PATCHED77"
    else
      echo "REFUSÉ: le container 6/7 (sha $H…) est INCOHÉRENT (le 7e site split-form garde 250000 — 4.32e)."
      echo "        Ne pas booter un binaire à moitié tourné. Produire le 7/7:";
      echo "        gspbuild.py patchrm gsp_ga10x.bin 0x19f000 0x1071000 250000 280000 out.bin sites=6 split=1";
      echo "        OU mieux: restaurer le stock (restore) — la voie 280 W est le feed hôte (4.32).";
      exit 1;
    fi
    [ -f "$FW.stock" ] || cp "$FW" "$FW.stock"
    sha16 "$FW.stock"
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
