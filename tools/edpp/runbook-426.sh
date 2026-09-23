#!/usr/bin/env bash
# RUNBOOK 426 — le jour de la capture recv, scripté de bout en bout.
#
# ── VERDICTS BANCARISÉS (lire avant tout geste) ────────────────────────
# 4.25 : le hook receveur est ARMÉ (patch_rpc_recv.py, byte-exact,
#        idempotent, --revert propre). La prédiction §7.2 = 96 B de
#        réponse (40 préfixe + 24 params {limitMin=100000, limitRated=
#        240000, limitMax=250000} + 32 résidu zéro) — CHAQUE valeur
#        reste HYPOTHÈSE jusqu'à la capture. Aucune valeur n'est
#        bankée comme observée.
# 4.32/4.34 : le patch rm.elf = logique TEMPORELLE → REVERT. Ce
#        runbook exige le firmware STOCK (le sha vérifié plus bas) —
#        le container 6/7 est REFUSÉ ici comme partout.
# 4.36 : la chasse statique a atteint son plancher (3 sondes = zéro).
#        Les vraies données = CETTE capture (le recv-hook sur le stock).
# 4.37 : la sonde data-twin (v437a) prouve que les défauts 1000000
#        sont référencés par des descripteurs statiques data (25
#        pointeurs), jamais adressés par le code — la capture doit
#        regarder le chemin RPC de création d'objets, pas un loader.
# ────────────────────────────────────────────────────────────────────────
#
# Usage : sudo bash runbook-426.sh <étape>
#   prereq    : le firmware stock vérifié (le sha), le DKMS tree présent
#   patch     : applique le hook recv (+ le send hook si présent)
#               — byte-exact, le revert est toujours dispo (`restore`)
#   restore   : le revert des deux patchs (byte-exact, prouvé 4.25)
#   initramfs : le plumbing modprobe (RpcDump=1 [+ EdppRecvMode])
#   capture   : la récolte journal + l'analyse (l'analyseur 4.25)
#   regkeys   : le pack des cartes d'expériences 4.37b (le jour 2)
set -e
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
SRC=${NVSRC:-/usr/src/nvidia-610.57.04}
REPO=/home/cheurteen/Projects/GPU-          # adapter si besoin
RECV=$REPO/tools/edpp/patch_rpc_recv.py
SEND=$REPO/tools/edpp/patch_rpc_final.py
ANALYZE=$REPO/tools/edpp/rpcdump_recv_analyze.py
CARDS=$REPO/lab/jalon411/v437b_regkey_cards.json
LOG=/tmp/capture-426.txt

case "$1" in
  prereq)
    echo "== le firmware = le STOCK obligatoire =="
    sha256sum "$FW" | cut -c1-16
    sha256sum "$FW.stock" 2>/dev/null | cut -c1-16 || echo "(pas de FW.stock — le premier jour: cp $FW $FW.stock)"
    [ -d "$SRC" ] || { echo "ABSENT: $SRC (le DKMS tree 610.57.04)"; exit 1; }
    grep -q "Issue RPC" "$SRC/src/nvidia/src/kernel/vgpu/rpc.c" && \
      { echo "le recv hook est DÉJÀ appliqué — restore d'abord si doute"; }
    echo "prereq OK"
    ;;
  patch)
    [ -f "$FW.stock" ] || cp "$FW" "$FW.stock"
    python3 "$RECV" --src "$SRC"
    [ -f "$SEND" ] && python3 "$SEND" --src "$SRC" || echo "(pas de send hook — recv seul OK pour le §7.2)"
    echo "patch appliqué. DKMS rebuild maintenant:"
    echo "  dkms build/install nvidia 610.57.04 (ou le flot distro) puis reboot"
    ;;
  restore)
    python3 "$RECV" --src "$SRC" --revert
    echo "recv reverté (byte-exact, 4.25)."
    ;;
  initramfs)
    echo "== les clés de capture (lecture unique au boot) =="
    echo "  mode complet (les 2 côtés, 3-4 Mo/boot) : RpcDump=1"
    echo "  EDPp only                              : RpcDump=1 RpcRecvMode=2"
    echo "  si le bit SBIOS ne vient pas (pas de GET) : ajouter EdppForceGet=1"
    echo "(le modprobe conf dans l'initramfs, le ré-alignement Blake2b après rebuild — 4.23)"
    ;;
  capture)
    journalctl -b -k | grep -E "RPCRECV|RPCDUMP76" > "$LOG" || true
    wc -l "$LOG"
    echo "== 1. le predict (la table §7.2 attendue) =="
    python3 "$ANALYZE" --predict
    echo "== 2. l'analyse de la capture réelle =="
    python3 "$ANALYZE" "$LOG" 2>/dev/null || python3 "$ANALYZE" < "$LOG"
    echo "== 3. le verdict §7.2 attendu de l'analyseur: len==96, le triplet"
    echo "   {100000,240000,250000} @ {40,44,48}, paramsSize==24, résidu zéro"
    echo "== 4. si zéro GET : le journal doit montrer l'absence du flow"
    echo "   _PLATFORM_SETEDPPEAKLIMITINFO_SET — un négatif honnête (4.25 §3)"
    ;;
  regkeys)
    echo "== le pack 4.37b : une clé, un boot, un delta =="
    python3 - "$CARDS" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1]))
print("chemin : ", d["regkey_path"])
print("protocole : ", d["protocol"])
for c in d["cards"][:10]:
    print(f"  {c['name']:38s} xrefs={c['pic_xrefs']:2d} risk={c['risk']:7s} test={c['test_value'][:40]}")
print("REFUSÉS:", ", ".join(r["name"] for r in d["refused_gate"]))
EOF
    ;;
  *) echo "usage : $0 {prereq|patch|restore|initramfs|capture|regkeys}"; exit 1 ;;
esac
