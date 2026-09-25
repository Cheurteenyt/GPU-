#!/usr/bin/env bash
# RUNBOOK 460 — LE JOUR NVML BYPASS : le contrôle direct par ioctl (la
# passe 4.60). USERSPACE PUR : zéro boot, zéro patch driver, zéro
# écriture firmware. Le GSP = le juge final ; la réversibilité = par
# construction (un ioctl = un appel, --restore).
#
# ── LES VERDICTS BANCARISÉS (lire avant tout geste) ────────────────────
# Le frame = PROUVÉ sur l'arbre EXACT 610.57.04 (imports/open-gpu-
# kernel-modules-610.57.04/) : NV_ESC_RM_CONTROL=0x2A (NVOS54=32B,
# 0xC020552A), NV_ESC_RM_ALLOC=0x2B (NVOS64=48B, 0xC030552B), FREE=0x29
# (12B), CHECK_VERSION_STR=210 ('F', 72B, 0xC04846D2) — les tailles =
# la validation kernel (nv.c nv_validate_ioctl_data + osapi.c
# RmValidateIoctl + escape.c, committés).
# LA DÉCOUVERTE 4.60 : les cmds power-limit NV0080 = ABSENTS du SDK
# public 610.57.04 (closed-only FINN). La famille publique = RatedTdp
# {0x2080206e/f} (résolue dans NOTRE rm.elf par 4.21, handler
# 0x163c42c). LES IDs EXACTS DU GET/SET mW = DÉCIDÉS PAR v460b SUR LA
# MACHINE (le shim LD_PRELOAD sur le -pl 250 qui a RÉUSSI) — pas par
# nous, pas ici. INDECIDABLE-BY-BYTES ici = décidé là-bas.
# Les leçons qui tiennent : /tmp = VOLATILE (copier les preuves) ;
# selftest d'abord ; le gate ACK ; le rollback = rien à rouler (le
# SET-back = le restore) — MAIS le ledger = sauvegardé hors /tmp.
# ────────────────────────────────────────────────────────────────────────
set -uo pipefail

EDPP="$(cd "$(dirname "$0")" && pwd)"
ACK="${RUNBOOK_460_ACK:-0}"
PL_NEW="${PL_NEW:-280000}"
PL_RESTORE="${PL_RESTORE:-250000}"
WORK="${V460_WORK:-$HOME/v460-day}"
mkdir -p "$WORK"

hdr() { echo; echo "== $* =="; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] manquant : $1"; exit 2; }; }

if [ "$ACK" != "1" ]; then
  echo "RUNBOOK_460_ACK=1 requis (le gate de la maison). Aujourd'hui :"
  echo "  §0 les guards + le selftest      (sans ACK)"
  echo "  §1 la capture du -pl 250         (sans ACK, lecture seule)"
  echo "  §2 l'analyse + la table          (sans ACK)"
  echo "  §3 le dry-run v460a              (sans ACK)"
  echo "  §4 LE SET $PL_NEW mW             (ACK requis)"
  echo "  §5 le verdict + la charge        (ACK requis)"
  echo "  le restore : PL_RESTORE=$PL_RESTORE"
  exit 1
fi

hdr "§0 : LES GUARDS (le état machine, la lecture seule)"
need gcc; need python3; need nvidia-smi
nvidia-smi -q -d POWER | sed -n '1,20p' | grep -E "Power Limit|Driver Version" || true
nvidia-smi --query-gpu=driver_version,name,power.limit --format=csv
VER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -1)
echo "driver live : $VER (l'attendu : 610.57.04 — sinon STOP, la table = un autre arbre)"
[ "$VER" = "610.57.04" ] || { echo "[!] STOP : le driver ≠ 610.57.04"; exit 2; }

hdr "§0.1 : LE SELFTEST OFFLINE (24 checks — TOUT VERT ou STOP)"
python3 "$EDPP/v460a_nvml_bypass.py" --selftest || { echo "[!] selftest = rouge"; exit 2; }

hdr "§1 : LA CAPTURE (le shim LD_PRELOAD sur le -pl 250 qui a réussi)"
cd "$WORK"
gcc -shared -fPIC -O2 -Wall -o v460b_ioctl_trace.so "$EDPP/v460b_ioctl_trace.c" -ldl || exit 2
echo "[*] le SET de référence (250) — la séquence NVML réelle, capturée :"
sudo LD_PRELOAD="$PWD/v460b_ioctl_trace.so" NV460_TRACE="$WORK/v460-pl250.log" \
     nvidia-smi -pl 250 || { echo "[!] le -pl 250 a échoué — la séquence de référence doit RÉUSSIR"; exit 2; }
echo "[*] copie du ledger hors /tmp : $WORK (déjà hors /tmp — la leçon 4.45)"
wc -l "$WORK/v460-pl250.log"

hdr "§2 : L'ANALYSE (la table de décode : qui = GET, qui = SET, où = le mW)"
python3 "$EDPP/v460b_analyze.py" "$WORK/v460-pl250.log" --pl 250 \
        --out "$WORK/v460-decode.json" || exit 2
echo "[*] la table : $WORK/v460-decode.json — VÉRIFIER le §set (cmd + offsets) ci-dessus"

hdr "§3 : LE DRY-RUN (la chaîne alloc + le GET — zéro écriture)"
sudo python3 "$EDPP/v460a_nvml_bypass.py" --table "$WORK/v460-decode.json" \
     --gpu 0 --ledger "$WORK/v460a-dryrun.json" || exit 2

hdr "§4 : LE SET $PL_NEW mW (LE BYPASS ARMÉ — le GSP = le juge)"
sudo python3 "$EDPP/v460a_nvml_bypass.py" --table "$WORK/v460-decode.json" \
     --mw "$PL_NEW" --arm --probe-ratedtdp --ledger "$WORK/v460a-set.json"
echo "   le code de sortie = le verdict brut ; le détail = le ledger"

hdr "§5 : LE VERDICT (l'observable binaire + la charge)"
echo "   [5.1] la relecture croisée :"
nvidia-smi --query-gpu=power.limit --format=csv,noheader
nvidia-smi -q -d POWER | grep -E "Power Limit" || true
echo "   [5.2] le cross-check NVML (accepte-t-il 280 maintenant ?) :"
echo "     sudo nvidia-smi -pl 280   # accepté = le break confirmé par NVML"
echo "   [5.3] LA CHARGE (le pilierB/Q2RTX, la limite tenue) :"
echo "     nvidia-smi --query-gpu=power.draw,clocks.sm,temperature.gpu --format=csv -l 5"
echo "   [5.4] le restore (le retour en arrière, prouvé par construction) :"
echo "     sudo python3 $EDPP/v460a_nvml_bypass.py --table $WORK/v460-decode.json --restore $PL_RESTORE --arm"

hdr "LA MATRICE DU VERDICT (le code 460a = la localisation du mur)"
echo "   SET rejeté (status != NV_OK)         -> LE MUR = kernel/x86-RM (le code nomme : 0x2E INVALID_LIMIT, 0x1B PERMISSIONS...)"
echo "   SET NV_OK + GET/smi inchangés        -> LE MUR = GSP (le check effectif = firmware-side ; le négatif DÉFINITIF, propre)"
echo "   SET NV_OK + GET/smi = $PL_NEW           -> LE BREAK (la NVML-check = le seul mur ; la double-couverture du runbook-457 §5)"
echo
echo "le ledger du jour :"
echo "  echo \"\$(date -Is) v460 verdict=\$?\" >> $WORK/bootledger.log"
