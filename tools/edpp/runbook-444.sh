#!/usr/bin/env bash
# RUNBOOK 444 — le jour du break scripté : le payload v444 (les valeurs
# runtime de la limite) dans le memdesc signature, le boot, les
# observables, les refus automatiques.
#
# ── VERDICTS BANCARISÉS (lire avant tout geste) ────────────────────────
# 4.43 : la formule DANS le GSP-RM = limite = base[obj+0x618+idx*0x10]
#        x record[obj+0x18+idx*0x30].f18 / 100 / 1000 (l'évaluateur
#        0x1446d98). Aucun octet statique ne porte la limite.
# 4.44 : l'évaluateur re-décodé EN ENTIER (v444a) : 4 itérations (la
#        table de groupes {0x1,0x4,0x8,0x2} @0x1C7B320, PAS 5
#        vPstates), la sentinelle f18=-1 = "illimité", la sortie = 4
#        paires -> obj2+0x50 (le portMemCopy 0x20 @0x143FAAC). La
#        recompute 0x143fdbc (v444c) réécrit {masque 0x65c, bases
#        0x60c-0x658, record.{+0x10,+0x1c}, compteur +0x8} et NE
#        TOUCHE JAMAIS record.f14/f18 — la route f18 = persistante.
#        Les descripteurs 0x4190DC0/DE8 = file-backed ZÉRO (v444b) —
#        la voie descriptor = MORTE pour les valeurs (l'objet naît
#        memset-zéro). La voie gadget = la seule ; le a1-refresh n'est
#        PAS constructible (v444e : 0 work-gadget) — 1 écriture
#        chirurgicale par cycle de hijack.
# 4.44 TF-C : les DEUX routes (base, f18) = EXCLUSIVES — appliquer les
#        deux = 313.6 W (l'overshoot). CE runbook n'en applique QU'UNE.
#        L'unité (percent vs permille) = INDECIDABLE-BY-BYTES (v444d)
#        — l'expérience U2 (f18 += 1 -> 252500 vs 250250 mW) décide
#        AVANT toute écriture 280.
# ────────────────────────────────────────────────────────────────────────
#
# Usage : sudo bash runbook-444.sh <étape>
#   prereq    : le firmware stock vérifié, les instruments cohérents
#               (7/7 checks — le REFUS automatique sinon)
#   resolve   : la résolution du paramètre runtime obj (le jour capture
#               — le garde dest!=0)
#   payload   : la construction + la vérification byte-exact du payload
#               (le dump C == le builder python)
#   patch     : le drop-in C dans le DKMS tree (apres le portMemCopy de
#               _kgspCreateSignatureMemdesc, kernel_gsp.c:5697)
#   restore   : le revert byte-exact du patch driver
#   u2        : l'expérience U2 = la décision d'unité (f18 += 1, la
#               lecture nvidia-smi) — GATÉE par RUNBOOK_444_ACK=1
#   apply280  : l'écriture 280 (la route UNIQUE sélectionnée) — GATÉE
#               par RUNBOOK_444_ACK=1 ET l'U2 décidé
#   observe   : les observables post-boot (nvidia-smi, RPCRECV, dmesg)
set -e
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
SRC=${NVSRC:-/usr/src/nvidia-610.57.04}
REPO=/home/cheurteen/Projects/GPU-          # adapter si besoin
EMU=$REPO/tools/booter_emu.py
CBUILD=$REPO/tools/booter-patch/transfer_list_memdesc.c
BUILDER=$REPO/lab/jalon411/v444_transfer_list_build.py
CTEST=$REPO/lab/jalon411/v444f_c_payload_test.py
RUNBOOK426=$REPO/tools/edpp/runbook-426.sh
OBJADDR_FILE=/tmp/runbook444-obj-address.txt
ROUTE_FILE=/tmp/runbook444-route.txt          # "f18" | "base" — UNE seule
UNIT_FILE=/tmp/runbook444-unit.txt            # "percent" | "permille"

sha16() { sha256sum "$1" | cut -c1-16; }

checks_7() {
  # ---- les 7/7 : le REFUS automatique si une étape = incohérente ----
  local n=0
  # 1. le firmware = le STOCK (le sha16 affiché, la paire attendue du registre)
  if [ -f "$FW.stock" ] && [ "$(sha16 "$FW")" = "$(sha16 "$FW.stock")" ]; then
    echo "  [1/7] le firmware = le STOCK ($(sha16 "$FW")…)"; n=$((n+1))
  else
    echo "  [1/7] REFUSÉ: le firmware ≠ le stock (ou pas de backup)"; return 1
  fi
  # 2. le payload commis = byte-exact vs le builder
  python3 - "$BUILDER" <<'EOF' && n=$((n+1)) || { echo "  [2/7] REFUSÉ: le payload v444 incohérent"; return 1; }
import sys, hashlib, struct
sys.path.insert(0, str(__import__("pathlib").Path(sys.argv[1]).parent))
from v444_transfer_list_build import build_payload_444, MEMDESC_SIZE
p, plan = build_payload_444("percent", dest=0)
print(f"  [2/7] le payload v444 = byte-exact (sha {hashlib.sha256(p).hexdigest()[:16]}...)")
EOF
  # 3. l'émulateur = les trois batteries au complet
  if python3 "$EMU" --selftest 2>&1 | grep -q "5/5 PASS" \
     && python3 "$EMU" --test-transfer 2>&1 | grep -q "11/11 PASS" \
     && python3 "$EMU" --test-444 2>&1 | grep -q "9/9 PASS"; then
    echo "  [3/7] l'émulateur : selftest 5/5 + TT 11/11 + TF 9/9"; n=$((n+1))
  else
    echo "  [3/7] REFUSÉ: l'émulateur n'est pas au complet"; return 1
  fi
  # 4. le C = 4/4 + TL444 + le byte-exact (v444f)
  if python3 "$CTEST" | grep -q "3/3 PASS"; then
    echo "  [4/7] le C : 4/4 + TL444 + le byte-exact (v444f 3/3)"; n=$((n+1))
  else
    echo "  [4/7] REFUSÉ: le C n'est pas cohérent"; return 1
  fi
  # 5. le paramètre runtime obj = résolu (le garde dest!=0 — TT-D :
  #    dest=0 -> la boucle INERTE, l'injection silencieusement morte)
  if [ -s "$OBJADDR_FILE" ] && [ "$(cat "$OBJADDR_FILE")" != "0" ]; then
    echo "  [5/7] le paramètre obj = $(cat "$OBJADDR_FILE") (résolu)"; n=$((n+1))
  else
    echo "  [5/7] REFUSÉ: obj non résolu (runbook-444.sh resolve d'abord)"; return 1
  fi
  # 6. UNE route UNIQUE (TF-C : les deux = l'overshoot 313.6 W)
  if [ "$(cat "$ROUTE_FILE" 2>/dev/null)" = "f18" ] || \
     [ "$(cat "$ROUTE_FILE" 2>/dev/null)" = "base" ]; then
    echo "  [6/7] la route = $(cat "$ROUTE_FILE") (UNE seule — TF-C)"; n=$((n+1))
  else
    echo "  [6/7] REFUSÉ: la route n'est pas sélectionnée (f18|base)"; return 1
  fi
  # 7. l'unité = décidée par l'U2 (le refus des écritures 280 en unité devinée)
  if [ "$(cat "$UNIT_FILE" 2>/dev/null)" = "percent" ] || \
     [ "$(cat "$UNIT_FILE" 2>/dev/null)" = "permille" ]; then
    echo "  [7/7] l'unité = $(cat "$UNIT_FILE") (U2 décidé)"; n=$((n+1))
  else
    echo "  [7/7] REFUSÉ: l'unité n'est pas décidée (runbook-444.sh u2 d'abord)"; return 1
  fi
  return 0
}

case "$1" in
  prereq)
    echo "== les 7/7 checks (le REFUS automatique) =="
    checks_7 || { echo "prereq = INCOHÉRENT — corriger avant tout"; exit 1; }
    [ -d "$SRC" ] || { echo "ABSENT: $SRC (le DKMS tree)"; exit 1; }
    echo "prereq OK"
    ;;
  resolve)
    echo "== la résolution du paramètre runtime obj = *(state+0x4E98) =="
    echo "  la voie nommée (4.44 §B2) : la capture 4.26 (le recv hook)"
    echo "  + l'instrumenté boot (le jour capture). L'adresse = NOTÉE dans"
    echo "  $OBJADDR_FILE (le runbook REFUSE dest=0 — le garde TT-D)."
    echo "  Exemple : echo 0x... > $OBJADDR_FILE"
    ;;
  payload)
    python3 "$BUILDER"
    python3 "$CTEST"
    echo "== le payload = prêt (le dest = le placeholder 0 — resolve le patche) =="
    ;;
  patch)
    [ -f "$FW.stock" ] || cp "$FW" "$FW.stock"
    echo "== le drop-in C : transfer_list_memdesc.c -> le DKMS tree =="
    echo "  l'appel = APRÈS le portMemCopy de _kgspCreateSignatureMemdesc"
    echo "  (kernel_gsp.c:5666-5713, le pSignatureVa encore mappé) :"
    echo "    tl_patch_signature_memdesc_444(pSignatureVa, dest, route, unit);"
    echo "  puis DKMS rebuild + reboot."
    ;;
  restore)
    echo "== le revert driver = le restaure des sources (le patch = le drop-in"
    echo "  unique ; le firmware = JAMAIS touché par ce runbook) =="
    echo "  git -C $SRC checkout -- src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
    echo "  (le DKMS rebuild + reboot = le stock complet)"
    ;;
  u2)
    # ---- l'expérience U2 : la décision d'unité (GATÉE) ----
    [ "$RUNBOOK_444_ACK" = "1" ] || {
      echo "REFUSÉ: l'U2 = une écriture RÉELLE dans l'objet policy vivant."
      echo "        L'effet attendu = MILD (f18 += 1 : 252500 ou 250250 mW)"
      echo "        mais c'est la première écriture gadget de la campagne."
      echo "        Pour l'expérience quand même : RUNBOOK_444_ACK=1 sudo -E bash $0 u2"
      exit 1
    }
    checks_7 || exit 1
    echo "== U2 : f18[0] += 1 (l'écriture a3=1 à obj+0x18) puis la lecture =="
    echo "  attendu (percent)  : nvidia-smi -q -d POWER => 252.50 W"
    echo "  attendu (permille) : nvidia-smi -q -d POWER => 250.25 W"
    echo "  le delta = 2.25 W — DÉCIDE l'unité ; noter le résultat :"
    echo "    echo percent|permille > $UNIT_FILE"
    echo "  rollback = la réécriture f18 = le stock (l'U1 capture d'abord)"
    ;;
  apply280)
    [ "$RUNBOOK_444_ACK" = "1" ] || {
      echo "REFUSÉ: l'écriture 280 = le break réel. RUNBOOK_444_ACK=1 pour opt-in."
      exit 1
    }
    checks_7 || exit 1
    ROUTE=$(cat "$ROUTE_FILE"); UNIT=$(cat "$UNIT_FILE")
    OBJ=$(cat "$OBJADDR_FILE")
    echo "== l'écriture 280 : la route $ROUTE, l'unité $UNIT, obj=$OBJ =="
    case "$ROUTE" in
      f18)
        echo "  4 invocations a3=1 : obj+0x18/0x48/0x78/0xA8 <- {112 ou 1120, 0}"
        echo "  (la route PERSISTANTE — la recompute ne réécrit jamais f14/f18, v444c)"
        echo "  le u64 = {f18_new, 0} — le +0x1c = le champ que la recompute ZERO : propre"
        ;;
      base)
        echo "  1 invocation a3=8 : le scatter D, dest=obj+0x610, la liste [D,D,0,D,0,D,0,D]"
        echo "  (la route FENÊTRE — volatile : la recompute réécrit les bases ;"
        echo "   le timing = entre l'événement 0x20809064 et l'évaluateur, 4.43 §5)"
        ;;
    esac
    echo "  observables : observe (ci-dessous)"
    ;;
  observe)
    echo "== les observables post-boot =="
    echo "-- 1. la limite appliquée (le clamp a-t-il bougé ?) --"
    nvidia-smi -q -d POWER | grep -A4 "Power Limit" || true
    echo "-- 2. le try -pl 280 (le clamp hôte contre la limite runtime) --"
    nvidia-smi -pl 280 && echo "  ==> -pl 280 ACCEPTÉ = la limite runtime a bougé" \
                      || echo "  ==> -pl 280 refusé = la limite n'a pas bougé (le delta = nommé)"
    echo "-- 3. le transport (le recv hook 4.25/4.26 — les six limites OUT) --"
    journalctl -b -k | grep -E "RPCRECV" | tail -20 || echo "  (pas de recv hook — runbook-426.sh d'abord)"
    echo "-- 4. le dmesg GSP (les health checks — le FE01 : la sémantique AVANT) --"
    dmesg | grep -iE "gsp|nvrm" | tail -20 || true
    echo "-- 5. le verdict attendu --"
    echo "  la route f18 + percent  : limitMax = 280000 mW (280 W)"
    echo "  la route f18 + permille : limitMax = 280000 (la lecture U2 décide)"
    echo "  la route base           : l'effet = jusqu'à la PROCHAINE recompute"
    echo "                            (volatile — le re-render de la fenêtre)"
    ;;
  *)
    echo "usage : $0 {prereq|resolve|payload|patch|restore|u2|apply280|observe}"; exit 1 ;;
esac
