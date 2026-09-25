#!/usr/bin/env bash
# RUNBOOK 453 — le jour r2 : LA SONDE TAPIS (le control lane, la passe
# 4.53). Le tapis = l'anti-stratégie au RA inconnu (la leçon r1 : le RA
# = au-delà du bloc ctx, le mot > 145 — INDECIDABLE-BY-BYTES, le ROM
# fermé). Peu importe le mot du RA : le retour tombe sur une entrée
# VIVANTE (l'entrée-spine ou le terminal 0x100b3e, TR 18/18 + TR2
# 21/21) — l'observable = le comportement ≠ le spin-garbage de r1.
#
# ── VERDICTS BANCARISÉS (lire avant tout geste) ────────────────────────
# 4.45-machine (r0/r1) : le hijack = CONFIRMÉ EN SILICIUM (le copy+
#        overflow AVANT le verify, SANS 0x1d) ; le spin = UNIFORME sur
#        fill_len {64,96,112} x fill_value {0,0x4a7} => le RA = dans la
#        queue 0xFF AU-DELÀ du bloc ctx (le mot > 145). LE LEVIER = la
#        relocalisation + le tapis (le builder v446).
# 4.53 T1 (v446) : le layout TOTALEMENT relocalisable ; le mode CARPET
#        pair = {entrée-spine, terminal} répété sur toute la zone
#        post-fill ; le mode aligned = le pop-aligné (+8 = TOUJOURS un
#        terminal — la propriété auto-assertée au build). Selftest
#        28/28 (3 bugs attrapés AVANT le founder : la diff reloc sans
#        le walk cell ; le G40 @508 dont le pop sort de la fenêtre ; le
#        mask c.ldsp 0x6002).
# 4.53 T4 (TR2 21/21, l'image réelle) : LA DÉCOUVERTE du pass — le ctx
#        = a4-RELATIF aux offsets OCTETS FIXES (le slot @a4+0x488, le
#        dest @a4+0x498) ; le ctx du v445 @0x488 = la CONJUGAISON
#        a4 = PAY. La relocalisation du ctx = le PAIR (ctx_off, a4).
#        Le walk cell + la liste = LIBRES ([sp+8]). Les classes du
#        tapis pair : l'impair = la capture IMMÉDIATE (le compteur
#        +1), le pair = la marche G40 (sans écriture), la queue = la
#        classe nommée (le walk cell hors fenêtre). L'aligned = 100%
#        capture un-pas (27/27 + la queue nommée 2/2).
# 4.45 TÂCHE B (les murs, inchangés) : W1 le 1er write = [a1] = le
#        RÉSIDU (sauvage) ; W3 le post-write = la ré-entrée = le spin.
#        Les opérandes de la capture = le résidu ROM (a1/a3/a4) —
#        INDECIDABLE-BY-BYTES (le R0 de runbook-445 les découvre).
# ────────────────────────────────────────────────────────────────────────
#
# Usage : sudo bash runbook-453.sh <étape>
#   prereq    : les 9 checks (les 6 batteries + le selftest v446 + les
#               comptes bankés + le sha du firmware stock) — le refus
#               automatique sinon
#   build     : le tapis PAIR (le défaut v446, fill_len=112) + le
#               header C + le sha
#   patch     : le drop-in C dans le DKMS tree (la mécanique 4.44/4.45,
#               l'ancre apres le portMemCopy) — le build = le juge ;
#               dkms + limine-mkinitcpio (le UKI = le module embarqué,
#               la leçon #1 de 4.44-machine — sinon = le faux négatif)
#   r2a       : LE BOOT TAPIS (pair). GATÉ : RUNBOOK_453_ACK=1.
#               L'observable = la CARTE : progress / boot / hang
#               (POSER : echo <mode> > $MAP_FILE)
#   r2b       : le tapis ALIGNED (le pop-aligné). GATÉ : RUNBOOK_453_ACK=1
#               ET la carte r2a POSÉE (le chaînage = la discipline 445)
#   observe   : dmesg (GFW_BOOT progress, le code booter), nvidia-smi,
#               la carte
#   restore   : le revert byte-exact + dkms + UKI. LE ROLLBACK = LE
#               DRIVER SEUL (~2 commandes depuis les stocks, prouvé 3x
#               le jour machine ; 0 chaîne v445/v446 dans le module
#               stock, le firmware sha = c0156954 intact)
set -e
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
SRC=${NVSRC:-/usr/src/nvidia-610.57.04}
GSPDIR=$SRC/src/nvidia/src/kernel/gpu/gsp
REPO=${REPO:-/home/cheurteen/Projects/GPU-}   # adapter si besoin
EMU=$REPO/tools/booter_emu.py
BUILDER=$REPO/lab/jalon411/v446_rop_payload_build.py
BIN=$REPO/lab/jalon411/v446_rop_payload.bin
JSN=$REPO/lab/jalon411/v446_rop_payload.json
HDR=/tmp/runbook453/v446_payload.h
MAP_FILE=/tmp/runbook453-map.txt              # la carte r2a (progress/boot/hang)
MODE2_FILE=/tmp/runbook453-r2a-mode.txt       # le mode de panne brut (dmesg)
CARPET_MODE=${CARPET_MODE:-pair}              # pair | aligned

sha16() { sha256sum "$1" | cut -c1-16; }

checks_9() {
  echo "== les 9/9 checks (le refus automatique sinon) =="
  python3 "$EMU" --selftest     | tail -1 | rg -q "5/5 PASS"     || { echo REFUS: selftest; exit 2; }
  python3 "$EMU" --test-transfer| tail -1 | rg -q "11/11 PASS"  || { echo REFUS: test-transfer; exit 2; }
  python3 "$EMU" --test-444     | tail -1 | rg -q "9/9 PASS"    || { echo REFUS: test-444; exit 2; }
  python3 "$EMU" --test-rop     | tail -1 | rg -q "18/18 PASS"  || { echo REFUS: test-rop; exit 2; }
  python3 "$EMU" --test-timings | tail -1 | rg -q "5/5 PASS"    || { echo REFUS: test-timings; exit 2; }
  python3 "$EMU" --test-rop2    | tail -1 | rg -q "21/21 PASS"  || { echo REFUS: test-rop2; exit 2; }
  echo "   [1-6] les batteries: 5/5, TT 11/11, TF 9/9, TR 18/18, TT-T 5/5, TR2 21/21 OK"
  python3 "$BUILDER" --selftest | tail -1 | rg -q "28/28 PASS"  || { echo REFUS: v446 selftest; exit 2; }
  echo "   [7] le selftest v446 28/28 (les invariants + le tree guard + le C byte-exact) OK"
  python3 - "$BUILDER" "$JSN" <<'EOF'
import hashlib, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("B", sys.argv[1])
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
p, _ = B.build_carpet(fill_len=112, mode="pair")
got = hashlib.sha256(p).hexdigest()
want = json.load(open(sys.argv[2]))["sha256"]
sys.exit(0 if got == want else 3)
EOF
  [ $? -eq 0 ] || { echo "REFUS: le builder != le payload commis"; exit 2; }
  echo "   [8] le payload tapis pair byte-exact OK"
  [ -f "$FW" ] || { echo "REFUS: le firmware absent"; exit 2; }
  echo "   [9] le firmware $FW présent ($(sha16 "$FW")) — le stock = c0156954… attendu"
  echo "== 9/9 OK =="
}

stage_prereq() { checks_9; }

stage_build() {
  checks_9
  mkdir -p /tmp/runbook453
  CARPET_MODE="$CARPET_MODE" python3 - "$BUILDER" "$HDR" <<'EOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("B", sys.argv[1])
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
mode = __import__('os').environ.get("CARPET_MODE", "pair")
p, m = B.build_carpet(fill_len=112, mode=mode)
open(sys.argv[2], "w").write(B.emit_c(p))
open("/tmp/runbook453/v446_payload_r2.bin", "wb").write(p)
import hashlib; print(f"tapis {mode}: {len(p)} B, sha16={hashlib.sha256(p).hexdigest()[:16]}, "
                      f"spine={m['spine_entries']} terminal={m['terminals']}")
EOF
  echo "build: le header = $HDR (le symbole v446_payload) — le drop-in"
  echo "  l'embarque (le pattern r1point 4.45-machine)."
}

stage_patch() {
  [ -f "$HDR" ] || { echo "REFUS: build d'abord (le header absent)"; exit 3; }
  cp "$HDR" "$GSPDIR/v446_payload.h"
  echo "patch: le header copié dans le DKMS tree. LE DROP-IN = le"
  echo "  v445_memdesc_patch.c (l'ancre exacte apres le portMemCopy de"
  echo "  _kgspCreateSignatureMemdesc, la mécanique 4.44) — le payload"
  echo "  embarqué = MAINTENANT le tapis v446. Le build = le juge."
  echo "  RITUEL COMPLET : dkms build/install --force + limine-mkinitcpio"
  echo "  (le UKI = le module EMBARQUÉ — la leçon 4.44-machine #1)."
  echo "  VÉRIF d'embarquement : strings le .ko | rg v446_payload"
}

ack_gate() {
  [ "$RUNBOOK_453_ACK" = "1" ] || { echo "REFUS: RUNBOOK_453_ACK!=1 (la gate)"; exit 4; }
}

stage_r2a() {
  ack_gate
  [ -f "$HDR" ] || { echo "REFUS: build d'abord"; exit 3; }
  echo "r2a = LE BOOT TAPIS (mode=$CARPET_MODE). La question : la CARTE."
  echo "  Le dmesg à lire (le timeout du driver = ~2-4 min) :"
  echo "    'GSP failed to halt with GFW_BOOT: (progress 0x??)'"
  echo "  LA DÉCISION (le mode de décision du founder) :"
  echo "    progress  : le progress ≠ 0xff OU une étape dmesg INÉDITE"
  echo "                (le flux = allé plus loin que le spin r1 — la"
  echo "                capture = un état DIFFÉRENT, la carte = marquée)"
  echo "    boot      : le boot COMPLÈTE (le wallpaper arrive, le driver"
  echo "                proceed) — le capture + le rejoin (inattendu, à"
  echo "                documenter tel quel)"
  echo "    hang      : progress 0xff + le timeout = le spin (le march"
  echo "                pair OU le RA hors classe capture — INCONCLUSIF"
  echo "                pour la capture, la classe = le march vivant ≠ le"
  echo "                trap 0xFF de r1 si le pattern diffère)"
  echo "  RAPPELS honnêtes : le 1er write de la capture = [a1] = le"
  echo "  RÉSIDU (W2, sauvage) ; les opérandes = le résidu ROM (R0 de"
  echo "  runbook-445 les découvre) ; le reset = le chemin du driver."
  echo "  POSER : echo <progress|boot|hang> > $MAP_FILE"
  echo "          echo '<la ligne dmesg brute>' > $MODE2_FILE"
}

stage_r2b() {
  ack_gate
  [ -f "$MAP_FILE" ] || { echo "REFUS: r2a non exécuté (la carte absente)"; exit 5; }
  echo "r2b = le tapis ALIGNED (le pop-aligné : +8 = TOUJOURS un"
  echo "  terminal — la capture un-pas, LES DEUX classes, TR2-E 27/27)."
  echo "  La comparaison pair vs aligned = la traverse : si aligned ≠"
  echo "  pair sur la carte => le RA = la classe march du pair (le"
  echo "  capture n'a jamais eu lieu) ; si identiques => le RA = déjà"
  echo "  la classe capture (le terminal a déjà parlé)."
  echo "  BUILD : CARPET_MODE=aligned bash $0 build  puis patch + boot."
  echo "  POSER : echo 'aligned:<mode>' >> $MAP_FILE"
}

stage_observe() {
  echo "== les observables =="
  dmesg | rg -i "GFW_BOOT|booter|NVRM|Xid" | tail -14 || true
  [ -f "$MAP_FILE" ] && { echo "== la carte =="; cat "$MAP_FILE"; } || true
  nvidia-smi -q -d POWER | sed -n '1,10p' || true
  echo "RPCRECV: le flux SBI (le runbook-426 §7) — les events du booter."
}

stage_restore() {
  echo "restore: le revert byte-exact du patch driver (le header + le"
  echo "  drop-in) + dkms build/install --force + limine-mkinitcpio."
  echo "  LE ROLLBACK = LE DRIVER SEUL (~2 commandes, prouvé 3x le jour"
  echo "  machine). VÉRIF : 0 'v446_payload' dans le module stock ; le"
  echo "  firmware $FW = $(sha16 "$FW") (le stock = c0156954… intact)."
  echo "  Le boot suivant = le memdesc réécrit STOCK par le driver."
}

case "${1:-}" in
  prereq)  stage_prereq ;;
  build)   stage_build ;;
  patch)   stage_patch ;;
  r2a)     stage_r2a ;;
  r2b)     stage_r2b ;;
  observe) stage_observe ;;
  restore) stage_restore ;;
  *) rg -n "^#   (prereq|build|patch|r2a|r2b|observe|restore)" "$0" ;;
esac
