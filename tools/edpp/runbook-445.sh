#!/usr/bin/env bash
# RUNBOOK 445 — le jour du break ROP : le payload débordant v445 dans le
# memdesc signature (écrit PAR LE DRIVER, la mécanique 4.44), le boot,
# les observables, les refus automatiques.
#
# ── VERDICTS BANCARISÉS (lire avant tout geste) ────────────────────────
# 4.44-machine : le memdesc REPLACÉ = rejeté (le booter 0x1d) — le
#        memdesc = l'entrée de VÉRIFICATION. La lane "remplacement" =
#        MORTE. La lane vivante = le DÉBORDEMENT (le paper Zenodo
#        20916112, prouvé en silicium sur CETTE carte, le spin 0x4a7) :
#        la copie du memdesc sur la pile = DMA NON BORNÉ -> le payload
#        déborde -> le canari vaincu par l'uniformité -> le retour
#        détourné -> la chaîne ROP. Le verify ne s'exécute jamais.
# 4.45 TÂCHE A (v445a/v445b) : la copie = PAS dans bootloader.asm
#        (négatif borné : 44 frames, max 0x620 < 0x1000 ; 0 écriture
#        pile dans les boucles ; 10 services SBI sans destination pile ;
#        le booter = compilé SANS stack-protector) — la copie = dans le
#        BOOT ROM (fermé). Le canari/l'ordre/la distance = INDECIDABLE-
#        BY-BYTES — les expériences R0/R1 de CE runbook les décident.
# 4.45 TÂCHE B (v444e re-run + v445b) : 0 work-gadget dans le booter
#        (a1/a4 = le résidu ROM au terminal) ; le 1er write = [a1] =
#        SAUVAGE (inhérent) ; le post-write = la ré-entrée = le SPIN
#        (l'état final observé par le paper). Lane G (les gadgets du
#        ROM @0xf754/0xf76c, le paper) = la lane constructible ; Lane B
#        (0x100b3e) = la mécanique prouvée émulateur TR 18/18, le jour J
#        = SI le résidu R0 s'avère favorable.
# 4.45 TÂCHE B.2 (le mur du timing) : la cible f18 (obj+0x18+idx*0x30)
#        = allouée PAR LE RM APRÈS le boot — INATTEIGNABLE au stade ROM.
#        Les 5 options analysées : O1 f18 direct = MORT ; O2 les
#        graines survivantes = MORT (le memset) ; O3 le patch RM/WPR =
#        REFUSÉ (le 0xb, 4.38) ; O4 les boot-params = MORT (aucun champ
#        statique ne nourrit f18) ; O5 les registres MMIO (la route du
#        paper) = le SEUL survivant byte-cohérent.
# ────────────────────────────────────────────────────────────────────────
#
# Usage : sudo bash runbook-445.sh <étape>
#   prereq    : le firmware stock, les batteries émulateur (4), le
#               payload byte-exact, les comptes bankés (8/8 checks)
#   payload   : la construction v445 + le sha (le dump == le builder)
#   patch     : le drop-in C dans le DKMS tree (apres le portMemCopy de
#               _kgspCreateSignatureMemdesc, kernel_gsp.c:5697 — la
#               mécanique 4.44, le payload v445)
#   restore   : le revert byte-exact du patch driver (le rollback =
#               inchangé : le memdesc = réécrit stock par le driver)
#   r0        : le débordement BÉNIN (le fill seul + l'épine inerte
#               0x100aec, le ctx zéro = INERT — TT-D) : le mode de
#               panne DIFFÉRENTIEL vs 0x1d = la preuve du hijack.
#               GATÉ : RUNBOOK_445_ACK=1
#   r1        : l'échelle du fill (la distance de débordement) — la
#               balayage R1. GATÉ : RUNBOOK_445_ACK=1 ET r0 = hijack
#   r2        : la chaîne complète (les writes). GATÉ :
#               RUNBOOK_445_ACK=1 ET r1 = la distance trouvée
#   observe   : nvidia-smi -q -d POWER, dmesg (les codes booter),
#               RPCRECV (le flux SBI)
set -e
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
SRC=${NVSRC:-/usr/src/nvidia-610.57.04}
REPO=${REPO:-/home/cheurteen/Projects/GPU-} # adapter si besoin
EMU=$REPO/tools/booter_emu.py
BUILDER=$REPO/lab/jalon411/v445_rop_payload_build.py
BIN=$REPO/lab/jalon411/v445_rop_payload.bin
JSN=$REPO/lab/jalon411/v445_rop_payload.json
SCAN=$REPO/lab/jalon411/v445a_booter_copy.py
FILLLEN_FILE=/tmp/runbook445-filllen.txt    # la distance (u64)
FILLVAL_FILE=/tmp/runbook445-fillval.txt    # la valeur du canari-vaincu
MODE_FILE=/tmp/runbook445-r0-mode.txt       # le mode de panne r0

sha16() { sha256sum "$1" | cut -c1-16; }

checks_8() {
  echo "== les 8/8 checks (le refus automatique sinon) =="
  # 1-4. les batteries émulateur = les oracles sans risque
  python3 "$EMU" --selftest     | tail -1 | rg -q "5/5 PASS"     || { echo REFUS: selftest;     exit 2; }
  python3 "$EMU" --test-transfer| tail -1 | rg -q "11/11 PASS"  || { echo REFUS: test-transfer; exit 2; }
  python3 "$EMU" --test-444     | tail -1 | rg -q "9/9 PASS"    || { echo REFUS: test-444;     exit 2; }
  python3 "$EMU" --test-rop     | tail -1 | rg -q "18/18 PASS"  || { echo REFUS: test-rop;     exit 2; }
  echo "   [1-4] les batteries: selftest 5/5, TT 11/11, TF 9/9, TR 18/18 OK"
  # 5. le payload byte-exact vs le builder
  python3 - "$BUILDER" "$JSN" <<'EOF'
import hashlib, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("B", sys.argv[1])
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
p, _ = B.build()
got = hashlib.sha256(p).hexdigest()
want = json.load(open(sys.argv[2]))["sha256"]
sys.exit(0 if got == want else 3)
EOF
  if [ $? -ne 0 ]; then echo "REFUS: le builder != le payload commis"; exit 2; fi
  echo "   [5] le payload byte-exact OK"
  # 6. les comptes bankés re-assert (84 c.ret, 515 auipc)
  python3 "$SCAN" 2>/dev/null | rg -q "c.ret bytes 0x8082 = 84.*MATCH" || { echo REFUS: c.ret; exit 2; }
  python3 "$SCAN" 2>/dev/null | rg -q "auipc asm lines = 515.*MATCH"   || { echo REFUS: auipc; exit 2; }
  echo "   [6] les comptes bankés (84 c.ret, 515 auipc) OK"
  # 7. le garde dest != 0 (le TT-D : dest=0 = l'injection silencieusement morte)
  python3 - "$JSN" <<'EOF'
import json,sys; d=json.load(open(sys.argv[1]))
assert d["meta"]["dest"] != 0 and d["meta"]["slot0"] >= 1
EOF
  echo "   [7] le garde dest!=0 + slot0>=1 OK"
  # 8. UNE route, UNE cible (la leçon TF-C : pas d'application double)
  [ -f "$FILLVAL_FILE" ] || { echo "   [8] le fill_value = non posé (r0/r1 le décident) — OK au stade prereq"; }
  echo "== 8/8 OK =="
}

stage_prereq() {
  checks_8
  [ -f "$FW" ] || { echo "REFUS: le firmware absent"; exit 2; }
  echo "prereq: le firmware $FW présent ($(sha16 "$FW"))"
  echo "prereq: la lane = le DÉBORDEMENT (le memdesc = le véhicule, PAS le"
  echo "        remplacé — la leçon 4.44-machine). Les cibles = la classe"
  echo "        MMIO (O5) — la f18 = le mur du timing (le findings §B.2)."
}

stage_payload() {
  python3 "$BUILDER"
  echo "payload: $(sha16 "$BIN") ($(stat -c%s "$BIN") octets)"
}

stage_patch() {
  echo "patch: le drop-in C (la mécanique 4.44, le payload v445) —"
  echo "  l'ancre = kernel_gsp.c:5697 (apres le portMemCopy de"
  echo "  _kgspCreateSignatureMemdesc), le build = le juge (la leçon"
  echo "  4.44-machine #4 : l'ancre = le texte EXACT)."
  echo "  RAPPEL: dkms build/install + limine-mkinitcpio (le UKI = le"
  echo "  module EMBARQUÉ — la leçon #1) sinon = le chargement de"
  echo "  l'ANCIEN module = le faux négatif silencieux."
}

stage_restore() {
  echo "restore: le revert byte-exact du patch driver + dkms +"
  echo "  limine-mkinitcpio. Le memdesc = réécrit STOCK par le driver au"
  echo "  boot suivant = le rollback inchangé (~10 min, prouvé 4.44-machine)."
}

ack_gate() {
  [ "$RUNBOOK_445_ACK" = "1" ] || { echo "REFUS: RUNBOOK_445_ACK!=1 (la gate)"; exit 4; }
}

stage_r0() {
  ack_gate
  echo "r0 = le DÉBORDEMENT BÉNIN : le fill seul + l'épine INERTE"
  echo "  (l'entrée 0x100aec, le ctx zéro file-backed = INERT, TT-D —"
  echo "  ZÉRO écriture). La question : le MODE DE PANNE."
  echo "  - si la panne != 0x1d (le hang, le code différent, le spin) :"
  echo "    le verify = CONTOURNÉ = le hijack confirmé (le paper)."
  echo "  - si la panne = 0x1d : l'ordre copie/compare = mauvais chez"
  echo "    nous -> LA LANE = MORTE avant de coder (la réponse honnête)."
  echo "  Observables : dmesg (le code), le spin PC si lisible, le SBI."
  echo "  POSER le mode observé : echo <mode> > $MODE_FILE"
}

stage_r1() {
  ack_gate
  [ -f "$MODE_FILE" ] || { echo "REFUS: r0 non exécuté (le mode absent)"; exit 5; }
  rg -qv "0x1d" "$MODE_FILE" || { echo "REFUS: r0 = 0x1d (la lane morte — pas de r1)"; exit 5; }
  echo "r1 = l'ÉCHELLE du fill : la balayage de fill_len (la distance au"
  echo "  slot de retour). Le pas = 8 u64, la borne = 0x1000/8. Le critère :"
  echo "  le CHANGEMENT de mode de panne = la distance trouvée."
  echo "  POSER : echo <fill_len> > $FILLLEN_FILE ; echo <fill_value> > $FILLVAL_FILE"
  echo "  (le fill_value = la valeur du canari-vaincu — le paper = la"
  echo "   source; l'hypothèse zéro = le candidat par défaut, ACK-gaté)."
}

stage_r2() {
  ack_gate
  [ -f "$FILLLEN_FILE" ] || { echo "REFUS: r1 non exécuté"; exit 6; }
  echo "r2 = la CHAÎNE complète (les writes) — le payload reconstruit avec"
  echo "  fill_len=$(cat "$FILLLEN_FILE"), fill_value=$(cat "$FILLVAL_FILE" 2>/dev/null || echo 0)."
  echo "  RAPPELS honnêtes (le findings §B) : le 1er write = [a1] = le"
  echo "  résidu = SAUVAGE ; le post-write = le SPIN (l'état final du"
  echo "  paper). La cible = la classe MMIO (O5) — PAS la f18 (le mur du"
  echo "  timing). Le reset = le chemin du driver (le timeout GSP)."
}

stage_observe() {
  echo "== les observables =="
  nvidia-smi -q -d POWER | sed -n '1,12p' || true
  nvidia-smi -pl 280 2>&1 || true
  dmesg | rg -i "booter|NVRM|Xid" | tail -12 || true
  echo "RPCRECV: le flux SBI (les events du booter) — le runbook-426 §7."
}

case "${1:-}" in
  prereq)  stage_prereq ;;
  payload) stage_payload ;;
  patch)   stage_patch ;;
  restore) stage_restore ;;
  r0)      stage_r0 ;;
  r1)      stage_r1 ;;
  r2)      stage_r2 ;;
  observe) stage_observe ;;
  *) rg -n "^#   (prereq|r0|r1|r2|observe|payload|patch|restore)" "$0" ;;
esac
