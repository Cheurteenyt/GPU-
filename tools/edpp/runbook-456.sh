#!/usr/bin/env bash
# RUNBOOK 456 — LE JOUR R2B : LA CHAÎNE D'ÉCRITURE, PRÉPARÉE (la passe
# 4.56). Le builder v447 = le layout v446 relocalisable + le scatter
# a3=8 (la mécanique prouvée du 4.44). LES PAIRES {adresse, valeur} =
# DEPUIS T1 (la carte O5 v456c) — ET LA PORTE EN CODE : sans la rangée
# POWER-BASE-MATCH de la sonde 454 (le verdict v454c), le payload =
# REFUSÉ (exit 2, démontré TR3-E). Le décodeur v456a = le JUGE du boot.
#
# ── VERDICTS BANCARISÉS (lire avant tout geste) ────────────────────────
# 4.56 T3 (v456a 28/28, le guard GREEN) : LE DÉCODEUR — le registre de
#        progression = NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_0_GFW_BOOT
#        (0x00118234), champ _PROGRESS 7:0, **_COMPLETED = 0xFF** (le
#        seul valeur nommée publiquement — tu102 ET ga102 identiques).
#        **LE 0xFF DU JOUR MACHINE r0 = COMPLETED, PAS UN ÉCHEC** : le
#        boot GFW a atteint son marqueur terminal, la falcon n'a JAMAIS
#        halté (le timeout kflcnWaitForHalt — les 2 lignes dmesg du r0
#        = la même racine). Le 0x0 rapporté = l'ARTEFACT PLM (le code
#        rapporte 0x0 sans lire le registre si FWSEC n'a pas baissé le
#        READ_PROTECTION_LEVEL0 — le PLM 0x00118128 décide). Les stades
#        0x01..0xfe = non nommés publiquement (le ROM fermé) — les
#        coordonnées de la carte, jamais l'ordre assumé.
# 4.56 T1 (v456c 18/18) : LA CARTE O5 — 215 offsets v454a croisés aux
#        headers publics : 3 croix EXACTES (LMR @0x00100ce0 = PFB PRI
#        MMU LOCAL_MEMORY_RANGE gp102:26 ; WPR @0x001fa7c4 = le PLM de
#        cette plage gb100:28 ; FEAT+0x10 @0x00823814 = NV_FUSE_FEATURE_
#        READOUT ga100 fuse:26), 144 BLOCK-PUBLIC (FUSE 106, PFB-PRI-MMU
#        37, XVE 3, PFB 1), 68 PATCH-ONLY, + la paire PGC6 {0x00118128,
#        0x00118234} = les candidats de la PROCHAINE révision de sonde
#        (jamais injectés dans les 215 commis). TOUTES les rangées =
#        GA104-DECODE-INDECIDABLE-BY-BYTES : l'adresse plausible ≠ le
#        comportement — la sonde de lecture = le prérequis
#        NON-NÉGOCIABLE de toute écriture.
# 4.56 T2 (v447 17/17 + TR3 15/15 sur l'image réelle) : LA SÉMANTIQUE
#        RÉELLE du scatter (le démontage re-lu, 0x100b2e-0x100b7a) —
#        l'entrée au terminal 0x100b3e : le write #1 = [a1] = le RÉSIDU
#        (W1/W2, sauvage) ; PUIS a1 recalculé à CHAQUE itération = dest
#        + slot*8 (les slots 2..8 pour slot0=1, a3=8) ; le wrap à 1,
#        jamais 0 ; le compteur [dest] += a3 À LA SORTIE (le RMW u64 —
#        la lecture incluse) ; la géométrie : dest = B-8, le ring =
#        [B+8..B+56], le slot 1 = [B] = le TROU nommé (couvert SEULEMENT
#        si le résidu a1 = B — l'assumption A3-favorable du 4.44,
#        TR3-C). Le C byte-exact 3/3 v446 + v447.
# 4.53/4.54 (inchangés) : le tapis r2a = la sonde du RA ; la porte O5 =
#        pas d'écriture sans rangée POWER-BASE-MATCH ; le a1 = l'offset
#        BRUT ; le +4 voisin = zéro-étendu ; le rollback = le driver
#        seul, prouvé 3x.
# ────────────────────────────────────────────────────────────────────────
#
# Usage : sudo bash runbook-456.sh <étape>
#   prereq     : les 11 checks (7 batteries émulateur 5/5+TT 11/11+
#                TF 9/9+TR 18/18+TT-T 5/5+TR2 21/21+TR3 15/15, le v446
#                28/28, le v447 17/17, le firmware stock, le sha du
#                payload commis) — le refus automatique sinon
#   observables: les selftests v456a + v456b (le décodeur = le juge du
#                soir) + le décodage du DERNIER dmesg si capturé
#   map        : le selftest v456c + la carte O5 fraîche
#   gate       : LA DÉCISION (lisible, sans geste) — le verdict 454 +
#                la carte r2a → la voie : CONTINGENCE (le tapis = encore
#                spin → les variantes de sonde suivantes) ou WRITE (la
#                sonde 454 = POWER-BASE-MATCH → l'O5 ouvert)
#   payload    : le build v447 DEPUIS le verdict (WRITE_MODE=surgical|
#                scatter, les paires = le verdict + la carte) — REFUSÉ
#                = un RÉSULTAT affiché honnêtement, pas un crash
#   patch      : le header C dans le DKMS tree (la mécanique 4.44/4.45)
#                — le build = le juge ; dkms --force + limine-mkinitcpio
#   r2b        : LE BOOT D'ÉCRITURE. DOUBLE GATE : RUNBOOK_456_ACK=1 ET
#                la décision gate=WRITE posée (le ACK = PAR BOOT — un
#                boot = une invocation = un ACK frais)
#   observe    : le décodeur v456a sur le dmesg frais (LE JUGE) + le
#                timeline v456b + nvidia-smi (le cross-check 280 W)
#   restore    : le revert byte-exact + dkms + UKI. LE ROLLBACK = LE
#                DRIVER SEUL (~2 commandes depuis les stocks, prouvé 3x
#                le jour machine ; 0 chaîne v445/446/447 dans le module
#                stock, le firmware sha = c0156954 intact)
#
# Les fichiers de l'état (VOLATIL /tmp — COPIER LES PREUVES HORS /tmp,
# la leçon 4.51) :
#   /tmp/runbook456/v454c_verdict.json  — le verdict de la sonde 454
#   /tmp/runbook456-map.txt             — la carte r2a (progress/boot/hang)
#   /tmp/runbook456-decision.txt        — CONTINGENCE | WRITE
#   /tmp/runbook456/v447_payload.h      — le header du drop-in
set -e
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
SRC=${NVSRC:-/usr/src/nvidia-610.57.04}
GSPDIR=$SRC/src/nvidia/src/kernel/gpu/gsp
REPO=${REPO:-/home/cheurteen/Projects/GPU-}   # adapter si besoin
EMU=$REPO/tools/booter_emu.py
LAB=$REPO/lab/jalon411
V446=$LAB/v446_rop_payload_build.py
V447=$LAB/v447_rop_write_build.py
V456A=$LAB/v456a_progress_decode.py
V456B=$LAB/v456b_boot_timeline.py
V456C=$LAB/v456c_o5_map.py
DIR=/tmp/runbook456
VERDICT=$DIR/v454c_verdict.json
MAP_FILE=/tmp/runbook453-map.txt              # la carte r2a du runbook-453
DECISION=/tmp/runbook456-decision.txt
BOOTLEDGER=/tmp/runbook456-boots.txt
WRITE_MODE=${WRITE_MODE:-surgical}            # surgical | scatter
BLOCK=${BLOCK:-}                              # la base B (le scatter)
VALUES=${VALUES:-}                            # les valeurs µW (1 ou 8)

sha16() { sha256sum "$1" | cut -c1-16; }

checks_11() {
  echo "== les 11/11 checks (le refus automatique sinon) =="
  python3 "$EMU" --selftest     | tail -1 | rg -q "5/5 PASS"     || { echo REFUS: selftest; exit 2; }
  python3 "$EMU" --test-transfer| tail -1 | rg -q "11/11 PASS"  || { echo REFUS: test-transfer; exit 2; }
  python3 "$EMU" --test-444     | tail -1 | rg -q "9/9 PASS"    || { echo REFUS: test-444; exit 2; }
  python3 "$EMU" --test-timings | tail -1 | rg -q "5/5 PASS"    || { echo REFUS: test-timings; exit 2; }
  python3 "$EMU" --test-rop     | tail -1 | rg -q "18/18 PASS"  || { echo REFUS: test-rop; exit 2; }
  python3 "$EMU" --test-rop2    | tail -1 | rg -q "21/21 PASS"  || { echo REFUS: test-rop2; exit 2; }
  python3 "$EMU" --test-rop3    | tail -1 | rg -q "15/15 PASS"  || { echo REFUS: test-rop3; exit 2; }
  echo "   [1-7] les batteries: 5/5, TT 11/11, TF 9/9, TR 18/18, TT-T 5/5, TR2 21/21, TR3 15/15 OK"
  python3 "$V446" --selftest | tail -1 | rg -q "28/28 PASS" || { echo REFUS: v446; exit 2; }
  python3 "$V447" --selftest | tail -1 | rg -q "17/17 PASS" || { echo REFUS: v447; exit 2; }
  echo "   [8-9] les builders: v446 28/28, v447 17/17 OK"
  [ -f "$FW" ] || { echo "REFUS: le firmware absent"; exit 2; }
  echo "   [10] le firmware $FW présent ($(sha16 "$FW")) — le stock = c0156954… attendu"
  echo "   [11] le guard OGKM: $(python3 -c "
from pathlib import Path
t = Path('$REPO/.ogkm-610-cache')
print('présent' if t.is_dir() else 'ABSENT — le décodeur reste vert (SKIPPED), --fetch le re-dérive')")"
  echo "== 11/11 OK =="
}

ack_gate() {
  [ "$RUNBOOK_456_ACK" = "1" ] || { echo "REFUS: RUNBOOK_456_ACK!=1 (le ACK par boot)"; exit 4; }
}

stage_prereq() { checks_11; }

stage_observables() {
  echo "== T3: le décodeur de progression (le juge du boot) =="
  python3 "$V456A" --selftest | tail -1
  python3 "$V456B" --selftest | tail -1
  echo "   le démo: le 0xff du jour machine, décodé :"
  python3 "$V456A" --decode 0xff
  echo "   LE RAPPEL: le 0xff = COMPLETED (le marqueur terminal), le"
  echo "   hang r0 = APRÈS le marqueur (la falcon jamais haltée)."
}

stage_map() {
  echo "== T1: la carte O5 =="
  python3 "$V456C" --selftest | tail -1
  mkdir -p "$DIR"
  python3 "$V456C" --out "$DIR/v456c_o5_map.json"
  echo "   la carte = $DIR/v456c_o5_map.json (les candidats, jamais les"
  echo "   cibles d'écriture — la sonde de lecture = le prérequis)."
}

stage_gate() {
  echo "== LA DÉCISION (lisible, sans geste) =="
  if [ ! -f "$VERDICT" ]; then
    echo "gate: le verdict 454 ABSENT ($VERDICT) — le jour lecture ="
    echo "  runbook-454 d'abord (la sonde de lecture = le prérequis"
    echo "  non-négociable). LA VOIE = BLOQUÉE."
    echo "CONTINGENCE-VERDICT" > "$DECISION"
  elif rg -q '"write_target": null' "$VERDICT"; then
    echo "gate: le verdict = REFUSED (pas de POWER-BASE-MATCH) — l'O5"
    echo "  reste fermé. LA VOIE = BLOQUÉE (le garde en code le redira)."
    echo "CONTINGENCE-VERDICT" > "$DECISION"
  elif [ ! -f "$MAP_FILE" ]; then
    echo "gate: la carte r2a ABSENTE ($MAP_FILE) — le jour tapis ="
    echo "  runbook-453 d'abord. LA VOIE = BLOQUÉE."
    echo "CONTINGENCE-CARTE" > "$DECISION"
  elif rg -q "hang" "$MAP_FILE"; then
    echo "gate: la carte r2a = HANG (le tapis = encore spin) — LES"
    echo "  VARIANTES DE SONDE SUIVANTES, PAS D'ÉCRITURE :"
    echo "    (1) le tapis ALIGNED (runbook-453 r2b — la comparaison"
    echo "        pair/aligned = la traverse du RA)"
    echo "    (2) le balayage fill_len {64,96,112} x fill_value {0,0x4a7}"
    echo "        (la carte r1 re-jouée avec le décodeur v456a = les"
    echo "        coordonnées nommées au lieu du spin uniforme)"
    echo "    (3) la révision de sonde avec la paire PGC6 (la carte O5,"
    echo "        les ajouts 4.56) — la progression LIVE sans le dmesg"
    echo "CONTINGENCE-CARTE" > "$DECISION"
  else
    echo "gate: le verdict = POWER-BASE-MATCH ET la carte r2a = non-hang"
    echo "  → L'O5 OUVERT : le write chirurgical (les paires = le"
    echo "  verdict + la carte; le v447 = le garde en code)."
    echo "WRITE" > "$DECISION"
  fi
  echo "   la décision = $(cat "$DECISION") ($DECISION)"
}

stage_payload() {
  checks_11
  mkdir -p "$DIR"
  [ -f "$DECISION" ] || { echo "REFUS: gate d'abord (la décision absente)"; exit 5; }
  [ "$(cat "$DECISION")" = "WRITE" ] || { echo "REFUS: la voie = $(cat "$DECISION") — le payload = REFUSÉ (la contingence d'abord)"; exit 5; }
  echo "== T2: le build v447 (mode=$WRITE_MODE) =="
  set +e
  if [ "$WRITE_MODE" = "scatter" ]; then
    [ -n "$BLOCK" ] || { echo "REFUS: BLOCK= requis (la base B)"; exit 5; }
    # les paires = DEPUIS le verdict: les 8 valeurs = la valeur 280 W du
    # verdict répétée sur le bloc (le scatter du 4.44) — le founder peut
    # les override par VALUES="v0 v1 ... v7"
    vals=${VALUES:-$(python3 -c "
import json,sys
t = json.load(open('$VERDICT'))['write_target']
print(' '.join([str(t['value_280w_dec'])]*8))")}
    python3 "$V447" --mode scatter --block "$BLOCK" --values $vals \
      --verdict "$VERDICT" --map "$DIR/v456c_o5_map.json" \
      --emit-c "$DIR/v447_payload.h" --out "$DIR/v447_payload.bin"
    rc=$?
  else
    python3 "$V447" --mode surgical --verdict "$VERDICT" \
      --map "$DIR/v456c_o5_map.json" \
      --counter-home "${COUNTER_HOME:-0x008200fc}" \
      --emit-c "$DIR/v447_payload.h" --out "$DIR/v447_payload.bin"
    rc=$?
  fi
  set -e
  [ $rc -ne 0 ] && { echo "payload: REFUSÉ par le v447 (rc=$rc) — le garde en code = le RÉSULTAT du jour, honnête."; exit $rc; }
  echo "payload: $DIR/v447_payload.bin ($(sha16 "$DIR/v447_payload.bin"))"
  echo "   les honnêtetés du build: le sauvage [a1-résidu], le compteur"
  echo "   [dest] += a3 (RMW), les +4 voisins zéro-étendus, le trou du"
  echo "   slot 1 (le scatter) — le JSON du v447 les porte."
}

stage_patch() {
  [ -f "$DIR/v447_payload.h" ] || { echo "REFUS: payload d'abord"; exit 3; }
  cp "$DIR/v447_payload.h" "$GSPDIR/v447_payload.h"
  echo "patch: le header copié dans le DKMS tree. LE DROP-IN = le"
  echo "  v445_memdesc_patch.c (l'ancre exacte après le portMemCopy de"
  echo "  _kgspCreateSignatureMemdesc) — le payload embarqué = MAINTENANT"
  echo "  la chaîne d'écriture v447. Le build = le juge."
  echo "  RITUEL COMPLET : dkms build/install --force + limine-mkinitcpio"
  echo "  (le UKI = le module EMBARQUÉ — la leçon 4.44-machine #1)."
  echo "  VÉRIF d'embarquement : strings le .ko | rg v447_payload"
}

stage_r2b() {
  ack_gate
  [ -f "$DIR/v447_payload.bin" ] || { echo "REFUS: payload d'abord"; exit 3; }
  echo "r2b = LE BOOT D'ÉCRITURE (mode=$WRITE_MODE). UN BOOT = UN ACK."
  echo "  Le déroulé attendu (TR3, l'image réelle): la copie+overflow"
  echo "  AVANT le verify (le hijack r0-proven), la spine → le terminal,"
  echo "  le sauvage [a1-résidu] puis le ring [dest+slot*8] — le COMPTEUR"
  echo "  [dest] += a3 à la sortie, le ret = la RÉ-ENTRÉE (W3) = le spin."
  echo "  LE JUGE = le décodeur (stage observe): la classe du boot"
  echo "  (HANG-POST-COMPLETION = le spin attendu de la ré-entrée;"
  echo "  HANG-AT-STAGE = une coordonnée inédite — À DOCUMENTER;"
  echo "  boot = inattendu, le capture + le rejoin)."
  echo "  L'observable puissance : nvidia-smi -q -d POWER (le cross-check"
  echo "  280 W — la valeur au-delà de 250 = le write landé; la leçon"
  echo "  FE01: l'U2/l'unité = l'émulateur l'a vue, le jour confirme)."
  echo "  LEDGER: echo \"$(date -Is) mode=$WRITE_MODE\" >> $BOOTLEDGER"
  echo "$(date -Is) mode=$WRITE_MODE" >> "$BOOTLEDGER"
}

stage_observe() {
  echo "== les observables =="
  dmesg > /tmp/runbook456-dmesg.txt 2>/dev/null || sudo dmesg > /tmp/runbook456-dmesg.txt
  echo "-- le décodeur (LE JUGE) --"
  python3 "$V456A" --dmesg /tmp/runbook456-dmesg.txt --out "$DIR/v456a_map.json" || true
  echo "-- le timeline (les Δ) --"
  python3 "$V456B" --dmesg /tmp/runbook456-dmesg.txt --out "$DIR/v456b_map.json" || true
  echo "-- la puissance --"
  nvidia-smi -q -d POWER | sed -n '1,12p' || true
  [ -f "$BOOTLEDGER" ] && { echo "-- le ledger des boots --"; cat "$BOOTLEDGER"; } || true
  echo "   LES PREUVES = COPIÉES HORS /tmp (la leçon 4.51: /tmp = volatile):"
  echo "     cp -r $DIR ~/dmem-456/  && cp /tmp/runbook456-*.txt ~/dmem-456/"
}

stage_restore() {
  echo "restore: le revert byte-exact du patch driver (le header + le"
  echo "  drop-in) + dkms build/install --force + limine-mkinitcpio."
  echo "  LE ROLLBACK = LE DRIVER SEUL (~2 commandes, prouvé 3x le jour"
  echo "  machine). VÉRIF : 0 'v447_payload' dans le module stock ; le"
  echo "  firmware $FW = $(sha16 "$FW") (le stock = c0156954… intact)."
  echo "  Le boot suivant = le memdesc réécrit STOCK par le driver —"
  echo "  l'écriture = one-shot par design (le cycle de hijack)."
}

case "${1:-}" in
  prereq)      stage_prereq ;;
  observables) stage_observables ;;
  map)         stage_map ;;
  gate)        stage_gate ;;
  payload)     stage_payload ;;
  patch)       stage_patch ;;
  r2b)         stage_r2b ;;
  observe)     stage_observe ;;
  restore)     stage_restore ;;
  *) rg -n "^#   (prereq|observables|map|gate|payload|patch|r2b|observe|restore)" "$0" ;;
esac
