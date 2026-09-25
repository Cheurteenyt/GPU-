#!/usr/bin/env bash
# RUNBOOK 454 — le jour LECTURE : LA SONDE BAR0 (le read lane, la passe
# 4.54). Le premier geste NON-NÉGOCIABLE du cœur MMIO O5 (4.53 §5) :
# la sonde de LECTURE décide — jamais une écriture avant une ligne
# de lecture. ZÉRO patch, ZÉRO dkms, ZÉRO UKI, ZÉRO boot : la lane =
# read-only PAR CONSTRUCTION (le code = la garantie : v454b = mmap
# PROT_READ, aucun chemin d'écriture n'existe dans l'outil).
#
# ── VERDICTS BANCARISÉS (lire avant tout geste) ────────────────────────
# 4.53 §5 : la table PLM cmpunlocker croisée GA104 = INDECIDABLE-BY-
#        BYTES ; la sonde de LECTURE = le premier geste (le write-test
#        = REFUSÉ sans une ligne read-test) ; notre carte = 250 W
#        stock ⇒ un registre u32 lisant 0x0EE6B280 = 250000000 µW =
#        le POWER-BASE DÉCODÉ sur GA104 (la formule 4.44 : limit =
#        base × f18/100/1000) ; les tout-0xFFFFFFFF = les candidats
#        MORTS (le négatif honnête) ; la lecture ≠ la sémantique
#        d'écriture (la transferabilité reste INDECIDABLE même si la
#        lecture est plausible).
# 4.54 T1 (v454a 22/22) : la table = 215 offsets SOURCÉS (17 SAFE =
#        le patch cmpunlocker lui-même : 11 PLM + 2 WPR2 + 4 config
#        host ; 198 RISK = les voisinages bornés ±0x40 sur les blocs
#        power {0x0082xxxx, 0x001fa7xx, 0x009axxxx}, stride 4, XVE/
#        PJTAG/LMR HORS SCOPE). 4 bugs attrapés au lab par le
#        selftest (la regex WR32 constantes-seules ; le garde compte
#        codé en dur ; le quantificateur any(not(...)) ; le modèle
#        de dédup du test).
# 4.54 T2 (v454b 22/22) : la sonde = PROT_READ seul, UN u32 par
#        offset (jamais de polling, jamais de répétition), le mode
#        synthétique = le MÊME chemin de code ; la porte deux tiers :
#        PROBE_454_ACK=1 (SAFE) + PROBE_454_NB=1 (RISK, opt-in — les
#        registres inconnus PEUVENT être read-sensibles : FIFO, R1C).
# 4.54 T3 (v454c 24/24) : les verdicts 7 classes ; la PORTE O5 EN
#        CODE : sans ligne POWER-BASE-MATCH exacte ⇒ write_lane =
#        "REFUSED" (machine-lisible) ; les formes floues (POWER-FORM)
#        = des PISTES, jamais des cibles.
# 4.54 T4 (v454d 16/16) : le plan a3=1 chirurgical = la PARAMÉTRIQUE
#        seulement (a1 = l'offset BRUT, la liste = [280000000 µW],
#        l'effet de bord +4 DOCUMENTÉ, l'align8 = INDECIDABLE, le
#        block a3=8 REFUSÉ sans l'évidence) — le payload = la
#        PROCHAINE passe (v446, émulé AVANT le boot, ACK-gaté).
# ────────────────────────────────────────────────────────────────────────
#
# Usage : sudo bash runbook-454.sh <étape>
#   prereq    : les 6/6 checks (les 4 selftests v454 + la table +
#               le GPU) — le refus automatique sinon
#   table     : v454a construit la table candidates (les offsets
#               SOURCÉS, jamais inventés)
#   probe     : LA SONDE. GATÉ : PROBE_454_ACK=1 (+ PROBE_454_NB=1
#               pour les voisinages). Zéro écriture n'existe ici.
#   match     : v454c classifie + la PORTE O5 (REFUSED/NAMED)
#   plan      : v454d — le plan a3=1 SI la porte = NAMED ; sinon le
#               refus honnête affiché (le lane fermé = le résultat)
#   observe   : le résumé des verdicts + nvidia-smi (le cross-check
#               250 W stock) + les fichiers posés
#   restore   : RIEN À RESTAURER (par construction — aucun patch, aucun
#               module, aucun firmware touché ; la lane = lecture
#               seule). L'étape existe pour la clôture du protocole.
#
# Les sorties : $RUN454_DIR (défaut /tmp/runbook454 — VOLATILE : la
# leçon 4.51 — copie les dumps/verdicts hors /tmp si tu les gardes).
set -e
REPO=${REPO:-/home/cheurteen/Projects/GPU-}
L411=$REPO/lab/jalon411
RUN454_DIR=${RUN454_DIR:-/tmp/runbook454}
PCI=${PCI:-}                                  # ex: 0000:01:00.0 (option)

TABLE=$L411/v454a_probe_table.json
DUMP=$RUN454_DIR/v454b_probe_dump.json
VERDICT=$RUN454_DIR/v454c_verdict.json
PLAN=$RUN454_DIR/v454d_write_plan.json

say() { echo "== $* =="; }

checks_6() {
  say "les 6/6 checks (le refus automatique sinon)"
  python3 "$L411/v454a_probe_table.py" --selftest | tail -1 | rg -q "22/22 PASS" || { echo REFUS: v454a; exit 2; }
  python3 "$L411/v454b_bar0_probe.py" --selftest | tail -1 | rg -q "22/22 PASS" || { echo REFUS: v454b; exit 2; }
  python3 "$L411/v454c_shape_match.py" --selftest | tail -1 | rg -q "24/24 PASS" || { echo REFUS: v454c; exit 2; }
  python3 "$L411/v454d_write_plan.py" --selftest | tail -1 | rg -q "16/16 PASS" || { echo REFUS: v454d; exit 2; }
  echo "   [1-4] les selftests v454 : 22/22, 22/22, 24/24, 16/16 OK"
  [ -f "$TABLE" ] || { echo "REFUS: la table absente — lance 'table'"; exit 2; }
  python3 - "$TABLE" <<'EOF'
import json, sys
t = json.load(open(sys.argv[1]))
c = t["counts"]
assert c["SAFE-PROBE"] == 17 and c["RISK-PROBE"] > 0, c
assert all(r["offset"] % 4 == 0 for r in t["rows"])
print(f"   [5] la table: {len(t['rows'])} offsets (SAFE {c['SAFE-PROBE']} / RISK {c['RISK-PROBE']}), alignée u32 OK")
EOF
  [ -d /sys/bus/pci/devices ] && ls /sys/bus/pci/devices >/dev/null 2>&1 \
    && echo "   [6] le sysfs PCI présent" \
    || { echo "REFUS: /sys/bus/pci absent"; exit 2; }
  say "6/6 OK — la lane lecture est armée (mais ne lit rien sans ACK)"
}

stage_prereq() { checks_6; }

stage_table() {
  checks_6 >/dev/null 2>&1 || true
  (cd "$REPO" && python3 "$L411/v454a_probe_table.py" --out "$TABLE")
  say "la table construite — CHAQUE offset = SOURCÉ (le patch ou le voisinage nommé)"
  echo "   SAFE 17 = les adresses du patch cmpunlocker lui-même (le"
  echo "   geste de lecture que le patch fait sur GA100). RISK = les"
  echo   "   voisinages bornés — OPT-IN via PROBE_454_NB=1 à l'étape probe."
}

stage_probe() {
  [ "$PROBE_454_ACK" = "1" ] || { echo "REFUS: PROBE_454_ACK!=1 — même une lecture = un geste machine, gated"; exit 4; }
  mkdir -p "$RUN454_DIR"
  say "LA SONDE (read-only, un u32 par offset, jamais de répétition)"
  PCI_ARGS=""
  [ -n "$PCI" ] && PCI_ARGS="--pci $PCI"
  (cd "$REPO" && python3 "$L411/v454b_bar0_probe.py" \
      --table "$TABLE" --out "$DUMP" $PCI_ARGS) \
    || { echo "REFUS: la sonde a échoué (le driver stock monte-t-il resource0 ?)"; exit 3; }
  [ "$PROBE_454_NB" = "1" ] \
    && echo "   PROBE_454_NB=1 : les voisinages RISK inclus (lecture unique)" \
    || echo "   PROBE_454_NB absent : les 198 RISK SKIPPÉS (l'opt-in reste ouvert)"
  echo "   le dump = $DUMP — LA PREUVE. Copie-la hors /tmp (la leçon volatile)."
}

stage_match() {
  [ -f "$DUMP" ] || { echo "REFUS: le dump absent — lance 'probe'"; exit 3; }
  say "L'ANALYSE (les 7 classes + la porte O5)"
  (cd "$REPO" && python3 "$L411/v454c_shape_match.py" --dump "$DUMP" --out "$VERDICT")
  echo "   le verdict = $VERDICT"
  echo "   RAPPEL 4.53 §5 : la lecture plausible ≠ la sémantique d'écriture"
  echo "   — la transferabilité reste INDECIDABLE même avec un marqueur."
}

stage_plan() {
  [ -f "$VERDICT" ] || { echo "REFUS: le verdict absent — lance 'match'"; exit 3; }
  say "LE PLAN a3=1 (la paramétrique — PAS une écriture)"
  if (cd "$REPO" && python3 "$L411/v454d_write_plan.py" --verdict "$VERDICT" --out "$PLAN"); then
    echo "   le plan = $PLAN — le payload = la PROCHAINE passe (v446),"
    echo "   émulée (--test-rop2) AVANT tout boot, ACK-gatée."
  else
    echo "   LE LANE RESTE FERMÉ (la porte O5 = REFUSED) — le résultat"
    echo "   HONNÊTE : les candidats testés ne décodent pas le power-base"
    echo "   sur GA104. Les pistes = les POWER-FORM (l'analyse du verdict)."
    return 0   # le refus = un résultat, pas un échec du runbook
  fi
}

stage_observe() {
  say "les observables"
  [ -f "$VERDICT" ] && python3 - "$VERDICT" <<'EOF'
import json, sys
v = json.load(open(sys.argv[1]))
print("comptes:", " ".join(f"{k}={n}" for k, n in sorted(v["counts"].items())))
print("write_lane:", v["write_lane"])
for m in v["marker_rows"]:
    print(f"  MARQUEUR @0x{m['offset']:08x} ({m['name']}) {m['value_hex']} — {m['note']}")
EOF
  [ -f "$PLAN" ] && echo "le plan: $PLAN" || true
  nvidia-smi -q -d POWER 2>/dev/null | sed -n '1,12p' || true
  echo "  (le cross-check : la carte = 250 W stock — le marqueur attendu = 0x0EE6B280)"
}

stage_restore() {
  say "restore: RIEN À RESTAURER — PAR CONSTRUCTION"
  echo "   cette lane n'a patché AUCUN module, AUCUN firmware, AUCUN"
  echo "   boot. Le rollback = N/A (la propriété de la lane lecture)."
  echo "   VÉRIF de complétude : 0 écriture dans v454b (le selftest"
  echo "   l'assert) ; les fichiers posés = les JSONs de $RUN454_DIR."
}

case "${1:-}" in
  prereq)  stage_prereq ;;
  table)   stage_table ;;
  probe)   stage_probe ;;
  match)   stage_match ;;
  plan)    stage_plan ;;
  observe) stage_observe ;;
  restore) stage_restore ;;
  *) rg -n "^#   (prereq|table|probe|match|plan|observe|restore)" "$0" ;;
esac
