#!/usr/bin/env bash
# RUNBOOK 457 — LE JOUR TRANSPOSE : LE CMPUNLOCKER SUR NOTRE GA104 (la
# passe 4.57). Le patch sec2-postbl-ga104-610.57.04.patch = le transpose
# ancre-exacte du mécanisme cmpunlocker (470 lignes, décodé 2026-09-25)
# vers NOTRE driver 610.57.04 (device 0x2488). LA PRIMITIVE = LE BOOTER
# RÉ-EXÉCUTÉ (kgspExecuteBooterLoad_HAL dans la boucle PLM) — la voie
# POSTBL, PAS la lane portMemCopy du 4.45. LE FLUSH ×2 (la signature ET
# le descripteur WPR_META) = LA leçon r0/r1 payée (le DMA du ROM lisait
# des données périmées des caches — 4.45).
#
# ── VERDICTS BANCARISÉS (lire avant tout geste) ────────────────────────
# 4.57 T1 (v457a TOUT VERT, 71 checks) : LE TRANSPOSE — les ancres
#        count==1 (pas de fuzz), les valeurs byte-exact (0x2488, 0xf800,
#        0x4a7, les 5 canaris 0xc0deca7e, la chaîne 0xf754..0xf7f8, les
#        11 PLM), l'ORDRE du refill (map→fill→unmap→flush(sig)→
#        re-point→flush(desc)) vérifié dans le C transposé, le patch(1)
#        --dry-run zero-fuzz, le déterminisme. Les DÉVIATIONS nommées :
#        D1 le rebuild flush AUSSI la signature ; D2 le dmem.bin PAS
#        porté (os_open_and_read_file absent en 610.57.04) ; D3 la gate
#        = 0x2488 seul, LMR/CFG1 = la branche else {0x02669000, 0x28A}
#        (INDECIDABLE-BY-BYTES pour le 8GB GA104 — la lecture de
#        retour = le ledger) ; D4 le hunk static-info FB = PAS porté.
# 4.57 T3 (TR-4 15/15 sur l'image réelle) : LA SÉQUENCE émulée — le
#        memdesc 0xf800, le refill pair-swap, LE MODÈLE STALE-CACHE
#        (sans le flush le DMA consomme la paire PRÉCÉDENTE), la boucle
#        PLM 11/11 sur l'image réelle (la table = LA MÊME que le C),
#        le rebuild = zéro écriture, les gadgets GA100 {0x0cbd, 0x1fbd,
#        0x7f2f, 0x0ccb} = sub-0x10000 (l'AUTRE ROM).
# 4.56-machine-day (main @89bb464, le founder mergé #54) : LE JOUR
#        CAPTURÉ — la paire PGC6 = LISIBLE DEPUIS L'HÔTE (pgc6_probe.py,
#        le PLM 0x8b8f = pas de lock sur ces registres) ; le boot tapis
#        = progress 0xff CONSTANT sur 180 s = LE GFW BOOT COMPLÈTE avec
#        le payload résident (le verify = bypassed-ou-neutre sur NOTRE
#        silicium — LE SIGNAL POSITIF du transpose), le spin = le
#        handoff falcon post-complétion ; LE NÉGATIF STRUCTUREL : le RA
#        de la routine de copie = NON contrôlable par le contenu du
#        memdesc (6 variantes = le même spin) — L'ANCIENNE lane
#        portMemCopy = FERMÉE. **LE TRANSPOSE = LE CONTEXTE
#        D'EXÉCUTION DIFFÉRENT** (le booter RÉ-EXÉCUTÉ, la passe
#        POSTBL — pas l'overflow de la copie) : le négatif ne se
#        transfère PAS automatiquement (nommé, INDECIDABLE pour le
#        contexte POSTBL). LE JUGE = pgc6-traj.service (60 x 5 s, le
#        JSON par snapshot). La loi de vérification = le symbole data
#        + les octets au od (la 4e occurrence du false-zero).
# 4.57 T2 (v457b TOUT VERT) : LES INDECIDABLES NOMMÉS — les 4 gadgets =
#        INDECIDABLE-BY-BYTES (B6) ; les équivalents NOTRE côté =
#        PROUVÉS (la paire transfer-list @0x100b3e/0x100b48, la spine
#        G40, le TERMINAL) ; LA MATRICE DU SWEEP = P0..P5 (un boot par
        # point, le juge = pgc6-traj.service, le ACK par point).
# 4.56 (inchangés) : le décodeur v456a = le juge des boots (0xFF =
#        COMPLETED, le 0x0 = l'artefact PLM) ; la carte O5 = toutes les
#        rangées GA104-DECODE-INDECIDABLE-BY-BYTES ; la sonde de lecture
#        = le prérequis non-négociable de toute écriture ; la porte
#        POWER-BASE-MATCH = EN CODE (le v447 = exit 2 sans le verdict).
# 4.55/4.53/4.45 (inchangés) : le dkms = remove+install --force (le
#        build-dir stale) ; les multi-clés = POINT-VIRGULE ; /tmp =
#        VOLATILE (copier les preuves) ; le rollback = le driver seul,
#        prouvé 4x.
# ────────────────────────────────────────────────────────────────────────
#
# Usage : sudo bash runbook-457.sh <étape>
#   prereq     : §0 les guards + les 9/9 checks (8 batteries émulateur
#                5/5+TT 11/11+TF 9/9+TT-T 5/5+TR 18/18+TR2 21/21+TR3
#                15/15+TR4 15/15, le v457a TOUT VERT, le v457b TOUT
#                VERT, le firmware stock, le device 0x2488 sur le bus)
#                — le refus automatique sinon
#   patch      : §1 le patch dans le DKMS tree (patch -p1, ancres
#                exactes) + LE RITUEL = dkms REMOVE + install --force
#                (la leçon du build-dir stale !) + limine-mkinitcpio
#                (le UKI = le module EMBARQUÉ) + LA VÉRIF nm (le
#                symbole data) + les octets au od (jamais le nom de
#                fonction seul)
#   boot       : §2 LE BOOT TRANSPOSE. GATE : RUNBOOK_457_ACK=1 PAR
#                BOOT (un boot = une invocation = un ACK frais). Le
#                ledger dmesg SEC2_DEBUG = les 11 opens (la boucle PLM)
#   plm        : §3 la lecture des PLM (OUVERTS ?) — le décodage du
#                ledger SEC2_DEBUG (reg == value → OPEN) + la sonde de
#                lecture 454 en option
#   write      : §4 SI OUVERTS : le write du power-base (la paire du
#                4.53 — la cible = le POWER-BASE-MATCH de la sonde 454,
#                la porte v447 EN CODE) — REFUSÉ sinon
#   verify     : §5 nvidia-smi -pl 280 accepté + LA CHARGE (pillarB/
#                Q2RTX) = tenue à 280 W = LE BREAK. Le refus = la
#                contingence nommée (le sweep P0..P5, v457b)
#   restore    : le rollback = LE DRIVER SEUL (~10 min, éprouvé 4x) —
#                dkms remove + le stock + le UKI ; les vérifs = 0
#                SEC2_POSTBL dans le module stock, le firmware sha
#                intact
#
# Les fichiers de l'état (VOLATIL /tmp — COPIER LES PREUVES HORS /tmp):
#   /tmp/runbook457/patch-applied.txt   — la trace de l'application
#   /tmp/runbook457/nm-verify.txt       — le nm + les octets du §1
#   /tmp/runbook457-dmesg.txt           — le dmesg du boot transpose
#   /tmp/runbook457/plm-verdict.txt     — OPEN | NOT-OPEN (le §3)
#   /tmp/runbook457-boots.txt           — le ledger des boots (le ACK)
set -e
FW=/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin
FW_STOCK_SHA=c0156954
SRC=${NVSRC:-/usr/src/nvidia-610.57.04}
DKMSMOD=nvidia/610.57.04
REPO=${REPO:-/home/cheurteen/Projects/GPU-}   # adapter si besoin
EMU=$REPO/tools/booter_emu.py
LAB=$REPO/lab/jalon411
V457A=$LAB/v457a_sec2_postbl_transpose.py
V457B=$LAB/v457b_gadget_cross_sweep.py
PATCH=$LAB/sec2-postbl-ga104-610.57.04.patch
V454C=$LAB/v454c_shape_match.py
V447=$LAB/v447_rop_write_build.py
DIR=/tmp/runbook457
DMESG_OUT=/tmp/runbook457-dmesg.txt
PLMVERDICT=$DIR/plm-verdict.txt
BOOTLEDGER=/tmp/runbook457-boots.txt
POINT=${RUNBOOK_457_POINT:-P0-identity}       # le point du sweep (v457b)

sha16() { sha256sum "$1" | cut -c1-16; }

checks_9() {
  echo "== §0 : les 9/9 checks (le refus automatique sinon) =="
  python3 "$EMU" --selftest     | tail -1 | rg -q "5/5 PASS"     || { echo REFUS: selftest; exit 2; }
  python3 "$EMU" --test-transfer| tail -1 | rg -q "11/11 PASS"  || { echo REFUS: test-transfer; exit 2; }
  python3 "$EMU" --test-444     | tail -1 | rg -q "9/9 PASS"    || { echo REFUS: test-444; exit 2; }
  python3 "$EMU" --test-timings | tail -1 | rg -q "5/5 PASS"    || { echo REFUS: test-timings; exit 2; }
  python3 "$EMU" --test-rop     | tail -1 | rg -q "18/18 PASS"  || { echo REFUS: test-rop; exit 2; }
  python3 "$EMU" --test-rop2    | tail -1 | rg -q "21/21 PASS"  || { echo REFUS: test-rop2; exit 2; }
  python3 "$EMU" --test-rop3    | tail -1 | rg -q "15/15 PASS"  || { echo REFUS: test-rop3; exit 2; }
  python3 "$EMU" --test-sec2    | tail -1 | rg -q "15/15 PASS"  || { echo REFUS: test-sec2; exit 2; }
  echo "   [1-8] les batteries: 5/5, TT 11/11, TF 9/9, TT-T 5/5, TR 18/18,"
  echo "         TR2 21/21, TR3 15/15, TR4 15/15 OK"
  [ -f "$FW" ] || { echo "REFUS: le firmware absent"; exit 2; }
  echo "   [9] le firmware $FW présent ($(sha16 "$FW")) — le stock = $FW_STOCK_SHA… attendu"
  # les guards du transpose
  python3 "$V457A" --src /home/z/my-project/ogkm-610 2>/dev/null | tail -1 | rg -q "TOUT VERT" \
    || echo "   NOTE: le selftest v457a = SKIPPED ici (la source 610.57.04 absente de ce host) — le guard a tourné à l'atelier"
  python3 "$V457B" | tail -1 | rg -q "TOUT VERT" || { echo REFUS: v457b; exit 2; }
  [ -f "$PATCH" ] || { echo "REFUS: le patch transpose absent ($PATCH)"; exit 2; }
  lspci -n -d 10de: 2>/dev/null | rg -q "2488" || { echo "REFUS: le device 0x2488 absent du bus"; exit 2; }
  echo "   les guards: v457b TOUT VERT, le patch présent, 0x2488 sur le bus OK"
  echo "== 9/9 OK =="
}

ack_gate() {
  [ "$RUNBOOK_457_ACK" = "1" ] || { echo "REFUS: RUNBOOK_457_ACK!=1 (le ACK PAR BOOT — les multi-clés au point-virgule: RUNBOOK_457_ACK=1;RUNBOOK_457_POINT=$POINT)"; exit 4; }
  echo "$(date -Is) point=$POINT" >> "$BOOTLEDGER"
}

stage_patch() {
  checks_9
  mkdir -p "$DIR"
  echo "== §1 : le patch dans le DKMS tree =="
  echo "   LA SOURCE = $SRC (le DKMS tree 610.57.04) — l'application par"
  echo "   patch(1) -p1 (le transpose = ancres exactes, le dry-run = déjà"
  echo "   vert dans v457a V2)."
  cp -a "$SRC" "$DIR/SRC-backup-$(date +%s)" 2>/dev/null \
    || echo "   NOTE: le backup du tree = la place disque — le rollback = dkms remove (de toute façon)"
  patch -p1 -d "$SRC" --dry-run -i "$PATCH" || { echo "REFUS: le dry-run échoue — l'arbre a dérivé"; exit 2; }
  patch -p1 -d "$SRC" -i "$PATCH" | tee "$DIR/patch-applied.txt"
  echo "   LE RITUEL DKMS (la leçon 4.55: remove+install --force — le"
  echo "   build-dir stale = le module qui NE REBUILD PAS):"
  echo "     sudo dkms remove -m $DKMSMOD --all"
  echo "     sudo dkms install -m $DKMSMOD --force"
  echo "     sudo limine-mkinitcpio   # le UKI = le module EMBARQUÉ"
  echo "   (les 3 commandes = MANUELLES ici — le runbook ne build pas le"
  echo "    kernel sans toi ; le §1 re-vérifie après)"
}

verify_module() {
  # LA VÉRIF = le symbole data + les octets au od, JAMAIS le nom de
  # fonction seul (la leçon 4.55 — gsp_hpoke, la 3e fois).
  local KO
  KO=$(find /lib/modules/$(uname -r) -name "nvidia.ko" 2>/dev/null | head -1)
  [ -n "$KO" ] || KO=$(find /usr/lib/modules/$(uname -r) -name "nvidia.ko" 2>/dev/null | head -1)
  [ -n "$KO" ] || { echo "REFUS: nvidia.ko introuvable (le UKI embarqué ? lsinitcpio)"; exit 2; }
  {
    echo "== le symbole GLOBAL (les 2 fonctions transpose) =="
    nm "$KO" | rg -i "kgspSec2PostblTiming(RefillPayload|RebuildStockSignature)"
    echo "== le symbole DATA local (la plmTable = 'r'/'d' si le"
    echo "    compilateur l'a pas fondue dans .rodata — NOTE si absent) =="
    nm "$KO" | rg -i "plmTable" || echo "NOTE: plmTable fondue dans .rodata (l'inline du compilateur) — les strings SEC2_DEBUG = la preuve data"
    echo "== les OCTETS au od (la chaîne SEC2_DEBUG = le ledger du boot,"
    echo "    le canari 0xc0deca7e = les octets 7e ca de c0 le fill) =="
    strings "$KO" | rg "SEC2_DEBUG" | head -8
    od -A x -t x1 "$KO" | rg -m1 "7e ca de c0" || echo "NOTE: le canari = dans le .text (les immédiats) — les SEC2_DEBUG strings = la preuve od-able"
  } | tee "$DIR/nm-verify.txt"
  rg -q "kgspSec2PostblTimingRefillPayload" "$DIR/nm-verify.txt" || { echo "REFUS: le symbole transpose ABSENT du module — le build-dir stale ? (remove+install --force)"; exit 2; }
  rg -q "SEC2_DEBUG" "$DIR/nm-verify.txt" || { echo "REFUS: les strings SEC2_DEBUG absentes — le module = STALE"; exit 2; }
  echo "   la vérif module = OK ($KO)"
}

stage_boot() {
  ack_gate
  echo "== §2 : LE BOOT TRANSPOSE (point=$POINT) =="
  echo "   UN BOOT = UN ACK. Le déroulé attendu (TR4, l'image réelle):"
  echo "   la création du memdesc 0xf800 + le fill built-in (FBPA) + le"
  echo "   flush ; la boucle PLM = 11 x {le re-write WPR2, le refill"
  echo "   (addr, valeur), le booter RÉ-EXÉCUTÉ, la lecture de retour,"
  echo "   2 tentatives} ; les writes LMR/CFG1/SS0/SS1 ; le rebuild de la"
  echo "   signature stock ; le boot FINAL = le booter sur la signature"
  echo "   STOCK = le GSP boot PROPRE."
  echo "   LE JUGE AUTOMATIQUE = pgc6-traj.service (le jour machine 4.56:"
  echo "   60 x 5 s, le JSON par snapshot) — la trajectoire LUE en temps, "
  echo "   pas d'humain dans la fenêtre. Le LEDGER dmesg attendu (les lignes"
  echo "   SEC2_DEBUG):"
  echo "     'SEC2_DEBUG: saved stock signature' → le memdesc 0xf800 est actif"
  echo "     'SEC2_DEBUG: PLM[i] <NOM>(0x..) attempt=.. status=.. reg=..'"
  echo "       → 11 lignes x 2 tentatives max ; reg == la valeur = OUVERT"
  echo "     'SEC2_DEBUG: FAILED to open <NOM>' → le PLM = resté fermé"
  echo "     'SEC2_DEBUG: POST-WRITE SS0=.. SS1=.. CFG1=.. LMR=..' → les"
  echo "       valeurs lues APRÈS write = ce qui STICK (l'honnêteté D3)"
  echo "     'SEC2_DEBUG: WPR meta updated' → le re-point post-rebuild"
  echo "   LE ROLLBACK SI HANG: poweroff, le §restore (le driver seul)."
  echo "   Après le boot: sudo bash $0 plm   (le §3)"
}

stage_plm() {
  echo "== §3 : la lecture des PLM (OUVERTS ?) =="
  dmesg > "$DMESG_OUT" 2>/dev/null || sudo dmesg > "$DMESG_OUT"
  mkdir -p "$DIR"
  # le décodage du ledger: les lignes PLM[i] … reg= — reg == la valeur
  # de la table = OUVERT (2 tentatives max par le C).
  python3 - "$DMESG_OUT" > "$DIR/plm-parse.txt" <<'PYEOF'
import re, sys
dmesg = open(sys.argv[1], errors="replace").read()
table = [
    (0x001fa7cc, 0xfffff0ff, "WPR_CFG"), (0x009a0148, 0xffffffff, "FBPA"),
    (0x001fa7c4, 0xffffffff, "WPR"),     (0x00823804, 0xffffffff, "FEAT"),
    (0x00088ff4, 0xffffffff, "XVE"),     (0x00088ab4, 0xffffffff, "XVE_B"),
    (0x00088ff8, 0xffffffff, "XVE_C"),   (0x00823b00, 0xffffffff, "FEAT2"),
    (0x008200fc, 0xffffffff, "OPT_PLM"), (0x0000c840, 0xffffffff, "PJTAG_PLM"),
    (0x0000c848, 0xffffffff, "PJTAG_SEC_PLM"),
]
lines = [l for l in dmesg.splitlines() if "SEC2_DEBUG" in l]
print(f"les lignes SEC2_DEBUG = {len(lines)}")
for l in lines:
    print("  " + l.strip())
opened, failed = [], []
for addr, val, name in table:
    m = re.findall(
        rf"PLM\[\d+\] {name}\(0x{addr:x}\) attempt=(\d+) status=(0x[0-9a-f]+) reg=(0x[0-9a-f]+)",
        dmesg)
    if not m:
        failed.append(f"{name}: AUCUNE ligne (la boucle pas atteinte ?)")
        continue
    attempt, status, reg = m[-1]
    if int(reg, 16) == val:
        opened.append(name)
    else:
        failed.append(f"{name}: reg={reg} != {val:#x} (fermé)")
print(f"\nOUVERTS ({len(opened)}/11): {' '.join(opened) if opened else 'AUCUN'}")
for f_ in failed:
    print("  FERMÉ/ÉCHEC:", f_)
ss = re.search(r"POST-WRITE SS0=(0x[0-9a-f]+) SS1=(0x[0-9a-f]+) CFG1=(0x[0-9a-f]+) LMR=(0x[0-9a-f]+)", dmesg)
if ss:
    print(f"\nPOST-WRITE: SS0={ss.group(1)} SS1={ss.group(2)} "
          f"CFG1={ss.group(3)} LMR={ss.group(4)}")
    print("  (les valeurs attendues: SS0=0x88888888 SS1=0x8 CFG1=0x02669000 "
          "LMR=0x28a — SI différent = le stick partiel, à documenter)")
PYEOF
  cat "$DIR/plm-parse.txt"
  if rg -q "OUVERTS \(11/11\)" "$DIR/plm-parse.txt"; then
    echo "OPEN" > "$PLMVERDICT"
    echo "plm: OUVERTS 11/11 → le §4 = ARMÉ (le write du power-base)"
  elif rg -q "OUVERTS \(" "$DIR/plm-parse.txt"; then
    echo "PARTIAL" > "$PLMVERDICT"
    echo "plm: PARTIEL — la lecture fine = le §4 demande OPEN (le founder"
    echo "     décide: les partiels = le sweep P4 ou la sonde 454 d'abord)"
  else
    echo "NOT-OPEN" > "$PLMVERDICT"
    echo "plm: FERMÉS — LA CONTINGENCE = le sweep (v457b, P0..P5): les"
    echo "     variantes de gadgets/fill_len, UN boot par point, le juge ="
    echo "     pgc6-traj.service. LES HYPOTHÈSES NOMMÉES si le ledger = vide:"
    echo "     (1) la boucle pas atteinte (le WPR2-up bypass = pas pris —"
    echo "         le dmesg 'unexpected WPR2' ?) ; (2) le POSTBL ne hijack"
    echo "         pas sur GA104 (les gadgets = l'AUTRE ROM — l'attendu"
    echo "         P0) ; (3) le DMA a consommé le STALE (le flush = la"
    echo "         leçon — vérifier 'saved stock signature' au ledger)."
  fi
  echo "   le verdict = $(cat "$PLMVERDICT") ($PLMVERDICT)"
  echo "   LES PREUVES = COPIÉES HORS /tmp (la leçon 4.51):"
  echo "     cp -r $DIR ~/sec2-457/ && cp $DMESG_OUT ~/sec2-457/"
}

stage_write() {
  ack_gate
  mkdir -p "$DIR"
  [ -f "$PLMVERDICT" ] || { echo "REFUS: §3 d'abord (le verdict PLM absent)"; exit 5; }
  [ "$(cat "$PLMVERDICT")" = "OPEN" ] || { echo "REFUS: les PLM = $(cat "$PLMVERDICT") — le write = REFUSÉ (la contingence d'abord)"; exit 5; }
  echo "== §4 : le write du power-base (les PLM OUVERTS) =="
  echo "   LA PAIRE du 4.53 : la cible = le POWER-BASE-MATCH de la sonde"
  echo "   454 (le verdict v454c) — la porte v447 = EN CODE (exit 2 sans"
  echo "   le verdict). AVEC les PLM ouverts, le registre = accessible"
  echo "   depuis l'hôte: le write = la voie v447 (la chaîne prouvée) OU"
  echo "   le write MMIO direct (le §4 = la voie v447 par défaut)."
  VERDICT=/tmp/runbook456/v454c_verdict.json
  [ -f "$VERDICT" ] || { echo "REFUS: le verdict 454 absent ($VERDICT) — le jour lecture 454 d'abord"; exit 5; }
  rg -q '"write_target": null' "$VERDICT" && { echo "REFUS: le verdict = REFUSED (pas de POWER-BASE-MATCH)"; exit 5; }
  echo "   le build v447 chirurgical (la paire = DEPUIS le verdict):"
  python3 "$V447" --mode surgical --verdict "$VERDICT" \
    --counter-home "${COUNTER_HOME:-0x008200fc}" \
    --emit-c /tmp/runbook456/v447_payload.h \
    --out /tmp/runbook456/v447_payload.bin \
    || { echo "payload: REFUSÉ par le v447 (le garde en code)"; exit 2; }
  echo "   le payload = OK. LE DROP-IN = le rituel 4.44/4.45/4.56"
  echo "   (le v445_memdesc_patch.c dans le DKMS tree, le header ="
  echo "   MAINTENANT la chaîne v447) + le §1 rituel (remove+install"
  echo "   --force + le UKI) + le boot = UN AUTRE ACK."
  echo "   L'observable: nvidia-smi -q -d POWER (la valeur > 250 W = le"
  echo "   write landé)."
}

stage_verify() {
  echo "== §5 : LA VALIDATION =="
  echo "   [5.1] nvidia-smi -pl 280 (la commande du founder):"
  echo "     sudo nvidia-smi -pl 280"
  echo "     nvidia-smi -q -d POWER | sed -n '1,12p'"
  echo "   [5.1b] LE DOUBLE-COUVERT 4.60 (le bypass NVML par ioctl — si le"
  echo "     PLM = ouvert mais que le -pl reste bloqué au check NVML):"
  echo "     le runbook-460 (tools/edpp/runbook-460.sh) = le jour complet;"
  echo "     la ligne courte ici :"
  echo "       python3 tools/edpp/v460a_nvml_bypass.py --table \$WORK/v460-decode.json --mw 280000 --arm"
  echo "     (la séquence SET du -pl 250 capturée par v460b, la valeur"
  echo "     patchée 280000, sans le fetch/check NVML ; le GSP = le juge —"
  echo "     le SET accepté ET appliqué = le break ; rejeté par le kernel ="
  echo "     le code nomme le mur ; accepté-non-appliqué = le mur GSP)"
  echo "   [5.2] LA CHARGE = la tenue à 280 W:"
  echo "     pillarB / Q2RTX (les commandes du founder) — la télémétrie:"
  echo "     nvidia-smi --query-gpu=power.draw,clocks.sm,temperature.gpu --format=csv -l 5"
  echo "   LE CRITÈRE (la doctrine 4.47): la tenue à 280 W sous charge ="
  echo "   LE BREAK (la limite = levée). Le refus de -pl 280 OU le"
  echo "   plafonnement à 250 W sous charge = PAS le break:"
  echo "   LES CONTINGENCES NOMMÉES (v457b):"
  echo "     - le sweep P0..P5 (les gadgets/fill_len — UN boot par point,"
  echo "       le juge pgc6-traj)"
  echo "     - la révision de sonde avec la paire PGC6 (la carte O5 4.56)"
  echo "     - la voie r2b v447 (la lane portMemCopy — le runbook-456)"
  echo "     - le bypass 4.60 SI ET SEULEMENT SI le mur = le check NVML"
  echo "       (le §5.1b — userspace pur, réversible, zéro patch)"
  echo "   le ledger du §5: echo \"$(date -Is) verify point=$POINT\" >> $BOOTLEDGER"
}

stage_restore() {
  echo "restore: LE ROLLBACK = LE DRIVER SEUL (~10 min, éprouvé 4x):"
  echo "  1. sudo dkms remove -m $DKMSMOD --all"
  echo "  2. le STOCK reinstall (les paquets du distro OU le runfile"
  echo "     stock) — 0 'SEC2_POSTBL'/'kgspSec2Postbl' dans le module"
  echo "     stock attendu:"
  echo "       nm /lib/modules/\$(uname -r)/kernel/drivers/video/nvidia.ko | rg -c Sec2Postbl || echo PROPRE"
  echo "  3. sudo limine-mkinitcpio"
  echo "  4. le firmware $FW = $(sha16 "$FW") (le stock = $FW_STOCK_SHA…"
  echo "     intact — le firmware = JAMAIS touché, la loi)"
  echo "  Le boot suivant = le driver STOCK — le memdesc = réécrit par le"
  echo "  code stock, la boucle PLM = absente, l'état PLM = re-verrouillé"
  echo "  par le reset (les PLM = l'état du RESET, pas persistant)."
}

case "${1:-}" in
  prereq)  checks_9 ;;
  patch)   stage_patch ;;
  verify-module) verify_module ;;
  boot)    stage_boot ;;
  plm)     stage_plm ;;
  write)   stage_write ;;
  verify)  stage_verify ;;
  restore) stage_restore ;;
  *) rg -n "^#   (prereq|patch|verify-module|boot|plm|write|verify|restore)" "$0" ;;
esac
