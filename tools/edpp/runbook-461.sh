#!/usr/bin/env bash
# runbook-461.sh — PASS 4.61 — THE DMEM TAIL-WRITE DAY (the gated day).
#
# THE MISSION (the founder, verbatim anchors):
#   §0 les guards (le marker 0x0EE6B280 = lu AVANT = la preuve de ciblage)
#   §1 le patch two-sided + le dkms remove+install --force + limine +
#      la vérification nm/od
#   §2 le boot = l'écriture + le ledger pre/post
#   §3 LA LECTURE DE LA LIMITE : nvidia-smi -q -d POWER
#      -> si le max = 280 -> §4 nvidia-smi -pl 280
#      -> §5 LA CHARGE (pillarB/Q2RTX tenue à 280 W) = LE BREAK
#   the rollback = driver only.
#
# ZÉRO BOOT d'abord: §0 = the selftests + THE PLAN GATE — the day
# REFUSES before §1 unless the v461a scan found the base-marker object
# in the dumps (the targeting proof). The GATED NULL plan = the honest
# close (the T5 contingencies printed, NOTHING boots).
#
# THE ACK LAW: every boot = RUNBOOK_461_ACK=1 (+ RUNBOOK_461_SEL=<1..4>
# the group). THE MULTI-KEY LAW (the 4.51 lesson): the multi-keys =
# the SEMICOLON: "RmGspDmemDump=1;RmGspDMemWrite=1" — the space form =
# never parsed. THE VERIFICATION LAW (the 4.56 lesson): nm the .ko for
# the DATA SYMBOL (gspDmemWriteState) + the NVRM-461 bytes — NEVER the
# function name alone (the inline erases it).
#
# THE ROLLBACK = DRIVER ONLY (§6): the firmware file NEVER touched
# (the §0 sha guard holds all day).
set -uo pipefail

REPO="${REPO:-/home/z/my-project/gpu-repo}"
TREE="${TREE:-/usr/src/nvidia-610.57.04}"
DMEM_DIR="${DMEM_DIR:-$HOME/dmem-451}"
WORK="${WORK:-/tmp/runbook-461}"        # VOLATILE — the copy-out law (4.51)
FW_SHA_STOCK="c0156954"                  # the banked stock GSP firmware sha
DEV_ID="0x2488"                          # GA104

g_ok=0; g_tot=0
chk() { g_tot=$((g_tot+1)); if "$@" >/dev/null 2>&1; then g_ok=$((g_ok+1));
        echo "  [PASS] $*"; else echo "  [FAIL] $*"; fi; }
die() { echo "REFUSÉ: $*" >&2; exit 2; }
section() { echo; echo "== $* =="; }

# ───────────────────────────────────────────────── §0 — LES GUARDS ──
section "§0 LES GUARDS (zéro boot: le selftest et le plan d'abord)"

[ "${RUNBOOK_461_ACK:-}" = "1" ] || \
  die "le jour n'est pas armé — RUNBOOK_461_ACK=1 requis (le jour gaté)"

echo "-- la machine --"
lspci -d 10de:$DEV_ID >/dev/null 2>&1 || true
chk test -c /dev/nvidiactl
chk bash -c "lspci -n -d 10de: | grep -q $DEV_ID"

echo "-- le guard firmware (JAMAIS touché — le sha = le stock) --"
FW="$(find /lib/firmware/nvidia/${TREE##*/} -name 'gsp.bin' 2>/dev/null | head -1)"
[ -n "$FW" ] || die "gsp.bin introuvable"
FW_SHA="$(sha256sum "$FW" | cut -c1-8)"
[ "$FW_SHA" = "$FW_SHA_STOCK" ] || \
  die "le sha firmware ($FW_SHA) != le stock ($FW_SHA_STOCK) — STOP"

echo "-- les batteries bancarisées (la reproduction D'ABORD) --"
chk python3 "$REPO/lab/jalon411/v461a_target_map.py" --selftest
chk python3 "$REPO/lab/jalon411/v461b_dmem_write_two_sided.py"

echo "-- LE PLAN GATE: le scan des dumps (la preuve de ciblage) --"
mkdir -p "$WORK"; cp -a "$REPO/lab/jalon411"/*.py "$WORK/" 2>/dev/null || true
DUMPS=()
for f in "$DMEM_DIR"/args.bin "$DMEM_DIR"/libosinit.bin \
         "$DMEM_DIR"/statemonitor.bin "$DMEM_DIR"/wpr2meta.bin \
         "$DMEM_DIR"/sysmemheap.bin "$DMEM_DIR"/logs0.bin; do
  [ -f "$f" ] && DUMPS+=("$f")
done
[ ${#DUMPS[@]} -gt 0 ] || die "aucun dump dans $DMEM_DIR — le jour 4.51 \
doit produire les dumps d'abord (RmGspDmemDump=1), la lane 4.61 = \
l'instrument prêt, pas le devin"

python3 "$REPO/lab/jalon411/v461a_target_map.py" \
  --out "$WORK/v461a_target_map.json" \
  --plan-out "$WORK/v461a_plan.json" \
  --emit-c "$WORK/gsp_dmem_write_plan.h" \
  "${DUMPS[@]}" | tee "$WORK/v461a_scan.log"

N_ENTRIES="$(python3 -c "import json;print(len(json.load(open('$WORK/v461a_plan.json'))['entries']))")"
[ "$N_ENTRIES" -gt 0 ] || {
  cat <<'EOF'
REFUSÉ AVANT TOUT PATCH — the GATED NULL plan (the honest close):
  the base-marker object (0x0EE6B280 family, the 0x10-stride quad +
  the f18 quad) is NOT in any host-reachable dump. The banked model
  says the object lives in the RM FB/WPR2 heap (4.51 verdict 1).
  THE T5 ROUTES (nothing boots today):
    (a) the re-dump day with RmGspDmemDump=1 + this scan (the fresh
        dumps decide — the same boot may carry BOTH keys, the
        SEMICOLON form);
    (b) the route-W read probe (the 4.52 §5 design) — the seal's
        CPU-read behavior decides;
    (c) the 0x0-read artifact check = the PGC6 probe bis (the 4.51
        pattern) if any read returned 0x0;
    (d) the persistence route = the f18 lane (the 4.44 PERSISTENT
        class) — the 4.62 pass.
EOF
  exit 3
}
echo "le plan = $N_ENTRIES entrée(s) — LA REVUE HUMAINE = le step \
obligatoire avant §1 (cat $WORK/v461a_plan.json)"

# ─────────────────────────────────────────────── §1 — LE PATCH ──
section "§1 LE PATCH TWO-SIDED (the drop-in + le dkms --force + la loi nm/od)"

echo "-- les anchors de l'arbre (8, >=7 requis — le juge du build) --"
a=0
for pat in "pGspArgumentsCached" "pSysmemHeapDescriptor" \
           "pRmStateMonitorBuffer" "pWprMeta" \
           "memdescMap" "memdescUnmap" "osReadRegistryDword" \
           "kgspStartLogPolling"; do
  if grep -rq "$pat" "$TREE/src/nvidia/src/kernel/gpu/gsp/" 2>/dev/null; then
    a=$((a+1)); echo "  [anchor ok] $pat"
  else
    echo "  [ANCHOR MISSING] $pat"
  fi
done
[ "$a" -ge 7 ] || die "les anchors insuffisants ($a/8) — l'arbre cible = \
pas le 610.57.04 attendu"

cp "$REPO/tools/edpp/gsp_dmem_write.c" "$TREE/src/nvidia/src/kernel/gpu/gsp/"
cp "$WORK/gsp_dmem_write_plan.h" "$TREE/src/nvidia/src/kernel/gpu/gsp/"

KGSP="$TREE/src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
grep -q 'gsp_dmem_write_schedule' "$KGSP" || {
  cp "$KGSP" "$WORK/kernel_gsp.c.stock"
  python3 - "$KGSP" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
if '#include "gsp_dmem_write.c"' not in s:
    anchor = '#include "gsp_hpoke.c"'
    assert s.count(anchor) == 1, "l'anchor include absent"
    s = s.replace(anchor, anchor + '\n#include "gsp_dmem_write.c"', 1)
hook = 'gsp_hpoke_schedule(pGpu, pKernelGsp);'
if 'gsp_dmem_write_schedule(pGpu, pKernelGsp);' not in s:
    assert s.count(hook) == 1, "l'anchor hook absent"
    s = s.replace(hook, hook +
                  '\n    gsp_dmem_write_schedule(pGpu, pKernelGsp);  // 4.61', 1)
open(p, 'w').write(s)
print("PATCH OK: kernel_gsp.c = l'include + la hook line 4.61")
PY
}

echo "-- la face nv.c (le publisher, le marker = obligatoire) --"
python3 "$REPO/tools/edpp/patch_nv_461.py" || die "le patch nv.c = échoué"
grep -q "DmemWriteMarker" "$TREE/kernel-open/nvidia/nv.c" || \
  die "le DmemWriteMarker ABSENT de nv.c — le build passerait mais la \
write = un no-op silencieux (la loi 4.55)"

echo "-- le rituel dkms (remove + install --force — la leçon bancarisée) --"
dkms remove -m nvidia -v "${TREE##*/}" --all || true
dkms install -m nvidia -v "${TREE##*/}" --force || die "le dkms = échoué"

echo "-- limine-mkinitcpio (le UKI = le module EMBARQUÉ) --"
limine-mkinitcpio || mkinitcpio -P || die "l'initramfs = échoué"

echo "-- LA LOI DE VÉRIFICATION: nm le .ko (le symbole DATA) + les octets --"
KO="$(find "/lib/modules/$(uname -r)" -name 'nvidia.ko*' 2>/dev/null | head -1)"
[ -n "$KO" ] || die "le nvidia.ko introuvable"
nm "$KO" 2>/dev/null | grep -q "gspDmemWriteState" || \
  die "le symbole gspDmemWriteState ABSENT du module (la loi nm — \
jamais le nom de fonction seul)"
strings -a "$KO" 2>/dev/null | grep -q "NVRM-461" || \
  strings -a "$KO" 2>/dev/null | grep -q "RmGspDMemWrite" || \
  die "les octets NVRM-461/RmGspDMemWrite absents du module (la loi od)"
echo "le module = VÉRIFIÉ (le symbole data + les octets)"

# ──────────────────────────────────────────────── §2 — LE BOOT ──
section "§2 LE BOOT = L'ÉCRITURE + LE LEDGER (l'ACK PAR BOOT)"

SEL="${RUNBOOK_461_SEL:-1}"
case "$SEL" in 1|2|3|4) ;; *) die "RUNBOOK_461_SEL=$SEL hors {1..4}" ;; esac
[ "${RUNBOOK_461_BOOT_ACK:-}" = "1" ] || \
  die "le boot n'est pas armé — RUNBOOK_461_BOOT_ACK=1;RUNBOOK_461_SEL=$SEL \
(les DEUX clés, un boot par écriture)"

CONF="/etc/modprobe.d/nvidia.conf"
cp "$CONF" "$WORK/nvidia.conf.stock" 2>/dev/null || true
echo "options nvidia NVreg_RegistryDwords=\"RmGspDMemWrite=$SEL\"" > "$CONF"
echo "le conf = RmGspDMemWrite=$SEL (UNE écriture par boot, sel=$SEL)"
echo "(le multi-clés = le POINT-VIRGULE: \"RmGspDmemDump=1;RmGspDMemWrite=$SEL\" \
si le dump coexiste — l'espace = jamais parsé, la leçon 4.51)"
echo
echo ">>> REBOOTEZ. Au retour:"
echo ">>>   dmesg | grep NVRM-461 > $WORK/ledger-461.txt"
echo ">>>   nvidia-smi -q -d POWER > $WORK/power-after.txt"
echo ">>>   puis re-lancez: RUNBOOK_461_STAGE=3 bash $0"
echo ">>>   le ledger pre/post = LE LEDGER (la loi: le printk = la \
surface fiable)"

# ─────────────────────────────── §3 — LA LECTURE DE LA LIMITE ──
if [ "${RUNBOOK_461_STAGE:-}" = "3" ]; then
section "§3 LA LECTURE DE LA LIMITE (nvidia-smi -q -d POWER)"

LEDGER="$WORK/ledger-461.txt"
[ -f "$LEDGER" ] || die "le ledger absent — dmesg | grep NVRM-461 d'abord"
cat "$LEDGER"
grep -q "verdict=WRITE-DONE" "$LEDGER" || {
  echo "LE VERDICT = $(grep -o 'verdict=[A-Z-]*' "$LEDGER" | tail -1)"
  echo "STALE-PLAN = le marker n'a pas tenu (la recompute a couru, ou la \
base a bougé) — le ciblage = réfuté CE boot; le re-scan décide."
  exit 4
}
echo "LA LECTURE (la mission): nvidia-smi -q -d POWER —"
nvidia-smi -q -d POWER | grep -E "Power Limit|Default Power Limit|Max Power Limit|Min Power Limit" | tee "$WORK/power-limits.txt"
MAXW="$(nvidia-smi -q -d POWER | grep -A1 "Max Power Limit" | grep -oE "[0-9.]+" | head -1)"
echo "le max = ${MAXW} W"
if python3 -c "exit(0 if float('${MAXW:-0}') >= 279.5 else 1)"; then
  echo "LE MAX = 280 — §4 = ARMÉ (la commande du founder)"
  echo ">>> RUNBOOK_461_STAGE=4 bash $0"
else
  echo "LA LIMITE = RESTÉE À ${MAXW} W — la T5 route A:"
  echo "  la base = RE-ÉCRASÉE par la recompute (le recompute runtime-fed, \
la classe VOLATILE 4.44) — capturer QUI et QUAND = le ledger ci-dessus + \
les snapshots pgc6-traj; LA PASSE 4.62 = la route de la persistance \
(la lane f18 = la classe PERSISTANTE, jamais réécrite par la recompute)."
  echo "  (si la lecture = 0x0: l'artefact PLM — la sonde bis avec la \
paire PGC6 = le pattern 4.51, tools/edpp/pgc6_probe.py)"
  exit 5
fi
fi

# ──────────────────────────────── §4 — LA COMMANDE DU FOUNDER ──
if [ "${RUNBOOK_461_STAGE:-}" = "4" ]; then
section "§4 nvidia-smi -pl 280 (la commande du founder)"
nvidia-smi -pl 280 && echo "ACCEPTÉ" || {
  echo "REFUSÉE par le check NVML — LE DOUBLE-COUVERT 4.60 (runbook-457 \
§5.1b): la lane bypass userspace pure:"
  echo "  python3 $REPO/tools/edpp/v460a_nvml_bypass.py --table \
\$WORK/v460-decode.json --mw 280000 --arm"
  exit 6
}
echo ">>> §5 = LA CHARGE: RUNBOOK_461_STAGE=5 bash $0"
fi

# ─────────────────────────────────────────────────── §5 — LA CHARGE ──
if [ "${RUNBOOK_461_STAGE:-}" = "5" ]; then
section "§5 LA CHARGE (pillarB/Q2RTX tenue à 280 W) = LE BREAK"
python3 "$REPO/tools/edpp/pillarB-sysmem.py" --selftest || \
  die "la batterie = échouée"
python3 "$REPO/tools/edpp/pillarB-sysmem.py" 2>&1 | tee "$WORK/charge-461.log"
echo "LA TÉLÉMÉTRIE PENDANT LA CHARGE (le 2e terminal):"
echo "  nvidia-smi --query-gpu=power.draw,clocks.sm,pstate --format=csv -l 1"
echo "LA TENUE = le draw plafonné à 280 W = THE BREAK (la doctrine 4.47)."
echo "le ledger du jour: echo \"$(date -Is) charge stage5\" >> $WORK/bootledger-461.txt"
fi

# ───────────────────────────────────────── §6 — LE ROLLBACK ──
section "§6 LE ROLLBACK (LE DRIVER SEUL — ~10 min, le rituel bancarisé)"
cat <<EOF
  cd $TREE
  git checkout -- src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c
  git checkout -- kernel-open/nvidia/nv.c
  rm -f src/nvidia/src/kernel/gpu/gsp/gsp_dmem_write.c
  rm -f src/nvidia/src/kernel/gpu/gsp/gsp_dmem_write_plan.h
  dkms remove -m nvidia -v ${TREE##*/} --all
  dkms install -m nvidia -v ${TREE##*/} --force
  limine-mkinitcpio
  rm -f $CONF   # (le stock = $WORK/nvidia.conf.stock)
  reboot
  # la vérification du retour: 0 strings NVRM-461 dans le module stock,
  # le sha firmware = $FW_SHA_STOCK (JAMAIS touché)
EOF
echo
echo "§0..§6 = le jour 4.61. La réversibilité = par construction: \
l'ancien = dans le plan (old_hex), le restore = le même instrument \
avec le plan reverté, OU le rollback driver seul."
