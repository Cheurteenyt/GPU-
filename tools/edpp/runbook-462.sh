#!/usr/bin/env bash
# runbook-462.sh — PASS 4.62 — ROUTE W: LIRE LE HEAP FB (the gated day).
#
# THE MISSION (the founder, verbatim anchors):
#   (T1) la sonde B1 = la lecture BAR1/ReBAR (8192 MiB standing — zéro
#        patch driver, le pattern v454b PROT_READ) sur la région WPR2
#        — les adresses FB = nos données (wpr2meta.bin capturé);
#   (T2) la sonde MD = memdescCreateExisting + memdescDescribe(ADDR_
#        FBMEM) + memdescMap READABLE (les ancres 4.52: :943/:1009/:990);
#   (T3) le scan v451a des données lues (les marqueurs 0x0EE6B280 =
#        la base 250 W = le shape-match);
#   (T4) le selftest + le runbook;
#   les plausibility guards = all-zeros/FF = le seal a répondu (le
#   négatif nommé).
#
# ZÉRO BOOT d'abord: §0 = the selftests + THE PLAN GATE (the S8 dump
# decode — no window survives = the REFUSAL, nothing boots). §1 = the
# B1 probe HOT (zero patch, zero boot — the read-only gesture, the
# ACK still required: even the reads are gated, the 4.54 discipline).
# §2 = the scan. §3-§4 = the MD boot (the corroboration + the
# cross-read; the seal-negative on B1 = the MD boot BECOMES the
# decider). §5 = THE DECISION TABLE (the 4.52 §5 law, in code).
#
# THE ACK LAW: §1 = ROUTE_W_462_ACK=1; the MD boot = RUNBOOK_462_BOOT_ACK=1
# (+ RUNBOOK_462_SEL=<the window>). THE MULTI-KEY LAW (banked twice):
# the multi-keys = the SEMICOLON — the space form = never parsed.
# THE VERIFICATION LAW (the 4.56 lesson): nm the .ko for the DATA
# SYMBOL (gspWpr2ReadState) + the NVRM-462 bytes — NEVER the function
# name alone (the inline erases it).
#
# THE ROLLBACK = DRIVER ONLY (§6): the firmware file NEVER touched
# (the §0 sha guard holds all day).
set -uo pipefail

REPO="${REPO:-/home/z/my-project/gpu-repo}"
TREE="${TREE:-/usr/src/nvidia-610.57.04}"
DMEM_DIR="${DMEM_DIR:-$HOME/dmem-451}"
OUT="${OUT:-$HOME/route-w-462}"          # the copy-out law: NOT /tmp
WORK="${WORK:-/tmp/runbook-462}"        # VOLATILE — the scratch only
FW_SHA_STOCK="c0156954"                  # the banked stock GSP firmware sha
DEV_ID="0x2488"                          # GA104

g_ok=0; g_tot=0
chk() { g_tot=$((g_tot+1)); if "$@" >/dev/null 2>&1; then g_ok=$((g_ok+1));
        echo "  [PASS] $*"; else echo "  [FAIL] $*"; fi; }
die() { echo "REFUSÉ: $*" >&2; exit 2; }
section() { echo; echo "== $* =="; }

# ───────────────────────────────────────────────── §0 — LES GUARDS ──
section "§0 LES GUARDS (zéro boot: les selftests et le plan d'abord)"

[ "${RUNBOOK_462_ACK:-}" = "1" ] || \
  die "le jour n'est pas armé — RUNBOOK_462_ACK=1 requis (le jour gaté)"

echo "-- la machine --"
chk bash -c "lspci -n -d 10de: | grep -q $DEV_ID"
chk test -c /dev/nvidiactl

echo "-- le guard firmware (JAMAIS touché — le sha = le stock) --"
FW="$(find /lib/firmware/nvidia/${TREE##*/} -name 'gsp.bin' 2>/dev/null | head -1)"
[ -n "$FW" ] || die "gsp.bin introuvable"
FW_SHA="$(sha256sum "$FW" | cut -c1-8)"
[ "$FW_SHA" = "$FW_SHA_STOCK" ] || \
  die "le sha firmware ($FW_SHA) != le stock ($FW_SHA_STOCK) — STOP"

echo "-- les batteries bancarisées (la reproduction D'ABORD) --"
chk python3 "$REPO/lab/jalon411/v462a_wpr2_read.py" --selftest
chk python3 "$REPO/lab/jalon411/v462b_md_probe_battery.py"
chk python3 "$REPO/lab/jalon411/v462c_route_w_scan.py" --selftest

echo "-- LA PLAN GATE: le decode S8 (les adresses FB = nos données) --"
S8="$DMEM_DIR/wpr2meta.bin"
[ -f "$S8" ] || die "wpr2meta.bin absent dans $DMEM_DIR — le jour 4.51 \
doit produire les dumps d'abord (RmGspDmemDump=1); la lane route-W = \
l'instrument prêt, pas le devin"
mkdir -p "$OUT" "$WORK"
S4_ARGS=()
[ -f "$DMEM_DIR/libosinit.bin" ] && S4_ARGS=(--libosinit "$DMEM_DIR/libosinit.bin")

python3 "$REPO/lab/jalon411/v462a_wpr2_read.py" \
  --wpr2meta "$S8" "${S4_ARGS[@]}" \
  --out "$OUT" \
  --plan-out "$WORK/v462a_plan.json" \
  --emit-c "$WORK/wpr2_read_plan.h" | tee "$WORK/v462a_decode.log"
[ "${PIPESTATUS[0]}" = "0" ] || die "le decode S8 = échoué (les \
invariants ou INDECIDABLE — le journal ci-dessus = l'évidence, rien \
ne boote)"

echo "-- le guard ReBAR (le 8192 MiB standing — ring 18) --"
GPU_PCI="$(lspci -n -d 10de: | grep "$DEV_ID" | cut -d' ' -f1 | head -1)"
[ -n "$GPU_PCI" ] || die "la GPU GA104 introuvable"
BAR1_SZ="$(cat "/sys/bus/pci/devices/$GPU_PCI/resource1_sz" 2>/dev/null \
           || stat -c %s "/sys/bus/pci/devices/$GPU_PCI/resource1" 2>/dev/null \
           || echo 0)"
[ "$BAR1_SZ" = "8589934592" ] || \
  echo "  [warn] la BAR1 = ${BAR1_SZ} B != 8192 MiB — la fenêtre \
linéaire = l'hypothèse Nommée (la sonde refusera le guard size; le \
ReBAR doit être le standing banké)"

echo "le plan = émis ($WORK/wpr2_read_plan.h) — LA REVUE HUMAINE = le \
step obligatoire avant §3 (cat $WORK/v462a_plan.json)"

# ───────────────────────────── §1 — LA SONDE B1 (HOT, zéro patch) ──
section "§1 LA SONDE B1 = LA LECTURE BAR1/ReBAR (zéro patch, zéro boot — \
l'ACK: même les lectures sont gatées)"

export ROUTE_W_462_ACK=1
python3 "$REPO/lab/jalon411/v462a_wpr2_read.py" \
  --wpr2meta "$S8" "${S4_ARGS[@]}" \
  --pci "$GPU_PCI" --bar 1 \
  --out "$OUT" | tee "$WORK/v462a_b1.log"
B1_RC="${PIPESTATUS[0]}"
echo "le retour B1 = $B1_RC (4 = THE SEAL ANSWERED — le négatif nommé)"
echo "-- le guard zero-Xid après la lecture --"
dmesg | tail -50 | grep -qi "xid" && \
  echo "  [warn] un Xid dans le dmesg récent — la lecture a touché; \
le journal décide" || echo "  [PASS] zéro Xid"

# ───────────────────────────── §2 — LE SCAN (T3) DES DONNÉES B1 ──
section "§2 LE SCAN DES DONNÉES LUES (les marqueurs 0x0EE6B280 = la base \
250 W = le shape-match)"

B1_DUMPS=()
for f in "$OUT"/v462a_b1_win*.bin; do
  [ -f "$f" ] && B1_DUMPS+=("$f")
done
if [ ${#B1_DUMPS[@]} -eq 0 ]; then
  echo "aucun dump B1 (le §1 = REFUSED/SEAL) — le scan = sur les \
blobs MD après le §4"
else
  python3 "$REPO/lab/jalon411/v462c_route_w_scan.py" \
    --out "$OUT/v462c_scan_b1.json" "${B1_DUMPS[@]}" | tee "$WORK/v462c_b1.log"
  echo "le scan B1 = écrit ($OUT/v462c_scan_b1.json)"
fi

# ─────────────────────── §3 — LE PATCH MD (la sonde memdesc) ──
section "§3 LE PATCH TWO-SIDED MD (the drop-in + le dkms --force + la loi nm/od)"

echo "-- les anchors de l'arbre (8, >=7 requis — le juge du build) --"
a=0
for pat in "memdescCreateExisting" "memdescDescribe" "memdescMap" \
           "memdescUnmap" "osReadRegistryDword" "pWprMeta" \
           "ADDR_FBMEM" "kgspStartLogPolling"; do
  if grep -rq "$pat" "$TREE/src/nvidia/src/kernel/gpu/gsp/" \
        "$TREE/src/nvidia/generated/" 2>/dev/null; then
    a=$((a+1)); echo "  [anchor ok] $pat"
  else
    echo "  [ANCHOR MISSING] $pat"
  fi
done
[ "$a" -ge 7 ] || die "les anchors insuffisants ($a/8) — l'arbre cible = \
pas le 610.57.04 attendu"

cp "$REPO/tools/edpp/gsp_wpr2_read.c" "$TREE/src/nvidia/src/kernel/gpu/gsp/"
cp "$WORK/wpr2_read_plan.h" "$TREE/src/nvidia/src/kernel/gpu/gsp/"

KGSP="$TREE/src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
grep -q 'gsp_wpr2_read_schedule' "$KGSP" || {
  cp "$KGSP" "$WORK/kernel_gsp.c.stock"
  python3 - "$KGSP" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
if '#include "gsp_wpr2_read.c"' not in s:
    anchor = '#include "gsp_dmem_write.c"'
    if anchor not in s:
        anchor = '#include "gsp_hpoke.c"'
    if anchor not in s:
        anchor = '#include "gsp_dmem_dump.c"'
    assert s.count(anchor) == 1, "l'anchor include absent"
    s = s.replace(anchor, anchor + '\n#include "gsp_wpr2_read.c"', 1)
hook = 'gsp_dmem_write_schedule(pGpu, pKernelGsp);'
if hook not in s:
    hook = 'gsp_hpoke_schedule(pGpu, pKernelGsp);'
if hook not in s:
    hook = 'gsp_dmem_dump_schedule(pGpu, pKernelGsp, pGspFw);'
assert s.count(hook) == 1, "l'anchor hook absent"
s = s.replace(hook, hook +
              '\n    gsp_wpr2_read_schedule(pGpu, pKernelGsp);  // 4.62', 1)
open(p, 'w').write(s)
print("PATCH OK: kernel_gsp.c = l'include + la hook line 4.62")
PY
}

echo "-- la face nv.c (le publisher, le marker = obligatoire) --"
python3 "$REPO/tools/edpp/patch_nv_462.py" || die "le patch nv.c = échoué"
grep -q "Wpr2ReadMarker" "$TREE/kernel-open/nvidia/nv.c" || \
  die "le Wpr2ReadMarker ABSENT de nv.c — le build passerait mais la \
lecture = un no-op silencieux (la loi 4.55)"

echo "-- le rituel dkms (remove + install --force — la leçon bancarisée) --"
dkms remove -m nvidia -v "${TREE##*/}" --all || true
dkms install -m nvidia -v "${TREE##*/}" --force || die "le dkms = échoué"

echo "-- limine-mkinitcpio (le UKI = le module EMBARQUÉ) --"
limine-mkinitcpio || mkinitcpio -P || die "l'initramfs = échoué"

echo "-- LA LOI DE VÉRIFICATION: nm le .ko (le symbole DATA) + les octets --"
KO="$(find "/lib/modules/$(uname -r)" -name 'nvidia.ko*' 2>/dev/null | head -1)"
[ -n "$KO" ] || die "le nvidia.ko introuvable"
nm "$KO" 2>/dev/null | grep -q "gspWpr2ReadState" || \
  die "le symbole gspWpr2ReadState ABSENT du module (la loi nm — \
jamais le nom de fonction seul)"
strings -a "$KO" 2>/dev/null | grep -q "NVRM-462" || \
  strings -a "$KO" 2>/dev/null | grep -q "RmGspWpr2Read" || \
  die "les octets NVRM-462/RmGspWpr2Read absents du module (la loi od)"
echo "le module = VÉRIFIÉ (le symbole data + les octets)"

# ─────────────────────── §4 — LE BOOT MD (l'ACK PAR BOOT) ──
section "§4 LE BOOT MD = LA LECTURE memdesc + LE LEDGER (l'ACK par boot)"

SEL="${RUNBOOK_462_SEL:-1}"
[ "${RUNBOOK_462_BOOT_ACK:-}" = "1" ] || \
  die "le boot n'est pas armé — RUNBOOK_462_BOOT_ACK=1;RUNBOOK_462_SEL=$SEL \
(les DEUX clés, une fenêtre par boot)"

CONF="/etc/modprobe.d/nvidia.conf"
cp "$CONF" "$WORK/nvidia.conf.stock" 2>/dev/null || true
echo "options nvidia NVreg_RegistryDwords=\"RmGspWpr2Read=$SEL\"" > "$CONF"
echo "le conf = RmGspWpr2Read=$SEL (UNE fenêtre par boot, sel=$SEL)"
echo "(le multi-clés = le POINT-VIRGULE: \"RmGspDmemDump=1;RmGspWpr2Read=$SEL\" \
si le dump coexiste — l'espace = jamais parsé, la leçon 4.51)"
echo
echo ">>> REBOOTEZ. Au retour:"
echo ">>>   dmesg | grep NVRM-462 > $OUT/ledger-462.txt"
echo ">>>   cat /sys/kernel/debug/gsp_wpr2_read/win/window$SEL.bin > $OUT/v462b_md_win$SEL.bin 2>/dev/null"
echo ">>>   sha256sum $OUT/v462b_md_win$SEL.bin | cut -c1-16   # le sha16 du cross-read"
echo ">>>   python3 $REPO/lab/jalon411/v462c_route_w_scan.py --out $OUT/v462c_scan_md.json $OUT/v462b_md_win$SEL.bin:md-window$SEL"
echo ">>>   puis re-lancez: RUNBOOK_462_STAGE=5 bash $0"

# ───────────────────── §5 — LA TABLE DE DÉCISION (en code) ──
if [ "${RUNBOOK_462_STAGE:-}" = "5" ]; then
section "§5 LA TABLE DE DÉCISION (la loi 4.52 §5, en code)"

LEDGER="$OUT/ledger-462.txt"
[ -f "$LEDGER" ] || die "le ledger absent — dmesg | grep NVRM-462 d'abord"
cat "$LEDGER"
MD_BLOB="$OUT/v462b_md_win$SEL.bin"
B1_OK=0; MD_OK=0; MD_FAULT=0
grep -q "verdict=READ-DONE" "$LEDGER" && MD_OK=1
grep -qE "verdict=MAP-FAIL|verdict=NULL-PLAN" "$LEDGER" && MD_FAULT=1
[ -f "$OUT/v462c_scan_b1.json" ] && \
  ! grep -q "SEAL-NEGATIVE" "$WORK/v462c_b1.log" 2>/dev/null && B1_OK=1

if [ "$B1_OK" = "1" ] && [ "$MD_OK" = "1" ]; then
  echo "B1 clean + MD clean => ROUTE W OPENS (la décision 4.52 §5):"
  echo "  la write lane = le MÊME chemin WRITEABLE (la prochaine passe:"
  echo "  ONE champ par boot, la pre-vérification du marqueur = la loi 4.61,"
  echo "  le plan = les OCTETS TROUVÉS ici par v462c — jamais le devin)."
  echo "  le cross-read: les sha16 B1 vs MD — l'égalité = les deux routes"
  echo "  lisent LA MÊME mémoire (le firewall granulaire = l'évidence nommée)."
  exit 10
elif [ "$B1_OK" = "0" ] && [ "$MD_FAULT" = "1" ]; then
  echo "B1 = le seal a répondu ET MD = MAP-FAIL => LE SEAL REFUSE LES"
  echo "LECTURES CPU (le négatif nommé, la décision 4.52 §5):"
  echo "  route W = CLOSE honnêtement; la lane ROP = le dernier recours"
  echo "  (la chaîne 4.45/4.57, le sweep = la position du retour);"
  echo "  le falcon-internal = le négatif nommé de la 4.51, CONFIRMÉ."
  exit 11
elif [ "$MD_OK" = "1" ] && [ "$B1_OK" = "0" ]; then
  echo "MD clean + B1 seal => LE DÉSACCORD = LA DONNÉE (le firewall ="
  echo "granulaire: le memdesc-map CPU lit, l'aperture BAR1 = scellée):"
  echo "  la lane MD = LA route (le scan v462c sur le blob MD = le juge;"
  echo "  le sha16 MD = la référence du cross-read)."
  exit 12
else
  echo "l'état = mixte — le ledger + les scans = l'évidence; relisez"
  echo "$OUT/v462c_scan_*.json et le journal (le verdict = aux octets)."
  exit 13
fi
fi

# ─────────────────────────────── §6 — LE ROLLBACK ──
section "§6 LE ROLLBACK (LE DRIVER SEUL — ~10 min, le rituel bancarisé)"
cat <<EOF
  cd $TREE
  git checkout -- src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c
  git checkout -- kernel-open/nvidia/nv.c
  rm -f src/nvidia/src/kernel/gpu/gsp/gsp_wpr2_read.c
  rm -f src/nvidia/src/kernel/gpu/gsp/wpr2_read_plan.h
  dkms remove -m nvidia -v ${TREE##*/} --all
  dkms install -m nvidia -v ${TREE##*/} --force
  limine-mkinitcpio
  rm -f $CONF   # (le stock = $WORK/nvidia.conf.stock)
  reboot
  # la vérification du retour: 0 strings NVRM-462 dans le module stock,
  # le sha firmware = $FW_SHA_STOCK (JAMAIS touché)
EOF
echo
echo "§0..§6 = le jour 4.62. LA LECTURE = passive par construction: un map,"
echo "une copie, un unmap — aucun chemin d'écriture n'existe (la sonde ="
echo "la garantie, le code = la preuve). Les sorties = $OUT (la loi copy-out)."
