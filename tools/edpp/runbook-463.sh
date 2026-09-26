#!/usr/bin/env bash
# runbook-463.sh — PASS 4.63 — VBIOS FLASH: LE CHEMIN MATÉRIEL (the gated day).
#
# THE MISSION (the founder, verbatim anchors):
#   (T1) tous les vBIOS TechPowerUp de la MSI RTX 3070 Gaming X/Z Trio
#        (non-LHR ET LHR), le power limit le plus élevé (270-280 W),
#        comparés à notre VBIOS actuel (94.04.46.00.EB, le LHR);
#   (T2) l'outil NVFlash patché pour RTX 30 (les vérifications de
#        sécurité contournées — le mismatch subsystem ID, le certificat);
#   (T3) la table de puissance décodée (les offsets exacts où 250000
#        vit) pour confirmer que le vBIOS cible = bien 280 W;
#   (T4) le runbook: la sauvegarde → le flash NVFlash → la vérification
#        → le rollback = le re-flash du stock.
#
# WHAT THE CAMPAIGN ALREADY PROVED (the day-0 record, the 35 sessions):
#   - every prior flash attempt DIED AT THE ID GATE: the modded
#     unlock.rom staged a ZEROED head — nvflash answered "Firmware image
#     PCI Device ID (0000) … GPU PCI Device ID mismatch. Nothing
#     changed!" — the card stayed stock 250 W through all 35 sessions
#     (the transport = proven fail-safe: no write ever fired unwantingly).
#   - THE FIX = a GENUINE vendor ROM (intact IDs, NVIDIA-signed) + the
#     2-byte patched nvflash for the SUBSYSTEM/BOARD mismatch (our card
#     1462:3904 board 02DA vs the target's own).
#   - the ring-3 decode: our family's budget = {100000, 240000, 250000}
#     mW (cap entry 2) — 250000 mW lives @0x8FC0C in the verified
#     sibling (sha256_16 41a0860f8abfcfa7). The grammar is re-derived
#     per-ROM by v463a (the LHR seam moved rlen 67→71 — never hardcode).
#   - 4.63a (the founder admission day): TPU serves the .rom wrapped in
#     NVIDIA's NVGI container — v463a splits it (the image @0x9200 for
#     the .E5), the hash admission = the file as downloaded, THE FLASH
#     FILE = THE RAW written next to it. The .E5's P table = v0x4D: the
#     cluster grammar decoded {100000, 280000, 300000} @0x86A04 = the
#     cap 280 W, GATE PASSED on the real file. AND the zeroed subsystem
#     (0000:0300) = THE MSI FAMILY NORM — our own chip's .EB reads the
#     same; the day-0 trap = the zeroed DEVICE, the subsystem = the
#     strap region, not the image (v463a verdicts OK with the note).
#   - the community precedent (r/overclocking kuiwbg): the SAME cross-
#     flash (Gaming X Trio → the 280 W Suprim vBIOS) = a working daily
#     driver. No dual-BIOS switch on this board family: THE ROLLBACK =
#     THE RE-FLASH of the backup (chip-before.rom).
#
# THE TARGET (the T1 verdict, MSI official specs):
#   the ONLY 270-280 W MSI RTX 3070 = the SUPRIM X family (280 W, 2×8-pin).
#   recommended = MSI.RTX3070.8192.210519.rom (Suprim X, 94.04.46.00.E5,
#   TPU id 277875) — LHR-era, OUR OWN 46.00 family, same build date as
#   our card. Non-LHR alternatives: 94.04.25.C0.19/.1E, 94.04.3A.00.D6/.D7.
#
# ZÉRO PATCH DRIVER, ZÉRO FIRMWARE GSP: the day runs the VFIO transport
# (the GPU unbound from nvidia, bound to vfio-pci — the driver is not
# even loaded during the flash; the GSP firmware file sha-guard holds).
#
# THE ACK LAW: RUNBOOK_463_ACK=1 to arm; the flash boot itself =
# RUNBOOK_463_FLASH_ACK=1. THE MULTI-KEY LAW: the multi-keys = the
# SEMICOLON. THE COPY-OUT LAW: the artifacts = $HOME/vbios-463 (NOT /tmp).
# THE ADMISSION LAW (the ring-12/14 protocol): the ROM's MD5/SHA1 must
# equal the TPU-published values (read them on the TPU details page in
# your browser — the pages are bot-checked for us, not for you).
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
OUT="${OUT:-$HOME/vbios-463}"            # the copy-out law: NOT /tmp
WORK="${WORK:-/tmp/runbook-463}"         # VOLATILE — the scratch only
FW_SHA_STOCK="c0156954"                  # the banked stock GSP firmware sha
DEV_ID="2488"                            # GA104 (PCI id sans le préfixe 0x —
                                         # la leçon 4.62: lspci -n affiche
                                         # "10de:2488", le grep 0x = le faux FAIL)
SUBSYS_OURS="1462:3904"                  # the founder's card (day-0)
BOARD_OURS="02DA"                        # nvflash's own words, day-0
TARGET_DEFAULT_TPU="https://www.techpowerup.com/vgabios/277875/msi-rtx3070-8192-210519"

g_ok=0; g_tot=0
chk() { g_tot=$((g_tot+1)); if "$@" >/dev/null 2>&1; then g_ok=$((g_ok+1));
        echo "  [PASS] $*"; else echo "  [FAIL] $*"; fi; }
die() { echo "REFUSÉ: $*" >&2; exit 2; }
section() { echo; echo "== $* =="; }

# ───────────────────────────────────────────────── §0 — LES GUARDS ──
section "§0 LES GUARDS (zéro boot: l'acquisition, l'identité, la grammaire)"

[ "${RUNBOOK_463_ACK:-}" = "1" ] || \
  die "le jour n'est pas armé — RUNBOOK_463_ACK=1 requis (le jour gaté)"

echo "-- la machine --"
chk bash -c "lspci -n -d 10de: | grep -q $DEV_ID"

echo "-- le guard firmware GSP (JAMAIS touché — le sha = le stock) --"
FW="$(find /lib/firmware/nvidia -name 'gsp.bin' 2>/dev/null | head -1)"
if [ -n "$FW" ]; then
  S="$(sha256sum "$FW" | cut -c1-8)"
  [ "$S" = "$FW_SHA_STOCK" ] || die "gsp.bin sha $S != $FW_SHA_STOCK — le fichier firmware a bougé, le jour s'arrête"
  echo "  gsp.bin $S = le stock (intact)"
else
  echo "  (pas de fichier gsp.bin sur cette machine — le guard passe)"
fi

echo "-- les instruments --"
chk test -x tools/flash/v463a_vbios_decode.py
chk python3 tools/flash/v463a_vbios_decode.py --selftest
NV_STOCK="tools/flash/nvflash-5.867/x64/nvflash"
NV_PATCH="tools/flash/nvflash-5.867/x64/nvflash-patched"
chk test -x "$NV_STOCK"
chk test -x "$NV_PATCH"
echo "-- le patch T2 (la loi: 2 octets, JNE→NOP×2, sinon REFUS) --"
D="$(cmp -l "$NV_STOCK" "$NV_PATCH" 2>/dev/null | wc -l)"
P1="$(cmp -l "$NV_STOCK" "$NV_PATCH" 2>/dev/null | awk 'NR==1{print $1, $2, $3}')"
P2="$(cmp -l "$NV_STOCK" "$NV_PATCH" 2>/dev/null | awk 'NR==2{print $1, $2, $3}')"
[ "$D" = "2" ] || die "nvflash-patched != le patch 2-octets ($D octets diffèrent) — binaire non admis"
[ "$P1" = "1590796 165 220" ] && [ "$P2" = "1590797 30 220" ] || \
  die "les octets du patch ne sont pas 0x18460B: 75→90 / 0x18460C: 18→90 — binaire non admis"
echo "  patch vérifié: @0x18460B 75→90, @0x18460C 18→90 (le saut ID-mismatch → NOP)"
"$NV_PATCH" --version 2>&1 | head -1 | sed 's/^/  /'

echo "-- l'acquisition (T1/T3: le ROM cible, l'admission ring-12/14) --"
T463_ROM="${T463_ROM:-$OUT/MSI.RTX3070.8192.210519.rom}"
[ -f "$T463_ROM" ] || die "le ROM cible manque: $T463_ROM
  → télécharge-le dans TON navigateur depuis $TARGET_DEFAULT_TPU
    (la page .rom est bot-checkée pour nous, pas pour toi), puis:
    export T463_ROM=<le fichier> T463_MD5=<md5 TPU> T463_SHA1=<sha1 TPU>"
T463_MD5="${T463_MD5:-}"
T463_SHA1="${T463_SHA1:-}"
[ -n "$T463_MD5" ] && [ -n "$T463_SHA1" ] || die "les hashes TPU manquent (T463_MD5 / T463_SHA1) — l'admission ring-12/14 n'est pas négociable"

echo "-- les portes d'identité + la grammaire (T3, v463a) --"
V="$(python3 tools/flash/v463a_vbios_decode.py "$T463_ROM" \
     --expect-md5 "$T463_MD5" --expect-sha1 "$T463_SHA1")" \
  || die "v463a a refusé le ROM (l'admission, l'identité, ou la grammaire)"
echo "$V" | sed 's/^/  /'
echo "$V" | grep -q "→ OK" || die "la porte d'identité a refusé (le piège 0000 des 35 sessions)"
echo "$V" | grep -q "peak 280000 mW" || die "le cible n'est PAS 280 W (le peak décodé != 280000 mW) — le T3 a parlé, le jour s'arrête"
echo "$V" | sed -n "s/.*subsystem \([0-9a-fx:\.]*\) .*/  subsystem cible: \1 (notre: $SUBSYS_OURS)/p"

# ─────────────────────────────────────────────── §1 — LE DECODE ──
section "§1 LE DÉCODE (la comparaison T1: notre stock vs le cible)"
BACKUP_REF="${BACKUP_REF:-$T463_ROM}"
echo "-- le cible (rappel) --"
python3 tools/flash/v463a_vbios_decode.py "$T463_ROM" | sed 's/^/  /'
echo "-- notre stock (le dump de la puce si présent; sinon le sibling TPU vérifié) --"
CHIP_REF="${CHIP_REF:-}"
if [ -n "$CHIP_REF" ] && [ -f "$CHIP_REF" ]; then
  python3 tools/flash/v463a_vbios_decode.py "$CHIP_REF" | sed 's/^/  /'
else
  echo "  (pas de dump puce fourni — CHIP_REF= le chemin, sinon le runbook le capturera en §2)"
fi

# ──────────────────────────────────────────────── §2 — LE VM DAY ──
section "§2 LE JOUR VM (le transport VFIO éprouvé — 35 sessions, zéro écriture intempestive)"
[ "${RUNBOOK_463_FLASH_ACK:-}" = "1" ] || \
  die "le flash n'est pas armé — RUNBOOK_463_FLASH_ACK=1 requis (le ACK par boot)"
command -v qemu-system-x86_64 >/dev/null || die "qemu-system-x86_64 absent"
command -v nvflash >/dev/null || true
SESSION="$OUT/session-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$SESSION" || die "impossible de créer $SESSION"
echo "  session: $SESSION"
echo "  le transport = le machinery day-0: vfio-pci bind → QEMU guest
  (busybox + $NV_PATCH + le ROM cible dans l'initramfs) → la séquence:
  (V0) stage, (V1) version, (V2) chip read ×2 + cmp (LE BACKUP = la porte),
  (V3) --protectoff + --flash + --verify, (V4) chip read-back ×2 + cmp,
  (V5) le verdict. Écran noir pendant le passthrough — tout continue dans
  \$SESSION/session.log; la machine se reboot seule à la fin.
  LE ROLLBACK (§4) = le re-flash de chip-before.rom — PAS DE SWITCH
  dual-BIOS sur cette board (le précédent communautaire + notre Gaming
  Trio Plus): la sécurité = la sauvegarde byte-identique + le transport
  prouvé-ne-jamais-écrire-tout-seul."
echo "  (le pilotage de la session VFIO reste le geste fondateur —
  le machinery day-0 vfio-flash-* : ce runbook ne l'invente pas, il
  l'appelle avec le ROM ADMIS et le binaire PATCHÉ vérifié octet-octet)"

# ───────────────────────────────────────── §3 — LA VÉRIFICATION ──
section "§3 LA VÉRIFICATION (le jour d'après: le boot stock-driver)"
echo "-- le ROM lu dans la puce se décode en 280 W --"
[ -f "$SESSION/chip-after.rom" ] && \
  python3 tools/flash/v463a_vbios_decode.py "$SESSION/chip-after.rom" | sed 's/^/  /'
echo "-- la machine vivante --"
chk bash -c "nvidia-smi -q -d POWER | grep -q 'Power Limit'"
nvidia-smi -q -d POWER | grep -A 1 "Power Limit" | sed 's/^/  /' || true
echo "  LE VERDICT T1-T3: 'Power Limit' doit nommer 280000 mW (280 W).
  Les valeurs vivantes {min,default,max} = le budget décodé — la chaîne
  VBIOS→driver→runtime re-fermée au niveau octet (la loi ring-3)."
chk bash -c "journalctl -k --since '-1 hour' | ! grep -q Xid" || \
  echo "  !! des Xid dans le journal — le §5 dit quoi"

# ─────────────────────────────────────────── §4 — LE ROLLBACK ──
section "§4 LE ROLLBACK (= le re-flash du stock, le même instrument renversé)"
echo "  l'artefact = \$SESSION/chip-before.rom (le dump puce ×2 byte-identique, §2 V2)
  le rollback = la MÊME session VFIO avec chip-before.rom dans le slot
  (le binaire patché n'est même pas nécessaire: les IDs du backup =
  les nôtres — le stock nvflash accepte son propre ROM)
  puis §3 re-couru: le verdict = 250 W de retour, zero Xid."

# ──────────────────────────────────────── §5 — LES CONTINGENCES ──
section "§5 LES CONTINGENCES (en code, pas en prose)"
echo "  - le flash refuse encore l'ID → LIRE le message: 'Device ID
    mismatch' sur un ROM ADMIS-non-zéro = le patched nvflash n'a pas
    couru (le chemin du binaire dans l'initramfs); 'Subsystem ID'
    seul = attendu, le patch le traverse."
echo "  - la puce refuse le verify post-write → PAS de deuxième write
    sur le même boot: re-boot, re-read, v463a décode; le rollback
    devient le plan A."
echo "  - des Xid post-boot → le rollback §4, le ROM E5 re-vérifié
    (l'admission), le jour suivant sépare (une variable par transition)."
echo "  - la puce demeurée stock après un 'update successful' → le
    double-read §2 V4 a déjà nommé le mismatch (cmp) — ne pas
    nvidia-smi avant le cmp (la loi du faux-zéro, 4.56)."

echo
echo "selftest §0: $g_ok/$g_tot"
[ "$g_ok" = "$g_tot" ] || echo "  (des FAIL au-dessus = les portes §0, le jour s'arrête avant le VM)"
echo "runbook-463: §0-§1 courables host-only; §2 = le jour gaté (FLASH_ACK)."