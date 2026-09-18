#!/bin/bash
# campagne-dial-gate.sh — PORTE DE SÉCURITÉ pour l'injection de dials NVreg (omarchy)
# Campagne RTX 3070 · vague 3 · Task 63 · pour le chat machine de Cheurteenyt
# (re-constitué après rotation d'environnement — Task 64)
#
# Rôle : valider UN dial AVANT tout reboot, et laisser une porte de sortie
# imprimable. Aucune modification système sans validation explicite.
#
# Usage :
#   ./campagne-dial-gate.sh "RmBootGspRmWithBoostClocks=1"
#   ./campagne-dial-gate.sh --status          (état live, sans rien écrire)
#   ./campagne-dial-gate.sh --rollback        (afficher le one-liner de sortie)
#
# Règles non négociables (rappel par la porte elle-même) :
#   1 dial par reboot · jamais de dial le jour d'un update pilote/kernel
#   · jamais le jour du flash vBIOS · tout Xid en session = dial retiré.

set -u

CONF="/etc/modprobe.d/nvidia-dials.conf"
PARAM="NVreg_RegistryDwords"
MODCONF="/etc/modprobe.d/nvidia.conf"

die() { echo "✗ REFUS : $*" >&2; exit 1; }

# ---------------------------------------------------------------- status ---
if [[ "${1:-}" == "--status" ]]; then
  echo "=== ÉTAT LIVE (sans écriture) ==="
  echo "→ Conf active :"
  cat "$CONF" 2>/dev/null || echo "  (aucune — baseline vierge, parfait pour Phase V)"
  echo "→ Paramètre vu par le noyau (ce que le RM a RÉELLEMENT reçu au boot) :"
  if [[ -r "/sys/module/nvidia/parameters/$PARAM" ]]; then
    echo "  $PARAM = $(cat "/sys/module/nvidia/parameters/$PARAM")"
  else
    echo "  (module nvidia non chargé ou param absent — vérifier dmesg | grep -i nvrm)"
  fi
  echo "→ Modconf omarchy (early KMS) :"
  cat "$MODCONF" 2>/dev/null || echo "  (absente)"
  echo "→ Derniers événements driver/GSP :"
  journalctl -b -k --no-pager 2>/dev/null | grep -iE "nvrm|gsp|xid" | tail -8 || echo "  (rien)"
  echo "→ Xid en session courante :"
  journalctl -b -k --no-pager 2>/dev/null | grep -i "xid" | tail -4 || echo "  (aucun — propre)"
  exit 0
fi

if [[ "${1:-}" == "--rollback" ]]; then
  echo "=== PORTE DE SORTIE (à courir en TTY ou depuis Limine-édit) ==="
  echo "  sudo rm -f '$CONF' && sudo mkinitcpio -P && sudo reboot"
  echo "  (Sauvetage écran noir : menu Limine → E sur l'entrée → ajouter en fin"
  echo "   de cmdline :  module_blacklist=nvidia,nvidia_drm  → booter → la porte"
  echo "   ci-dessus → retirer le module_blacklist ensuite.)"
  exit 0
fi

# ------------------------------------------------------------ validation ---
[[ $# -eq 1 ]] || die "usage : campagne-dial-gate.sh \"Dial=Valeur\" | --status | --rollback"
DIAL="$1"

echo "=== PORTE DE SÉCURITÉ DIAL — $DIAL ==="

# 0) Anti-combinaison : pas de dial le jour d'un update pilote/kernel ou de flash
pacman -Q nvidia-open-dkms nvidia-utils linux 2>/dev/null
last_pac=$(grep -hE "\b(nvidia-open-dkms|nvidia-utils|linux) " /var/log/pacman.log 2>/dev/null | tail -1 | grep -oE "^\[[^]]+\]" || true)
echo "→ Dernier update lié (pacman.log) : ${last_pac:-inconnu}. Si c'est AUJOURD'HUI : attendre demain. [Règle anti-combinaison]"

# 1) Le nom de paramètre noyau existe ? (protection typo au niveau param)
modinfo -p nvidia 2>/dev/null | grep -q "^$PARAM" \
  || die "paramètre $PARAM introuvable dans le module nvidia (modinfo). Ne pas écrire la conf."
echo "✓ Param noyau présent : $PARAM"

# 2) Syntaxe du dial : NomValeur en un bloc, sans espace ni guillemet interne
[[ "$DIAL" =~ ^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_,\.\-]+$ ]] \
  || die "syntaxe de dial suspecte (« $DIAL »). Format attendu : Nom=Valeur (alphanumérique), sans espaces."
echo "✓ Syntaxe dial propre"

# 3) Pas d'espace dans le multi-dials point-virgule (sinon quoting casse tôt)
[[ "$DIAL" != *" "* ]] || die "espace détecté — séparer les multi-dials par ';' SANS espaces."
echo "✓ Pas d'espace parasite"

# 4) Diff non destructif : montrer ce qui sera écrit
echo "→ Contenu qui sera écrit dans $CONF :"
echo "    options nvidia $PARAM=\"$DIAL\""
if [[ -f "$CONF" ]]; then
  echo "⚠ Une conf existe déjà :"
  cat "$CONF"
  echo "  (multi-dials = fusionner à la main avec ';' — jamais deux lignes options nvidia)"
fi

# 5) Rollback imprimable AVANT commit
ROLLBACK="/root/DIAL-ROLLBACK.txt"
echo "  sudo rm -f $CONF && sudo mkinitcpio -P && reboot
  (Sauvetage écran noir : Limine → E → ajouter : module_blacklist=nvidia,nvidia_drm
   → booter → rollback ci-dessus → retirer le module_blacklist.)" \
  | sudo tee "$ROLLBACK" >/dev/null 2>&1 && echo "✓ Rollback écrit : $ROLLBACK" \
  || echo "! Rollback non écrit (sudo refusé ?) — le one-liner est ci-dessus, le noter."

# 6) Checklist humaine finale — RIEN n'est écrit tant que l'humain n'a pas dit oui
cat <<'CHECK'

=== CHECKLIST AVANT COMMIT (répondre à voix haute) ===
  [ ] c'est le SEUL changement système de ce boot
  [ ] pas d'update pilote/kernel prévu aujourd'hui
  [ ] pas de flash vBIOS prévu aujourd'hui (phases M et D jamais le même jour)
  [ ] le one-liner de rollback est noté/imprimé
  [ ] le TTY (Ctrl+Alt+F3) et le menu Limine ont été vus fonctionner au moins une fois
  [ ] la session MangoHud de mesure est prête (baseline A/B comparable)

Commit ensuite MANUELLEMENT :
  echo 'options nvidia NVreg_RegistryDwords="DIAL"' | sudo tee /etc/modprobe.d/nvidia-dials.conf
  sudo mkinitcpio -P && sudo reboot     # ← LE PIÈGE OMARCHY : sans mkinitcpio, rien ne change

Puis vérifier l'ARRIVÉE réelle :
  ./campagne-dial-gate.sh --status
CHECK
echo "=== PORTE TERMINÉE — rien n'a été écrit dans la conf. ==="
