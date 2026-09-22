#!/usr/bin/env bash
# ROLLBACK 4.23 — à lancer depuis un TTY si le boot graphique échoue
# avec EdppOverride actif. Ctrl+Alt+F3 puis:
#   sudo bash ~/Projects/compute-lab/bench/undo-edpp.sh && reboot
set -e
sed -i 's/;EdppOverride=280000//' /etc/kernel/cmdline
grep -q EdppOverride /etc/kernel/cmdline && { echo "ERREUR: le paramètre persiste"; exit 1; }
mkinitcpio --kernel 7.2.5-3-omarchy --uki /boot/EFI/Linux/omarchy_linux-omarchy.efi
echo "Le rewrite = désactivé (le module patché reste, il ne réécrit rien sans la clé)."
echo "reboot maintenant."
