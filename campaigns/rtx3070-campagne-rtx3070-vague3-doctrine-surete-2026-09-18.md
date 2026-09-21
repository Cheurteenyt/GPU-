# CAMPAGNE RTX 3070 — Vague 3 : doctrine de sûreté, diagnostic « plus détecté », playbook de sauvetage
**Task 63 · session cloud du 18/09/2026 · Super Z · pour le chat machine de Cheurteenyt**
*(re-constitué après rotation d'environnement — Task 64)*

> Directive fondatrice (verbatim) : « il faut qu'on continue de chercher, faut aussi faire
> attention parce que y'a aussi le pilote graphique NVIDIA sur linux, si on modifie des
> choses et que ça détecte plus le gpu. »

La crainte reçoit ici une réponse **mécanique, pas rassurante** : qu'est-ce qu'un dial
cassé fait *vraiment* au pilote, pourquoi il ne peut jamais tuer la détection de façon
persistante, et comment on sort d'un écran noir en 30 secondes — avec des chemins de
sauvetage **vérifiés dans les fichiers omarchy**, pas du lore.

---

## 1. La réponse mécanique : « plus détecté » permanent est impossible par construction

Le canal `NVreg_RegistryDwords` est **de la RAM volatile côté hôte** :
- la conf vit dans UN fichier texte (`/etc/modprobe.d/nvidia-dials.conf`) ;
- au chargement du module, la chaîne est passée au GSP-RM par **RPC registre** ;
- le GSP l'applique en mémoire — **zéro écriture NVRAM, zéro flash, zéro SPI, zéro vBIOS**.

Un power cycle efface tout. Supprimer le fichier + `mkinitcpio -P` = retour stock
**garanti par construction**. La détection PCI (la couche « la carte existe ») est
structurellement hors de portée d'un dial. Le pire cas réel n'est pas « carte morte »,
c'est « pilote qui refuse de s'initialiser » — et ça se répare au clavier.

## 2. Les quatre classes de panne réelles (et ce qu'on voit)

| Classe | Cause | Symptôme | Réversibilité |
|---|---|---|---|
| **A — Syntaxe** | quoting cassé, espace parasite, deux lignes `options nvidia` | module refuse de charger ; Hyprland ne démarre pas ; **le TTY (Ctrl+Alt+F3) survit** | rm fichier + `mkinitcpio -P` |
| **B — Valeur mauvaise au boot** | dial connu + valeur incohérente → GSP init fail | même tableau que A : `nvidia-smi` « No devices » ; `dmesg` raconte pourquoi | idem + ne pas re-tenter |
| **C — Runtime** | dial chargé OK, comportement cassé sous charge | session crash, Xid, perf effondrée | reboot sans le dial |
| **D — « Plus détecté » permanent** | — | **n'existe pas pour les dials** (§1). Si un jour : matériel (bus, alim) ou flash vBIOS (dual-BIOS) | — |

Un **nom de dial mal orthographié est inoffensif** — le RM cherche par nom à runtime
et ignore l'inconnu (prouvé ring 30). Seul le *nom du paramètre noyau*
(`NVreg_RegistryDwords`) doit être exact — le gate script le vérifie.

## 3. Diagnostic différentiel en 3 commandes

```bash
lspci -d 10de:                    # la carte EXISTE-t-elle sur le bus ?
dmesg | grep -iE "nvrm|nvidia|gsp" | tail -30   # pourquoi le pilote refuse ?
cat /sys/module/nvidia/parameters/NVreg_RegistryDwords  # ce que le RM a REÇU au boot
```

`lspci` vide → problème **hardware/BIOS** (hors dials ; si jour du flash → dual-BIOS
immédiat). `lspci` OK + dmesg erreur → **classe A ou B** → playbook §4. Le `cat` sysfs
est la vérité d'arrivée : si ton dial n'y figure pas, il n'a jamais été appliqué
(piège mkinitcpio oublié).

## 4. Le playbook de sauvetage omarchy (vérifié dans les fichiers)

Vérifié dans `etc/limine-entry-tool.d/omarchy-defaults.conf` et
`default/limine/limine.conf` : `ENABLE_LIMINE_FALLBACK=yes` ;
`BOOT_ORDER="*, *fallback, Snapshots"` (**snapshots Snapper bootables**) ; timeout non
nul (menu toujours accessible) ; `hash_mismatch_panic: no`.

**Échelle de sauvetage :**

1. **TTY** (Ctrl+Alt+F3) — 95 % des cas : `--rollback` (§5) et c'est fini.
2. **Éditeur Limine au boot** — menu Limine → `E` → ajouter en fin de cmdline :
   `module_blacklist=nvidia,nvidia_drm` → booter → rollback §5 → retirer le
   `module_blacklist` ensuite.
3. **Entrée fallback / snapshot Snapper** — présents par défaut (vérifié).
4. **Live USB** — dernier recours : chroot, `rm`, `mkinitcpio -P`.

**Piège de panique** : `default_entry: 2` — omarchy boote par défaut la **deuxième**
entrée. Ne jamais conclure « ma conf a cassé le boot » à cause de l'ordre du menu.

## 5. La porte de sortie permanente (à imprimer AVANT le premier dial)

```bash
sudo rm -f /etc/modprobe.d/nvidia-dials.conf && sudo mkinitcpio -P && sudo reboot
# Sauvetage écran noir : Limine → E → module_blacklist=nvidia,nvidia_drm → boot →
# la ligne ci-dessus → retirer le module_blacklist.
```

Le gate script (`campagne-dial-gate.sh`) écrit ce one-liner dans
`/root/DIAL-ROLLBACK.txt` **avant** tout commit. `--status` = état live ; `--rollback`
= la sortie.

## 6. Les règles anti-danger (rappel dur)

- **R0 — Un seul changement par boot.**
- **R1 — Syntaxe gate avant reboot** : `modinfo -p nvidia | grep NVreg_RegistryDwords`
  + pas d'espaces dans le multi-dials (`A=1;B=2`, guillemets autour).
- **R2 — Le piège omarchy** : **`sudo mkinitcpio -P` après chaque changement**, sinon
  le dial n'existe pas (et on croit « dial muet »).
- **R3 — Jamais combiner** : pas de dial le jour d'un update pilote/kernel, **jamais
  le jour du flash vBIOS** (Phases M et D des jours distincts).
- **R4 — Xid = kill** : toute Xid nouvelle en session avec un dial → dial retiré.
- **R5 — Baseline vierge** : la Phase V se fait **sans aucun dial**.
- **R6 — Vérifier l'ARRIVÉE** : post-reboot, `--status` montre le dial dans sysfs.
- **R7 — Dual-BIOS** : le filet hardware pour tout ce qui touche la ROM (Phase M).

## 7. Le radar Xid

| Xid | Sens | Lecture campagne |
|---|---|---|
| 13 / 31 | exception moteur / page fault mémoire | instabilité workload ou vRAM OC |
| 43 | erreur applicative | bénin, hors campagne |
| 79 | **GPU fallen off the bus** | LE signal hardware — sous dial : retirer ; sous flash : dual-BIOS |
| 119 / 120 | fautes GSP-RM | **suspects dials n°1** |

Règle R4 prime : une Xid inexpliquée = dial retiré.

## 8. Ce qui reste DANGEREUX pour de vrai

**Le flash vBIOS** (Phase M — d'où le gate d'identité, verify, dual-BIOS SECONDARY) ;
**`RMOverrideVfsConfig`** (sommet tier-2 — même son pire cas est une classe B
réversible) ; les **`RMBug*`** (jamais touchés sans cause). La seule vraie mort
possible de la détection — matérielle ou flash raté — est la zone où la doctrine
existante s'applique, pas ici.

---

## 9. Registre d'honnêteté

- **Prouvé local (fichiers omarchy lus)** : fallback Limine ; snapshots Snapper dans
  l'ordre de boot ; timeout non nul ; `default_entry: 2` ; early-load mkinitcpio.
- **Comportement noyau documenté** : `module_blacklist` refuse le chargement ; params
  cmdline priment sur modprobe.d ; params exposés sous
  `/sys/module/nvidia/parameters/` ; nom de dial inconnu = ignoré (cross ring 30).
- **Inféré/standard** : la touche `E` de l'éditeur Limine (standard ; sinon échelons
  3-4 couvrent).
- **Muré par construction** : aucun chemin des Phases D/L n'écrit en NVRAM/flash/SPI.
- **Zéro octet des dépôts touché** — instruments persistés (`campagne-dial-gate.sh`).
