# CAMPAGNE RTX 3070 — Vague 2 : le pont omarchy, les punitions cartographiées, le firmware jugé sur pièces
**Task 62 · session cloud du 18/09/2026 · Super Z · pour le chat machine de Cheurteenyt**
*(re-constitué après rotation d'environnement — Task 64)*

> Directive fondatrice (verbatim) : « je veux que tu continues à voir où on peut être +
> optimiser… on est sur omarchy et c'est basé sur linux, le gpu je sais que c'est pas les
> mêmes pilotes NVIDIA que sur windows… y'a plein de choses qui nous punissent sur cette
> carte graphique par le constructeur et qui n'améliorent pas la sécurité de
> l'utilisateur mais qui le contraignent à ne pas accéder à ce qu'on veut. Mais je pense
> que le code du firmware aussi est à chier aujourd'hui, le logiciel de la rtx 3070
> etc… Je te laisse travailler sur tout ça, soit vraiment ingénieux. »

Matière minée : `tools/gsp-extract/rm-strings.txt` (9 054 lignes, census du RM RISC-V
17,2 Mo du ring 30), le fwimage map du ring 28, `install/hardware/nvidia.sh` +
`bin/omarchy-hw-nvidia*` + `default/hypr/nvidia.lua` du dépôt omarchy (clone local
Task 1), et l'intégralité des 31 rings de GPU-.

---

## 0. Les cinq vérités nouvelles de la vague 2

**V4 — Le pont des 881 dials est INTÉGRAL sous omarchy — avec un piège spécifique.**
omarchy détecte la GA104 (device ≥ 0x1e00) via `omarchy-hw-nvidia-gsp` et installe
**`nvidia-open-dkms`** (lu dans `install/hardware/nvidia.sh`). Le module noyau ouvert
exige le GSP (pas de mode firmwareless), **mais** le canal registre
`NVreg_RegistryDwords` traverse le module ouvert vers le GSP-RM sans rien perdre :
les **881 dials restent tous disponibles**. Le piège omarchy : les modules nvidia sont
en early-load (`MODULES+=(nvidia nvidia_modeset nvidia_uvm nvidia_drm)` dans
`/etc/mkinitcpio.conf.d/nvidia.conf`) — les options `modprobe.d` sont **cuites dans
l'initramfs**, donc tout changement de dial exige `sudo mkinitcpio -P` avant reboot.
Oublier cette étape = croire qu'un dial ne fait rien alors qu'il n'a jamais été chargé.

**V5 — Le LHR n'est PAS dans le firmware. La punition invisible.** Zéro string
ethash/LHR/hashrate dans les 9 054 lignes du census RM (grep triple vérifié). Le
limiteur Lite Hash Rate vit côté **pilote fermé hôte** (libcuda + nvlddmkm), pas dans
le GSP-RM. Verdict : contrainte commerciale pure — zéro valeur de sécurité, et **hors
sujet pour notre campagne** (il ne touche que le compute ethash, pas le gaming). Mais
c'est la preuve du patron : la punition la plus célèbre de la 3070 est là où on ne peut
pas lire, cachée dans le blob hôte — exactement ce que soupçonnait le fondateur.

**V6 — La machinerie de licence datacenter tourne dans une carte de joueur.**
Le census contient `GridLicenseEnforcement`, `UnlicensedUnrestrictedStateTimeout`,
`UnlicensedRestricted1StateTimeout`, `GridLicensedFeatures`, `VGPU_GRID_SW_LICENSING`,
`RmEnableVgpu64kPageSize`, `RMSetVgpuGspPluginOffloadMode`. Le firmware vGPU/Grid —
produit datacenter à licence payante — est **embarqué dans le GSP d'une RTX 3070 grand
public**. Code à chier preuve n°1 : des restes commerciaux en romaine dans le firmware
de tous.

**V7 — L'anti-tamper protège le mauvais objet.** Le mur GSP est massif et réel :
NVPKA engine en mode RSA, authentification devinit complète (AES-ECB/HSMODE, sign,
resign, patcher), vérification des signatures ROM par le GFW parser, bindata chiffré
(entropie 8.000, ring 28). **Et pourtant** la table power du vBIOS est non-signée
(ring 26 : scan ASN.1/RSA zéro hit) — nous avons flashé 6 octets sans le moindre
obstacle. La signature protège le *code* (qu'on n'a pas besoin de modifier) et laisse
ouvertes les *données* (qu'on modifie). L'inverse d'un modèle de sécurité cohérent.

**V8 — 31 plaies de silicon portées en public.** Le census embarque 31 dials
`RMBug*` nommés par numéro de bug interne (8 à 9 chiffres) : `RMBug1698088War`,
`RMBug200333878War`, `RMWarBug988798`, `RmSec2Bug2540582War`… Et un dial littéralement
nommé **`RMEnableJadePhyFixedClkCARHack`** — un *hack* assumé dans un nom de
production. Des années de bugs silicon court-circuités à chaud, stockés en clair,
jamais documentés pour le propriétaire.

---

## 1. La taxonomie des punitions — cinq couches, verdictées

| # | Couche | Mécanisme | Preuve | Sécurité réelle ? | Notre voie d'accès |
|---|---|---|---|---|---|
| 1 | **Bugs silicon** | 31 workarounds `RMBug*War` | census 881 dials | neutre (cru technique) | dials de skip ; ne pas toucher sans raison |
| 2 | **Heuristiques perf RM** | `RmPerfLimitsOverride`, `RMDisablePerfIntersect`, `PERFORMANCE_CAP0/1`, `RMPriorityThrottleDelay`, `RMRestrictVARange` | census + rings 15/30 | partiellement (protège VRM/thermique **borné par le design board**) | **les dials = notre levier n°1** (Phase D) |
| 3 | **Anti-tamper GSP** | signatures RSA/AES devinit, GFW ROM-sign, bindata chiffré | census (codes FWSEC/UDE/UCODE) + ring 28 | **oui** (bloque malware persistant GPU) — mais verrouille aussi l'audit | lecture seule : strings census + window asm |
| 4 | **Pilote fermé hôte** | LHR (V5), télémétrie (absente du RM — hôte), locks NVAPI | zéro string RM + lore publique | non (contrainte commerciale) | module ouvert omarchy = déjà la voie propre |
| 5 | **Restes commerciaux** | Grid/vGPU licensing (V6) | strings Grid* | non (dormant, pure contrainte) | rien à faire — mais à documenter |

Synthèse honnête : **une seule des cinq couches est de la sécurité réelle** (anti-
tamper), et c'est aussi la seule qui nous empêche de *lire*. La couche 2 contient une
vraie fonction de protection hardware (le VRM ne mentira pas) — la question n'est pas
de la tuer mais de l'explorer.

---

## 2. Le pont omarchy — les directives exactes

### 2.1 Injection d'un dial (protocole complet, 1 dial par reboot — inchangé)

```bash
# 1) Écrire le dial (séparateur point-virgole, guillemets obligatoires en multi)
echo 'options nvidia NVreg_RegistryDwords="RmBootGspRmWithBoostClocks=1"' \
  | sudo tee /etc/modprobe.d/nvidia-dials.conf

# 2) LE PIÈGE OMARCHY — reconstruire l'initramfs (modules en early-load) :
sudo mkinitcpio -P

# 3) Reboot, puis vérifier que le RM a bien booté et qu'il a vu la conf :
sudo dmesg | grep -iE "nvrm|gsp|registry" | head -20
nvidia-smi -q -d PERFORMANCE && nvidia-smi -q -d CLOCK

# 4) Session MangoHud réelle (protocole ring 31) → keep/kill.
#    Kill = supprimer le fichier + mkinitcpio -P + reboot. Totalement réversible.
```

Multi-dials (après validation individuelle) :
`options nvidia NVreg_RegistryDwords="RmBootGspRmWithBoostClocks=1;RMDisablePerfIntersect=1"`

### 2.2 Ce qui change et ne change pas sous omarchy (Wayland/Hyprland)

- **Ventilateurs** : LACT (courbe battant le stock rings 14/25) fonctionne sur Wayland
  via l'API NVML coolers — pas de Coolbits, pas de session X. `RmFan2XOverride` :
  **inutile pour nous** (19 °C de marge, V2).
- **Environnement** : omarchy pose déjà `NVD_BACKEND=direct` + `LIBVA_DRIVER_NAME=nvidia`.
- **GSP off** : **impossible** en `nvidia-open-dkms`. L'expérience A/B GSP-RM vs
  RM-in-kernel exigerait un switch vers le module fermé — coût : sortir du chemin
  omarchy, pour un RM qui est le même blob. Verdict : **tier-3, non prioritaire**.

### 2.3 Le pont unifié Windows ↔ Linux

Les 881 noms de dials du census sont **les mêmes clés que les regkeys Windows**
(`HKLM\SYSTEM\...\nvlddmkm`). Le registre NVIDIA est un canal de configuration unique
host→GSP dont les deux OS ne sont que des frontends. Tout le lore des forums Windows
s'applique tel quel à `NVreg_RegistryDwords` — et réciproquement.

---

## 3. Catalogue dials tier-2 (au-delà du shortlist ring 30)

| Dial | Lecture | Régime | Risque |
|---|---|---|---|
| `RMOverrideVfsConfig` / `2` / `3` | override direct des tables voltage-frequency | **B** | **élevé** — potentiel le plus haut |
| `RmClkControllersOverride` | override des contrôleurs de clock | B | moyen |
| `RmPerfCfControllersOverrides` / `RmPerfCfPolicyOverrides` / `RmPerfCfPmSensorOverrides` | les 3 étages controller/policy/sensor du cadre CF | B | moyen (gradué) |
| `RMExtPerfControl` | contrôle perf externe (client-driven) | B/A | à sonder |
| `RmPerfChangeSeqOverride` | override de la séquence de changement d'état | B | moyen |
| `RMPriorityThrottleDelay` | délai du throttle de priorité | A/B | bas |
| `RmVoltThresholdCtrlCtrl`, `RmVoltPowerUpDelayUsOverride`/`Down` | seuils/timing voltage | B | bas-moyen |
| `RMDisableGpuStateLoadBoost` | désactive le boost au load-state | B | bas (census ring 30) |
| `RmPerfRatedTdpLimit`, `RMPowerSupplyCapacity`+`RMEnablePowerSupplyCapacity` | comptabilité TDP/PSU | A | bas — second ordre |
| `RMBug*` (31) | workarounds silicon | — | **laisser** |

Intégration : **Phase D1 = l'ordre ring 30/31 inchangé**. **Phase D2 = ce catalogue**,
après les premiers keep/kill D1, toujours 1 dial/reboot, toujours MangoHud réel.

---

## 4. Le firmware jugé sur pièces — la critique ringée

1. **La table power ment par conception** (rings 3/16/23/61) : 20 entrées, deux
   définitions board-total contradictoires (cap 250 W vs sense entrée 13 = 252 W),
   sémantique des rails non documentée. Triple-cross obligatoire pour agir.
2. **L'usine livre des mines** (ring 5) : un bin zero-record d'usine parmi les 7 bins
   de timings vRAM.
3. **L'opacité par architecture** (ring 28) : 408 KiB de zéros réservés dans la région
   bootloader, bindata chiffré sans framing standard, 13 sections nommées illisibles.
4. **17,2 Mo pour des horloges** (ring 30 + vague 2) : 881 dials non documentés, 31
   cicatrices de bugs internes, du licensing datacenter embarqué, un hack nommé en
   prod. Le code est **bon** ; la **doctrine** est mauvaise.
5. **L'inertie d'écosystème** (rings 17/18 + BIOS-) : CSM 25-ans tue Above-4G ;
   l'heuristique ASUS refuse le ReBAR d'un vBIOS ReBAR-natif ; SPI muré SMU-locked.
6. **La couche hôte abandonnée** : `nvidia-settings` ère GTK2, télémétrie hôte,
   GFE/NVIDIA App = upsell. Le vrai tooling Linux vient de la communauté (LACT,
   MangoHud, nvtop). omarchy a fait le choix correct (`nvidia-open-dkms`).

**Verdict synthétique** : le firmware NVIDIA n'est pas mauvais par incompétence mais
par choix architectural — l'opacité *est* le produit. On ne le corrige pas, on le
**lit**.

---

## 5. Directive Phase L pour le chat machine (s'insère dans le séquençage Task 61)

- **L0 (5 min, sans risque)** — état du pont : `pacman -Q nvidia-open-dkms nvidia-utils`
  · `cat /etc/modprobe.d/nvidia.conf` · `nvidia-smi -q | grep -A2 GSP`.
- **L1 (fusionné avec Phase V)** — la session de classification **sans aucun dial**
  (baseline vierge).
- **L2 (après verdict V)** — premier dial selon le régime (ordre ring 30/31), avec le
  protocole omarchy §2.1 : write → `mkinitcpio -P` → reboot → `dmesg` → verify →
  MangoHud → keep/kill.
- **L3** — catalogue tier-2 §3 après les premiers résultats D1 ; `RMOverrideVfsConfig`
  en dernier, watchdog stabilité.
- **Rappel permanent** : dual-BIOS sur SECONDARY = le filet ; le kit 280 W (Phase M,
  autre chat) reste sur son rail propre.

---

## 6. Registre d'honnêteté

- **Prouvé** : zéro string LHR/ethash dans 9 054 lignes ; 881 dials re-validés ; 31
  `RMBug*` + 1 `*Hack*` ; strings Grid/vGPU ; stack anti-tamper complète ; omarchy
  installe `nvidia-open-dkms` pour GA104 ; le piège mkinitcpio.
- **Inféré** : l'emplacement exact du LHR (libcuda/nvlddmkm) ; neutralité des ~83
  dials `RMLpwr*` pour une desktop en charge.
- **Muré** : lecture exécutable du rm.elf complet côté cloud ; bindata chiffré.
- **Nuance de version (L0)** : le census a été fait sur le GSP embarqué dans la ROM ;
  au runtime, le pilote charge le `gsp.bin` du paquet `nvidia-utils` (potentiellement
  plus récent). Les **noms** de dials sont une API stable, mais vérifier la version :
  `nvidia-smi -q | grep -A2 GSP` — si différente du build ROM, re-censuser le gsp.bin
  du paquet (5 min) avant d'interpréter un dial muet.
- **Zéro octet des dépôts touché** — scripts persistés sous `scripts/`.
