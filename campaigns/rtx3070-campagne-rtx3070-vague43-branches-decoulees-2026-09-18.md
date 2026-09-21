# CAMPAGNE RTX 3070 — Vague 4.3 : LES BRANCHES DÉROULÉES
## Le dispatcher des limites, les rails de tension, la mécanique P-state — lus dans les octets
**Task 66 · session cloud du 18/09/2026 · Super Z · pour le chat machine de Cheurteenyt**

> Directive fondatrice (verbatim) : « nous on veut que tu aille beaucoup plus loin analyse
> du code grande investigations pour trouvé des améliorations tu dois recherche de la
> complexité et regardé les calculs qu'il y a tu doit vraiment aller très loin. »
> Signal : « Allons y on fait que du travail cloud on doit être ingenieux. »

La vague 4.2 (Task 65) avait cartographié les structures. Cette session **déroule les
branches** : chaque mode du dispatcher de limites a été suivi instruction par instruction
jusqu'à son effet machine — flags de P-state, rails de tension, tables de conversion,
accumulateurs de puissance. Nouvel instrument : `scripts/v43_annotate.py` (annotateur de
fenêtres : résolution auipc/addi → noms de strings, cibles de branches, appels).

---

## 0. Rituels

- **Dérive #48 radiée** : le résumé de continuation affirmait « Task 64 à écrire, vague 4
  non démarrée » — le disque montrait Tasks 64-65 COMPLETS (livrables 13:10/13:39,
  instruments v42, rm.elf 16 912 384 o, cache intact). Compteur : ZÉRO.
- Repos : `repo-bios 528eae3` / `repo-gpu b5259ca`, les deux CLEAN.
- Nouveaux instruments : `scripts/v43_annotate.py` (annotations d'exécution),
  `scripts/v43_phdrs.py` (program headers), `scripts/v43_mathmap.py` (carte M-extension).

---

## 1. DÉCOUVERTE N°0 — LE TROISIÈME SEGMENT : le mystère `rm.bindata.bin` SAUTE

Les program headers de rm.elf (`v43_phdrs.py`) révèlent un **troisième segment** que la
cartographie Task 64 avait raté :

```
[0] LOAD X-R  va 0x1000000  15,2 Mo   (texte)
[1] LOAD -WR  va 0x4000000  1,69 Mo   (données)
[2] 0x60000000 R-- va 0x20000000 TAILLE FICHIER ZÉRO
```

Or les vtables des constructeurs d'objets-limite pointent vers `0x2035xxxx` — DANS la
fenêtre 0x20000000, hors de tout octet du fichier. Conclusion structurelle : la fenêtre
VA 0x20000000 est **chargée au runtime** par un autre composant du pack GFW —
et `rm.bindata.bin` (75 Mo dans gsp.bin, entropie 8.0, « muré » au Task 65) est
l'hypothèse forte pour son contenu : **le rodata chiffré du RM** (vtables + tables
constantes), déchiffré au chargement. L'entropie 8.0 n'était pas un coffre de données
cachées : c'est LE segment de données constantes, chiffré sur disque.

Conséquence : toute sémantique « qui évalue quoi » restera lisible dans le CODE (texte),
mais les valeurs initiales des objets (courbes VF calibrées usine) sont dans le blob
chiffré. Les dials du registre restent la voie d'injection — ils s'installent AU-DESSUS
de ces objets.

## 2. DÉCOUVERTE N°1 — `RmPerfLimitsOverride` : QUATRE champs de 2 bits, cascade réelle

Le Task 65 en voyait deux (bits[7:6], bits[5:4]). Le déroulé complet du dispatcher
(0x1bacc62 site 1 + 0x1bad36e/0x1bad3f4/0x1bad45c site 2 — **une seule et même fonction**)
montre **QUATRE champs de 2 bits**, évalués en cascade du haut vers le bas :

| Champ | mode 0 | mode 1 | mode 2 | mode 3 |
|---|---|---|---|---|
| **bits[7:6]** | reconstruction de tous les objets-limite depuis la table plateforme (boucle 0x1DF5730→0x1DF75D0, stride 0x20, ~245 enregistrements) | idem mode 0 **+ raze un octet d'état** (`-0x3a8(s2)`) | construction d'objets alternatifs (vtables 0x20358268/0x20358280) | 2 constructeurs avec paire de vtables dédiée |
| **bits[5:4]** | rien | **raze flag byte** `s3+0x2E9` → cascade continue | **set flag byte** `s3+0x2E9 = 1` → cascade | 2 constructeurs (vtables 0x20358850/0x20358868) |
| **bits[3:2]** | rien | **raze flag byte** `s8+0x9B5` | **set flag byte** `s8+0x9B5 = 1` | 2 constructeurs (vtables 0x20358880/0x20358898) |
| **bits[1:0]** | rien | **raze flag byte** `s8+0x9B4` | **set flag byte** `s8+0x9B4 = 1` → poke global (§3) | lecture du dial voisin `DisableDynamicPstate` |

Lecture littérale des octets : le champ haut ne « consomme » pas la valeur — les champs
bass continuent à s'appliquer. Les modes 1/2 des trois champs bas sont des **toggles de
flags d'état orthogonaux** ; les modes 3 sont des **reconstructions d'objets**. La valeur
du dial est donc un **mot de 4 commutateurs**, pas un scalaire : l'espace de test est
256 valeurs, mais la combinaison « raze tous les flags » = `0b010101` (0x15) et
« set tous » = `0b101010` (0x2A) sont des cibles uniques et lisibles.

Sur le statut 0x56 « dial absent » (Task 64) : il construit **deux objets fallback**
deux vtables distinctes (0x1bad51e-0x1bad596) — l'absence du dial n'est pas un « ne rien
faire », c'est une reconstruction par défaut.

## 3. DÉCOUVERTE N°2 — `DisableDynamicPstate` + la structure P-state globale `0x111xxx`

Nouveau dial jamais catalogué, **dans la même fonction** que RmPerfLimitsOverride
(string @0x1e71118). Deux consommateurs :

- **Consommateur 2 (0x162beb0)** : le moteur de décision — lit un objet chaîné
  (`obj+0x158 → +0xe0 → +0x2000-0x300`), un compteur u16 `+0x2d0`, applique un masque
  `0xFFFF`, compare contre un mot-masque `+0x1AE8`, et si ça passe :
  ```
  [0x11152c + plat] |= 0x400
  [0x111520 + plat]  = 0x400
  [0x1113d0 + plat]  = 0
  ```
  où `plat` = pointeur par-plateforme lu d'une table de données (même mécanisme que les
  6 profils du Task 65).
- **Consommateur 1 (0x162c004)** : la boucle d'acquisition — 5 itérations (`s5=5`),
  deux appels par itération, paires u32 stockées stride 8 : **la lecture des 5 domaines**
  (GPC, DRAM, XBAR, NVD, PCIE — les mêmes que les contrôleurs CF nommés).

Et le pire des bonus : le mode 2 de bits[1:0] de RmPerfLimitsOverride aboutit au **même
poke** (chunk 0x1bad4ac / 0x1bad8dc, identique octet pour octet). Le champ bas du dial
maître et `DisableDynamicPstate` actionnent **le même interrupteur global** — le bit 0x400
de l'état P-state.

## 4. DÉCOUVERTE N°3 — LES RAILS DE TENSION NOMMÉS : le mur « VRel » identifié à l'objet près

Dans les 6 tables de descripteurs plateforme (Task 65), une famille apparaissait sans
être décodée : **RELIABILITY_***. Extraction complète (`tables.json`) :

| Tables | Rails embarqués | type | accès |
|---|---|---|---|
| 0-2 (vieilles plateformes) | RELIABILITY_LOGIC, RELIABILITY_SRAM (+ALT) | 1 | **2 (lecture seule)** |
| 3 | **RELIABILITY_NVVDD** (type 15), **RELIABILITY_MSVDD** (type 16) | 15/16 | **2** |
| 4-5 (récentes) | NVVDD_0/**_1**, MSVDD_0/**_1** (+ALT) — **dual-state** | 15/16 | **2** |

- **NVVDD = rail core, MSVDD = rail mémoire** — le split dual-rail Ampere est écrit dans
  la table. GA104 = schéma table 3+ (NVVDD/MSVDD).
- L'expansion _0/_1 (idx_b 260-263 insérés, idx_a décalés) = **deux états de tension par
  rail** (base/alt).
- **access=2 vs 255 (rw) pour tout le reste** : les rails de fiabilité sont des objets de
  calibration **non surchargables par cette voie de table** — c'est le mur.

**Le mur 1890 MHz de Genshin (vague 1 : voltage-limited) est donc`RELIABILITY_NVVDD`** :
l'objet de calibration du rail core, instancié par le moteur générique depuis la table
plateforme, consulté par l'évaluateur VF. On ne le pousse pas directement — on remplace
l'évaluateur (RMClkVfOverride) ou on ignore la validation des points (RmVFPointCheckIgnore),
exactement la hiérarchie du Task 65 — mais avec le NOM de l'objet mur.

## 5. DÉCOUVERTE N°4 — LA FAMILLE P-STATE COMPLÈTE, une seule fonction

Trois dials jamais cartographiés tombent dans **la même fonction d'init P-state**
(0x164d000-0x164e000) :

- `RMForcePstate` (0x164d4de) : lit le dial voisin **`AllowMaxPerf`** (string @0x1e71198,
  encore un nouveau) — `bit1 → ori [s1+0x8e000+0x78], 8` (flag 0x8 posé) ;
  `bit9 → branche dédiée 0x164d9ac`. Force un P-state + pose les flags « max perf ».
- `RMEnableOverclockingAllPstates` (0x164d538) : teste flags `0x11`/`0x1100` sur
  `[s1+0x8e000+0x38]` — débarrasse les garde-fous d'overclocking par P-state ; les objets
  P-state font **0x108 octets** (memset 0x108 visible deux fois).
- `DisableOverclockedPstates` (0x164d336) : garde d'entrée sur `[a1+0x2a8]`, canonique
  `0x4161230` — même trame.
- `DisableAsyncPstates` : 1 consommateur (fenêtre archivée).

Tous consomment la même structure d'état et s'articulent avec le softFloor du Task 65 :
**la famille complète de contrôle P-state est maintenant à un nom de dial près**.

## 6. DÉCOUVERTE N°5 — LA MATHÉMATIQUE DES UNITÉS ET L'ACCUMULATEUR

- **Les fréquences internes sont en kHz.** Une fonction de construction exporte la table
  P-state : 16+ entrées stride 0x10, chaque valeur divisée par **1000** (`divu` par
  0x3e8, 11 sites de conversion dans la zone perf) — **kHz → MHz à l'export hôte**.
  Offsets sources du canal : triplets `+0x20/+0x28/+0x30` puis séries `+0x70…+0x198` —
  les (min/cur/max) par domaine.
- **L'accumulateur de puissance vivant** (fonction 0x1777310, à côté du consommateur
  PstateEstLUT @0x17777a0) : appels virtuels par pointeur de fonction `+0x2d8` du canal,
  puis `lw a5, 0x7c(s2) ; addw a5, a5, s3 ; sw a5, 0x7c(s2)` — **le delta de puissance
  est ADDITIONNÉ au compteur +0x7c**, signe inversé (`negw`) pour le second accesseur.
  L'invariant « total ≥ somme des parties » du Task 65 est maintenu à chaque delta.
- **Conversion d'unité générale** : fonction 0x162bd94 : `divuw a5, a0, 1000` après
  lecture d'un champ — le RM divise par 1000 en trois endroits du pipeline perf.
- **Carte arithmétique** (`v43_mathmap.py`) : 4 427 sites M-extension dans le texte
  (3 739 mul, 506 divu, 167 remu). Le cluster le plus dense (0x1a4xxxx, 54/16 Ko) est le
  sous-système **trace/logging (CRC/LZ)**, PAS le moteur perf — le moteur perf
  (0x16-0x17xxxxx, ~1 100 sites) travaille surtout en mul/divu 32 bits, sans
  fixed-point 64-bit massif : **les calculs de fréquence/puissance sont en unités
  entières directes (kHz, mW), pas en virgule fixe**.

## 7. LA CARTE DES LEVIERS, VERSION 4.3

| Rang | Levier | Ce que 4.3 ajoute | Premier essai guidé |
|---|---|---|---|
| 1 | `RmPerfLimitsOverride` | 4 commutateurs orthogonaux : 0x15 raze les 3 flags, 0x2A les pose tous, 0x40 = reconstruction+raze | balayage {1, 2, 0x15, 0x2A, 0x40, 0x80}, 1 dial/reboot, lecture Clocks Event Reasons |
| 2 | `RMClkVfOverride` | remplace l'évaluateur qui consulte RELIABILITY_NVVDD (rails nommés §4) | garder `=1` ; isoler les bits hauts |
| 3 | `RmVFPointCheckIgnore` | bit de capacité (+0x324/+0x328) qui court-circuite la validation des points contre le rail | xref de l'objet d'état avant essai (jalon restant) |
| 4 | `DisableDynamicPstate` / bits[1:0] | action concrète = poke 0x400 sur l'état P-state global `0x111xxx` | utile pour figer les régimes pendant la mesure |
| 5 | `RMForcePstate` + `AllowMaxPerf` | bit1 → flag 0x8 posé dans l'état P-state ; bit9 → branche dédiée | forcer P0 stable pour baselines |
| 6 | `RMEnableOverclockingAllPstates` | débarrasse les garde-fous par P-state (objets 0x108 o) | après 1-5, jamais seul |
| 7 | flash 280 W (autre chat) | n'agit PAS sur RELIABILITY_NVVDD ni sur le softFloor — rang 0 confirmé | selon matrice vague 1 |

## 8. Ce que la machine peut maintenant TRANCHER (Phase D réécrite)

1. **Baseline** (Phase V vague 1) → régime lié par workload.
2. **RmPerfLimitsOverride = 0x15** puis **0x2A** : les deux totems de commutateurs —
   l'un raze les flags d'état limites, l'autre les pose. Les Clocks Event Reasons diront
   QUI a bougé (VRel→NVVDD ? PowerRel ?).
3. **RMClkVfOverride = 1** isolé : remplacement d'évaluateur.
4. **RmVFPointCheckIgnore** : après xref complète de l'objet +0x324/+0x328 (jalon 4.4).
5. Chaque étape : `campagne-dial-gate.sh` avant, MangoHud + `nvidia-smi -q -d CLOCK,PERFORMANCE`
   après, un dial / un reboot, kill-switch vague 3 inchangé.

## 9. Registre d'honnêteté

- **Prouvé (octets, cette session)** : le 3e program header (VA 0x20000000, taille 0) ;
  les 4 champs de 2 bits de RmPerfLimitsOverride et la cascade complète ; les flag bytes
  (s3+0x2E9, s8+0x9B4/0x9B5, s2-0x3a8) ; les 6 paires de vtables des modes 3 ; le dial
  `DisableDynamicPstate` (2 consommateurs, moteur 0xFFFF/+0x2d0/+0x1AE8, poke 0x400) ;
  la structure P-state globale `0x111xxx+plat` ; les rails RELIABILITY_LOGIC/SRAM →
  NVVDD/MSVDD → NVVDD_0/1+MSVDD_0/1 avec access=2 ; la famille P-state complète
  (RMForcePstate/AllowMaxPerf/RMEnableOverclockingAllPstates/DisableOverclockedPstates/
  DisableAsyncPstates, objets 0x108) ; les conversions kHz→MHz (div 1000 ×11) ;
  l'accumulateur +0x7c ; la carte M-extension (4 427 sites, cluster logging ≠ perf).
- **Inféré (solide)** : rm.bindata.bin = rodata chiffré chargé à 0x20000000 (hypothèse
  cohérente avec entropie 8.0 + vtables hors fichier + segment taille zéro) ; la
  sémantique exacte de chaque flag byte côté runtime (les SET/RAZE sont prouvés, leurs
  effets fins à mesurer sur machine).
- **Muré** : les valeurs de calibration des rails (dans le blob chiffré) ; la table des
  sections (zeroed) ; les vtables elles-mêmes (hors fichier).
- **Zéro octet des dépôts GPU-/BIOS- touché** — lecture pure, comme toujours.
