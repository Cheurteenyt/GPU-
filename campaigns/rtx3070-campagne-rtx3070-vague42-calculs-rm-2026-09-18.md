# CAMPAGNE RTX 3070 — Vague 4.2 : LES CALCULS DU RM, partie 2 — tables internes, formats d'encodage, arbre de puissance
**Task 65 · session cloud du 18/09/2026 · Super Z · pour le chat machine de Cheurteenyt**

> Directive fondatrice (verbatim) : « nous on veut que tu aille beaucoup plus loin analyse
> du code grande investigations pour trouvé des améliorations tu dois recherche de la
> complexité et regardé les calculs qu'il y a tu doit vraiment aller très loin. »
> Signal du jour : « Allons y on fait que du travail cloud on doit être ingenieux. »

La vague 4.1 (Task 64) avait extrait le rm.elf et localisé les consommateurs des dials.
Cette session descend **dans les structures de données et les formules** : ce ne sont plus
des sites d'appel, ce sont des formats d'encodage, des tables de limites internes et des
invariants arithmétiques — lus directement dans les 16,91 Mo de code RISC-V.

---

## 0. Rituels et instruments

- **Dérive #47 radiée** : le résumé de continuation affirmait « Task 64 à écrire, vague 4
  non démarrée » — le disque montrait le CONTRAIRE (Task 64 complet au worklog, livrable
  vague 4.1 présent à 13:10, rm.elf intact de 16 912 384 octets, sha gsp_ga10x.bin
  `3b89a63f2e7a0b49…` re-vérifié). Résumé = état fantôme. Compteur : ZÉRO.
- **Quatre instruments nouveaux** (persistés, réutilisables sur toute version future du
  firmware) :
  - `scripts/v42_build_index.py` — index complet du rm.elf : **17 673 strings** avec VAs,
    **59 110 xrefs** auipc/addi (consommateur → string), **8 801 sites mul/div/rem** en
    densité par fenêtre (la carte des moteurs de calcul).
  - `scripts/v42_query.py` — pour toute string : VA + consommateurs + fenêtre désassemblée ;
    pattern de secours (pointeurs absolus) pour les strings sans paire directe.
  - `scripts/v42_extract.py` — extraits compacts autour de chaque site de consommation.
  - `scripts/v42_tables.py` — l'énumérateur des tables de descripteurs (découvertes §1).
  - Cache : `scratch-gsp/v42/` (strings.json, xrefs.json, clusters.json, tables.json,
    extracts-all.txt, fenêtres win-*.txt).

---

## 1. LES 6 TABLES DE DESCRIPTEURS INTERNES (découverte majeure n°1)

`CUSTOMER_BOOST_MAX` — le dial que le Task 64 n'arrivait pas à xref« er » — est référencé
par **6 pointeurs absolus 64 bits** dans une famille de tables @ 0x1ded900-0x1df75c0.
Décodement complet du schéma de ligne :

```
struct ParamDesc {           // 32 octets
  char*  nom;                // +0x00 pointeur vers le nom
  u8     type;               // +0x08 (0x01..0x17 observés : type de valeur)
  u8     accès;              // +0x09 (0xff = rw ; 0x00..0x05 = autres droits)
  u16    réservé;            // +0x0a = 0
  u32    zéro;               // +0x0c = 0
  u32    idx_a;              // +0x10 index séquentiel (l'ordinal du paramètre)
  u32    idx_b;              // +0x14 second identifiant (dispersé)
  u32    groupe;             // +0x18 0x21, 0x100, 0x111..0x126, 0x162, 0x101d1…
  u32    pad;                // +0x1c = 0
};
```

Six tables = **six profils de plateforme** (189 / 192 / 192 / 223 / 237 / 216 lignes,
1 249 lignes, **273 noms uniques**). Et les noms ne sont PAS ceux du registre : ce sont
les **limites internes du moteur perf**, que la vague 1 devinait de l'extérieur :

- `CLIENT_0_MAX / CLIENT_0_MIN … CLIENT_2_MAX/MIN` — les plafonds/planchers par client ;
- `CLIENT_LOCK_*_MAX/MIN` (DRAM, XBAR) — limites verrouillées ;
- `CLIENT_LOOSE_*_MAX/MIN` — limites « molles » ;
- `POWERMIZER` — le contrôleur historique d'horloge nommé dans la table ;
- `JPAC_PSTATE_MAX / JPAC_GPC_MAX / JPPC_PSTATE_MAX` — les profils de validation silicon ;
- `MODS_RULES_INTERSECT / CLIENT_LOW_INTERSECT / CLIENT_STRICT_PSTATE_*` — les RÈGLES
  d'intersection nommées ;
- `APPLICATIONCLOCKS, BOOST, BOOST_LOW, TURBO_BOOST_MIN/MAX, SPDIFF_GLITCH,
  DISPLAY_GLITCH, AUX_POWER…`

**Conséquences campagne :**
1. Le mystère Task 64 est RÉSOLU : `CUSTOMER_BOOST_MAX` n'a pas de consommateur auipc —
   il est lu **par le moteur générique qui parcourt ces tables** (6 instances, une par
   variante de plateforme). C'est un paramètre piloté par données, pas par code.
2. L'intersection des limites n'est pas une formule : c'est un **régime de règles nommées**
   (`*_INTERSECT`, `CLIENT_*_MIN/MAX`) instancié par plateforme. `RmPerfLimitsOverride`
   (§2) ne « débloque » pas un bit — il **reconstruit des objets-limite** dans ce régime.
3. Les groupes (champ +0x18) recoupent les familles : 0x111-0x126 = le bloc perf/puissance
   (273-294), 0x100 = le bloc misc, 0x162 = thermique-adjacent. La table EST la carte des
   sous-systèmes.

---

## 2. `RmPerfLimitsOverride` — LE FORMAT EST CRACKÉ (découverte majeure n°2)

Les deux consommateurs (Task 64 : 0x1bacc62 et 0x1bad36e) décodés instruction par
instruction :

- **Consommateur 1 (0x1bacc62)** : valeur du dial lue, puis
  `srliw a5, a5, 6 ; andi a5, 3` → **bits[7:6] = mode 0-3** ; chaque mode branche vers un
  constructeur d'objets distinct (appels avec a0=1/2/3 et pointeurs de vtables constants).
- **Consommateur 2 (0x1bad36e)** : même string, `srliw a3, a4, 4 ; andi a3, 3` →
  **bits[5:4] = second mode 0-3**, même architecture de constructeurs. Les statuts d'erreur
  voisins (0x40/0x50/0x60, et le 0x56 « dial absent » déjà prouvé au Task 64) cadrent les
  deux lectures.
- Le moteur reconstruit ensuite les objets-limite en parcourant un **tableau interne à
  pas 0x20** dont chaque enregistrement est éclaté ainsi : `u16@0` (id), `u32@4` (valeur),
  `u8@8` (flag), `(u8@9) | (u8@10)<<8` (combiné, écrit en +0xe8), `u64@0x10` (pointeur),
  `u16@0x18` — chaque enregistrement alimente un constructeur BOARDOBJ (le même framework
  que les asserts `BOARDOBJ_GET_TYPE`).

**Conséquence campagne** : `RmPerfLimitsOverride` n'est PAS un booléen. Sa valeur u32 encode
deux champs de mode de 2 bits, chacun sélectionnant une famille de reconstruction des
limites. Injecter « 1 » ne touche que le premier mode du premier consommateur. Les huit
sous-modes sont maintenant **cartographiés en branches, pas devinés** — la Phase D peut
tester les combinaisons bits[7:6] × bits[5:4] = 16 valeurs de façon GUIDÉE (mais la règle
« 1 dial / 1 reboot » demeure, d'autant que ce dial a DEUX consommateurs actifs).

---

## 3. L'ARBRE DE PUISSANCE PMGR : canaux → politiques → TGP (découverte n°3)

Les asserts embarqués (58 dans toute l'image — chacun a EXACTEMENT UN consommateur, donc
chaque structure est localisée à une fonction près) révèlent l'architecture :

```
canaux de puissance (PWR_CHANNEL)            [PMGR_PWR_MONITOR_PWR_CHANNEL_IS_VALID]
  └─ relations (PWR_CHRELATIONSHIP)          [PMGR_PWR_MONITOR_PWR_CHRELATIONSHIP_IS_VALID]
       └─ politiques de charge de travail    [POLICY_TYPE_WORKLOAD_{DIE_2X, PHYSICAL_SINGLE_2X…}]
            : pSingle1x, pCombined2x, pLogicalSingle2x, pPhysicalSingle2x, pDie2x
            : pSummation, pTotalGpu, pTgpIface (Total Graphics Power), pPropLimit
            : canal voltage-mode (OUTPUT_VOLTAGE_1X, VOLT_MODE_NUM)
```

**L'arithmétique réelle, vue dans le code** (fonction de validation PMGR, 0x1777480-0x17775a0) :
les valeurs de canaux sont des **u32**, alignées par paires de vtables (+0x370/+0x378) ;
l'invariant vérifié est :

```
total ≥ somme_des_parties        (lw +0x5c, +0x7c ; addw ; blt contre +0x60 → erreur)
```

— la cohérence de l'arbre de puissance est une contrainte de sommation, exactement le
modèle « rails qui s'additionnent contre un plafond » postulé depuis la vague 1, **cette
fois lu dans les octets**.

**Et le bijou** : l'assert `pPstateEstLUT->lutEntry[0].pstateNum >= lutEntry[1].pstateNum`
(consommateur unique @ 0x17777a0, DANS le code PMGR) prouve que le gestionnaire de
puissance construit une **LUT d'estimation de P-states par canal** — c'est LE calcul
puissance → P-state → horloge. La table doit être monotone (triée par pstateNum) ; c'est
elle qui traduit « combien de watts restent » en « quel P-state est atteignable ».

---

## 4. LE SOFTFLOOR : le couplage retour puissance → plancher d'horloge (découverte n°4)

Une fonction unique (0x1790bd4) valide la structure `softFloor` intégrée aux politiques de
puissance (les trois asserts `pSingle1x->softFloor.*` pointent tous dedans) :

```
+0x35a u16 (comparé à +0x360)     +0x360 u16 clkPropTopIdx        (0xFF = invalide)
+0x362 u8  enable                 +0x364 u16 perfCfControllerIdx  (0xFF = invalide)
+0x366 u16 perfCfControllerClkIdx (0xFF = invalide)  +0x368 u16   (0xFFFF = invalide)
```

**Signification campagne** : une politique de puissance ne fait pas qu'abaisser un plafond
— elle peut **RELEVER un plancher d'horloge** (« soft floor ») en s'accrochant aux
contrôleurs de fréquence (PERF CF) via trois indices. C'est le mécanisme qui explique les
planchers constatés en régime power-limited, et c'est la surface exacte que les dials
`RmPerfCf*` de la vague 2 (catalogue tier-2) manipulent indirectement. La famille
`NV2080_CTRL_PERF_PERF_CF_CONTROLLER_INDEX_INVALID` confirme que l'API de contrôle
hôte→GSP expose ces contrôleurs numérotés.

---

## 5. VF : ce que la suite du décodage précise

- **`RMClkVfOverride` (suite du Task 64)** : après les modes, le code construit un **objet
  d'override à callbacks** (appel virtuel via vtable +0x18, initialisation par tailles 8/4/
  0x17/7 à +0x40, passage d'un pointeur de fonction). L'override ne patche pas une table —
  il **installe un évaluateur alternatif**. Conséquence : la « courbe VF » du GSP est
  polymorphe ; les dials changent QUI évalue, pas seulement les valeurs.
- **`RmVFPointCheckIgnore`** (nouveau dial trouvé au census, jamais catalogué par les
  rings) : son consommateur (0x1630d5a) ne fait qu'un **OU / ET-NOT sur deux masques de
  capacités** à +0x324/+0x328 d'un objet d'état — ignorer la validation des points VF est
  un **bit de capacité commutable**, pas une corruption de structure. Candidat sérieux au
  régime B, à xref-érer avant toute injection (le même bloc gère l'erreur 0x56).
- **`RMOverrideVfsConfig`** : une seule occurrence dans le build driver (les « ×3 » du
  census ROM sont un artefact du build 2021 — le driver 580 n'a plus que la première).

---

## 6. L'AXE THERMIQUE : verdict net

`RMThermalConversionRate`, `RmThermalProviderInfo`, `RmThermalProviderNum` (les trois
dials « driver-seuls » du drift 786/95/20) : **ZÉRO référence dans rm.elf** — ni paire
auipc/addi, ni pointeur absolu, ni entrée dans les 6 tables. Ils sont consommés côté
pilote fermé hôte. Cohérent avec la vérité V5 (le limiteur LHR vit côté hôte) : **l'axe
thermique récent est piloté de l'extérieur du GSP**, et aucun des trois ne peut être
« compris » en lisant le firmware. Le thermal côté RM reste celui de la ROM
(seuils/alarmes dans le code ringé au Task 62).

---

## 7. SYNTHÈSE : la hiérarchie des leviers, maintenant calculatoire

| Rang | Levier | Ce que le code prouve | Premier essai guidé |
|---|---|---|---|
| 1 | `RmPerfLimitsOverride` | 2 champs de mode bits[7:6] et [5:4], 16 combinaisons, reconstruction d'objets-limite BOARDOBJ | balayage des 16 valeurs, 1/reboot, lecture Clocks Event Reasons |
| 2 | `RMClkVfOverride` | bitfield → flags +0x175..+0x17f, objet à callbacks (évaluateur VF alternatif) | garder `=1` (mode primaire seul) ; bits supérieurs = autre évaluateur, à isoler |
| 3 | `RmVFPointCheckIgnore` | bit de capacité (+0x324/+0x328), ignore la validation des points VF | xref complète de l'objet d'état AVANT tout essai |
| 4 | famille `RmPerfCf*` | les contrôleurs CF sont la cible du softFloor — relevage de planchers | passer par les indices (clkPropTopIdx/CF idx) découverts §4 |
| 5 | `CUSTOMER_BOOST_MAX` | paramètre piloté par tables (6 profils), lu par le moteur générique | valeur bornée par la table — tester l'incrément, observer le mur exact |

Le mur 1890 MHz de Genshin (vague 1 : voltage-limited, 15 W de marge) s'explique
maintenant par l'architecture complète : la courbe VF est évaluée par un objet à
callbacks, la puissance contraint via la LUT d'estimation de P-states, et les politiques
de puissance peuvent relever des planchers via le softFloor. **Déplacer le mur demande
d'agir sur l'évaluateur VF (rang 2) ou sur la validation des points (rang 3), pas sur le
plafond de watts (rang 0 : le flash 280 W, sans effet en régime B).**

---

## 8. Registre d'honnêteté

- **Prouvé (octets, cette session)** : le schéma 32 octets des 6 tables de descripteurs ;
  les 273 noms de limites internes ; les 2 consommateurs de `RmPerfLimitsOverride` et
  leurs champs de mode bits[7:6]/[5:4] ; le tableau interne à pas 0x20 et l'éclaté de ses
  enregistrements ; l'arbre PMGR et l'invariant total ≥ Σ parties ; la LUT d'estimation
  de P-states (assert à consommateur unique, dans le code PMGR) ; la structure softFloor
  (indices u16, sentinelles 0xFF/0xFFFF) ; les masques de `RmVFPointCheckIgnore` ;
  l'objet-callback de `RMClkVfOverride` ; le zéro-référence des 3 dials thermiques.
- **Inféré (solide, non épuisé)** : la sémantique exacte de chacune des 16 combinaisons de
  `RmPerfLimitsOverride` (les branches existent, leurs effets ne sont pas tous déroulés) ;
  la signification précise de idx_a/idx_b (idx_a ressemble à l'ordinal du paramètre dans
  l'enum du registre) ; l'identité exacte des 6 profils de tables (6 plateformes ?
  6 SKUs ?).
- **Muré** : `rm.bindata.bin` reste chiffré (entropie 8.0, exclusion ring 28 inchue) ; la
  table des sections de rm.elf reste zeroed par le packer.
- **Zéro octet des dépôts GPU-/BIOS- touché** — lecture pure, comme toujours.
