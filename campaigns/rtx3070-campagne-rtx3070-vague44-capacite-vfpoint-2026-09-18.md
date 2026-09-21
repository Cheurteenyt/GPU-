# CAMPAGNE RTX 3070 — Vague 4.4 : LE JALON RmVFPointCheckIgnore EST SOUFFLÉ
## La chaîne complète dial → bit de capacité → court-circuit de validation, instruction par instruction
**Task 67 · session cloud du 18/09/2026 · Super Z · pour le chat machine de Cheurteenyt**

> Directive fondatrice (verbatim) : « nous on veut que tu aille beaucoup plus loin analyse
> du code grande investigations pour trouvé des améliorations tu dois recherche de la
> complexité et regardé les calculs qu'il y a tu doit vraiment aller très loin. »

Le Task 66 avait posé le jalon : « xref complète de l'objet d'état RmVFPointCheckIgnore
(+0x324/+0x328) ». Ce livrable le SOLDE : l'écriture du bit, le mécanisme de commit, le
handler du dial, les vtables, les lecteurs du bit et le dispatcher qui court-circuite —
tout est maintenant lisible dans les octets.

---

## 0. Rituels

- **Dérive évitée avant tout minage** : le résumé de continuation affirmait « rm.asm
  (désassemblage, matière principale vague 4, jamais minée) » et « Task 64 à écrire ».
  Le disque montrait : rm.asm = 48 octets (un shell objdump, PAS un désassemblage),
  Tasks 64-66 COMPLETS au worklog, rm.elf 16 912 384 o intact, instruments v42/v43 en
  place. Le disque prime — compteur de dérives : ZÉRO.
- Repos : `repo-bios 528eae3` / `repo-gpu b5259ca`, les deux CLEAN.
- Nouveaux instruments : `scripts/v44_xref_field.py` (scan binaire EXACT des load/store
  à immédiat donné — pas de capstone intégral : toute instruction 32 bits RVC est à
  adresse paire, donc un pas de 2 voit chaque instruction une fois ; les load/store
  compressés ne peuvent pas encoder 0x324/0x328 — zéro faux négatif),
  `scripts/v44_callers.py` (jal inversé), `scripts/v44_focus.py` (contexte serré).

---

## 1. L'ÉCRIVAIN : `requestCapabilityChange` (0x1630c48), déroulée intégralement

Signature reconstruite : `f(obj a0, state a1, bit_index a2, direction a3)`.

```
st = [a1 + 0x1b8]                     ; l'OBJET D'ÉTAT CAPACITÉS (0x88+0x130)
if (a1 == 0)                     → log + return 0x56     ; le code « absent » du Task 64
ok = sub_1630b60(a0)                  ; garde cookie 0x4161230 + résolution d'objet
m  = 1 << bit_index                   ; a2 est un INDEX DE BIT, pas un masque
```

Deux blocs symétriques (bnez s6 → SET, sinon CLEAR) :

| Champ de l'objet | Rôle prouvé |
|---|---|
| **+0x324** | le mot de capacité **effectif** (u32) |
| **+0x328** | masque **pending** (opération en cours — ré-entrance) |
| **+0x32c** | flag d'opération unitaire |
| **+0x350** | pointeur de **callback de recalage** (appelé avec l'objet, l'état, le bit) |

Mécanique SET (0x1630d2a-0x1630d7e) : si bit déjà posé → log et sortie (0x56) ;
sinon `[+0x328] |= m` (pending) → **CALL [+0x350]** → si OK : `[+0x328] &= ~m` puis
**`[+0x324] |= m`** (commit). CLEAR symétrique : si d'autres bits restent posés, écriture
directe sans callback ; si le bit est le DERNIER, le callback devient **obligatoire**
(le sous-système doit être informé que plus aucun check n'est ignoré).

Lecture du code d'erreur : le **0x56** réutilisé ici n'est pas « dial absent » au sens
Task 64 — c'est le générique « état déjà conforme / rien à faire » de ce module.

**Aucune référence matérielle à 0x1630c48 dans le fichier** : 0 jal direct, 0 paire
auipc/addi, 0 pointeur 64 bits — la fonction n'est joignable que **par vtable**, dans le
rodata chiffré chargé à 0x20000000 (découverte 4.3-n°0 confirmée en usage réel : les
constantes de log de la fonction pointent 0x202c56xx/0x202c67xx/0x202c68xx).

## 2. LE HANDLER DU DIAL (0x1631010) — et les vtables qui ne sont PAS chiffrées

Le consommateur de la string `RmVFPointCheckIgnore` @0x1e71130 (site unique 0x1631048) :

```
CALL parseur_générique(a1="RmVFPointCheckIgnore", a2=&valeur)   ; LE même parseur que les 881
if (valeur != 0)  → 0x16313ec : [state+0x2e3] = 1               ; activation
; chemin d'instanciation (0x16313f4+) :
s4 = [s1+0x130]                       ; l'objet d'état
[s4+0x5e8] = 0xb                      ; constante 11 : type/ID du checker
[s4+0x000] = 1 (u16)                  ; version/compteur
CALL constructeur
[s4+0x348] = 0x16844bc                ; vtable 1   ← DANS LE TEXTE
[s4+0x350] = 0x1684880                ; LE callback de recalage ← DANS LE TEXTE
[s4+0x358] = 0x1684330                ; vtable 3
[s4+0x388] = 0x16745b8                ; vtable 4
[s4+0x380] = 0x1674f0c                ; vtable 5
```

**Renversement partiel du mur du chiffrement** : les vtables de CET objet sont posées
par auipc/addi depuis le handler — cinq adresses de fonctions du texte sortent du blob
pour la première fois. Le callback +0x350 du setter (§1) est donc **nommé** : 0x1684880.

## 3. LE CALLBACK (0x1684880) et la CORRECTION du « poke 0x400 »

```
callback(obj, state, a2, idx):
  if (idx != 0) → tail-call 0x16843b4 (chaînage d'objets-liés : [a2+0xB8C], test type==5,
                 itération code 0x65, stride 0x168 vus au §5)
  if ([state+0x2d4] != 0) → return 0                 ; déjà revalidé
  if ([state+0x2a8] == 0) → return 0
  CALL revalidation(compte=4)                        ; les 4 domaines ?
  si échec → logs (constantes 0x202d3148/0x202d3160)
```

**Correction honnête du Task 4.3** : le « poke 0x400 » (`lui a4, 0x111` puis
`[plat+0x52c] |= 0x400 ; [plat+0x520] = 0x400 ; [plat+0x3d0] = 0`) apparaît dans le
setter, le handler ET ce callback. Ce n'est PAS la signature du dial
`DisableDynamicPstate` : c'est l'**invalideur générique de l'état P-state global**
(bit 0x400 = « état dirty, à re-évaluer ») que tout changement de configuration déclenche.
Le dial garde ses 2 consommateurs propres (0x162beb0/0x162c004), mais le poke n'était
pas son empreinte exclusive.

## 4. LES LECTEURS : qui consulte le mot de capacité (le court-circuit)

Le scan binaire exact donne 509 accès bruts aux offsets 0x324/0x328 dans tout le texte
(offets génériques d'autres objets inclus). Le cluster du module perf :

```
0x1630ca2..0x1630db4   12 accès  ← le setter lui-même (§1)
0x1634ada, 0x1634bbe, 0x1634ff4, 0x1635282, 0x163551a, 0x16355be   ← le MOTEUR
0x1636a78, 0x1636fc2   lwu        ← autres lectures du même sous-système
0x1646362, 0x16464e4              ← zone P-state (0x164d000 = famille P-state Task 66)
0x1674628, 0x1674f22              ← près des vtables posées au §2
```

**Le moteur d'acquisition/évaluation (0x1634a38)** — le consommateur décisif :

```
; chemin d'entrée : champ P-state [base+0x8e078], callback virtuel +0x1a8, masque +0x2d0
a5 = [s1+0x1b8]                       ; l'objet d'état (le MÊME que le setter)
a5 = [a5+0x324]
if (a5 & 1)  → 0x1634bc6 : CALL chercheur(objet=[obj+0x1CD0], type=0xc)   ; BIT 0 POSÉ
if (a5 & 0x100) → chemin normal sans log                                  ; BIT 8
[req+0x18] = ([a5+0x324] >> 8) & 1        ; propagation du bit 8 dans une requête
```

- **Bit 0 = RmVFPointCheckIgnore** (test `andi 1` @0x1634bc2) : quand posé, le moteur
  remplace son chemin de validation par une **requête de type 0xc** au chercheur
  d'objets 0x1457440 (hash table à +0x48, clé de 64 octets — architecture BOARDOBJ).
- Les requêtes du chemin normal passent par le même chercheur avec les types
  **0x10, 0x13, 0x1d** — l'espace des types est un enum, 0xc en est le membre « skip ».
- **Bit 8** = un second check du même sous-système (non attribué à un dial nommé —
  candidats naturels : les dials sœurs du §6), lu deux fois : contrôle de flux
  (0x1634ff8) ET propagation dans un objet de requête (0x1635286 → [req+0x18]).

## 5. La table à pas 0x168

Au-delà du callback (0x16849a4+) : itération `idx * 0x168 + (sous_idx + 1) * 32` —
une table d'entrées de 360 octets, sous-éléments de 32 octets, lecture `lw` du champ
voulu, puis appel de sous-routine. Le RM indexe ses points/entrées VF par **stride
multiplicatif**, jamais par copies : encore une structure de données vivante où les
dials s'installent AU-DESSUS sans la modifier.

## 6. LA FAMILLE COMPLÈTE des CheckIgnore (8 dials, consommateurs cartographiés)

| Dial | String VA | Sites | Module |
|---|---|---|---|
| `RmVFPointCheckIgnore` | 0x1e71130 | **1** (0x1631048) | perf (le nôtre) |
| `RMHwSpeedoCheckIgnore` | 0x1e714f0 | 4 (0x16ae514…) | validation silicon |
| `RmPmgrIddqCheckIgnore` | 0x1e71568 | 3 | validation silicon (PMGR) |
| `RmSramVminCheckIgnore` | 0x1e71580 | 3 | validation silicon (SRAM) |
| `RmPmgrIsenseCheckIgnore` | 0x1e71648 | 3 | validation silicon (PMGR) |
| `RMDevidCheckIgnore` | 0x1e086d8 | 3 (0x144db5e…) | init/devinit |
| `RmClkAdcCalRevCheckIgnore` | 0x1dfbb50 | 3 (0x114d566…) | clocks ADC |
| `RmClkAdcTempErrRevCheckIgnore` | 0x1dfbb70 | 2 | clocks ADC |

Le mot de capacité +0x324 est un **registre de bits partagé par sous-système** : chaque
check possède son index de bit, chaque dial possède son handler, tous écrivent via la
même primitive (§1). Le RM n'a pas une porte « tout ignorer » : il a 32 portes
individuelles par objet d'état.

## 7. LES RAILS : la famille complète, zéro référence de code

Trente noms énumérés (RELIABILITY_LOGIC/SRAM/ALT, RELIABILITY_NVVDD/MSVDD,
RELIABILITY_*_NVVDD_0/1 et _MSVDD_0/1, OVERVOLTAGE_*, VMIN_NVVDD/MSVDD,
THERM_POLICY_NVVDD, MODS_RULES_*) : **aucune paire auipc/addi ne les référence**.
Comme CUSTOMER_BOOST_MAX (Task 65), ils sont consommés **par pointeurs depuis les
tables de descripteurs** (stride 0x20) — le moteur d'instanciation copie le nom dans
l'objet au boot. Conséquence de campagne : la consultion du rail par l'évaluateur VF
passe par l'objet instancié, jamais par le nom — ignorer la validation (bit 0) est
donc bien le SEUL chemin logiciel vers l'au-delà de RELIABILITY_NVVDD, comme hiérarchisé
en 4.3, mais maintenant prouvé des deux côtés (écrivain ET lecteur).

## 8. LA CARTE DES LEVIERS, version 4.4

| Rang | Levier | État 4.4 | Premier essai guidé |
|---|---|---|---|
| 1 | `RmPerfLimitsOverride` | inchangé (4 commutateurs, totems 0x15/0x2A) | balayage guidé 4.3 |
| 2 | `RMClkVfOverride` | inchangé (évaluateur alternatif à callbacks) | `=1` isolé |
| 3 | **`RmVFPointCheckIgnore`** | **chaîne complète prouvée : parseur → 0x1631010 → instanciation 5 vtables → setter vtable → commit +0x324 bit 0 → moteur 0x1634a38 requête type 0xc** | valeur ≠ 0 (le dial est booléen côté parseur : `=1`), un seul reboot, lecture Clocks Event Reasons AVANT/APRÈS |
| 4 | famille CheckIgnore (7 autres) | consommateurs cartographiés, modules identifiés | NE PAS toucher avant le bit 0 (devinit/silicon : risque réel, gain Genshin nul) |
| 5 | `DisableDynamicPstate` | 2 consommateurs propres ; le poke 0x400 ré-attribué à l'invalideur générique | figer les régimes pour la mesure |
| 6 | flash 280 W | rang 0 confirmé | matrice vague 1 |

**Phase D, étape 4 réécrite** : `RmVFPointCheckIgnore=1` est maintenant le premier essai
de rang 3 avec un protocole complet — gate avant, baseline Clocks Event Reasons,
injection, reboot, re-lecture, MangoHud sur le workload voltage-limited (Genshin),
kill-switch vague 3 inchangé. Si le mur 1890 bouge d'un seul point VF, la théorie
« le mur est la validation, pas le watt » est confirmée côté machine.

## 9. Registre d'honnêteté

- **Prouvé (octets, cette session)** : la déroulée intégrale du setter 0x1630c48
  (pending/callback/commit, code 0x56, index de bit) ; le joignable-par-vtable-uniquement
  (0 jal/0 auipc/0 pointeur) ; le handler 0x1631010 et les 5 vtables-texte
  (0x16844bc/0x1684880/0x1684330/0x16745b8/0x1674f0c) ; le callback 0x1684880 et son
  tail-call de chaînage ; les lecteurs bit 0 (0x1634bc2) et bit 8 (0x1634ff8/0x1635286) ;
  le chercheur BOARDOBJ 0x1457440 (hash +0x48, clé 64 o, types 0xc/0x10/0x13/0x1d) ;
  la table à pas 0x168 / sous-32 ; la famille des 30 noms de rails sans référence de
  code ; la ré-attribution du poke 0x400 (invalideur générique, PAS empreinte
  DisableDynamicPstate) ; 509 accès bruts +0x324/+0x328 archivés (scratch-gsp/v44/).
- **Inféré (solide)** : le bit 8 appartient à un des checks sœurs (Speedo/Iddq/Vmin/
  Isense) — pas attribué nominativement ; la revalidation « compte=4 » du callback =
  les 4 domaines CF ; la constante 0xb à +0x5e8 = type d'objet checker.
- **Muré** : les vtables réellement utilisées au runtime restent à confirmer dans le
  blob déchiffré (celles-ci sont celles posées par le handler) ; l'enum complet des
  types de requête ; les valeurs de calibration des rails (blob chiffré).
- **Zéro octet des dépôts GPU-/BIOS- touché** — lecture pure, comme toujours.
