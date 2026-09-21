# Campagne RTX 3070 — vague 4.9 : le constructeur introuvable prouvé, les listes par leurs racines, la source du mot packé

*Session cloud GLM 5.3 Flash — 2026-09-19 — GPU- `cc60c26` → vague 4.9, BIOS- `ac68d3c` (pause).*

## §0 — Trois vérités de la vague

1. **Le writeur nominatif du callback PMA (`+0x288`) n'existe pas — et c'est maintenant une preuve, plus une hypothèse.** Les 261 stores à `+0x288` de tout le segment X-R ont été recensés avec classification d'origine de valeur : **zéro** écrit une adresse de code calculée par `auipc`. Toutes ces valeurs transitent par la mémoire ou des registres chargés plus tôt — le pointeur de callback est posé **transitivement**, par copie runtime. L'hypothèse « initialisation en masse » de la 4.8 devient un fait structurel, troisièmement du genre (`+0x88130` vague 4.8, `+0x1100` cette vague, `+0x288` cette vague).
2. **Les « familles dominantes » de stores `+0x288` de la 4.7 (0x1915574 ×18, 0x193cc44 ×17) ne sont pas des régions de construction de vtables : ce sont des pointeurs vers des stubs no-op.** Vérification au fichier : `0x1915574` et `0x193cc44` sont des fonctions minuscules de six instructions (sauvegarde `s0`, retour immédiat, `a0 = 0` ou vide). Dix-huit familles d'objets reçoivent donc en `+0x288` un **callback par défaut qui ne fait rien** — et zéro gabarit statique du fichier ne contient ces pointeurs (0 qword égal dans les deux segments LOAD).
3. **La chaîne strap→code est fermée des deux bouts.** Le mot packé que la 4.8 avait laissé en champ décodé sort d'un **appel de vtable qui reçoit des offsets de registres matériels** : `0x68A00C + (index<<10)` puis `0x68A01C + (index<<10)`. Le callee lit le matériel et renvoie le mot ; les champs `[8:4]` et `[20:16]` passent dans la jump-table `0x1DEB210` (27 entrées, décodée au fichier cas par cas), `[23:22]`, `[11:10]`, `[1:0]` sont stockés bruts. C'est la jonction demandée par le ring 36 pour la chasse tension.

---

## §1 — Chantier 1 : le constructeur de l'état perf

### 1.1 La fenêtre demandée, balayée sans appel

Le §8 de la 4.8 proposait de balayer `0x164b000-0x164c500` autour du destructeur `0x164b7be` (`v49_ctor.py`). Résultat brut : **un seul prologue** (`0x164c7c8`), **zéro appel entrant** dans la fenêtre, **zéro store signature** (`+0x288/+0x324/+0x460/+0x88130`). Le destructeur n'est donc pas une fonction autonome de cette fenêtre — il appartient à un bloc plus vaste.

### 1.2 La fonction porteuse du destructeur : anatomie

`v49_ctor2.py` fixe les bornes par prologue : **`0x164b388` → `0x164c7c8`**, 1 585 instructions. Appels sortants résolus par script (après correction du masque 32 bits — les cibles wrap d'abord à `0x101457440` puis masquent en `0x1457440`) :

- **`0x1457440` — le chercheur, deux fois**, avec les types **`0xf`** (`0x164b3ee : c.li a1, 0xf`) et **`0x16`** (`0x164bb1e : c.li a1, 0x16`). Le teardown recherche donc les objets de type 0xf — **le type de repli PMA identifié en 4.7** — et un type 0x16 jamais vu jusqu'ici.
- **`0x1630b60`** (`0x164b772`), avec `a0 = s2` (l'état racine). Fonction propre (prologue, ancre globale `auipc s2`), voisine du setter `0x1630c48` mais distincte — non nommée.
- **`0x18e8ae0`** — l'utilitaire de destruction de la 4.8 — dix fois et plus.
- Les paires `0x1a9a3c2`/`0x1b4b55c` en quarantaine d'occurrences (assert/log), `0x173a4a4`, `0x164b210` (appel local), `0x18302f0`, `0x1670890`, `0x166f3c0`, `0x1705da0`, `0x18f1ce0`, `0x182aa18`.

**Zéro appelant direct** vers l'entrée `0x164b388` et **zéro référence adresse-prise** : le bloc est atteint par dispatch de pointeur, cohérent avec l'architecture BOARDOBJ.

### 1.3 Le root du teardown est le root du repli PMA

La dérivation du root des deux appels chercheur (`v49_lists2.py`) :

```asm
0x164b3d8  c.lui  s1, 4
0x164b3da  c.add  s1, a0          ; s1 = a0 + 0x4000
0x164b3dc  ld    a0, -0x330(s1)   ; a0 = [a0 + 0x3CD0]
0x164b3ee  c.li  a1, 0xf
0x164b3f0  auipc ra, 0xffe0c
0x164b3f4  jalr  ra, ra, 0x50     ; → 0x1457440
```

`[état+0x3CD0]` — **exactement le slot que la 4.7 avait vu alimenter le chemin de repli `0x14571b8` avec le type 0xf**. Double preuve, deux contextes indépendants : `+0x3CD0` est le **porteur de la liste des objets de repli PMA** (recherche au parse, libération au teardown).

### 1.4 La chasse au writeur : trois familles de scan, trois négatifs, une mécanique

`v49_ctor5.py` recense **261 stores `sd/sw` à `+0x288`** dans tout X-R (la 4.7 en comptait 243 avec un filtre plus serré) et classe l'origine de chaque valeur sur une fenêtre arrière de 12 instructions :

| Origine de la valeur | Count |
|---|---|
| transit par mémoire/registre (`other`) | 261 → 26 en clair, le reste via `ld` de pointeurs |
| chargement frame direct | 4 |
| chaîne `mv` | 3 |
| constante `li` | 2 |
| **`auipc` résolu (adresse de code calculée)** | **0** |

Complété par `v49_ctor6.py` sur le fichier : les pointeurs-stub `0x1915574`/`0x193cc44` sont bien du code (octets décodés en `c.addi sp, -0x10 ; c.sdsp s0 ; …`), et **aucun qword du fichier** (segments `0x1000000-0x1E85000` et `0x4000000-0x419C000`) ne contient ces valeurs — pas de gabarit statique. Conclusion : les pointeurs de callbacks `+0x288` sont **calculés au runtime puis copiés** par les constructeurs génériques ; aucun store nominatif n'existe. La question ouverte depuis la 4.7 est close par négation prouvée, pas par abandon.

### 1.5 L'entrée réelle du grand parseur — et un appel au setter dès l'entrée

`v49_ctor4.py` trouve le vrai prologue du grand parseur : **`0x1631010`** (la 4.6 l'ancrait à `0x1631300`, qui est mi-fonction). Signature d'entrée : `a0 → s2` (état dispatch), `a1 → s1` (état RM) — cohérente avec la signature du callback PMA `(dispatch, rm_state, 1)` de la 4.7. Premier fait nouveau : sur le chemin d'entrée `mode == 0`, le parseur appelle **le setter de changement de capacité `0x1630c48`** (`0x1631310 : auipc ra, 0 ; jalr -0x6c8 → 0x1630C48`) avec `(s2, s1, 1, 1)` — la construction d'état déclenche d'emblée une requête de capacité.

### 1.6 Ce que ça change pour les leviers

Le rang 3 (`PerfPmaControlReg=1`, « observation seule ») reçoit une explication mécanique partielle : la famille de valeurs par défaut de `+0x288` est des **stubs no-op**, et le chemin qui fait le travail réel est le repli type `0xf`. Le callback appelé sans garde nulle à `0x1632736` est garanti initialisé — la garantie tient par la construction transitive, qui pose toujours un pointeur (réel ou stub) avant tout appel.

---

## §2 — Chantier 2 : le catalogue des listes BOARDOBJ

### 2.1 Le chercheur, instruction-exact — deux précisions sur la 4.8

Le prologue de `0x1b3c4f0` (`v49_lists.py`) fixe la convention :

```asm
0x1b3c4fe  c.lui a5, 1
0x1b3c502  add   s2, a0, a5      ; s2 = root + 0x1000
0x1b3c506  ld    a0, 0x100(s2)   ; list = [root+0x1100]  — root = a0
0x1b3c50a  lbu   a5, 0x170(a0)   ; count = [list+0x170] (octet)
0x1b3c510  c.mv  s3, a1          ; clé = a1
0x1b3c512  c.mv  s4, a2          ; out-index = a2
; boucle : list est RECHARGÉE de [root+0x1100] à chaque itération
0x1b3c526  c.ld  a5, 0x38(a0)    ; accesseur = [list+0x38]
0x1b3c52e  c.jalr a5             ; item = accesseur(list, index)
0x1b3c530  c.lw  a5, 0x28(a0)    ; clé de l'item — LECTURE 32 BITS
0x1b3c532  bne   a5, s3, -0x1a
0x1b3c536  sw    s1, 0(s4)       ; trouvé : [out] = index, retour = item
; épuisement : retour 0x10000 (c.lui a0, 0x10) — out NON écrit
; liste vide  : retour 0
```

Deux précisions vs 4.8 : le code de retour d'épuisement est **`0x10000`** (et non `0xFFFF`), et la clé comparée est une **lecture 32 bits** à `[item+0x28]`. Détail structurel neuf : la liste est **rechargée à chaque itération** — le chercheur tolère une liste mutée sous ses pieds (concurrence RM).

### 2.2 Les racines des 52 appelants

`v49_lists.py` classe la dérivation de `a0` (root) chez les 52 appelants : 27 par registre préservé (chaîne), 15 par slot de frame, 2 gardes `beqz` directes, le reste mixte. Trois amas structurants :

1. **Le root de repli PMA `[état+0x3CD0]`** — teardown (§1.3) + repli 4.7. Le seul root nommé deux fois par preuve indépendante.
2. **Le grand parseur cherche la clé `0x10`** — à `0x1631568`, `a1 = 0x10`, root = handle de frame (`s0-0x90`, posé à `0x16314f2`, alimenté à `0x1631500` par le résultat 32 bits d'un appel précédent), out = `s0-0xa4`. La lecture `[handle+0x1100]` atterrit dans la frame du parent — trace d'un root embarqué dans une mega-frame d'appelant (le parseur est entré par pointeur, zéro appelant direct).
3. **Le constructeur de table clé→index à `0x17677xx`** — sept appels consécutifs au chercheur, root = `[s4+0x1ED0]`, garde `idx ≤ 0xa`, écriture de `0xFD0D`-valued halfwords à `[s3+0x64+idx*2]` : une table de correspondance clé→slot construite au runtime, avec la clé `0x40` visible en tête de bloc (`0x1767718 : addi a0, zero, 0x40`).

### 2.3 Zéro store à `+0x1100` — le troisième négatif structurel

Aucun `sd/sw` littéral à `+0x1100` dans tout X-R : personne n'« enregistre » une liste dans un root par store nominatif. Le câblage des listes est **transitif, comme les callbacks**. Trois champs indépendants (`+0x288`, `+0x1100`, `+0x88130`), trois chasses, trois négatifs du même profil : l'écriture nominative n'est pas le style de ce firmware ; le câblage est construit en masse au runtime.

### 2.4 Verdict du catalogue

Le « catalogue des listes » demandé par le §8 de la 4.8 n'est **pas statiquement énumérable** — et c'est le résultat : les listes `[root+0x1100]` vivent dans des objets runtime (frames, holders globaux chaînés), jamais dans des gabarits fichier. Ce que la vague nomme à la place : le root de repli PMA (`+0x3CD0`), le handle de frame du grand parseur (clé `0x10`), le root `[s4+0x1ED0]` du builder clé→index, et la preuve que le compteur/accesseur/clé (`+0x170`/`+0x38`/`+0x28`) est le seul contrat stable. Le croisement v42 (fenêtres dials) reste disponible pour la suite mais ne peut pas nommer des objets qui n'existent qu'au runtime.

## §3 — Chantier 3 : la chaîne strap→code, fermée des deux bouts

### 3.1 Les mappers vivent dans le cluster 0x1b3c — correction de la 4.8

Les deux « mappers » de la 4.8 étaient attribués au module `0x1bd9xxx`. Les références aux jump-tables (`v49_straps.py`) tranchent : les **fonctions** utilisatrices sont **`0x1b3c5ec`** (JT1, borne `c.li a5, 0x1b` = 27) et **`0x1b3c708`** (JT2, borne `c.li a5, 8`), dans le même cluster que le chercheur `0x1b3c4f0` — dispatch classique par offsets relatifs à la table :

```asm
0x1b3c616  auipc a4, 0x2af
0x1b3c61a  addi  a4, a4, -0x406  ; a4 = 0x1DEB210
0x1b3c61e  slli  a5, a0, 2
0x1b3c622  c.add a5, a4
0x1b3c624  c.lw  a5, 0(a5)       ; offset 32 bits signé
0x1b3c626  c.add a5, a4
0x1b3c628  c.jr  a5              ; saut base+offset
```

Le module `0x1bd9xxx` reste correct **pour les consommateurs** (§3.3) : la 4.8 confondait les deux côtés de l'appel.

### 3.2 Les tables, lues au fichier, cas par cas

`v49_straps2.py` lit les 35 entrées 32 bits au fichier (`LOAD1 : off = VA − 0x1000000`) et `v49_straps3.py` décode le corps de chaque case :

**JT1 `0x1DEB210` (5 bits → valeur)** — cibles 0x1b3c62a-0x1b3c6c6 :

| entrée | valeur | | entrée | valeur |
|---|---|---|---|---|
| 0 | `0x11` | | 9..16 | `8..0xf` (descendant) |
| 1 | `0` | | 17, 18, 19 | **chemin d'erreur** |
| 2..8 | `1..7` (k−1) | | 20, 21 | `0x1e`, `0x1f` |
| | | | 22, 23 | **chemin d'erreur** |
| | | | 24, 25, 26 | `0x1c` (store direct) |

Le chemin d'erreur (`0x1b3c62a`) construit un enregistrement de log (format en rodata volatile `auipc 0x1e80d`), passe par une garde `EBREAK` conditionnelle (`0x1b3c654 : lbu a5, [global] ; bnez → skip ; c.ebreak`), puis rejoint `0x1b3c65c : c.li a0, 0x1c`. La 4.8 avait vu « invalid → 0x1c loggé » ; le décodage complet ajoute `24..26 → 0x1c` **sans** log, et la borne exacte (au-delà de 27 → chemin d'erreur par le `bltu`).

**JT2 `0x1DEB280` (3 bits → valeur)** : `k → k+1` confirmé (`[0]→1 … [7]→8`), la case `[1]` portant l'épilogue partagé (store `[s1]` + vérification d'intégrité `xor` contre le canari `0(s3)` + retour).

### 3.3 Le consommateur et la source : la vtable qui lit le matériel

La fonction consommatrice **`0x1bd979c`** (module 0x1bd9xxx, frame 0x50, `v49_straps3.py`) :

```asm
0x1bd97b4  c.lui s4, 4
0x1bd97b6  c.add s4, a0          ; s4 = a0 + 0x4000
0x1bd97b8  ld    a5, -0x510(s4)  ; holder = [a0 + 0x3AF0]
0x1bd97c2  beqz  a2, ...         ; out requis
0x1bd97ca  c.ld  a0, 0x50(a5)    ; obj = [holder + 0x50]
0x1bd97cc  lui   s6, 0x68a       ; s6 = 0x68A000
0x1bd97d0  slliw s2, a1, 0xa     ; s2 = index << 10
0x1bd97d4  c.ld  a5, 0(a0)       ; vtbl
0x1bd97d6  addiw a1, s6, 0xc     ; a1 = 0x68A00C + (index<<10)
0x1bd97de  c.ld  a5, 0x28(a5)    ; vtbl+0x28
0x1bd97e8  c.jalr a5             ; MOT PACKÉ = fn(obj, 0x68A00C+(index<<10))
```

Le callee est un **accesseur matériel** : il reçoit un offset de registre dans la page **`0x68Axxx`**, indexé par pas de `0x400` (`index << 10`), et renvoie le mot packé. Deuxième appel au même slot avec **`0x68A01C + (index<<10)`** (`0x1bd9806`) — deux registres frères de la même page. Le bit 31 du premier mot est extrait séparément (`srliw a0, a0, 0x1f`) et stocké à `[out+0xc]`, le reste (`[30:0]`, masqué de `0x80000000`) à `[out+0]`.

Le décodage des champs du second mot (`0x1bd986a-0x1bd98a6`) complète la carte de la 4.8 :

| champ | extraction | destination |
|---|---|---|
| `[1:0]` | `andi a4, a0, 3` | `[s1+0x24]` brut |
| `[8:4]` | `andi a0, a3, 0x1f` | **JT1** → `[s1+0x2c]` (bloc out) |
| `[11:10]` | `srliw/andi 3` | `[s1+0x28]` brut |
| `[20:16]` | `andi a0, 0x1f` | **JT1** → `[s1+0x38]` |
| `[23:22]` | `srliw/andi 3` | `[s1+0x34]` brut |

Le mot complet est sauvegardé (`sext.w s5, a0`) entre les deux extractions — le compilateur relie les deux appels JT1 au même mot source.

### 3.4 Le wrapper d'entrée

`0x1bd979c` n'a **qu'un appelant** : le wrapper **`0x12b5c88`** (`0x12b5ca6`), qui garde `a3 != 0` puis décale les arguments — le consommateur reçoit `(a1, a2, a3)` du wrapper, son `a0` (porteur du `+0x3AF0`) étant l'`a1` du wrapper. Une couche de plus remonte vers l'ordonnanceur de domaines ; la remontée nominative au-delà reste ouverte (§5).

### 3.5 La jonction avec la chasse tension du fondateur

Ce que le ring 36/37 demandait (« la grammaire du levier de montée en tension ») a désormais son **point d'entrée côté code** : la page `0x68Axxx` — deux registres frères `+0x00C`/`+0x01C`, adressés par domaine (`index << 10`) — alimente les champs 5 bits décodés par JT1 (valeurs `0..0x11/0x1e/0x1f` — un espace de 28 identités, taille d'une famille de domaines clk/voltage) et les champs bruts 2 bits. Côté machine, les valeurs vivantes de ces registres (lecture `0x68A00C/0x68A01C` par domaine) croisées avec l'ancre 987 mV @ 1770 MHz donneront la table de correspondance champ→tension. Le code des cases JT1 (les `c.li` à `0x1b3c684-0x1b3c6c6`) est la **grammaire** demandée : 28 identités, deux inconnues loggées, trois valeurs d'extension `0x1e/0x1f`.

---

## §4 — Carte des leviers (mise à jour machine)

| Rang | Levier | État après la 4.9 |
|---|---|---|
| 1 | `RmVFPointCheckIgnore` | inchangé — protocole Phase D 1-4 intact |
| 2 | `RmPerfChangeSeqOverride` | inchangé — le bit 8 et sa sync un-site sont clos depuis la 4.8 |
| 3 | `PerfPmaControlReg=1` | **consolidé** : le writeur `+0x288` est prouvé transitif (§1.4), les valeurs par défaut sont des stubs no-op (§0.2) — « observation seule » a maintenant une mécanique, plus seulement une étiquette |
| — | *nouveau savoir* | la page `0x68Axxx` (`+0x00C`/`+0x01C` par domaine) est la source matérielle des champs de domaine décodés — cible de lecture pour la session live (§3.5) |

---

## §5 — Registre d'honnêteté

1. **Corrections de la 4.7/4.8** : les « régions de construction de vtables en masse » (`0x1915574`, `0x193cc44`) sont des **stubs no-op** — valeurs, pas sites (§0.2) ; les mappers JT vivent en `0x1b3c5ec/0x1b3c708`, pas en `0x1bd9xxx` (les consommateurs, eux, y sont) ; le miss du chercheur est `0x10000` (et la liste vide retourne `0`), pas `0xFFFF`.
2. **Le callback PMA réel de l'état racine n'est pas nommé.** La preuve d'absence porte sur le *mécanisme* (zéro store direct) ; l'identité du pointeur posé au runtime sur CET état reste hors d'atteinte statique. Le lien « stub no-op → PerfPmaControlReg observation seule » est une mécanique cohérente, pas une identification.
3. **`0x1630b60` (appelé par le teardown avec le root) n'est pas nommé** — fonction propre de la région setter, distincte de `0x1630c48`.
4. **Le root du grand parseur au site clé-0x10 est un handle de frame** dont la lecture `+0x1100` atterrit dans la frame parente — interprétation « root embarqué chez un mega-appelant » plausible mais non prouvée (le parseur n'a pas d'appelant direct pour vérifier la frame).
5. **Le callee de la vtable `+0x28`** (le lecteur de `0x68Axxx`) n'est pas déroulé — l'implémentation concrète dépend de la classe d'objet runtime ; seul le contrat (offset registre entrant, mot packé sortant) est prouvé.
6. **Arithmétique par script** : toutes les cibles de cette vague (calls auipc, jump-tables, stubs) ont été résolues par script après deux corrections en cours de route (masque 32 bits `v49_ctor2`, préfixe de displacement `v49_ctor5`) — leçon Task 70 appliquée.
7. **BIOS- reste en pause** (`ac68d3c`, CLEAN) — aucune opération.

---

## §6 — Jalon 4.10 proposé

1. **La remontée du domaine** : qui fournit `a0` au wrapper `0x12b5c88` (appelant → couche d'ordonnancement des domaines), et quel objet classe porte la vtable `+0x28` qui lit `0x68Axxx` — croiser avec les constructeurs runtime pour nommer la classe.
2. **La carte champ→sémantique** : les 28 identités JT1 face aux domaines connus (clk domains, voltage domains du GSP) — la table `0x1DEB210` est un espace de noms fermé ; chaque valeur a une identité à poser.
3. **Côté machine (jonction)** : lecture live de `0x68A00C`/`0x68A01C` par domaine pendant une montée de charge — le fondateur a l'ancre 987 mV @ 1770 ; les mots packés vivants donneront les champs `[8:4]`/`[20:16]` réels et nommeront la grammaire tension par la pratique.

Le dépôt GPU- est propre, poussé, et signé. BIOS- reste en pause.
