# Vague 4.8 — la bitmap en clair, le chercheur par clé, l'anatomie des constructeurs

**Campagne RTX 3070 — minage cloud de rm.elf (GSP RISC-V, 16 912 384 octets)**
**Date : 2026-09-19 · Auteur du minage : cloud GLM 5.3 Flash · Domaine : X-R 0x1000000-0x1C00000 (5 342 005 instructions, désassemblage linéaire intégral v45) + rodata file-backed (0x1C00000-0x1E85000, lisible)**

---

## §0 — Trois vérités de la vague

**Vérité 1 — le disque a encore devancé le résumé.** Le résumé de continuation déclarait la vague 4.5 à lancer (GPU- attendu c58f77e) ; le disque montrait les vagues 4.5 (`bd0dec5`), 4.6 (`58a8bad`) et 4.7 (`2f26072`) déjà soldées et poussées — Tasks 69-71 complètes. Au fetch, un commit fondateur de plus est rentré : **ring 36** (`268fd2e`, `lab/findings-gx36.md` — la structure chaînée vP-state, candidats tension 990, chasse à la tension côté machine) → ff-pull, les deux dépôts CLEAN. Compteur de dérives : une (résumé), radiée à l'ouverture, puis ZÉRO.

**Vérité 2 — la rodata file-backed est lisible, et elle vient de parler.** Le premier LOAD couvre 0x1000000-0x1E85000 en fichier ; la zone 0x1C00000-0x1E85000 (rodata pure) n'est PAS chiffrée partout. La vague 4.7 avait localisé la liste blanche 0x20-0x4F sans pouvoir la lire ; cette vague la lit **octet par octet dans le binaire** — et elle est en clair. Deux jump-tables de mappers sont décodées sur le même principe. La leçon Task 70 appliquée : chaque adresse (bitmap, tables, cibles de branches) provient du résolveur par script, jamais d'un calcul de tête — deux fois le script a corrigé l'intuition en cours de route.

**Vérité 3 — cette vague renverse deux noms de la 4.6/4.7.** L'« utilitaire de revalidation générique » `0x1b3c4f0` (52 appelants) n'est pas une revalidation : c'est un **chercheur générique par clé dans une liste BOARDOBJ** — et la « double passe P-states » (0x40 puis 8) est une double **recherche d'objets par clé** avec invocation de leurs callbacks, pas des passes de largeur variable. Les « copieurs champ-par-champ » du +0x288 (0x1156xxx/0x1159xxx) sont des **constructeurs à auto-pointeurs** qui ne peuvent pas alimenter le callback PMA. Les deux corrections sont prouvées instruction-exact et enregistrées au registre d'honnêteté.

Instruments persistés et commités cette vague : `v48_bitmap.py` (résolution+lecture de la bitmap), `v48_policy.py` (carte des branches du bloc politique, chasse aux écrivains de l'ID de séquence), `v48_pass.py` (déroulé de la grappe 0x1b3c4f0, census des clés), `v48_find.py` (fenêtre P-states, décodage des jump-tables, appelants des mappers), `v48_clone.py` (fenêtres des constructeurs + appelants), `v48_ctor.py`/`v48_ctor2.py`/`v48_ctor3.py`/`v48_ctor4.py` (quatre familles de scan pour l'écrivain de 0x88130/0x288 — les itérations du même chantier, gardées pour la traçabilité), `v48_vtbl288.py` (stores alimentés par slot de vtable). Cache TSV v45 réutilisé tel quel.

---

## §1 — Chantier 3 : la liste blanche 0x20-0x4F est EN CLAIR

La vague 4.7 avait clos le mécanisme sans la table : « une liste blanche de 32 IDs de séquences dont la sémantique exacte reste ouverte ». La table est désormais lue — elle tient en une valeur de 64 bits.

### 1.1 La politique complète, instruction-exact

```asm
0x16355e2  lbu  a5, 0x19(s3)       ; le FLAG +0x19 de la requête
0x16355e6  beqz a5, +0x112         ; flag nul → TOUTE la politique est sautée
0x16355ea  ld   a5, 0x2f8(s2)      ; l'objet séquence courant, à [s2+0x2f8]
0x16355ee  beqz a5, +0x2e          ; pas d'objet → chemin du refus
0x16355f0  lbu  a5, 0x180(a5)      ; l'ID de séquence = octet à [obj+0x180]
0x16355f4  li   a4, 0xff
0x16355f8  beq  a5, a4, +0x24      ; 0xff = « pas de séquence » → refus
0x16355fc  addiw a5, -0x20         ; normalisation
0x16355fe  andi a5, a5, 0xff
0x1635602  li   a4, 0x30
0x1635606  bltu a4, a5, +0x16      ; hors 0x20-0x4F → refus
0x163560a  auipc a4, 0x84e
0x163560e  ld   a4, 0x72e(a4)      ; LA BITMAP (64 bits, un seul ld)
0x1635612  srl  a5, a4, a5
0x1635616  andi a5, a5, 1          ; test du bit (id - 0x20)
0x1635618  bnez a5, +0x216         ; bit POSÉ → chemin du handler
```

### 1.2 La valeur de la bitmap, lue dans le fichier

Résolution par script : `auipc a4, 0x84e` à 0x163560a → base 0x1E8360A ; `ld a4, 0x72e(a4)` → **VA 0x1E83D38**, dans le premier LOAD (file-backed) → **offset fichier 0xE83D38**. Les 8 octets bruts :

```
01 00 21 00 01 00 01 00   →   0x0001000100210001 (petit-boutiste)
```

Cinq bits posés, dont quatre atteignables par la porte 0x20-0x4F (bits 0-47) :

| Bit posé | ID de séquence (bit+0x20) | Atteignable ? |
|---|---|---|
| 0 | **0x20** | oui |
| 16 | **0x30** | oui |
| 21 | **0x35** | oui |
| 32 | **0x40** | oui |
| 48 | 0x50 | **non** — la porte `bltu 0x30` l'écarte avant le test |

**La liste blanche autorise exactement quatre IDs : 0x20, 0x30, 0x35, 0x40.** Le cinquième bit (0x50) existe dans le mot mais est inatteignable par ce chemin. Aucun motif de chiffrement (marqueur `ffffe780` absent) — la valeur est opérationnelle telle quelle.

### 1.3 Les deux issues, et le code de refus

**Bit clair** (chute, 0x163561c) : format rodata `0x202c74f0` (région volatile, non lisible statiquement) chargé dans la frame, appel log (`0x1a9a3c2` puis `0x1b4b55c` — le couple bavard du dispatcher), lecture d'un flag de debug (`auipc 0x2b66 ; lbu`), `c.ebreak` si le flag est bas (assert de debug), puis **`s1 = 0x56` et retour** — le même code générique « non applicable » que le « déjà conforme » du setter (4.4). La requête est refusée proprement, avec trace.

**Bit posé** (0x163582e) : garde `[s3+0x314] ≤ 9` (compteur d'indices), écriture de `-1` à `[s3+0x31c]` (slot de sortie initialisé), puis appel du **handler de séquence `[s7+0x348]`** avec `(a0=s6, a1=s2, a2=s7, a3=&s3+0x314)` — le handler reçoit un pointeur vers le slot de sortie de la requête. Succès → épilogue ; erreur → log d'erreur puis retour.

### 1.4 La réponse à la question de sûreté du jalon 4.7

**La bitmap ne borne PAS le levier rang 2 (`RmPerfChangeSeqOverride`).** La preuve est structurelle : le chemin du dial (4.5 : valeur impaire → 0x1631824 → setter bit 8 direct) n'emprunte jamais ce bloc — pas de requête, pas de flag +0x19, donc `beqz` saute toute la politique. La liste blanche borne les **requêtes de changement de séquence émises par le moteur** (celles qui portent le flag +0x19) : quatre types de séquences exécutables, tout le reste se voit répondre 0x56. Pour la Phase D, c'est un garde-fou de plus connu et contourné par construction : le protocole du dial ne traverse jamais cette porte.

---

## §2 — Le renversement du bit 8 : le dispatcher le FORCE à l'entrée

La fenêtre amont (0x16354e0-0x16355a8, tirée par `v48_policy.py`) change la lecture de la 4.7 :

```asm
0x16354ea  ld   s2, -0x300(a5)      ; s2 = [s6+0x1D00] — l'état RM
0x1635502  call 0x15EB560           ; construit l'état de dispatch → s7
0x163550e  ld   a5, 0x130(a5)       ; a5 = [s2+0x88130] — l'objet capacité
0x1635516  beqz a5, +0x140          ; PAS d'objet → 0x1635656
0x163551a  lw   a5, 0x324(a5)
0x163551e  andi a5, a5, 0x100       ; le bit 8, lu directement (andi 0x100)
0x1635522  beqz a5, +0x134          ; bit 8 CLAIR → 0x1635656
0x1635526  (chemin principal)       ; bit 8 déjà posé → traitement direct
...
0x1635656  c.li a3, 1               ; ← le SITE DU FORCE : a3 = 1 CODÉ EN DUR
0x1635658  c.li a2, 8
0x1635662  call 0x1630c48           ; setter — SET bit 8 forcé
0x163566a  beqz s1, -0x144          ; succès → retour au chemin principal
```

**Le dispatcher arme lui-même le bit 8 quand il ne l'est pas** : objet capacité absent OU bit 8 clair → SET forcé (a3=1 constant, pas la valeur de la requête), puis retour au chemin principal. Le bit 8 est donc l'**état « traitement de changement de séquence en cours »** que le chemin principal exige posé avant de travailler — ce qui éclaire rétrospectivement la sémantique du dial (4.5) : `RmPerfChangeSeqOverride` (valeur impaire) simule cet état d'entrée pour court-circuiter le second check.

**Correction de la 4.7 enregistrée** : le site `0x1635662` n'est pas le bras SET de la synchronisation idempotente — c'est le force d'entrée. La sync, elle, est un **site unique** (0x16355d6) : `a3 = valeur voulue lue à [req+0x18]`, qui gère SET **et** CLEAR selon le delta. La mécanique idempotente tient ; sa décomposition en deux sites était fausse.

L'anatomie de la requête séquence sort complète de la même fenêtre : deux blobs de 0x20 octets à `+8` et `+0x10` (copiés vers `s7+0x30c` et `s7+0x318`), un mot à `+0x14` (vers `[s7+0x308]`), la valeur bit-8 à `+0x18`, le flag de politique à `+0x19`, un callback `[s7+0x390]` appelé en cours de chemin, le compteur `+0x314` (≤ 9) et le slot de sortie `+0x31c`. Un objet de requête de 0x320 octets dont chaque champ a désormais un consommateur nommé.

---

## §3 — Chantier 2 : 0x1b3c4f0 est un chercheur par clé, pas une revalidation

### 3.1 La grammaire de la fonction

Le déroulé intégral (475 instructions, `v48_pass.dump`) livre une fonction A de 0x1b3c4f0 à 0x1b3c55e, brève et bouclée :

```asm
0x1b3c502  add  s2, a0, 0x1000      ; s2 = root + 0x1000
0x1b3c506  ld   a0, 0x100(s2)       ; LA LISTE = [root+0x1100]
0x1b3c50a  lbu  a5, 0x170(a0)       ; le COMPTEUR = [list+0x170] (octet)
0x1b3c510  mv   s3, a1              ; la CLÉ (arg a1)
0x1b3c514  li   s1, 0               ; i = 0
0x1b3c526  ld   a5, 0x38(a0)        ; l'ACCESSEUR = [list+0x38] (vtable)
0x1b3c52e  jalr a5                  ; item = accesseur(list, i)
0x1b3c530  lw   a5, 0x28(a0)        ; la CLÉ DE L'ITEM = [item+0x28]
0x1b3c532  bne  a5, s3, ...         ; pas cette clé → i++
0x1b3c536  sw   s1, 0(s4)           ; trouvé : [arg a2] = i
0x1b3c546  li   a0, 0 ; ret         ; 0 = trouvé
0x1b3c550  lui  a0, 0x10 ; addi -1  ; 0xFFFF = pas trouvé
```

Signature : `find(root, clé, &index_sortie)`. La liste vit à `[root+0x1100]`, son compteur à `+0x170` (≤ 255), l'accesseur d'item à `+0x38`, la clé d'item à `+0x28`. Retour 0/0xFFFF. **Rien ici ne revalide quoi que ce soit** — c'est une recherche par clé, le motif BOARDOBJ le plus classique.

### 3.2 Le census des clés des 52 appelants

Le regard arrière `li a1` aux 52 sites (`v48_pass_a1.json`) donne la distribution des clés cherchées : **0x10 ×11, 0x8 ×5, 0x1 ×4, 0x40 ×3, 0x2 ×1, 0xff ×1** — plus 13 sites à clé dérivée de registre (`mv s3/s1/s9/a0/a5/s2/s4`) et 14 indéterminés (registre non immédiat). La « passe a1=0x40 » de la 4.6 était une **recherche de l'objet de clé 0x40**.

### 3.3 La boucle P-states réinterprétée, instruction-exact

La fenêtre 0x1631930-0x1631a70 (`v48_pstate_loop.dump`) ferme le dossier :

```asm
0x1631978  li   a1, 0x40            ; CLÉ 0x40
0x163197e  call 0x1b3c4f0           ; find(root, 0x40, &idx)
0x163198a  bnez s10, +0x36a         ; 0xFFFF → chemin d'erreur loggé
0x1631992  ld   a0, 0x100(a5)       ; la liste
0x1631996  lw   s9, -0xa4(s0)       ; l'INDEX TROUVÉ
0x163199c  andi a1, s9, 0xff
0x16319a0  jalr a5                  ; item = accesseur(list, idx)
0x16319a6  ld   a5, 0x60(a0)        ; LE CALLBACK DE L'ITEM = [item+0x60]
0x16319ac  jalr a5                  ; callback(s2, s6, item)
0x16319b2  sllw a5, a5, s9          ; 1 << idx
0x16319b6  or   a5, s4, a5          ; s4 |= 1 << idx  ← l'« accumulation » de la 4.6
0x16319c2  li   a1, 8               ; CLÉ 8
0x16319ca  call 0x1b3c4f0           ; find(root, 8, &idx) — idem
0x1631a50  call 0x1630c48           ; SET bit 9 (a2=9, a3=1) en sortie, confirmé
```

La « double passe » = **trouver l'entrée de clé 0x40, invoquer son callback `[item+0x60](s2, s6, item)`, accumuler son index dans le masque s4 ; puis la même chose pour la clé 8**. L'accumulation `s4 |= 1 << (val & 0xff)` de la 4.6 était `1 << index_trouvé`. Les « revalidations large/étroite » n'ont jamais existé — c'étaient deux objets-listes de clés 0x40 et 8 dont les callbacks sont déclenchés en séquence, chaque passage de la boucle.

---

## §4 — La grappe 0x1b3c4f0-0x1b3ca10 : cinq utilitaires, deux tables décodées

La fenêtre de 0x500 octets contient cinq fonctions distinctes, toutes caractérisées :

| # | Adresse | Rôle prouvé | Sortie d'erreur |
|---|---|---|---|
| A | 0x1b3c4f0 | **chercheur par clé** (§3) — 52 appelants | 0xFFFF |
| B | 0x1b3c560 | chercheur table 8 octets à `[x+0x1B10]`/`[x+0x1B18]`, rend 2 octets (entrées +4/+5) vers `[a2]`/`[a3]` | 0x4a (74) |
| C | 0x1b3c5ec | **mapper 1** : indice 0-0x1b → code, jump-table lisible | 0x1c (loggé) |
| D | 0x1b3c708 | **mapper 2** : indice 0-8 → code, jump-table lisible | 0 (assert) |
| E | 0x1b3c7f8 / 0x1b3c8c8 | pour-chaque-objet (`+0x3AF0`, callback `[obj+0x28]`, constante 0x111) ; remplisseur d'enregistrements `[+8]=arg, [+4]=hi, [+0]=lo, [+0xc]=0` | 0x37 / 0x44 |

### 4.1 Les jump-tables décodées (rodata file-backed)

**Mapper 1** (`0x1b3c5ec`) — table à **0x1DEB210** (27 mots signés relatifs, lus au fichier 0xDEB210) :

| Entrée | Code rendu | | Entrée | Code rendu |
|---|---|---|---|---|
| 0 | **0x11** | | 11 | 0xa |
| 1 | **0x0** | | 12 | 0xb |
| 2 | 0x1 | | 13 | 0xc |
| 3 | 0x2 | | 14 | 0xd |
| 4 | 0x3 | | 15 | 0xe |
| 5 | 0x4 | | 16 | 0xf |
| 6 | 0x5 | | 17/18/19 | 0x1c (chemin loggé) |
| 7 | 0x6 | | 20 | **0x1e** |
| 8 | 0x7 | | 21 | **0x1f** |
| 9 | 0x8 | | 22/23 | 0x1c (chemin loggé) |
| 10 | 0x9 | | 24/25/26 | 0x1c (silencieux) |

La structure parlante : l'indice 1 rend 0, les indices 2-16 rendent `i-1`, l'indice 0 rend 0x11, deux codes hors-séquence (0x1e/0x1f) aux indices 20/21, et 0x1c = code d'invalidité. Les appelants (4 sites, tous en 0x1bd9888-0x1bd9d26) extraient des **champs de 5 bits d'un mot packé** (`srliw 4 ; andi 0x1f` → bits [8:4] ; `srliw 0x10 ; andi 0x1f` → bits [20:16]) : un **décodeur de registre/strap** — l'indice physique entre, le code logique RM sort. Le module 0x1bd9xxx est le voisinage de la table de timings mémoire (ring 33) et du chercheur 0x1bd4230 : la chaîne strap→code→timing se dessine.

**Mapper 2** (`0x1b3c708`) — table à **0x1DEB280** (9 mots, lus au fichier 0xDEB280) : identité décalée **`i → i+1`** pour 0-8. Un simple normalisateur d'indice base-1, mêmes appelants (2 sites en 0x1bd9abc/0x1bd9f8a).

Ces deux tables sont les **premières structures de données rodata entièrement décodées** au-delà des dials : la frontière chiffrée n'est pas uniforme, et chaque mot lisible vaut une hypothèse de moins.

---

## §5 — Chantier 1 : l'anatomie du +0x288 — quatre familles de scan, une conclusion structurelle

Le jalon demandait de « remonter le clone-source du callback PMA ». Le clone-source a été remonté — et le clone n'existe pas. Résultat en trois couches :

### 5.1 Les « copieurs » sont des constructeurs à auto-pointeurs

La fenêtre du copieur type (0x115665e, `v48_cop_115665e.dump`) :

```asm
0x11565fc  addi t6, a2, 0x3b8       ; t6 = a2 + 0x3b8 — DANS l'objet lui-même
0x115665e  sd   t6, 0x288(a2)       ; [a2+0x288] = a2 + 0x3b8
```

Autour : `s7 = a2+0x550`, `s8 = a2+0x440`, `s3 = a2+0x280`, `s4 = a2+0x298`, `s5 = a2+0x4d8`, `s6 = a4+0x20`… puis des stores alignés : `[a2+0x1d0]=a2+0x1b0`, `[a2+0x240]=a4+0x20`, `[a2+0x290]=a2+0x298`, `[a2+0x1e0/0x1e8/0x1f0/0x1f8/0x200/0x208]=[a5+0xb0..0xd8]`… Ce n'est **pas une copie champ-par-champ depuis une source** : c'est un **constructeur qui câble un graphe d'auto-pointeurs** — le champ +0x288 de CETTE famille d'objets reçoit un pointeur vers une sous-structure interne (+0x3b8), pas une adresse de code. Ces sites ne peuvent donc pas alimenter le `jalr` du callback PMA — **l'hypothèse « clone » de la 4.7 est corrigée** : les 243 enregistrements à +0x288 mélangent des familles d'objets distinctes qui partagent l'offset, et celle-ci tient son +0x288 de son propre gabarit interne.

### 5.2 Le destructeur de l'état perf est localisé

Le scan avant depuis chaque `lui 0x88` (249 sites, `v48_ctor4.py`, 135 stores via base aliasée) livre exactement **deux** écritures liées à `[état+0x88130]` — et les deux sont des **nulls**. Le site 0x164b7be :

```asm
0x164b79c  lui  a5, 0x88 ; add a5, s2
0x164b7a2  ld   a1, 0x130(a5)       ; [s2+0x88130]
0x164b7a6  beqz a1, +0x12            ; null → rien à détruire
0x164b7b0  call 0x18e8ae0            ; (a0 = 0x4161fe0, rodata volatile) — destruction
0x164b7be  sd   zero, 0x130(a5)      ; PUIS null — le destructeur
0x164b7c2  lui  a5, 0x8f ; add a5, s2
0x164b7c8  ld   a0, 0x188(a5)        ; [s2+0x8F188] — même pattern
```

Croisement décisif : `[s2+0x8F188]` touche au couple `+0x8F180/181` où la 4.6 voyait la config 0x4C0 de `RMDisablePerfIntersect` — **c'est bien l'état perf RM** qui est détruit ici, et l'objet capacité est démonté avec lui. La durée de vie de l'objet capacité est prouvée liée à celle de l'état porteur.

### 5.3 L'initialisation massive du grand parseur — et la frontière honnête

L'autre null (0x1632150) est un faux positif fertile : le grand parseur **initialise un tableau de ~160 enregistrements de 0x14 octets** à `état+0x881A0` — `[+0]=0, [+4]=état+0x88000` (back-pointer systématique), `[+8..+0x10]=0` — jusqu'à `état+0x8A9A0` (l'adresse où la 4.6 voyait le type 0x13 écrit). Le sous-système VF-point du grand parseur a son réservoir d'enregistrements pré-câblé.

Quant au **writeur du pointeur de code à `[état+0x288]`** : quatre familles de scan l'ont cherché sans succès — valeurs constantes (4.7, 99 cibles), auto-pointeurs (5.1), adresse fusionnée `lui 0x88` (135 stores passés au crible), valeur chargée de slot de vtable auipc-résolu (`v48_vtbl288.py`, 0 hit). Conclusion structurelle assumée : le champ est posé par **initialisation en masse** (gabarit copié à l'allocation, ou écriture hors X-R), hors de portée du store unitaire. Ce qui reste prouvé et suffisant pour la sûreté : le champ contient une adresse de code au moment de l'appel (sinon `jalr` faulterait), sa garantie d'initialisation tient, et sa signature/condition d'invocation/repli sont closes depuis la 4.7.

---

## §6 — Carte des leviers (mise à jour machine)

**Aucun changement de rang, trois consolidations.**

| Rang | Levier | État après la 4.8 |
|---|---|---|
| 1 | `RmVFPointCheckIgnore` | inchangé — protocole Phase D 1-4 intact |
| 2 | `RmPerfChangeSeqOverride` | **consolidé et affiné** : le bit 8 est l'état « séquence en cours » que le dispatcher FORCE à l'entrée du traitement (§2) ; le dial simule cet état ; la liste blanche 0x20-0x4F **ne le borne pas** (chemin sans requête, §1.4) — poke du dial toujours seul point d'entrée sûr |
| 3 | `PerfPmaControlReg=1` (observation seule) | inchangé — callback non nommé (§5.3), mécanique close 4.7 |

Nouveau savoir défensif pour la machine : les requêtes de séquence du moteur sont bornées par une liste blanche de quatre IDs (0x20/0x30/0x35/0x40) avec refus 0x56 tracé — si un jour un chemin machine pousse une requête de séquence, ce refus est le symptôme attendu côté trace, et 0x56 dans un log RM signifiera « hors liste » avant toute autre hypothèse.

## §7 — Registre d'honnêteté

1. **Deux renversements de noms 4.6/4.7** : `0x1b3c4f0` = chercheur par clé (pas revalidation) ; les « passes » 0x40/8 = clés d'objets (pas des largeurs). L'accumulation `s4 |= 1 << (val & 0xff)` = `1 << index_trouvé`. Les conclusions structurelles des vagues précédentes (boucle interne du grand parseur, SET bit 9 en sortie, chemin mode 7) ne changent pas.
2. **Correction du site SET bit 8 de la 4.7** : `0x1635662` est le force d'entrée du dispatcher (a3=1 codé en dur), pas un bras de la sync — la sync est un site unique (0x16355d6, a3 = valeur de la requête, deux sens).
3. **Correction de l'hypothèse « clone » de la 4.7** : les copieurs 0x1156xxx/0x1159xxx sont des constructeurs à auto-pointeurs (`[obj+0x288] = obj+0x3b8`) ; ils ne peuvent pas alimenter le callback PMA de l'état RM. L'attribution nominative du handler reste ouverte (§5.3, quatre familles de scan en échec, hypothèse bulk-init).
4. **Les IDs 0x20/0x30/0x35/0x40 n'ont pas de noms** : la sémantique des quatre séquences autorisées est bloquée par le rodata volatile chiffré (formats de log à 0x202c74f0 etc. non lisibles statiquement). La structure (autorisation, refus 0x56, handler `[s7+0x348]`, garde ≤ 9) est close.
5. **Écrivains non localisés** : l'ID de séquence `[obj+0x180]` (0 candidat avec constantes en région perf) et le pointeur d'objet séquence `[s2+0x2f8]` (0 store unitaire global) — posés hors région perf ou par initialisation en masse.
6. **Le code du chemin de destruction** 0x164b7b0 (cible 0x18e8ae0, résolue par script ; a0 = 0x4161fe0 en rodata volatile, juste sous l'outlier 0x4162008 noté en 4.7) n'est pas déroulé — le pattern destroy+null est lui prouvé deux fois (0x88130, 0x8F188).
7. **Les clés du chercheur** (0x10/0x8/0x1/0x40/2/0xff…) désignent des objets des listes `[root+0x1100]` dont l'identité nominative (quelle liste, quels objets) reste ouverte — le croisement avec les tables v42 est le chantier naturel du jalon 4.9.
8. **Le contenu de la bitmap est vérifié par double lecture** : 8 octets bruts re-lus au fichier après résolution, aucun motif de chiffrement ; le bit 0x50 posé mais inatteignable est documenté tel quel (la porte `bltu 0x30` le précède).

## §8 — Jalon 4.9 proposé

Trois chantiers, dans l'ordre de valeur :

1. **Le constructeur de l'état perf** : le destructeur vit à 0x164b7xx — le constructeur est dans le même module. Balayer 0x164b000-0x164c500 pour l'allocation massive + les stores à 0x288/0x324/0x460/0x88130 et nommer l'init du callback PMA (la question ouverte depuis la 4.7, maintenant avec une fenêtre précise).
2. **Le catalogue des listes BOARDOBJ** : chaque appelant du chercheur `0x1b3c4f0` connaît son `root` — reconstruire la liste des listes (`root+0x1100`), leur compteur et leurs clés, et croiser avec les objets construits des tables v42 pour nommer la liste dont les clés 0x40/8 commandent la boucle P-states.
3. **La chaîne strap→code du module 0x1bd9xxx** : autour des mappers décodés (§4.1), remonter le mot packé d'entrée (bits [4:0]/[8:4]/[20:16]/[23:22]) jusqu'à sa source (registre lu, fuse, table vP-state?) — c'est le point de jonction naturel avec la chasse tension du ring 36 côté machine.

Côté machine, rappel inchangé : Phase V puis Phase D étapes 1-4 (0x15/0x2A, `RMClkVfOverride=1`, `RmVFPointCheckIgnore=1`, protocole vague 3), flash 280 W en cours de session chez le fondateur (ring 36 : ReBAR/BAR1 shrink scellé avant nvflash, vP-state tension chassée). Le ring 36 a scellé la découverte vP-state côté machine ; la vague 4.9 lui offre la jonction cloud (chantier 3). BIOS- reste en pause. Le dépôt GPU- est propre, poussé, et signé.
