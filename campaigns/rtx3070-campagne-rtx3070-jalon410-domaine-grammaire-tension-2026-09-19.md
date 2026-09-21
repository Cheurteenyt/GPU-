# Campagne RTX 3070 — jalon 4.10 : la remontée du domaine, les six registres, la grammaire tension

**Date : 2026-09-19 — session cloud, GLM 5.3 Flash — jalon 4.10 posé par Task 73 §6, signal fondateur : « Allons y jalon 4.10 ».**

Rituel d'ouverture : GPU- `790cb88` CLEAN (vague 4.9 poussée), BIOS- `ac68d3c` CLEAN (inchangé, en pause). Cache TSV v45 intact (5 342 005 instructions, 130 Mo). Dérive de jalon : ZÉRO. Instruments v50 persistés : `v50_wrapper`, `v50_domain`, `v50_reader`, `v50_ptr`, `v50_ptr2`, `v50_window`, `v50_slot28`, `v50_holder`, `v50_holder2`, `v50_jtscan`, `v50_micro`, `v50_semantics` (12 instruments).

---

## §0 — Trois vérités

1. **La page `0x68Axxx` contient SIX registres frères exploités, pas deux.** La 4.9 avait fermé la chaîne sur `+0x00C`/`+0x01C`. Le déroulé complet du wrapper `0x12b5c88` (74 instructions, jamais fait avant) montre qu'APRÈS l'appel du consommateur il enchaîne quatre lectures vtable de plus : `+0x008`, `+0x030`, `+0x368`, `+0x36C` — et le pré-wrapper en extrait une cinquième tranche de `+0x030`. La grammaire tension est plus large que la carte de la 4.9.
2. **La classe des domaines est nommée par son constructeur.** Le pré-wrapper `0x12c7a1e` a zéro appelant direct, zéro pointeur statique, zéro formation d'adresse classique — MAIS son vrai point d'entrée est un trampoline à `0x12c7a1c` (test `a3` intégré), et c'est CETTE adresse que le méga-constructeur `0x192xxxx` pose dans une vtable plate runtime, slot `[obj+0x928]`, entre deux autres méthodes du module. La chaîne est construite au runtime, pas orpheline : six mécanismes de référence négatifs, le septième positif et exact.
3. **L'espace de noms des domaines existe au fichier : sept noms, indexés 0..6.** `DRAMCLK, LTCCLK, XBARCLK, HUBCLK, SYSCLK, AWP, RRRB` (rodata `0x1e05fc0-0x1e05ff0`), construits en table runtime par le moteur de timings `0x136ecb4` (seule fonction qui les cite). Les 28 identités JT1 restent la grammaire des états PAR domaine — l'attribution nominative individuelle de chaque identité tranchera par la lecture live (§4).

## §1 — Chantier 1 : la remontée du domaine, fermée par la vtable runtime

### 1.1 Le wrapper complet — cinq lectures vtable, pas une

Déroulé intégral `0x12b5c88-0x12b5d4a` (74 insns, `v50_wrapper`/`v50_domain`) :

```asm
0x12b5c9e  c.beqz   a3, +0x10        ; la garde 4.9 confirmée
0x12b5ca6  auipc/jalr → 0x1bd979c    ; l'appel du consommateur (args translatés)
; --- puis, SANS branchement, quatre lectures vtable de plus ---
0x12b5cb2  ld   a5, -0x510(s1)       ; holder = [s1-0x510], s1 = a1+0x4000
0x12b5cb8  c.ld a0, 0x50(a5)         ; obj = [holder+0x50]
0x12b5cbe  lui  s4, 0x68a            ; s4 = 0x68A000
0x12b5cc4  addiw a1, s4, 8           ; +0x008 + (index<<10)  [s2 = a2<<10]
0x12b5ccc  c.ld a5, 0x28(a5→vtbl) ; c.jalr  ; bit 3 → sw [out+0x44]
0x12b5ce2  addiw a1, s4, 0x30        ; +0x030  ; bit 16 (sraiw 0x10) → sb [out+0xb5]
0x12b5d02  addiw a1, s4, 0x368       ; +0x368  ; SWAP des deux demi-mots → sw [out+0xe8]
0x12b5d2a  addiw a1, s4, 0x36c       ; +0x36C  ; 16 bits bruts → sh [out+0xec]
```

Le swap de `+0x368` est exact : `srliw a5, a0, 0x10 ; slli a0, a0, 0x30 ; slliw a5, a5, 0x10 ; srli a0, a0, 0x30 ; or` — les 16 bits bas deviennent hauts et réciproquement. C'est un codeur de format (type `1b1w2b2d` de la table timing ring 33 ?), pas une extraction de champ.

### 1.2 Le pré-wrapper et son trampoline

`0x12c7a1e-0x12c7a72` (33 insns) : sauvegarde `s1=a1, s2=a3, s3=a2`, appelle le wrapper tel quel, puis **cinquième extraction** : lit `+0x030+(idx<<10)` via la même vtable `+0x28`, fait `srliw a0, a0, 0x11` (bits 17 et au-dessus) et stocke le mot à `[out+0xb0]` — le bit 16 (du même registre) est extrait séparément par le wrapper vers `[out+0xb5]` : **les deux fonctions partagent le registre `+0x030` avec deux découpes différentes**.

Le point d'entrée réel (correction de la 4.9) :

```asm
0x12c7a14  c.jr     ra               ; fin de la fonction précédente
0x12c7a16  ld       a5, 0(zero)      ; barrière anti-exécution
0x12c7a1a  c.ebreak                  ; (trap au fallthrough)
0x12c7a1c  c.beqz   a3, +0x58        ; TRAMPOLINE : a3 nul → sortie 0x12c7a76
0x12c7a1e  c.addi16sp sp, -0x30      ; prologue (l'adresse qu'on croyait d'entrée)
```

Le pointeur posé dans la vtable est `0x12c7a1c` — l'adresse exacte de l'entrée, pas un tag. La garde `a3 != 0` du wrapper (`c.beqz a3, +0x10`) et le trampoline font le même test : le `a3` (4e argument) est la condition de validité de la requête à tous les étages.

### 1.3 Les six négatifs et le septième positif

Pour (pré-wrapper, wrapper, consommateur), recherche exhaustive de références :

| # | mécanisme | résultat |
|---|---|---|
| 1 | pointeur statique qword dans rm.elf (scan intégral, aligné 8) | 0 |
| 2 | formation auipc+addi → store (154 567 paires indexées) | 0 |
| 3 | formation lui+addi/addiw → store | 0 |
| 4 | jump-table rodata base+off (scan intégral 32 bits signés) | 0 |
| 5 | relocations ELF | aucune (ELF EXEC, 3 phdrs, pas de .rela) |
| 6 | micro-fenêtres ±0x80 (toute VA, pas seulement les prologues) | **1 : `0x12c7a1c` @ `0x1922358`** |
| 7 | appel direct jal/call | pré-wrapper 0 ; wrapper 1 (`0x12c7a32`) ; consommateur 1 (`0x12b5ca6`) |

Le septième mécanisme est le bon : le méga-constructeur (fonction > 8 000 insns contenant `0x1922358`, même famille que `0x1928b44` de la cartographie de fenêtre) forme `t3 = 0x12c7a1c` puis saute à `0x191f2a4` où il le stocke :

```asm
0x191f2a4  sd t4, -0x6e0(a1)   ; a1 = a0+0x1000  → [obj+0x920] = 0x12c79bc
0x191f2a8  sd t3, -0x6d8(a1)   → [obj+0x928] = 0x12c7a1c  (le pré-wrapper)
0x191f2ac  sd a7, -0x6d0(a1)   → [obj+0x930] = 0x1914594
; ... rangée de slots pas de 8 : -0x6c8 → 0x127d2f4, -0x6c0 → 0x19145ac,
;     -0x6b8 → 0x128e5a8, ... (toutes des entrées de fonctions vérifiées)
```

**La vtable plate runtime des domaines existe et le pré-wrapper en est la méthode slot `+0x8`.** Les méthodes voisines (`0x12c79bc` : même motif trampoline `c.beqz a3, 0x58` ; `0x127d2f4` : frame 0x70 ; `0x1914594`/`0x19145ac` : frames 0x10 compactes ; `0x128e5a8` : frame 0x40) forment l'interface d'une classe du module 0x12b5xxx-0x12c7xxx. La cartographie `v50_window` recense **351 formations d'adresses vers 30+ fonctions de cette fenêtre**, posées par sept méga-constructeurs `0x1928b44/0x1949cb4/0x1964a90/0x1973924/0x19751c0/0x197a2ac/0x1980e94` à des offsets fixes de structures `s1` (0x70..0x328) : le module entier est une famille de classes LTO, instanciée au runtime.

### 1.4 Ce qui reste ouvert (honnêteté)

- Le **lecteur** du slot vtable `+0x28` (l'accès matériel `0x68Axxx` proprement dit) : l'objet `[holder+0x50]` appartient à une classe dont la vtable `[obj+0]` n'est pas statique ; le contrat `(obj, offset_registre) → mot` est prouvé, l'implémentation concrète est par-classe runtime. Le census des appels via `+0x28` (3 090 sites) montre que c'est un slot générique du framework BOARDOBJ — le census seul ne nomme pas l'implémentation.
- L'écrivain du holder `[état+0x3AF0]` : zéro store `0x3af0` dans les méga-constructeurs `0x19xxxxx` ; le champ est écrit par un autre étage (probablement le constructeur de l'état RM, module non balayé).
- La fonction porteuse du méga-constructeur (`0x192xxxx`, > 8 000 insns) n'a pas de dénomination de début (prologue hors fenêtre de marche arrière 8 000) — le constructeur est identifié par son site, pas par son adresse d'entrée.

## §2 — Chantier 2 : la carte champ→sémantique

### 2.1 Les sept domaines, indexés 0..6

`0x1e05fc0-0x1e05ff0` (rodata file-backed, alignées 8) :

| index | nom | note |
|---|---|---|
| 0 | `DRAMCLK` | mémoire |
| 1 | `LTCCLK` | L2 |
| 2 | `XBARCLK` | interconnect |
| 3 | `HUBCLK` | hub |
| 4 | `SYSCLK` | système |
| 5 | `AWP` | domaine spécialisé (extension) |
| 6 | `RRRB` | domaine spécialisé (extension) |

La table runtime est construite par **`0x136ecb4`** (seule fonction du firmware qui forme ces adresses — `v50_semantics`/census ciblé) : sept `auipc+addi` vers les strings, sept `sd` à `0x08·k` d'un buffer `s5`, puis `ld a5, 0x400(s6) ; c.jalr a5` — l'appel d'un slot de méthode `+0x400` avec la table des noms en argument. La fonction est un **moteur de calcul de timings par domaine** : constante `0xE8D7A51 × 0x1000 = 999 448 120 832 ≈ 1e12`, divisions `divu` par les fréquences, multiplications `mul` — des conversions en **picosecondes** (latences par domaine), protégées par le canari d'intégrité vu au ring 39 (`xor` contre la valeur stockée en frame).

### 2.2 Le lexique tension/VMIN au fichier

Zone `0x1e78xxx` (census `v50_semantics`) — le vocabulaire complet des rails :

- **VMIN** : `VMIN_LOGIC`, `VMIN_SRAM`, `VMIN_NVVDD_0/1`, `VMIN_MSVDD_0/1` — croisement direct avec la table 7 entrées du ring 38-39 du fondateur.
- **OVERVOLTAGE** : `OVERVOLTAGE_LOGIC`, `OVERVOLTAGE_SRAM`, `OVERVOLTAGE_NVVDD(_0/_1)`, `OVERVOLTAGE_MSVDD(_0/_1)`.
- **RELIABILITY** : `RELIABILITY_NVVDD_0/1`, `RELIABILITY_MSVDD_0/1`, `RELIABILITY_ALT_NVVDD_0/1`, `RELIABILITY_ALT_MSVDD_0/1`.
- **Thermique/perf** : `THERM_POLICY_DOM_GRP_0/1`, `THERM_POLICY_NVVDD`, `THERM_POLICY_{DRAM,GPC,XBAR}_{LOW,DUMMY}`, `PMU_DOM_GRP_0/1`, `SLI_DOM_GRP_0_MIN`, `GPU_STATE_LOAD_BOOST_DOM_GRP_0/1`, `EXT_PERF_CONTROL`, `PERF_DAEMON`, `PERF_CF`.
- **Contrôleurs de fréquence** : `PERF_CF_CONTROLLER_{DRAM,GPC,NVD}_{MIN,MAX}`, `PERF_CF_CONTROLLER_XBAR_MAX` — les quatre familles de domaines sous contrôle de fréquence.
- **Rails** : `UNLOAD_DRIVER_VOLTAGE_RAIL_0..3`, `PWR_RAIL_MISMATCH`, `SEC_FAULT: _GPMVDD_VMON`, `SEC_FAULT: _GPCVDD_VMON`.

### 2.3 La carte des registres `0x68Axxx` par domaine (état 4.10)

| registre | champ | extraction | destination out | lu par |
|---|---|---|---|---|
| `+0x008` | bit 3 | `srliw 3 ; andi 1` | `[out+0x44]` (word) | wrapper |
| `+0x00C` | bit 31 / `[30:0]` | (4.9) | `[out+0xc]` / `[out+0x0]` | consommateur |
| `+0x01C` | `[1:0]`, `[8:4]`→JT1, `[11:10]`, `[20:16]`→JT1, `[23:22]` | (4.9) | `[out+0x24..0x38]` | consommateur |
| `+0x030` | bit 16 | `sraiw 0x10 ; andi 1` | `[out+0xb5]` (byte) | wrapper |
| `+0x030` | bits 17+ | `srliw 0x11` | `[out+0xb0]` (word) | pré-wrapper |
| `+0x368` | mot 32 bits | swap demi-mots | `[out+0xe8]` (word) | wrapper |
| `+0x36C` | `[15:0]` | brut | `[out+0xec]` (short) | wrapper |

Adressage : `0x68A000 + (index<<10) + off`, index = domaine (0..6, §2.1). Les 28 identités JT1 (`0..0x11`, extensions `0x1e/0x1f`, répétition `0x1c`) restent l'espace de noms fermé des états PAR domaine ; la lecture live nommera les identités par leurs valeurs réelles.

## §3 — Corrections aux vagues antérieures

1. **4.9, §3.4** : le wrapper n'est pas un simple traducteur d'arguments — c'est le cinquième consommateur de la page `0x68Axxx` (quatre registres frères de plus après l'appel du consommateur).
2. **4.9, §3.4/§5** : le pré-wrapper `0x12c7a1e` est renommé **`0x12c7a1c`** (point d'entrée réel = trampoline ; l'ancienne adresse est l'instruction suivant la garde).
3. **4.9, §5.5** : « l'implémentation concrète dépend de la classe d'objet runtime » reste vrai pour le lecteur, MAIS la classe porteuse de la chaîne (côté appelant) est maintenant nommée par son constructeur (§1.3) — la remontée demandée par le §6 de la 4.9 est faite jusqu'à la couche de construction.

## §4 — Jalon 4.11 proposé (côté code) + protocole live (jonction fondateur)

1. **Le constructeur du holder** : remonter l'écrivain de `[état+0x3AF0]` (hors `0x19xxxxx` — balayer les autres modules d'init RM), et l'objet `[holder+0x50]` : trouver le store qui pose ce pointeur — la classe du lecteur `+0x28` se nommera par son constructeur, comme le pré-wrapper (§1.3).
2. **Le moteur 0x136ecb4 en aval** : dérouler le slot `+0x400` qu'il appelle avec la table des noms — le consommateur des timings picoseconde par domaine (croisement VF point ring 37 : ancre 987 mV @ 1770).
3. **Les 28 identités JT1 face aux 7 domaines** : le champ `[8:4]` et `[20:16]` du registre `+0x01C` par domaine encodent des identités de la grammaire ; croiser avec `PERF_CF_CONTROLLER_*` (§2.2) pour poser au moins les identités min/max.
4. **Côté machine (fondateur)** — protocole de lecture live, par domaine (index 0..6), pendant montée de charge :
   - lire `0x68A008 / 0x68A00C / 0x68A01C / 0x68A030 / 0x68A368 / 0x68A36C` (chaque adresse = `0x68A000 + (index<<10) + off`) ;
   - extraire : bit 3 (+0x008) ; bit 31 et `[30:0]` (+0x00C) ; `[1:0]/[8:4]/[11:10]/[20:16]/[23:22]` (+0x01C) ; bit 16 et bits 17+ (+0x030) ; mot swappé (+0x368) ; 16 bits bas (+0x36C) ;
   - croiser avec l'ancre 987 mV @ 1770 MHz : les champs `[8:4]`/`[20:16]` vivants nommeront la grammaire tension par la pratique — chaque identité JT1 observée reçoit son nom réel (Vmin ? Vf point ? rail ?).

## §5 — Registre d'honnêteté

1. **L'implémentation du lecteur `+0x28` reste non nommée** : le slot est générique au framework (3 090 appels), la vtable de l'objet `[holder+0x50]` est runtime ; seul le contrat est prouvé. La classe de la chaîne appelante, elle, est nommée par son constructeur.
2. **L'écrivain du holder `[+0x3AF0]` n'est pas trouvé** (0 store `0x3af0` dans `0x19xxxxx`) — l'objet porteur du holder est créé ailleurs ; frontière honnête.
3. **Les 28 identités JT1 ne sont pas nommées individuellement** : 7 domaines ≠ 28 identités ; l'attribution est renvoyée à la lecture live (le code seul ne la porte pas, ou alors dans des structures chiffrées).
4. **`AWP`/`RRRB`** : noms de domaines de la table, sémantique non développée (pas de strings voisines exploitables) — honorés comme inconnus.
5. **Le méga-constructeur `0x192xxxx` est identifié par son site** (`0x1922358`/`0x191f2a4`), pas par son adresse d'entrée (prologue hors portée de marche arrière 8 000 insns).
6. **Arithmétique par script** : toutes les cibles de la vague (auipc, sauts de trampolines, VA de vtables, conversions fichier↔VA) vérifiées par les instruments v50 — leçon Task 70 appliquée.
7. **BIOS- reste en pause** (`ac68d3c`, CLEAN) — aucune opération.

---

*Dépôt GPU- propre, poussé, signé « cloud GLM 5.3 Flash ». BIOS- inchangé.*
