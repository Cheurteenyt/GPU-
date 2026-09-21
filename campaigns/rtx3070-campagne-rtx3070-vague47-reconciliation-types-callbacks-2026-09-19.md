# Vague 4.7 — la réconciliation des types, le bras moteur du bit 8, le callback du PMA

**Campagne RTX 3070 — minage cloud de rm.elf (GSP RISC-V, 16 912 384 octets)**
**Date : 2026-09-19 · Auteur du minage : cloud GLM 5.3 Flash · Domaine : X-R 0x1000000-0x1C00000 (5 342 005 instructions, désassemblage linéaire intégral v45)**

---

## §0 — Trois vérités de la vague

**Vérité 1 — le disque a devancé le résumé.** Au rituel d'ouverture, le disque montrait que les vagues 4.5 (`bd0dec5`) et 4.6 (`58a8bad`) étaient déjà soldées, commitées et poussées — le résumé de session les déclarait à venir. Compteur de dérives : ajusté à l'ouverture, puis ZÉRO pour toute la vague. Les deux dépôts sont restés CLEAN en permanence (GPU- et BIOS-, vérifiés au départ et après push).

**Vérité 2 — l'arithmétique d'adresses se vérifie par script, jamais de tête.** La leçon gravée en 4.6 a été appliquée de bout en bout : chaque cible d'appel de cette vague provient du résolveur auipc+jalr (`v47_resolve.py`), pas d'un calcul mental. Deux corrections en découlent directement : la « passe P-states » est `0x1b3c4f0` (le 4.6 écrivait 0x1b3c4f4), et le chemin type 0xf du grand parseur appelle `0x14571b8` (le 4.6 écrivait 0x14561b8). Le disque, via script, a tranché deux fois.

**Vérité 3 — il y a DEUX espaces de nombres « types », et ils ne se mélangent pas.** La question posée au jalon 4.7 (réconciliation N↔type-moteur) est close : les valeurs N vues au constructeur (17 valeurs sur 28 sites) et les types émis par le dispatcher moteur (4 valeurs) appartiennent à deux espaces distincts, prouvés chacun par leur propre site d'usage. La section §1 en donne la mécanique complète.

Instruments persistés et commités cette vague : `v47_explore.py` (déroulé dispatcher + sondes), `v47_explore2.py` (sondes corrigées : offsets hexadécimaux, appariement auipc+jalr), `v47_resolve.py` (résolution systématique des cibles avec contexte a1/a2/a3), `v47_hunt.py` (census global d'appelants + handlers enregistrés), `v47_registr.py` (enregistreurs de callbacks sur l'objet capacité). Cache TSV v45 réutilisé tel quel — aucune recompilation.

---

## §1 — La réconciliation N↔type-moteur : le chercheur 0x1457440 enfin appelé

La vague 4.5 avait frappé un mur : le « chercheur BOARDOBJ » `0x1457440` n'avait **aucun appelant direct** — ni `jal`, ni paire `auipc+jalr` dans tout le segment X-R. La vague 4.7 brise le mur par l'autre bout : ce n'est pas le chercheur qui manque d'appelants, c'est le chemin qui n'était pas le bon. Le dispatcher moteur `0x1634a38` l'appelle **quatre fois en ligne droite**, et le résolveur par script le prouve instruction-exact :

| Site d'appel | Cible | a1 (type) | a0 (objet recherché) | Contexte immédiat |
|---|---|---|---|---|
| `0x1634b5c` | `0x1457440` | **0x10** (16) | `[s2+0x3CD0]` | après le chemin `0x2c7`/flag |
| `0x1634ba4` | `0x1457440` | **0x13** (19) | `[s2+0x3CD0]` | après wipe `0x128/0x130` de `[s1+0x8e000]` |
| `0x1634bd6` | `0x1457440` | **0xc** (12) | `[s2+0x3CD0]` | **sous garde : bit 0 du mot de capacité posé** |
| `0x1634bfc` | `0x1457440` | **0x1d** (29) | `[s2+0x3CD0]` | dernier des quatre, chute commune |

Le `0x1457440` est donc bien ce que la 4.5 avait nommé : le **find-par-type** — il reçoit un pointeur d'objet racine (`a0`) et un sélecteur de type de requête (`a1`), et retourne l'objet correspondant. Les quatre types émis par le dispatcher moteur sont exactement `0xc`, `0x10`, `0x13`, `0x1d` — les quatre valeurs « normales » que les vagues 4.2→4.4 avaient observées côté construction sans pouvoir les relier à leur consommateur.

**La réponse à la question de la 4.6 est donc : les N du constructeur ne sont pas des types de requête.** Les N (0, 2, 4, 6, 7, 8, 12, 15, 16, 17, 22, 27, 28, 29, 30, 31) sont le paramètre taille/identité passé au préparateur `0x18E11F8(buf, 0x40, N)` — ils décrivent le FORMAT de la table chiffrée construite. Les types (0xc, 0xf, 0x10, 0x13, 0x1d) sont les sélecteurs consommés par le chercheur au moment du dispatch. Les deux espaces se croisent dans le code sans jamais se confondre : un site de construction porte un N, un site de consommation porte un type, aucun registre ne transporte l'un vers l'autre. La « réconciliation » est une **preuve de séparation**, pas une table de correspondance.

La garde du type 0xc mérite d'être isolée, car elle referme une boucle ouverte depuis la 4.4 :

```asm
0x1634bb8  ld   a5, 0x130(a5)      ; a5 = [s1+0x88130] — l'objet de capacité
0x1634bbc  beqz a5, +0xf2          ; pas d'objet → pas de requête VF
0x1634bbe  lw   a5, 0x324(a5)      ; LE mot de capacité
0x1634bc2  andi a5, a5, 1          ; bit 0 — le bit VF-point de la 4.4
0x1634bc4  beqz a5, +0xea          ; bit 0 clair → pas de type 0xc
0x1634bd0  li   a1, 0xc            ; TYPE 12 = VF
0x1634bd6  call 0x1457440          ; cherche
```

Le type de requête 0xc n'est émis par le moteur **que si le bit 0 du mot de capacité est posé**. La chaîne de la 4.4 (dial → setter → bit 0 → moteur) a désormais son second maillon de lecture nominatif : le dispatcher consomme le bit 0 au site `0x1634bc2` exactement comme ClkAdc consomme le bit 8 aux siens.

---

## §2 — Le dispatcher 0x1634a38 : carte complète des cibles

Le dispatcher moteur (fonction `0x1634a38`, fenêtre analysée 0x1634a38-0x1635700, 1 061 instructions) compte **65 appels** résolus par script, répartis ainsi :

| Cible | Appels | Rôle prouvé ou attribué | Sites clés |
|---|---|---|---|
| `0x1457440` | 4 | **find-par-type** (§1) | a1 = 0x10/0x13/0xc/0x1d |
| `0x1630c48` | 3 | **le setter de capacité** — SET bit 0 (`a2=0, a3=1`, `0x1634cba`), CLEAR bit 8 (`a2=8`, `0x16355d6`), SET bit 8 (`a2=8, a3=1`, `0x1635662`) | §3 |
| `0x1630b60` | 4 | resolver d'objet associé : lit `[x+0x1D00]`, tail-call via vtable `[obj+0x358]` | `0x1635140…` |
| `0x1a9a3c2` / `0x1b4b55c` | 19 + 12 | couple log (format / écriture) — 31 points de journalisation | partout |
| `0x164abc8` | 1 | appel avec `a2=0x55` (paramètre, pas un bit) | `0x1634b10` |
| `0x1712238` | 1 | `a2=4, a3=1` | `0x1634b3a` |
| `0x18a8e4c` | 2 | dont un `a1=16` | `0x1634b7a, 0x1634b8c` |
| `0x164fc24` | 1 | `a2=5` | `0x1634c5a` |
| `0x18a9844` | 1 | `a2=1, a3=0` | `0x1634ca8` |
| `0x1651f80` / `0x1651e4c` | 1 + 1 | fonctions de la famille du setter (voisinage 0x1651xxx) | `0x1634d0e, 0x1634f74` |
| `0x1a9cc94` | 2 | assert/log | `0x163511a, 0x16354b8` |
| `0x1742964` / `0x1742878` / `0x17424b8` / `0x1745090` | 2+2+2+1 | utilitaires (dont appels avec `a1=0`, `a1=32`) | `0x163522e…` |
| indirects `a5` (vtables) | 6 | dont `a2=2` (`0x1634aa8`, via `[s1+0x1A8]`), `a2=0/1` (via `[s7+0x238]`), un avec `a1=32` | `0x1634c88…` |

Trois constats structurels ressortent. D'abord, le dispatcher **n'a lui-même aucun appelant** ni `jal` ni `auipc+jalr` — il est atteint par pointeur (vtable chiffrée), exactement comme le chercheur en 4.5 : c'est un point d'entrée de seconde main, et cette famille de « zéro appelant direct » est désormais un motif reconnu de l'architecture RM, pas une anomalie de désassemblage. Ensuite, le couple log `0x1a9a3c2`/`0x1b4b55c` totalise 31 appels dans cette seule fonction : le dispatcher est le code le plus bavard de la région perf, ce qui en fait une cible de trace privilégiée côté machine (chaque décision de dispatch laisse une trace texte). Enfin, le dispatcher **arme lui-même le mot de capacité** (SET bit 0, SET/CLEAR bit 8) : il n'est pas seulement consommateur des bits, il est producteur — la carte des 42 sites d'appel du setter de la 4.5 gagne trois sites côté moteur, tous dans 0x1634xxx/0x1635xxx.

Le « bit 11 » observé à la pré-analyse (`0x16354b8`, `a2=11`) est **désamorcé** : le résolveur avec contexte montre qu'il s'agit d'un `c.li a2, 0xb` suivi de `beq a3, a2` (comparaison de type == 11) dont le `a2` a été capturé comme argument résiduel par la fenêtre de contexte. L'appel réel du site est un assert/log vers `0x1a9cc94`. Le census du setter reste donc : bits 0-11 par module, **aucun SET bit 11 depuis le dispatcher**.

---

## §3 — Le bit 8 par le moteur : la synchronisation idempotente

La 4.5 avait établi le bras driver du bit 8 : `RmPerfChangeSeqOverride` (valeur impaire) → `0x1631824` → setter(a2=8, a3=1), armé par ClkAdc, lu par le moteur aux sites `0x1634ff8`/`0x163551a` et par ClkAdc (4 `andi 0x100`). La 4.7 révèle le **second bras**, moteur cette fois, et il est plus structuré que le premier — c'est une synchronisation idempotente complète :

```asm
; — cote demande —
0x16355ae  lbu  a3, 0x18(s3)        ; la VALEUR VOULUE, champ +0x18 de la requête
; — cote etat actuel —
0x16355b2  ld   a5, 0x130(a5)       ; a5 = [s2+0x88130] — objet de capacité
0x16355ba  beqz a5, +0x304          ; pas d'objet → rien à synchroniser
0x16355be  lw   a5, 0x324(a5)       ; LE mot de capacité
0x16355c2  sraiw a5, a5, 8          ; décale le bit 8 en position 0
0x16355c6  andi a5, a5, 1           ; état actuel du bit 8
0x16355c8  beq  a4, a5, +0x1a       ; voulus == actuel → NE RIEN FAIRE
; — delta → mutation —
0x16355cc  li   a2, 8               ; CLEAR bit 8 (a3=0 implicite par chute)
0x16355d6  call 0x1630c48           ; setter
...
0x1635656  li   a3, 1
0x1635658  li   a2, 8               ; SET bit 8
0x1635662  call 0x1630c48           ; setter
```

Le pattern `sraiw 8 ; andi 1` est le **même motif de lecture que ClkAdc** (les 4 `andi 0x100` de la 4.5) — un troisième site consommateur avec l'instruction miroir. La logique est celle d'un assign idempotent : le moteur compare l'état voulu porté par la requête (champ `+0x18`) à l'état actuel porté par le mot de capacité (bit 8), et n'appelle le setter **que sur différence**. Le bit 8 n'est donc plus seulement « armé par le driver » : il est **entretenu par le moteur** comme le reflet fidèle de l'état demandé — deux producteurs (driver via dial, moteur via requête), un seul invariant (bit == valeur demandée).

La même fenêtre livre le contexte de la requête `s3` : `+0x14` (word copié vers `[s7+0x308]`, `0x1635562`), `+0x18` (la valeur du bit 8), `+0x19` (un flag testé à `0x16355e2`), `+0x8`/`+0x10` (passés en `a2` à des appels qui reçoivent `a1=0x20`). Et une **politique par bitmap** : après le flag `+0x19`, un identifiant est normalisé (`addiw -0x20 ; andi 0xff ; bltu 0x30` — l'espace 0x20-0x4F), indexé dans une table de 32 bits chargée par `auipc a4, 0x84e ; ld a4, 0x72e(a4)` puis testé par `srl ; andi 1` (`0x163560a-0x1635618`) : une **liste blanche de 32 IDs de séquences** dont la sémantique exacte (autorisation vs classification) reste ouverte, mais dont l'existence borne le champ d'action du bit 8 aux séquences listées.

**Conséquence machine (renforcement, pas changement)** : le rang 2 de la carte des leviers (`RmPerfChangeSeqOverride`) est consolidé. Le dial n'écrit pas seulement le bit une fois : il déclenche un invariant que le moteur ré-entretient à chaque passage du dispatcher. Un pokesur le dial resterait le seul point d'entrée sûr ; un poke direct du bit 8 dans le mot de capacité serait **réécrit ou corrigé** par la synchronisation moteur au prochain passage — raison de plus pour ne jamais toucher le mot directement.

---

## §4 — Le callback [s1+0x288] : mécanique complète, nom honnêtement non résolu

Le jalon 4.7 demandait le déroulé du callback `[s1+0x288]` déclenché par `PerfPmaControlReg==1`. La mécanique est désormais close instruction-exact, et le nom du handler est, en toute honnêteté, **non résolu** — avec la preuve de pourquoi.

La séquence complète au point final du grand parseur (`0x16326e0-0x1632746`) :

```asm
0x1632714  call 0x10432d4           ; lookup dial "PerfPmaControlReg" (a1=string)
0x163271c  sext.w a5, a0
0x1632720  bnez a5, +0x18           ; dial ABSENT (retour 0 ?) → chemin type 0xf
0x1632722  lw   a4, -0x1e4(s0)      ; valeur (frame s0)
0x1632726  li   a5, 1
0x1632728  bne  a4, a5, +0x10       ; valeur != 1 → chemin type 0xf
0x163272c  ld   a5, 0x288(s1)       ; LE CALLBACK
0x1632730  li   a2, 1               ; arg = 1
0x1632732  mv   a1, s1              ; état RM
0x1632734  mv   a0, s2              ; état dispatch
0x1632736  jalr a5                  ; APPEL — sans garde nulle
0x1632738  (chemin alternatif)      ; a0 = [s2+0x3CD0], a1 = 0xf
0x1632742  call 0x14571b8           ; chercheur-jumeau, type 0xf
```

Trois faits nouveaux par rapport à la 4.6. **Premier** : il y a DEUX sorties vers le chemin alternatif — dial absent OU valeur ≠ 1 — la 4.6 n'en voyait qu'une. **Deuxième** : l'appel du callback n'a **aucune garde nulle** sur `a5` : le champ `+0x288` de l'état RM est donc garanti initialisé par l'architecture avant tout passage ici — un contrat implicite fort. **Troisième** : le chemin alternatif appelle `0x14571b8` (corrigé par script depuis le 0x14561b8 du 4.6), fonction jumelle du chercheur `0x1457440`, avec le type **0xf** : le type 0xf n'est pas un « type de requête normal » émis au hasard, c'est le **type de repli du PMA** — ce que le moteur demande quand le dial PmaControl ne pilote pas la séquence.

L'enregistreur nominatif, lui, résiste — et la résistance est informative. Le scan global des stores liés à `+0x288` donne 243 enregistrements vers 99 cibles distinctes : le champ `+0x288` est un offset générique que des dizaines de structures partagent. Les deux familles dominantes (`0x1915574` ×18, `0x193cc44` ×17) sont des régions de construction de vtables en masse, pas des attributions singulières. Les candidats de la région d'init RM (`0x115665e`, `0x115996c`…) se révèlent être des **copieurs champ-par-champ** : des rafales de `sd` lisant chaque champ depuis une structure source (`0x1F0, 0x1D0, 0x1F8, 0x240, 0x288, 0x200…`) — le pointeur du callback PMA **transite par clone**, sans constante `auipc+addi` nommable sur son chemin. Sans rodata déchiffrée ni suivi complet de l'objet-source, l'attribution nominative s'arrête ici. Ce qui reste prouvé : la signature d'appel `(dispatch_state, rm_state, 1)`, la garantie d'initialisation, la condition d'invocation exacte, et le chemin de repli 0xf.

---

## §5 — La boucle P-states : adresse corrigée, 52 appelants, entrée = mode 7

**Correction d'adresse** : la passe appelée par la boucle du bit 9 est `0x1b3c4f0`, pas `0x1b3c4f4` (résolution par script des deux sites ; le 4.6 portait une adresse décalée de 4 octets, sans conséquence sur ses conclusions).

La boucle elle-même est **un bloc interne du grand parseur**, pas une fonction : la région `0x1631860-0x1631a80` (fenêtre W1 de la 4.6) vit à l'intérieur de la fonction unique `0x1631300-0x1632790`. Ses « branches d'entrée » sont donc des chemins internes du parseur, et l'analyse les résout ainsi :

- **La double passe confirmée** : `0x1631982` appelle `0x1b3c4f0` avec `a1=0x40` (64), puis `0x16319ca` avec `a1=8` — la passe 0x40 d'abord (revalidation large), la passe 8 ensuite (revalidation étroite), suivi des callbacks indirects `a5` en paires (`0x16319a0/0x16319ac` puis `0x16319e8/0x16319f6`), puis le SET bit 9 (`0x1631a50`, `a2=9, a3=1`) comme état de SORTIE. Le li `a5, 1` à `0x16319b0` entre les deux passes marque la bascule de phase.
- **La porte d'entrée de tout ce bloc est le chemin du mode 7** : dans `funcs.json`, la fonction grand parseur montre la séquence `0x16314d6` (constructeur `0x1456c7c` avec N=7) → région `0x1631500+` → **une PREMIÈRE double passe** `0x1b3c4f0` aux sites `0x1631568` (avec `a1=16`) et `0x16315b8` → bloc de logs `0x1631600-0x1631930` → la boucle du bit 9. Le mode 7 du grand parseur est donc le client qui arme la chaîne complète : ctor(N=7) → passe(a1=16) ×2 → [logs] → passe(0x40) → passe(8) → SET bit 9.
- **L'utilitaire `0x1b3c4f0` n'est pas une « passe P-states »** : le census global par script compte **52 appelants auipc+jalr** dans tout le segment X-R (de `0x10da2da` à `0x1bd4230`, répartition complète dans `v47_C_callers_1b3c4f0.txt`… `v47_hunt.py` stdout). C'est un **utilitaire générique de revalidation** — la boucle P-states n'est qu'un client parmi 52, aux côtés du petit parseur (sites `0x1631568`/`0x16315b8`), du grand parseur (`0x16325d6`, avec `a1=16`), et de clusters entiers (`0x16378e6-0x16383b4`, `0x1767796-0x1767886` à six sites consécutifs). Le nom « passe P-states » portait une hypothèse d'exclusivité que le disque ne confirme pas ; le renommage est enregistré.

---

## §6 — L'objet capacité se révèle : auto-enregistrement et port de callbacks

La chasse aux enregistreurs de callbacks a produit un recadrage structurel inattendu. Le callback du petit parseur (`0x169455c`, vu en 4.5 comme « callback à [état+0x460] ») est enregistré au site `0x16312b0` — et le contexte montre **qui** est l'objet porteur :

```asm
0x1631296  lui  a5, 0x88
0x163129a  add  a5, a5, s1        ; a5 = s1 + 0x88000
0x163129c  ld   a5, 0x130(a5)     ; a5 = [s1+0x88130] — L'OBJET DE CAPACITÉ
0x16312a0  li   a4, 4
0x16312a2  mv   a0, s1
0x16312a4  sb   a4, 0(a5)         ; [cap+0] = 4  (mode/état)
0x16312a8  auipc a4, 0x63
0x16312ac  addi a4, a4, 0x2b4     ; a4 = 0x169455c  (résolu par script)
0x16312b0  sd   a4, 0x460(a5)     ; [cap+0x460] = 0x169455c
```

Trois conclusions. **Un** : l'objet pointé par `[état+0x88130]` — le même que le dispatcher lit à `0x1634bb8` pour atteindre `+0x324` — est un **objet BOARDOBJ à part entière** qui porte son propre octet de mode (`+0`), son mot de capacité (`+0x324`) et ses callbacks (`+0x460`…). **Deux** : le petit parseur **s'auto-enregistre** — il écrit lui-même son callback et son mode dans l'objet capacité au moment du parse, ce qui explique pourquoi la 4.5 voyait le callback « à [état+0x460] » : l'état du petit parseur et l'objet capacité se recouvrent via `+0x88130`. **Trois** : la construction de l'objet capacité est **incrémentale** — le mode 4 écrit `+0`, le callback écrit `+0x460`, et rien n'indique un constructeur unique qui poserait tout d'un bloc.

Pour le callback PMA `+0x288` (§4), la même méthode donne une réponse négative mais propre : **aucune** fonction n'écrit à la fois `+0x460` et `+0x288` sur une base commune (croisement des 74 × 243 enregistrements liés : intersection vide, hors un outlier en région chiffrée `0x4162008`). Le callback PMA n'appartient pas au port de l'objet capacité — il vit sur l'état RM du grand parseur, rempli par clone. Les deux mécanismes (self-registration pour `+0x460`, clone pour `+0x288`) coexistent dans la même architecture, et la distinction est désormais prouvée des deux côtés.

---

## §7 — Carte des leviers (mise à jour machine)

**Aucun changement de rang, deux consolidations.**

| Rang | Levier | État après la 4.7 |
|---|---|---|
| 1 | `RmVFPointCheckIgnore` | inchangé — protocole Phase D 1-4 intact |
| 2 | `RmPerfChangeSeqOverride` | **consolidé** : le moteur entretient le bit 8 par sync idempotente (§3) — poke du dial = seul point d'entrée sûr, poke du bit = serait corrigé |
| 3 | `PerfPmaControlReg=1` (observation seule) | **mécanique close** (§4) : callback sans garde nulle + repli type 0xf — le callback restant inconnu, l'observation seule reste de mise |

La doctrine de sûreté (vague 3) ne change pas : rien de cette vague n'ouvre de nouveau levier machine, tout renforce la connaissance de ceux déjà cartographiés. Le type 0xf de repli (§4) et la liste blanche 0x20-0x4F (§3) sont des garde-fous de plus qu'il faut connaître avant la Phase D, pas des portes.

---

## §8 — Registre d'honnêteté

1. **Bit 11 désamorcé** : le `a2=11` du site `0x16354b8` était un artefact de fenêtre de contexte (`c.li a2, 0xb ; beq` de comparaison). Aucun SET bit 11 depuis le dispatcher. Le census 4.5 (bit 11 : 2 sites) reste valable — les sites sont ailleurs, non relocalisés cette vague.
2. **Callback PMA non nommé** : la mécanique d'invocation est complète, l'attribution nominative du handler est bloquée par les copieurs champ-par-champ (§4). Point reporté au jalon 4.8 avec la méthode proposée (suivi du clone-source).
3. **Deux corrections d'adresse vs 4.6** : `0x1b3c4f0` (passe, était 0x1b3c4f4) et `0x14571b8` (repli 0xf, était 0x14561b8). Les deux par script. Les conclusions de la 4.6 ne sont pas affectées.
4. **`lw [s0-0x1e4]` du §4** : la provenance exacte de cette valeur (valeur du dial lue plus tôt, ou autre champ) n'est pas tracée jusqu'à son écriture ; le test `==1` est prouvé, la sémantique du champ reste à confirmer.
5. **Liste blanche 0x20-0x4F** : la table bitmap est localisée (`auipc 0x84e ; ld 0x72e`), sa sémantique (autorisation ? classification ?) est ouverte.
6. **L'utilitaire 0x1b3c4f0** : renommé « revalidation générique » (52 appelants) ; sa décomposition interne (ce que fait une passe selon a1) n'est pas déroulée.
7. **Le dispatcher sans appelant** : atteint par pointeur (vtable chiffrée), l'origine du pointeur n'est pas résolue — même statut que le chercheur en 4.5, motif architectural assumé.

---

## §9 — Jalon 4.8 proposé

Trois chantiers, dans l'ordre de valeur machine :

1. **Suivre le clone-source du callback PMA** (`+0x288`) : partir des copieurs `0x1156xxx`/`0x1159xxx`, remonter la structure-source, et nommer le handler — l'objectif nominaliste que la 4.7 a laissé ouvert.
2. **Dérouler l'utilitaire de revalidation `0x1b3c4f0`** : ce que fait une passe selon `a1` (0x8/0x10/0x40 ont été vus ; les 52 appelants en utilisent d'autres) — la grammaire complète des passes.
3. **La liste blanche 0x20-0x4F** : lire la table bitmap (`auipc 0x84e`), croiser avec les IDs de séquences vus en 4.5/4.6, et décider si elle borne `RmPerfChangeSeqOverride` — c'est la question de sûreté la plus directe avant la Phase D.

Côté machine, rappel inchangé : Phase V puis Phase D étapes 1-4 (0x15/0x2A, `RMClkVfOverride=1`, `RmVFPointCheckIgnore=1`, protocole vague 3), flash 280 W demain dans une autre session. BIOS- reste en pause. Le dépôt GPU- est propre, poussé, et signé.
