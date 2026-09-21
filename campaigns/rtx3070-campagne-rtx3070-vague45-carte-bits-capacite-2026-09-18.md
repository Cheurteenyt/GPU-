# CAMPAGNE RTX 3070 — Vague 4.5 : LA CARTE DES BITS DE CAPACITÉ
## 42 appelants du setter, bits 0-11 attribués module par module, le bit 8 nominatif
**Task 69 · session cloud du 18/09/2026 · Super Z (GLM 5.3 Flash) · pour le chat machine de Cheurteenyt**

> Directive fondatrice (verbatim) : « nous on veut que tu aille beaucoup plus loin analyse
> du code grande investigations pour trouvé des améliorations tu dois recherche de la
> complexité et regardé les calculs qu'il y a tu doit vraiment aller très loin. »
> Signal du jour : « Allons y précise bien dans le commit que c'est cloud glm 5.3 flash
> et le repo doit toujours être clean. »

Le jalon posé par la vague 4.4 est soldé : « attribuer le bit 8 nominativement (xref des
handlers Speedo/Iddq/Vmin/Isense → même objet d'état ?), enum des types de requête ».
Cette session change de méthode — et la méthode change tout : plus de scans ponctuels,
**le rm.elf entier est désassemblé en linéaire** (5 342 005 instructions, capstone 5.0.7,
7 secondes de calcul), ce qui transforme des questions de xref en lectures de flot.

---

## 0. Les trois vérités nouvelles

**V1 — Le setter a 42 appelants directs, et le premier census les avait tous manqués.**
La vague 4.4 concluait « aucune référence matérielle à la fonction, joignable uniquement
par vtable du rodata chiffré » — vrai pour `jal`, mais faux en général : le RM appelle
`requestCapabilityChange` (0x1630c48) par paires **auipc+jalr** (adresse formée en
registre), invisibles au scan de jal. Le census complet (v45_callers2) trouve **42 sites
directs couvrant les bits 0 à 11**, dont 8 pour le bit 8. La leçon de méthode est
enregistrée : dans ce binaire, un « zéro référence » doit toujours être ré-énoncé par
cible formée, pas par mnémonique d'appel.

**V2 — Le bit 8 a un nom : RmPerfChangeSeqOverride.** La branche est explicite dans le
petit parseur : lookup du dial (0x1631382 → helper 0x10432d4), test `andi 1` sur la
valeur renvoyée, puis `bnez → 0x1631824` qui pose `a2=8, a3=1` et appelle le setter.
Le bit 8 est donc la capacité « second check désactivé » que le moteur teste
(0x1634ff8, propagation `sraiw 8` vers [req+0x18]) et que le module ClkAdc arme
symétriquement (SET si absent à 0x114c9b6/0x114e55c, CLEAR au démontage à
0x114cb32/0x114e626/0x114e71c).

**V3 — Six des huit dials CheckIgnore ne passent PAS par le mot de capacité.** Le jalon
4.4 supposait une famille unie (« même objet d'état ? »). La réponse est **non**, avec
preuve par absence : les régions des dials RMDevidCheckIgnore, RMHwSpeedoCheckIgnore,
RmPmgrIddqCheckIgnore, RmPmgrIsenseCheckIgnore et RmSramVminCheckIgnore (0x144d-0x145d,
0x16ae-0x16af, 0x1b17) ne contiennent **aucun** des 42 appelants du setter. Leur
consommation passe par le lookup de nom générique 0x10432d4 au site de check — la valeur
du dial décide du saut localement, point. Seuls RmVFPointCheckIgnore (bit 0) et la
chaîne ClkAdc/PerfChangeSeq (bit 8) écrivent l'objet d'état +0x324/+0x328.

---

## 1. La méthode (et pourquoi elle tient)

Le désassemblage linéaire intégral (v45_build_text) balaye le segment X-R
[VA 0x1000000, 0x1E85000[ = 15,3 Mo → **5 342 005 instructions** en TSV (136 Mo,
cache scratch-gsp/v45/text.tsv). Le sweep est aligné sur les adresses paires (RVC),
les zones rodata produisent du bruit filtrable par mnémonique — bénin pour nos
requêtes (cibles d'appel, immédiats de test, formations d'adresses). Huit instruments
persistés dans `tools/gsp-extract/` : v45_build_text, v45_callers (jal, négatif —
gardé comme garde), v45_callers2 (auipc+jalr, le bon), v45_xref (formations
auipc+addi et lui+addi des 8 strings CheckIgnore + carte du parseur), v45_bits
(census andi/shift près des accès +0x324/+0x328), v45_probe (18 sites strings),
v45_func (délimitation fonctionnelle), v45_focus (dump de fenêtre).

Les résolutions d'arguments (a0-a3) se font par marche arrière ≤ 80 instructions avec
suivi de registres concrets (li/c.li/addi/c.addi/mv/c.mv, base x0). Les registres
chargés depuis la pile restent « None » — honnête : on publie le bit, la direction et
la région, jamais une attribution non prouvée.

## 2. La carte des bits de capacité (l'objet d'état +0x324)

Census complet des 42 appelants directs du setter, par bit demandé (a2) et direction
(a3 : 1 = SET, 0 = CLEAR) :

| Bit | Sites | Région(s) | Lecture d'attribution |
|-----|-------|-----------|------------------------|
| **0** | 8 | parseur VF (0x1631366), moteur (0x1634cb6), 0x1242/0x146b/0x146c/0x1b8d/0x1bd3 | **RmVFPointCheckIgnore** (preuve moteur vague 4.4 + bloc SET après invalidation 8 entrées) |
| **1** | 5 | parseur VF (0x1631310), moteur (0x1634730/0x16347bc), 0x1690826, 0x1b9e3dc | bit-compagnon de séquence, posé DANS le même bloc que bit 0 (voir §3) |
| **2** | 2 | 0x1258800/0x1258880 (SET/CLEAR appariés) | région 0x1258 — non nommé |
| **3** | 2 | 0x11e4574/0x11e45e6 (SET/CLEAR appariés) | région 0x11e4 — non nommé |
| **4** | 3 | 0x114d062, 0x1323f26, 0x134d8b2 | région ClkAdc étendue + 0x132-0x134 |
| **6** | 2 | 0x10810ee/0x108123a (SET/CLEAR appariés) | région 0x1081 — non nommé |
| **7** | 6 | 0x10da73c-0x10df70a (3 couples SET/CLEAR) | région du décodeur de champs 0x10ae-0x10df |
| **8** | 8 | parseur perf (0x163182c), ClkAdc (0x114c9b6 SET, 0x114cb32 CLEAR, 0x114e55c SET, 0x114e626/0x114e71c CLEAR), moteur (0x16355d2/0x163565e) | **RmPerfChangeSeqOverride** (branche prouvée §4) |
| **9** | 3 | parseur perf (0x1631a4c), moteur (li a2,9 @0x163548c), 0x138ecd4/0x138ed3c | famille perf adjacente — candidat AllowMaxPerf/RMDisablePStates, non prouvé |
| **10** | 1 | 0x12980da (SET) | région 0x1298 — non nommé |
| **11** | 2 | 0x16eace6 (SET), 0x1b7965e (CLEAR) | région 0x16ea/0x1b79 — non nommé |

Les couples SET/CLEAR appariés à la même adresse ±0x30 (bits 2, 3, 6, 7) sont la
signature d'un cycle acquire/release : le module pose la capacité pour durer le temps
d'une opération, puis la retire. Le bit 0 et le bit 8 sont les deux seuls posés par un
chemin **dial** (persistants) — exactement les deux dials CheckIgnore du sous-système
perf/clocks. La cohérence est totale.

## 3. Le petit parseur déroulé : ce que fait VRAIMENT RmVFPointCheckIgnore

Le handler (0x1630e32-0x16313dc) exécute, dans l'ordre, pour le dial qui l'appelle :

1. `state->mode = 4` (octet à [état+0]) et installation du callback `0x169455c` à
   [état+0x460] — l'état passe en mode « revalidation ».
2. Appel du constructeur de requête 0x1456c7c (a1 = 0x16346c8, table/format en texte)
   — c'est la requête au sous-système, avant toute écriture de capacité.
3. **SET bit 1** (0x1631310, a2=1, a3=1) — la séquence de changement est marquée
   « en cours ».
4. **Invalidation de 8 entrées** : huit `sb -1` aux offsets +0x198/+0x1b0/+0x1c8/
   +0x1e0/+0x1f8/+0x210/+0x228/+0x240 (stride 0x18) — huit des 16 octets de métadonnées
   VF du state, remis à « invalide » (le -1 = 0xFF).
5. **SET bit 0** (0x1631366) — le court-circuit de validation proprement dit.
6. Lookup de RmPerfChangeSeqOverride (0x10432d4) ; si valeur & 1 → **le bloc bit 8**
   (voir §4) ; sinon poursuite.

La lecture d'ensemble : **RmVFPointCheckIgnore ne se contente pas de sauter un test —
il re-séquence toute la chaîne VF** (mode 4, callback, requête, invalidation, deux
bits). C'est un dial à effets structurants, pas un drapeau muet. Pour la campagne :
c'est le dial de l'étape 4 de la Phase D, et son effet traverse les deux bits 0 et 1
du même objet — d'où l'importance du protocole une-reboot-un-dial de la vague 3.

## 4. Le bit 8 nominatif : la chaîne complète

- **Déclencheur dial** : RmPerfChangeSeqOverride, valeur & 1 ≠ 0
  (branche 0x1631394 + 0x490 = 0x1631824).
- **Pose** : `c.li a3, 1; c.li a2, 8` → setter (0x163182c → 0x1630c48), précédé du
  poke 0x400 générique d'invalidation P-state (0x16317ec-0x163181c : lui 0x111,
  OR 0x400, sw — le même motif que la vague 4.4, encore lui, dans un troisième module).
- **Armement symétrique ClkAdc** : le module lit le mot (+0x324), teste 0x100, et s'il
  est absent le pose (0x114c9ae-0x114c9b6 : a3=1, a2=8, a1=s3, a0=s6). Au démontage,
  trois CLEAR (0x114cb32, 0x114e626, 0x114e71c). Le module ClkAdc référence par ailleurs
  les dials RmIsoHubMCLKSwitch, RMFBTrainingCMOS, RMFBTrainingCML (lookups 0x114ce24-
  0x114ce78) — la famille « horloge mémoire/entraînement FB ».
- **Lecteurs** : le moteur d'acquisition/évaluation teste 0x100 (0x1634ff4-0x1634ff8),
  propage le bit par `sraiw 8` vers [req+0x18] (0x1635282), et re-teste dans sa
  seconde phase (0x163551a) ; le module ClkAdc le teste à 4 sites (0x114c932,
  0x114e54a, 0x114e590, 0x114e708 — chaque andi collé à son lw +0x324).
- **Sémantique** : bit 8 = « la séquence de changement de perf est sous contrôle
  hôte, sauter le second check ». Le moteur y voit un feu vert de court-circuit, le
  module ClkAdc y veille comme condition de cohérence de ses propres checks horloge.

## 5. Les types de requête — état des lieux (partiel assumé)

Le chercheur BOARDOBJ 0x1457440 n'a **aucun** appelant direct (ni jal ni paire
auipc+jalr formant sa cible) : il est atteint par vtable du rodata chiffré, comme le
prévoyait la vague 4.4. L'enum repose donc sur les request-builders lisibles :
type **0xc** pour la requête VF-point (vague 4.4, prouvé), types « normaux »
**0x10 / 0x13 / 0x1d** (census v42), et le champ [req+0x18] recevant le bit propagé
pour la requête de second check. Le constructeur 0x1456c7c du parseur (appelé avec la
table 0x16346c8) est la meilleure porte d'entrée pour clore l'enum — jalon vague 4.6.

## 6. Mise à jour de la carte des leviers

- **Phase D étape 4 (inchangée, confirmée)** : `RmVFPointCheckIgnore=1` — la mécanique
  est maintenant connue jusqu'aux 8 entrées invalidées ; le protocole vague 3
  (une reboot, un dial, gate --status) s'applique tel quel.
- **Nouveau candidat rang 2** : `RmPerfChangeSeqOverride` (valeur impaire) — le seul
  chemin dial vers le bit 8. Il court-circuite le second check du moteur, MAIS il
  re-séquence aussi la chaîne VF (bit 1 + invalidations) : à tester SEULEMENT après
  l'étape 4, et jamais en même temps qu'elle.
- **Confirmés hors capacité** : RMHwSpeedo/Iddq/Isense/Vmin/Devid CheckIgnore agissent
  par lookup de nom au site de check — pas d'effet caché via le mot de capacité.
- **RMDisablePerfIntersect / PerfPmaControlReg / AllowMaxPerf / RMDisablePStates** :
  consommés dans le grand parseur perf (0x1631300-0x1632790, lookups à 0x1631e02/
  0x1631e28/0x16322c6/0x163270a) — la famille des bits 9/11 est probablement là ;
  xref de leurs blocs = jalon 4.6.

## 7. Registre d'honnêteté

1. Le census des 42 appelants couvre les appels **directs** (auipc+jalr et jal). Les
   appels par vtable chiffrée restent invisibles — le total est un plancher, pas un
   plafond. La vague 4.4 avait prouvé l'existence de ces chemins pour le callback.
2. L'attribution « bit 8 = RmPerfChangeSeqOverride » repose sur la branche explicite
   0x1631394→0x1631824 : prouvée statiquement. La contre-partie honnête : le champ
   signifiant du dial est sa **valeur**, testée `& 1` — les valeurs paires (2, 4…)
   pourraient coder d'autres modes non branchés ici.
3. Les bits 2, 3, 6, 7, 10, 11 sont attribués par **région**, pas par nom de dial —
   les libellés restent ouverts. Aucun n'est revendiqué.
4. Le secondaire 0x164a1c4 (100 appelants, « a2 » 0/1/3/4/5 + valeurs 129/175/188) est
   probablement un champ d'autre sémantique qu'un bit — la résolution a2 de mon
   instrument y est suspecte par construction. Publié comme ambiguïté, pas comme
   résultat.
5. La délimitation fonctionnelle (v45_func) est heuristique (prologue/épilogue) — les
   bornes peuvent déborder d'un bloc ; les attributions de la carte reposent sur les
   sites et les branches, jamais sur les seules bornes.
6. Instruments reproductibles : rm.elf sha256 de la vague 4 (16 912 384 o), cache
   text.tsv régénérable en 7 s, tous les chiffres de ce document sortent des huit
   scripts v45 commités.

## 8. Prochain jalon (vague 4.6)

Le grand parseur perf (0x1631300-0x1632790) est la pièce restante : xref des branches
de ses blocs RMDisablePStates/AllowMaxPerf/RMDisablePerfIntersect/PerfPmaControlReg →
attribution des bits 9/11 et du rôle exact du constructeur 0x1456c7c ; enum complet
des types de requête au chercheur par ses vtables Runtime-visibles (les 5 vtables de
la vague 4.4 donnent deux points d'ancrage). Côté machine, rien ne change : Phase V
puis Phase D étapes 1-4 selon le protocole vague 3.
