# CAMPAGNE RTX 3070 — Vague 4.6 : LE GRAND PARSEUR PERF ET L'ENUM DES REQUÊTES
## Les 4 dials consommés instruction-exact, le bit 9 corrigé, 52 requêtes et 17 types dénombrés
**Task 70 · session cloud du 18/09/2026 · Super Z (GLM 5.3 Flash) · pour le chat machine de Cheurteenyt**

> Directive fondatrice (verbatim, règle permanente) : « Allons y précise bien dans le commit
> que c'est cloud glm 5.3 flash et le repo doit toujours être clean. »
> Directive de recherche (verbatim) : « nous on veut que tu aille beaucoup plus loin analyse
> du code grande investigations pour trouvé des améliorations tu dois recherche de la
> complexité et regardé les calculs qu'il y a tu doit vraiment aller très loin. »

La vague 4.5 avait dressé la carte des bits de capacité et laissé deux chantiers ouverts :
le grand parseur perf (0x1631300-0x1632790, où les dials RMDisablePStates, AllowMaxPerf,
RMDisablePerfIntersect et PerfPmaControlReg sont consommés) et l'enum des types de requête
par le constructeur 0x1456c7c. Les deux chantiers sont soldés dans cette vague.

---

## 0. Les trois vérités nouvelles

**V1 — Le grand parseur est UNE fonction, et les quatre dials y sont consommés par lookup de
nom à des sites désormais prouvés.** L'épilogue (restauration s0-s11 + `c.jr ra` à 0x1632790)
cimente les bornes 0x1631300-0x1632790. Les quatre sites de lookup générique (0x10432d4) sont
RMDisablePStates à 0x1631e02, AllowMaxPerf à 0x1631e28, RMDisablePerfIntersect à 0x16322c6,
PerfPmaControlReg à 0x1632714 — l'appariement provisoire de la vague 4.5 est confirmé après
une correction de session : une addition fautive en cours de route a momentanément fait
douter du site PerfPmaControlReg ; le re-tranchage par double lecture du TSV et un scan global
des formations de l'adresse 0x1E71260 ont donné raison au disque initial. La leçon de méthode
est gravée : **l'arithmétique d'adresses se vérifie par script, jamais de tête.**

**V2 — Le bit 9 n'est le produit d'AUCUN des quatre dials.** La vague 4.5 le donnait comme
« candidat AllowMaxPerf/RMDisablePStates, non prouvé ». Le déroulé complet du bloc corrige :
le SET bit 9 (0x1631a44-0x1631a4c) est la sortie de la **boucle de revalidation des P-states**
(0x1631974-0x1631a0a), immédiatement précédé du poke 0x400 générique d'invalidation — le même
motif que les vagues 4.4/4.5, dans son quatrième site. Aucun des 42 appelants du setter ne
se trouve dans les blocs des quatre dials : la famille perf du grand parseur agit par
consultation de nom, pas par le mot de capacité. Le bit 9 reste attribué par mécanique
(« inventaire des P-states reconstruit »), non par dial.

**V3 — L'enum des types de requête est clos côté constructeur.** Le constructeur 0x1456c7c a
**52 appelants directs** (tous auipc+jalr, aucun jal), chacun avec **sa propre table de
format** (52 adresses distinctes, contenu chiffré/encodé — aucun pointeur vers des strings),
et le type (N, troisième argument du prep 0x18E11F8) prend **17 valeurs distinctes** sur les
28 sites résolubles : 0, 2, 4, 6, 7, 8, 12 (0xc), 15 (0xf), 16 (0x10), 17 (0x11), 22 (0x16),
27 (0x1b), 28 (0x1c), 29 (0x1d), 30 (0x1e), 31 (0x1f). Les types « normaux » du census v42
sont retrouvés exactement là où il faut : 0x10 aux deux sites attendus (dont 0x1b9e428, la
région du bit 1), 0x1d à 0x1ad103a, et le **0x13 est écrit en dur dans l'état** à
[s1+0x8A9A0] par le bloc RMDisablePStates/AllowMaxPerf. Le 0xf est vivant : 5 sites du ctor
PLUS un appel direct à la fonction sœur 0x14561b8 depuis le bloc PerfPmaControlReg.

---

## 1. La méthode

Six instruments v46 s'ajoutent aux huit v45 (cache `text.tsv` réutilisé tel quel — les 7 s de
désassemblage de la vague 4.5 continuent de s'amortir) : `v46_dials.py` (appariement
dial↔lookup dans la région, avec lecture des strings directement dans rm.elf au mapping
VA = off + 0x1000000), `v46_window.py` (dump multi-fenêtres en un chargement), `v46_ctor.py`
(appelants + fenêtre + lecture brute de la table 0x16346c8), `v46_check.py` (tranchage des
contradictions + sites d'appel clés + fin du ctor), `v46_enum.py` (census tables + scan global
des formations de PerfPmaControlReg), `v46_enum2.py` (enum N final, backward 16 instructions).
Chaque conclusion de ce document repose sur au moins deux lectures indépendantes du même TSV
ou sur une lecture TSV + vérification binaire (`cstr`).

## 2. La carte des quatre dials du grand parseur

**RMDisablePStates (0x1631e02) et AllowMaxPerf (0x1631e28) — un bloc commun.** Les deux
lookups écrivent dans la même cellule (s0-0x1d0) et leurs valeurs sont combinées par OR
(0x1631e38). Si les DEUX valent zéro, l'octet [s1+0x1AD8] reçoit 1 (0x1631e3c-0x1631e42) —
le drapeau « gestion P-states par défaut active ». Le chemin commun enchaîne alors, dans
l'ordre : tests d'octets data (0x1631e46-0x1631e56), la cellule [s1+0x2d2], **la remise à
zéro d'une table de 0x3000 octets à stride 0x18** (0x1631e62-0x1631e80 — les descripteurs
de points), **l'écriture du type 0x13 à [s1+0x8A9A0]** (0x1631e84-0x1631e8c), le test du mot
[s1+0x2d0] contre le masque 0xFFFFF000, l'octet [s1+0x2d3], le `ori 4` sur [s11+0xED0]
(0x1631eae-0x1631eba), **l'appel au petit parseur VF 0x1631010** (0x1631ec2 — le request-builder
de RmVFPointCheckIgnore, vague 4.4), deux appels 0x1BA72C4 et 0x169E2D4, puis **l'initialisation
d'une structure de 0x168 octets à s1+0x1B38** avec un compteur 0x100000001 à [s1+0x1B30]
(0x1631f1e-0x1631f5e). Lecture d'ensemble : activer l'un de ces deux dials re-déroule toute la
machinerie de description des points de perf, avec re-requête au sous-système VF.

**RMDisablePerfIntersect (0x16322c6) — la mécanique d'exclusion.** Si la valeur vaut 1,
l'octet [s1+0x2c8] est remis à zéro (0x16322ec). Le bloc appelle ensuite 0x1B4F024 avec
(a0=s4, **a1=5**, a2=&val), fait une **recherche d'objet par vtable [obj+0x38] indexée par la
valeur du dial** (0x1632330-0x1632340 — le même motif que la boucle P-states), puis lit la
config à [[s2+0x1D60]+0x4C0] et en extrait deux bits vers [s1+0x8F180] (bit 0x10, via `snez`)
et [s1+0x8F181] (bit >>5) — 0x163235e-0x163238c. Suit un appel à six arguments 0x19104F0 dont
le résultat est stocké à [s1+0x8F188]. Enfin le retour de 0x11835BC (appelé avec la string
'soSysMemFromCarveout', formée à 0x163242c) est **comparé à 0xd** (0x163244a-0x1632458) ; le
cas d'égalité mène à la formation de la string de timing DRAM **'3b1w1d4b'** (0x163245c →
0x1E71170) — le grand parseur parle de timings mémoire 3-bank/1-write/1-drive/4-bank quand le
chemin carveout système répond 13.

**PerfPmaControlReg (0x1632714) — le levier à deux visages.** La valeur du dial est testée
contre 1 (0x1632722-0x1632728). Si elle vaut 1 : **appel direct du callback [s1+0x288]** avec
(s2, s1, 1) (0x163272c-0x1632736) — un handler enregistré dans l'état, sémantique encore
inconnue. Si elle diffère : **appel de la fonction sœur du constructeur 0x14561b8 avec
a1=0xf** (0x1632738-0x1632746) — un type de requête posé en immédiat, cohérent avec les 5
sites 0xf de l'enum du ctor. Juste avant, le bloc avait appelé 0x1B0974C avec (a1=0x169819C,
a2=0xa, a3=9, a4=s1) (0x16326f2-0x1632704) — le couple (0xa, 9) note la présence simultanée
de ces deux constantes dans la zone.

**Épilogue** (0x1632764-0x1632790) : restauration des 12 registres, `c.jr ra`. La fonction
suivante commence à 0x1632792 (appel 0x11A3722 puis test `== 0x60`).

## 3. Le bit 9 et la boucle des P-states

Le bloc 0x1631974-0x1631a0a est une **double passe d'acquisition** : la fonction 0x1B3C4F4
est appelée avec (a0=s6, a1=0x40 puis a1=8, a2=&val) — deux tailles de balayage — et pour
chaque entrée trouvée, la vtable [obj+0x38] est appelée avec l'index (`andi a1, s9, 0xff`),
l'objet est filtré par [obj+0x60], et le masque s'accumule : **`s4 |= 1 << (val & 0xff)`**
(0x16319b0-0x16319ba et 0x16319fc-0x1631a06). La sortie de boucle exécute le **poke 0x400
double** (0x1631a0e-0x1631a3e : `or [table+0x52c], 0x400` ; `sw 0x400, [base+0x8f0]` ;
`sw zero, [base+0x3d0]`), puis **le SET bit 9** (0x1631a44 : a3=1, a2=9, a1=s1, a0=s2 →
setter 0x1630c48), puis un logging et le retour au petit parseur (0x16313AE). Le bit 9 est
donc l'état « le masque des P-states a été reconstruit et les caches invalidés » — posé à la
FIN de la revalidation, jamais par un dial. Les couples SET/CLEAR appariés vus à la 4.5
n'existent pas pour lui dans cette région : c'est un état de sortie de procédure.

## 4. Le constructeur 0x1456c7c déroulé

**Signature : `ctor(parent, table, buf, head_list)`** — a0 = l'objet parent (le même
[[s2+0x3CD0]] aux trois sites du parseur), a1 = la table de format du site, a2 = un buffer
local de 0x40 octets, a3 = un pointeur de tête de liste. Le pattern d'appel canonique est :

```
c.li  a2, N          ; le TYPE (N = 0..0x1f)
addi  a1, zero, 0x40 ; la taille du buffer
addi  a0, s0, -X     ; le buffer
prep(buf, 0x40, N)   ; 0x18E11F8 — remplit le buffer selon le type
ctor(parent, table, buf, &list)  ; 0x1456c7c
```

Le constructeur fait, dans l'ordre : lecture de l'octet [parent+0x50] ; allocation/récupération
du nœud via 0x18DE124(parent+0x58) ; copie de 0x40 octets via 0x18E1E20 ; **deux popcount
SWAR** (la séquence classique shift/and/sub/add/mul — l'une sur le premier qword du nœud →
[+0x8], l'autre sur le premier qword du buffer → [+0xC]) ; drapeau **[+0x10] = 1** (nœud
actif) ; **[+0x18] = la table** (sd s10) ; **chaînage `sd s4, 0(head)`** ; vérification du
canari de pile ; retour s11 (0 = OK, **0x31 = erreur**). Le nœud requête est donc
`{+0x8: popcount(id), +0xC: popcount(buf), +0x10: actif, +0x18: table_format, ...}` enchaîné
dans une file du parent — le RM construit une **file de requêtes par objet**, une par site
d'appel, avec 52 tables distinctes.

**La table 0x16346C8 n'est pas du texte.** Les 20 premières entrées de 8 octets ne contiennent
aucun pointeur VA valide — ce sont des mots encodés/chiffrés, avec le motif récurrent
`ffffe780` aux entrées 7, 10, 13, 16. Les formats de requête sont **opérés chiffrés**, comme
la rodata au-delà de la frontière cartographiée en vague 4 : le RM déchiffre ses descripteurs
à l'exécution. C'est cohérent, et ça borne honnêtement ce qu'on peut dire du contenu des
requêtes sans la clé.

## 5. L'enum des types (census N, 52 sites)

| N | Sites | Région(s) et lecture |
|---|-------|----------------------|
| 0 | 1 | 0x181786c |
| 2 | 1 | 0x16312f8 — **petit parseur VF, site 1** (a3 = s3+0x3f8, table 0x16346C8) |
| 4 | 1 | 0x1646bc4 |
| 6 | 2 | 0x10f5d78, 0x164710c |
| 7 | 2 | 0x1142c2a, 0x16314d6 — **petit parseur VF, site 2** (a3 = s3+0x330, table 0x167A2B0) |
| 8 | 5 | 0x10f5d22, 0x169f6e4, 0x16b115c, 0x17d5d7e, 0x1842042 |
| 12 (0xc) | 2 | 0x107ce9a, 0x114343a |
| 15 (0xf) | 5 | 0x107d0d6, 0x170c020, 0x1759fdc, 0x17d7a44, 0x1892704 — **+ l'appel direct 0x14561b8 du bloc PerfPmaControlReg** |
| 16 (0x10) | 2 | 0x1632840 (**post-grand-parseur**, a3 = s1+0x8F198, table 0x1697998), **0x1b9e428 (région du bit 1)** |
| 17 (0x11) | 1 | 0x138e9d0 |
| 22 (0x16) | 1 | 0x1badb32 |
| 27 (0x1b) | 1 | 0x169dfcc |
| 28 (0x1c) | 1 | 0x176ff14 |
| 29 (0x1d) | 1 | 0x1ad103a |
| 30 (0x1e) | 1 | 0x1758ed6 |
| 31 (0x1f) | 1 | 0x16ef60a |
| indéterminé | 24 | a2 calculé ou chargé hors fenêtre de 16 instructions |

Trois lectures. **Un** : les types « normaux » du census v42 (0x10/0x13/0x1d) sont retrouvés
dans leurs rôles — le 0x10 construit aux deux sites attendus dont la région du bit 1
(0x1b9e428, à 0x4c du SET bit 1 de la vague 4.5 : la requête et le bit compagnon sont du même
module), le 0x1d à 0x1ad103a, et le 0x13 **écrit en dur dans l'état** à [s1+0x8A9A0] par le
bloc DisablePStates/AllowMaxPerf — un type qui se pose comme champ, pas comme argument.
**Deux** : le 0xc de la vague 4.4 (type de l'objet moteur) n'apparaît qu'à 0x107ce9a et
0x114343a — le petit parseur VF construit N=2 et N=7. Il y a donc **deux niveaux de « type »** :
le N du prep (le format du buffer de description) et le type d'objet que le moteur 0x1634a38
dispatche — la réconciliation des deux est le jalon 4.7. **Trois** : le chercheur BOARDOBJ
0x1457440 reste invisible (vtable chiffrée, confirmé), mais il n'est plus nécessaire : le
CONSTRUCTEUR est le point d'entrée réel des requêtes, et il est entièrement appelé en direct.

## 6. Mise à jour de la carte des leviers

- **Rang 1 (inchangé)** : `RmVFPointCheckIgnore=1` — le protocole vague 3 s'applique tel quel.
- **Rang 2 (inchangé)** : `RmPerfChangeSeqOverride` (valeur impaire) — après l'étape 4, jamais
  simultané.
- **Nouveau, rang 3, OBSERVATION SEULE** : `PerfPmaControlReg=1` appelle un callback
  enregistré ([s1+0x288]) dont la sémantique est inconnue — ce n'est PAS une recommandation de
  test avant que la vague 4.7 ait déroulé ce callback. La valeur ≠1 construit une requête
  type 0xf via 0x14561b8.
- **Confirmé hors capacité** : les quatre dials du grand parseur n'écrivent JAMAIS le mot
  +0x324 — le seul SET de toute la région est le bit 9 de sortie de revalidation, sans dial.
  DisablePStates/AllowMaxPerf/DisablePerfIntersect/PerfPmaControlReg sont des leviers de
  re-dérivation des points de perf, pas des court-circuits de validation.
- **Machine inchangée** : Phase V puis Phase D étapes 1-4 selon le protocole vague 3 ;
  flash 280 W demain, autre chat.

## 7. Registre d'honnêteté

1. **24/52 types indéterminés** — le census N est un plancher : les a2 calculés (mv depuis
   un registre de pile, arithmétique) échappent à la fenêtre de 16 instructions. Les 28
   résolus sont prouvés individuellement (site du `li` cité dans `v46_enum2.json`).
2. **Les tables de format sont chiffrées** — contenu opéré non interprété ; toute affirmation
   sur le contenu précis d'une requête resterait spéculative sans la clé de déchiffrement.
3. **Une erreur arithmétique de session, corrigée par double lecture** : la formation de
   PerfPmaControlReg (0x163270A + 0x83F000 - 0x4AA = 0x1E71260) a été momentanément mise en
   doute par une addition de tête fautive ; le scan global des formations et la relecture du
   TSV ont confirmé le disque. L'arithmétique d'adresses se vérifie par script.
4. **Le bit 9** : le bloc SET et son contexte (poke 0x400, boucle d'accumulation `s4 |=
   1 << idx`) sont prouvés ; les branches d'ENTRÉE de la revalidation (0x163194a, 0x163195e)
   ne sont pas intégralement tracées — le déclencheur amont reste ouvert.
5. **Deux niveaux de type** (N du prep vs type dispatché par le moteur) : l'attribution 4.4
   « requête VF = type 0xc » n'est PAS révoquée — elle porte sur l'objet moteur ; la
   correspondance N↔type-moteur est le jalon 4.7.
6. **Reproductibilité** : six instruments v46 commités (`v46_dials`, `v46_window`,
   `v46_ctor`, `v46_check`, `v46_enum`, `v46_enum2`), cache TSV régénérable en 7 s, rm.elf
   sha256 inchangé depuis la vague 4, tous les chiffres sortent des JSON de
   `scratch-gsp/v45/`.

## 8. Prochain jalon (vague 4.7)

Trois fils sortent de cette vague : (1) la **réconciliation N↔type-moteur** — le dispatch
0x1634a38 et ses objets face aux 17 formats du ctor ; (2) le **callback [s1+0x288]** de
PerfPmaControlReg=1 — le premier handler d'état candidat à un court-circuit sans setter ;
(3) les **branches d'entrée de la boucle P-states** pour achever l'attribution du bit 9.
Côté machine, rien ne change : Phase V puis Phase D étapes 1-4 selon le protocole vague 3.
