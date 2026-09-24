# 4.46 — la chasse d'optimisation, ronde 3 : qui nourrit la formule,
# les récepteurs d'événements, la région opaque 0x20000000, et la
# surface booter

Mission : le brief « on va chercher des pistes d'optimisation firmware
du code — tu me diras ce que tu as trouvé de nouveau ». Les rondes 1-2
(4.33/4.35) ont énuméré puis cardé les knobs du rm.elf ; 4.36 a clos le
plan statique côté rm.elf. La ronde 3 attaque les quatre rectangles
jamais minés que les passes 4.40-4.45 ont ouverts : (A) les RÉCEPTEURS
de la famille d'événements 0x2080_9xxx (la source réelle des bases que
la formule multiplie), (B) l'écrivain des records f14/f18 (le négatif
4.44 §2.3 re-ouvert full-image, toutes encodages), (C) le backing de la
région 0x20000000 (la queue 4.43 #2), (D) la surface booter (les knobs,
les SBI, la cellule desc). Substrats : `rm-full.elf` (la loi
B_file = A_img − 0x38), `binaries/gsp-rm-17MB.bin` (le conteneur 2-LOAD
+ le data LOAD), `binaries/fwimage.bin` (le GFW, le répertoire 4.30),
`binaries/bootloader.bin` (le booter, 1 LOAD @VA 0x100000, 0x6d000).
Instruments : `v446a_events.py` (l'espace d'événements + les
installateurs), `v446b_records.py` (les écrivains de records
full-image + le template + les consommateurs), `v446c_region2000.py`
(le census de la région + les sondes de backing), `v446d_booter_
surface.py` (les knobs du booter + le SBI + la cellule desc), leurs
JSONs. PR-only, no merge, branche `pass/4.46-optimization-hunt3`
(stackée sur `pass/4.45-rop-runtime`, PR #34 ouverte).

## La reproduction des comptes bankés (avant de produire)

| compte | bancé | reproduit ce pass |
|---|---|---|
| le census auipc rm.elf | 416,206 | **416,206 exactement** (v446a/b/c re-asserts) |
| la loi de coordonnées | 512/512 | **512/512** |
| le census EDPp (v420) | 17/17 | **17/17, missing=[], extra=[]** (v443b re-run) |
| les WRITE-FIELD | 34/34 | **READ=20, WRITE=34, PASS=0** |
| booter_emu --selftest | 5/5 | **5/5** |
| booter_emu --test-transfer | 11/11 | **11/11** |
| booter_emu --test-444 | 9/9 | **9/9** |
| booter_emu --test-rop | 18/18 | **18/18** (TR, le nouveau bancé 4.45) |
| les gadgets du booter | 84 c.ret + 515 auipc | **84 c.ret exactement (v446d byte-census) ; 557 mots-opcode 0x17 sur le LOAD complet (515 bancés = la zone code — le delta = nommé, les 42 = les données DMEM de l'image)** |

## Verdict first

| question | ce que les octets disent | verdict |
|---|---|---|
| QUI reçoit 0x20809009/0x20809064 (les sources des bases) ? | **les récepteurs trouvés** : le dispatcher géant @0x18AB1A0 (le switch sur l'ID, ~7 KB, les arms 0x18AB-0x18AC) + un arm @0x1AEA0CA ; le handler 0x20809064 = **un lookup clé→ligne** : il scanne la table source à `(objet a0)+0x32BC8` ({u32 count @+0x32BC4 ; rows 0x10 = {key, A, B, D}}), matche le mot-clé de chaque entrée (le groupe {1,4,8,2} pré-placé par la recompute depuis la table statique 0x1C7B320), et **copie la row dans la réponse** — **D (row+0xC) = la base µW que la formule multiplie** | **PROUVÉ** (le mécanisme, fenêtre citée §1) — la source immédiate des bases = une table runtime à +0x32BC8 dans l'objet dispatch |
| un écrivain statique de la table {+0x32BC4, +0x32BC8} ? | 0 store statique aux offsets exacts (les 5 compositions voisines 0x32B18-0x32E98 = d'autres objets) — le remplissage = par bloc (la lane create/copy, le modèle 4.37/4.38) | **PROUVÉ (négatif borné)** : pas d'écrivain nommable |
| l'écrivain des records f14/f18 (full-image) ? | le template statique : **0 paire {f14, f18=100} ET 0 {f14, f18=1000} dans le data LOAD entier** (les deux lectures de l'unité) ; l'idiome ×0x30 : **6 sites byte-exacts full-image** (les 2 bancés + **4 nouveaux** 0x14D913E/0x1518888/0x1A49E0C/0x1BCE294, décodés un à un = d'autres systèmes de records, AUCUN n'écrit +0x14/+0x18) ; la marche de pointeur `addi rd, rd, 0x30` = **528 sites** — trop dense pour l'isolation statique ; l'init 0x14584D8 (décodée ce pass) = **une chaîne d'événements dispatcher** (0x2080A618, 0x2080A612) qui construit les objets 0x4E20/0xD450 et copie obj+0x668-0x688/0x664 — **elle ne touche jamais les records non plus** | **PROUVÉ (négatifs + la chaîne d'init)** : les records = remplis par la lane runtime (RPC/ctrl object-create, HYPOTHÈSE cohérente 4.37/4.38) — la dernière couture statique de la route f18 = MORTE |
| le backing de la région 0x20000000 (la queue 4.43 #2) ? | **71,541 compositions** (71,494 auipc + 47 lui) → **65,060 cibles distinctes** dans [0x2000000C, 0x203C5AEF] = **3.95 MB** bornés par le PT_TLS @0x203C6000 — la région = le vrai espace rodata/config du RM, référencé 71K fois ; le backing : les 2 LOADs = trop petits, le record GFW `rm.bindata.bin` (0x3d8a000 = 64.4 MB, flags 0) = le seul candidat — **pas de mapping identitaire, la sonde NUL-préambule max = 3/8 (le bruit), les hits u32 dans l'intervalle = SOUS l'espérance aléatoire (28.7K observés vs ~30.5K attendus)** | **PROUVÉ (la région, quantifiée) + INDECIDABLE-BY-BYTES (le backing : compressé/chiffré)** — la conséquence campagne : **le sol 4.36 = re-cadré** (§3.3) |
| les knobs du booter ? | le census round-values (la règle 4.33 lane A) sur le booter complet : **0 valeurs** — le booter ne porte AUCUNE constante de politique (le µs-ladder = RM-only) | **PROUVÉ (négatif quantitatif, première mesure)** |
| la cellule desc 0x16C088 : qui l'arme ? | **aucun compositeur statique de 0x16C088 dans le booter** (les 6 compositions 0x16C = les cellules voisines : le tableau logger 0x16C230-0x16C268 écrit par le setup `sd a0, 0(s6)` @0x101E0C, 0x16C340, 0x16CF88) — le setup lit desc+0x20/+0x28 mais personne n'écrit | **INDECIDABLE-BY-BYTES** (l'écrivain = driver ou ROM) — **la lane « DMEM-tail » nommée** : si la queue DMEM (0x16C000+) échappe à la couverture de la signature (le UNDECIDABLE 4.30), le driver arme le ring SANS ROP — l'expérience qui décide = le dump post-boot stock de la cellule (le runbook 4.44-machine) |

## 1. TÂCHE A — les récepteurs des événements : la source des bases

### 1.1 L'espace d'événements (v446a)

Le census des matérialisations lui{0x20808..0x2080F}+addi/c.addi
(toutes parités, l'image entière) : **28 sites, 21 IDs distincts** —
la première carte de la famille interne. Les clusters : 0x18AB-0x18AC
(le dispatcher, ci-dessous), 0x1BD96xx (un second module : 0x20808161,
0x20809019, 0x2080A06A, 0x2080B201, 0x2080E802), 0x1AEA0CA, 0x1447806
(0x2080A613, DANS le module policy). Les trois IDs bancés y figurent :
0x20809009 ×2 (les sites 0x18AC614/0x18AB4CA = les COMPARES du
récepteur, pas des émissions — le « site » 4.43 §2.3 = l'émission par
la recompute, les deux autres = la réception).

### 1.2 Le récepteur : le dispatcher @0x18AB1A0

Le prologue (`c.addi16sp sp, -0xc0` @0x18AB1A0, 12 s-regs) ouvre un
corps ~7 KB dont le squelette = un switch binaire sur l'ID entrant
(s1) : les `bgeu` partitionnent, les arms `lui a5, 0x20809 ;
c.addi a5, 9 ; bne s1, a5, 8` routent. La lecture du pointeur de
dispatch (s7 = 0x418FFA0 data, `ld a5, 0(s7)`) charge une table
statique {ptr, taille} : **{0x10E2B34, 0x1C8}, {0x10E30A0, 0x1F0},
{0x10E231C, 0x1F0}** (file-backed, dumpée) — la config statique du
dispatcher.

### 1.3 Le handler 0x20809064 : le lookup clé→ligne — LE MÉCANISME

La fenêtre 0x18ABCCA-0x18ABD22 (citée intégrale dans le JSON) :

```
0x18ABCCA  lui a7, 0x33 ; add t1, s10, a7    # la base = objet a0
0x18ABCD8  addi a7, a7, -0x438               # 0x32BC8
0x18ABCDC  lw a3, -0x43c(t1)                 # a3 = *(a0+0x32BC4) = le COUNT
0x18ABCE0  c.beqz a3, 0x3c                   # count = 0 -> rien
0x18ABCE2  slli a5, a0, 0x20 ; srli a1, a5, 0x1c   # a1 = entry = s6+8+k*0x10
0x18ABCF0  add a5, s10, a7                   # a5 = a0+0x32BC8 = LA TABLE
0x18ABCF4  srli a3, a4, 0x1c                 # a3 = count<<4 = la borne du scan
0x18ABCF8  c.lw a2, 0(a1)                    # a2 = la CLÉ de l'entrée
0x18ABCFE  c.addi a5, 0x10                   # le pas = 0x10
0x18ABD04  c.lw a4, 0(a5) ; bne a4, a2, -8   # row.w0 == clé ?
0x18ABD0A  c.lw a2, 4(a5) ; c.lw a3, 8(a5) ; c.lw a5, 0xc(a5)
0x18ABD10  c.sw a4, 0(a1) ; c.sw a2, 4(a1) ; c.sw a3, 8(a1) ; c.sw a5, 0xc(a1)
0x18ABD18  lw a6, 4(s6) ; c.addiw a0, 1 ; bltu a0, a6, -0x42
```

Le croisement avec le write set de la recompute (4.44 §2.1) verrouille
la sémantique : les clés = les valeurs de groupe {1, 4, 8, 2} que la
recompute pré-place à list[k*0x10+8] depuis la table statique 0x1C7B320
; la row copiée {w0, w1, w2, w3} atterrit sur les slots {list+8, +0xc,
+0x10, +0x14} = les A/B/C/D de la recompute ; **D (w3) = obj+0x618+k*0x10
= LA BASE µW que la formule `limite = base × f18/100/1000` multiplie**.
La source immédiate de la limite = **la table à (a0)+0x32BC8**.

### 1.4 Le négatif : personne n'écrit la table

Le census des compositions 0x32B00-0x33000 : 5 hits {0x32B9C,
0x32B1C, 0x32E98 ×2, 0x32B18} = d'autres objets ; **0 store statique
aux offsets exacts {+0x32BC4, +0x32BC8}** ni au count ni aux rows. Le
remplissage = par bloc (memcpy/create-payload) — la lane RPC
object-create (le modèle banké 4.37/4.38 pour B+0x8D9DC) = la lecture
cohérente, HYPOTHÈSE pour CETTE table.

## 2. TÂCHE B — l'écrivain des records f14/f18 : la couture statique est morte

### 2.1 Le template statique : 0 hit

La recherche structurelle dans le data LOAD ENTIER (VA 0x4000000..,
file 0xE9B000..0x1070000) : toute position (off & 0x2F) == 0x18 avec
u32 == 100 (percent) ou == 1000 (permille) et le voisin (off & 0x2F)
== 0x14 plausible : **0 paire, 0 run pitch-0x30** (les deux lectures
de l'unité). Les records ne naissent pas d'un template file-backed.

### 2.2 L'idiome ×0x30 full-image : 6 sites, aucun n'écrit f14/f18

L'encodage byte-exact bancé (0x03000E13 = li t3, 0x30) : **6 sites**
{0x143FEC0 (la recompute), 0x1446EDE (l'évaluateur), **0x14D913E,
0x1518888, 0x1A49E0C, 0x1BCE294 (nouveaux)**}. Le décodage un à un des
4 nouveaux : (a) 0x14D913E = un walker de records 0x30 avec 6 loads
u64 {0..0x28} sur *(X+0x168)+0xF0 — un autre système ; (b) 0x1518888 =
un builder qui stocke à +0x28/+0x30 d'entrées 0x30 ; (c) 0x1A49E0C =
une machine à états (les codes 0x10/0x11/0x13/0x14) ; (d) 0x1BCE294 =
un walker `mul + addi 0x22` avec des `lhu`. **Aucun store à +0x14/+0x18
d'une base ×0x30.** La marche de pointeur (`addi rd, rd, 0x30`) =
**528 sites** (le census + les 1,181 stores {+0x10..0x1C} dans leurs
fenêtres = l'enveloppe, JSON) — trop dense pour l'isolation : la forme
sans matérialisation du multiplicateur reste hors de portée du census.

### 2.3 L'init 0x14584D8 décodée : la chaîne d'événements (nouveau)

La fonction d'init du module policy (prologue cité, 0x1458490-0x1459132)
: alloue un objet **0x4E20** (l'allocateur bancé 0x18C373C, descripteur
0x418CDE8), le memset, puis **appelle LE MÊME dispatcher** (`ld a6,
0x138(state+0x4000)`, les slots +0xdc/+0xe4) avec **l'événement
0x2080A618** — le dispatcher REMPLIT l'objet ; l'init relit 8 u32
(s5+0x4DA0-0x4DBC) → **obj+0x668-0x688**, le byte s5+0x98 → obj+0x664
(avec le flag 0x100) ; puis alloue **0xD450** et refire
**0x2080A612** + 0x2080A618 avec des recopies croisées de bytes
(obj+0x689-0x68c). Le scan systématique de la fonction : **0
matérialisation de 0x30, 1 seul store small-disp** (0x145918A = un
helper de clear-bit, faux positif inspecté). **L'init ne touche jamais
les records.** Le graphe boardobj = construit par événements — le
remplissage des records = la lane runtime, cohérente avec 4.37/4.38.

## 3. TÂCHE C — la région 0x20000000 : quantifiée, et le mur du backing

### 3.1 Le census (v446c) : 71,541 références

Les paires auipc+addi/c.addi ET lui+addi (les deux opcodes, la
composition auipc = pc + (imm20<<12) + imm) vers [0x20000000,
0x20400000) : **71,541 compositions → 65,060 cibles distinctes**, le
span [0x2000000C, 0x203C5AEF] = **3.95 MB**, borné au-dessus par le
PT_TLS @0x203C6000 (memsz 0x1000) — la région = [0x20000000, 0x203C7000)
en pratique. La répartition : 35,567 refs @0x202xxxxx + 35,931
@0x203xxxxx + 42 @0x200xxxxx. Les sites cités 4.43 §1.2 (0x11C0900 →
0x202908F0, 0x11C07AC → 0x202909E0) = **reproduits par assert dur**
dans l'instrument.

### 3.2 Le backing : le bindata = compressé/chiffré

Le seul fichier avec la place = le record GFW **`rm.bindata.bin`**
(true fw off 0x12d1000, taille **0x3d8a000 = 64.4 MB**, flags 0 — la
grammaire 4.30 ; la tiling [0x6e000, 0x505b000) s'y termine). Les
sondes, toutes négatives : (a) pas de mapping identitaire (VA−
0x20000000 = offset bindata) — les octets aux VAs cités = du bruit ;
(b) la sonde NUL-préambule (8 VAs cités, le byte avant = 0, le byte sur
= imprimable, balayage de TOUS les offsets de mapping K) : **max = 3/8,
le bruit** (9 positions sur 64 MB) ; (c) les hits u32 dans l'intervalle
[0x20000000, 0x203C6000) = 28,659 — **SOUS** l'espérance aléatoire
(~30.5K pour 32.2M u32s × p≈0.00095) : pas de structure de pointeurs ;
(d) 1 magie ELF interne (0x1cefafe) = un faux positif probable ; (e) la
densité = homogène (printable ≈ 0.37, nonzero ≈ 0.996 sur 16 chunks).
Avec le négatif 4.29 (pas de stream LZ4 NVIDIA dans 1.81 GB) : **le
backing = compressé ou chiffré, le mécanisme = INDECIDABLE-BY-BYTES**.

### 3.3 LA CONSÉQUENCE CAMPAGNE : le sol 4.36 re-cadré

Le verdict 4.36 (« la chasse statique a atteint son sol ») = vrai POUR
LES OCTETS VISIBLES. Ce pass le quantifie et le borne : **71,541
références de code pointent dans une région opaque de 3.95 MB** — les
configs/tables/formats qui y vivent (le logger y compose ses
format-strings, 4.43 §1.2) = invisibles au census. **Tout négatif
statique à venir porte le double bornage : (i) pas dans les 2 LOADs
file-backed, (ii) pas décidable dans le rodata opaque.** Les knobs
4.33/4.35 = les knobs du code visible ; la surface réelle = plus
grande, mais murée par la compression — la route = le dump runtime (la
lane 4.26) ou l'émulateur, pas les octets.

## 4. TÂCHE D — la surface booter : 0 knobs, la cellule desc orpheline

### 4.1 Le census des knobs du booter (première mesure)

La règle lane A (|v| ≥ 1000, v % 1000 == 0, toutes formes lui/auipc +
addi/c.addi) sur le LOAD booter entier (VA 0x100000, 0x6d000) : **0
valeur**. Le booter = un chargeur sans constante de politique — le
µs-ladder et les knobs = la propriété exclusive du RM. (Le census auipc
du LOAD complet = 557 mots-opcode vs 515 bancés — le delta 42 = les
données DMEM de l'image, la zone code seule reproduit ; le c.ret = 84
exactement, le sha = ab90560bad520e65… exactement.)

### 4.2 Le SBI : la face appel = bankée, la face réception = ROM

Les 10 sites du wrapper (v445b, re-bancés) : les args = les littéraux
(0x1000000/0x200000 = les tailles WPR) et les paires {addr, taille} du
bloc de boot — la face réception (les handlers des fns {0x20..0x2e} et
des stubs a6∈{7,8,9,A}) = dans le BOOT ROM (fermé). Nos octets nomment
l'interface, jamais la sémantique interne — le négatif = borné, inchangé
depuis 4.31.

### 4.3 La cellule desc 0x16C088 : jamais écrite par le booter — la lane DMEM-tail

Les compositions 0x16C dans le booter (v446d) : **6 sites, aucun ne
vise 0x16C088** — {0x16C268, 0x16C248, 0x16C230} = le tableau logger
(écrit par le setup : `sd a0, 0(s6)` @0x101E0C, la fenêtre citée),
{0x16C340}, {0x16CF88→0x16D464}, {0x16BD2C}. Le setup du transfer ring
lit desc+0x20/+0x28 (le cap/dest, 4.42) mais **personne n'écrit la
cellule** dans le booter. Deux lectures : (a) l'écrivain = le driver ou
le ROM au staging — **la lane « DMEM-tail »** : si la queue DMEM
(0x16C000+, dans le LOAD, APRÈS le code) échappe à la couverture de la
signature memdesc (le UNDECIDABLE-BY-BYTES 4.30, jamais tranché), le
driver peut armer le ring au staging — **la boucle de transfert
écrirait nos {valeur, cible} LÉGITIMEMENT, sans débordement ni ROP** —
l'optimisation maximale de la lane 4.45 (un patch DMEM au lieu d'une
chaîne ROP) ; (b) la cellule = zéro pour toujours et le ring = du code
mort dans notre flux — cohérent avec « inerte sans setup » (4.42).
**L'expérience qui décide = le dump post-boot stock de {0x16C088,
+0x20, +0x28} + le test de couverture signature sur la queue DMEM**
(le runbook 4.44-machine r-série, le même jour machine) — si la queue
n'est pas couverte ET la cellule reste zéro : le driver-DMEM-patch = la
lane candidate au jour suivant, ACK-gatée.

## 5. La réconciliation avec les passes précédentes

- **4.43** : sa queue #2 (le backing 0x20000000) = payée — la région
  quantifiée (71,541 refs), le backing = muré (compressé) ; sa queue #3
  (les handlers 0x2080_9xxx) = payée — les récepteurs nommés, le
  mécanisme du remplissage des bases = le lookup clé→ligne PROUVÉ.
- **4.44** : son négatif §2.3 (les écrivains de f14/f18) = étendu
  full-image toutes encodages + le template mort ; sa chaîne d'init =
  complétée (les événements 0x2080A618/0x2080A612, les objets
  0x4E20/0xD450, les copies obj+0x668-0x688/0x664 — le « voisin +0x664
  inconnu » 4.42/4.44 gagne sa source : s5+0x98 | 0x100, un byte du
  premier objet boardobj).
- **4.36** : le sol = re-cadré (§3.3) — le double bornage des négatifs.
- **4.42/4.45** : la cellule desc = orpheline côté booter (§4.3) — la
  lane DMEM-tail = la candidate « sans ROP », gated sur la couverture
  signature ; la lane ROP = inchangée, toujours le plan A.
- **4.30** : le record `rm.bindata.bin` = le seul blob avec la place du
  backing — la grammaire GFW ressort comme l'inventaire des blobs.

## 6. Les leçons d'instrument

1. **AUIPC = 0x17, LUI = 0x37** — le census avec le mauvais opcode
   donnait 3 hits au lieu de 71,541 ; l'assert sur le site cité 4.43
   (0x11C0900 → 0x202908F0) a attrapé le bug AVANT le verdict. La
   règle : tout census qui compte un opcode = un assert sur un site
   cité par une passe antérieure.
2. **Le split immédiat S-type ≠ l'I-type** — le scan `ld` avec
   imm[11:5]|[4:0] donnait 19 sites fantômes ; l'I-type = imm = w>>20.
   Le même bug de seuil de signe (0x1000 vs 0x800) a avalé -0x168.
3. **L'espérance aléatoire AVANT de crier structure** — les 28,659
   hits u32 « pointeurs » dans le bindata semblaient une découverte ;
   l'espérance pour 32.2M u32s = ~30.5K → les hits = SOUS le hasard.
   Le réflexe coûté : trois lignes de probabilité.
4. **La sonde NUL-préambule = l'outil de rejet de mapping** — le balayage
   K (l'offset de mapping) avec la condition « byte avant = 0 ET byte
   sur = imprimable » sur des VAs cités : max 3/8 = le rejet propre
   d'un mapping plaintext, en une passe numpy.
5. **c.li ne porte pas 0x30** — l'imm6 signé 6 bits encode 48 comme
   −16 ; le census des encodages du pas ×0x30 = li/addi + les marches
   `addi rd, rd, 0x30` (528 sites — la forme invisible du multiplicateur).

## 7. La queue

1. Le dump runtime de la cellule desc {0x16C088, +0x20, +0x28} + le
   test de couverture signature de la queue DMEM (le jour machine, le
   runbook 4.44-machine) — **décide de la lane DMEM-tail** (le driver
   arme le ring sans ROP).
2. La lane 4.26 (le recv-hook capture) = toujours LA route des valeurs
   live — elle nommerait aussi le remplisseur réel de la table
   {count, rows} à +0x32BC8 (la lane RPC object-create, HYPOTHÈSE).
3. Le second dispatcher (le cluster 0x1BD96xx : 0x20808161/0x20809019/
   0x2080A06A/0x2080B201/0x2080E802) = son module et ses objets — la
   même attaque (le switch, les tables) peut nommer un autre sous-
   système (le candidat : les events thermiques/perf).
4. Le contenu du rodata opaque : le dump runtime de [0x20000000,
   0x203C7000) (la lane 4.26 ou l'émulateur) = la seule route — les
   configs invisibles y vivent peut-être (les knobs du code visible ne
   sont pas les knobs du binaire).
5. Les 528 marches ×0x30 : une passe CFG (le fork 4.36c) sur les 20
   sites avec un store {+0x14, +0x18} dans la fenêtre = le dernier
   espoir statique pour nommer l'écrivain des records — espérance
   faible, coût moyen.

## Discipline

L'evidence obligatoire (chaque claim = instrument-reproductible : les
JSONs v446a/b/c/d + les fenêtres citées + les shas) ; les négatifs
bornés (la table des bases, le template, l'idiome ×0x30, le backing,
les knobs booter, la cellule desc — chaque négatif = sa portée et son
expérience) ; les comptes bankés reproduits AVANT de produire (le
tableau en tête) ; l'exécution/machine = PAS notre terrain (les
expériences = nommées, gated) ; PR sans merge, branche
`pass/4.46-optimization-hunt3` stackée sur `pass/4.45-rop-runtime`.
