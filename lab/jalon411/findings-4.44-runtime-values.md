# 4.44 — de la formule au payload : les valeurs runtime de la limite et
# la chaîne d'écriture concrète vers l'objet 0x6d0

Mission : résoudre l'équation du 250 W par les DONNÉES (les unités, les
valeurs runtime), tracer le remplissage runtime des bases, et construire
la chaîne d'écriture concrète {valeur, cible} vers l'objet policy 0x6d0
— avec le payload byte-exact, la validation émulateur sur l'image
RÉELLE, et le runbook gaté. Substrats : `findings-4.43-power-enforcement-
map.md` (la formule), `findings-4.42-transfer-list-build.md` (le builder
v442e + le format plat u64 + l'émulateur TT 11/11),
`findings-4.40-rop-gadget-hunt.md` (le write-primitive 0x100b3e/0x100b48),
`tools/analysis/gsp-extract/` (rm-full.elf + bootloader.bin),
`tools/edpp/edpp_payload_1616.bin`, `tools/booter_emu.py`.
Instruments (tous commis, les JSON relisibles) : `v4440_baseline.py`
(les comptes bankés), `v444a_evaluator_full.py` (l'évaluateur EN
ENTIER), `v444b_descriptors.py` (les descripteurs + les allocateurs),
`v444c_recompute.py` (le write set de la recompute + la chasse aux
écrivains des records), `v444d_values_table.py` (le croisement des
captures + la table des valeurs), `v444e_gadget_chain.py` (le scan des
gadgets re-commis), `v444_transfer_list_build.py` + `v444f_c_payload_
test.py` (le builder v444 + le byte-exact C==python),
`tools/booter_emu.py --test-444` (TF 9/9), `tools/edpp/runbook-444.sh`.

## La reproduction des comptes bankés (avant de produire)

| compte | bancé | reproduit ce pass |
|---|---|---|
| le census auipc rm.elf | 416,206 (4.35b, 4.43) | **416,206 exactement** (v4440, v444a, v444b, v444c re-asserts) |
| la loi de coordonnées B_file = A_img − 0x38 | 512/512 | **512/512** |
| le census EDPp (v420) | 17/17 | **17/17, missing=[], extra=[]** (v443b ré-exécuté) |
| les WRITE-FIELD (4.38a) | 34/34 | **READ=20, WRITE=34, PASS=0** (v443b ré-exécuté) |
| les xrefs %lo-idiom (4.43b) | PstateEstLUT 1 @0x177d59c, OutputVoltage1x 1 @0x17822f8 | **identiques** |
| booter_emu --selftest | 5/5 (4.31) | **5/5** |
| booter_emu --test-transfer | 11/11 (4.42) | **11/11** |
| les gadgets du booter (4.40) | 84 rets, 515 auipc | **84 c.ret (0x8082) byte-exact ; 515 lignes auipc dans bootloader.asm** (v444e : le compte asm = la référence, le scan d'octets seul = 275+282 car il lit aussi les données) |
| le payload v442e commis | sha b77c6137… | **byte-exact (git diff = vide)** |
| la paire v442f | e85c14d5… | **e85c14d5ccbeabfd… reproduit** (le dump C == le python, v444f) |

## Verdict first

| question du brief | ce que les octets disent | verdict |
|---|---|---|
| l'évaluateur 0x1446d98 : les types réels, l'idx, la sortie 0x28 ? | **4 itérations** (a4 = 0..3, la borne = s8_init+0x20), l'idx = l'index du GROUPE de politique (la table {0x1,0x4,0x8,0x2} @**0x1C7B320** — PAS {0x1024,0x1026} @0x1C7B450, PAS 5 vPstates) ; record.f18/f14 = `c.lw` SIGNÉ + sentinelle **−1 = illimité**, immédiatement normalisés u32 (`slli 0x20/srli 0x20`) ; base = `lwu` ZÉRO-signé ; la sortie = le buffer pile 0x28 (5 slots × 8B, le slot 0 = zéros), les paires {f18-based, f14-based} = slots 1..4, copiées (0x20) à **obj2+0x50** par le bounds-checked copy 0x143FAAC/0x18BDA10 | **PROUVÉ** (les fenêtres citées §1) — la lecture « 5 vPstates » de 4.43 = **réfutée** pour cet évaluateur |
| les bases obj+0x600-0x660 : valeurs d'amorçage statiques ? | les descripteurs 0x4190DC0/0x4190DE8 = **file-backed dans le data LOAD du conteneur (offsets 0x102BDC0/0x102BDE8) et TOUT ZÉRO** (0x80 B chacun dumpés) ; l'objet naît **memset-zéro** (0x1458d08-d12) ; la recompute remplit depuis l'événement 0x20809064 (les résultats du vmethod) | **PROUVÉ : pures runtime** — la voie descriptor = MORTE pour les VALEURS |
| l'équation 250000 = base × f18/100/1000 se résout-elle par les données ? | la capture send (1616 B) : **0 paires solutionnables** (les 9 u32 non-nuls = 4 header + 5 params bancés 4.24) ; les dumps recv = **ARMÉS, JAMAIS exécutés** (0 fichiers dans le repo) ; les u32 {250000, 240000, 250000000, 240000000, 100000000} = **0 sites** dans rm.elf ET le conteneur | **INDECIDABLE-BY-BYTES aujourd'hui** — la famille (base, f18) = {(2.5e8, 100) percent, (2.5e7, 1000) permille}, l'expérience U2 (le runbook) décide |
| la modif minimale pour 280000 ? | le facteur ×28/25 = ×1.12 sur UN champ : la route **f18** (112 ou 1120, PERSISTANTE — la recompute ne réécrit jamais f14/f18, PROUVÉ v444c) ou la route **base** (0x10B07600 µW, VOLATILE — la recompute réécrit les bases) ; **les routes = EXCLUSIVES** (les deux = 313 600 mW) | **PROUVÉ (calculé, jamais deviné)** — le tableau §4 |
| la chaîne d'écriture ? | le write-primitive = le gadget 0x100b3e (émulateur-PROUVÉ) ; **0 work-gadget** (ld/addi sur a-regs → ret) dans le booter entier (le scan v444e, borné ±8 insns branch-free) → le a1-refresh = **pas constructible** → 1 écriture chirurgicale par invocation ; le scatter consécutif = inhérent (slot+1, wrap à 1) ; le chainable = 24 épilogues ra-reloading | **PROUVÉ (les bornes nommées)** — le design honnête §5 |
| le payload construit et validé ? | v444 : le ctx @0x488 + la liste D @0x500 (8 entrées) + la liste f18 @0x540 ; le C == le python **BYTE-EXACT dc0c1b40…** ; --test-444 = **9/9 PASS sur l'image réelle** (les 4 D u64 aux champs exacts, le f18 = 112 à obj+0x18, l'exclusivité des routes documentée par le test lui-même) | **PROUVÉ dans l'émulateur** — le jour machine = le runbook gaté |

## 1. TÂCHE A1 — l'évaluateur 0x1446d98 décodé EN ENTIER

### 1.1 Le prologue et la machine à phases — PROUVÉ

```
0x1446d98  c.addi16sp sp, -0x1f0        # le frame 0x1f0
0x1446db4  c.addi4spn  s0, sp, 0x1f0   # s0 = sp+0x1f0
0x1446db6  c.lui a5, 5 ; c.add a5, a0
0x1446dba  ld    s5, -0x168(a5)        # s5 = *(state+0x4E98) = l'OBJET 0x6d0
0x1446dbe  auipc s7, 0x2d49 ; addi s7, s7, 0x1e2   # s7 = 0x4190FA0 (data LOAD,
                                                 # la cellule de re-check, ZÉRO file-backed)
0x1446dc6  c.mv  s1, a0                # s1 = state
0x1446dc8  sd    a1, -0x1d8(s0)        # l'arg1 sauvegardé
0x1446de8  c.mv  s4, a2                # s4 = l'objet a2 (le RECEVEUR de la sortie)
0x1446dea  c.mv  s2, a3                # s2 = l'arg4
0x1446ddc  lbu   a4, 0(s5)             # obj->0x0 (le valide)
0x1446de2  lbu   a5, -0x158(a5)        # *(state+0x4EA8) = le BYTE DE PHASE
0x1446e2a-3c  beq a5, {1,2,3,4} → 0x1446E88 / 0x14470A0 / 0x1447146 / 0x1447188
0x1446e40-4a  (phase 0) a5++ ; sb a5, -0x158(a4)   # la phase avance
```

La fonction = GRANDE (≈0x1446d98..0x1447f00+, les branches lointaines
0x1447BFC/0x1447D7C/0x1447E4C/0x1447E8A) — et ses phases 2-4 appellent
**l'allocateur 0x18C373C et le release 0x18C3F80 avec LES MÊMES
descripteurs** (0x4190DE8/0x4190DC0, 21+ sites PIC dans le corps :
0x14471bc, 0x1447282, 0x1447326, 0x1447486, 0x1447562, 0x14475e0,
0x1447676, 0x14476de, 0x1447766, 0x14477cc, 0x1447870, 0x14478c2,
0x1447960, 0x1447bbc, 0x1447c4c, 0x1447c68, 0x1447d18, 0x1447d32,
0x1447d6a, 0x1447e94) : la machine à phases = un cycle
alloue-remplit-libère des sous-objets, la phase avance 1→4 puis
retourne à 0 (`c.addiw a5,1 ; andi 0xff ; bne a5,5` @0x14471a8-b0,
`sb zero` @0x14471b4).

### 1.2 Le bloc formule — COMPLET, y compris le gap 0x1446f3e-f44 — PROUVÉ

```
0x1446e0a  addi  s9, s4, 0x48          # s9 = a2obj+0x48 (la cellule tête)
0x1446e1e  sd    zero, 0x48(s4)        # a2obj+0x48 = 0
0x1446eb8  addi  s8, s0, -0x168        # s8 = sp+0x88 = LE BUFFER DE SORTIE
0x1446ebc  addi  a2, zero, 0x28        # memset(s8, 0, 0x28) — 5 slots u64
0x1446ec4  auipc ra, 0x79d ; jalr 0x360   # -> 0x1BE4224 (le memset, le MÊME
                                    # que la création : 0x1458d0e+0x78b000+0x516)
0x1446ecc  lw    a7, 0x65c(s5)         # a7 = le MASQUE obj->0x65c
0x1446ed0  auipc a2, 0x834 ; addi a2, a2, 0x450   # a2 = 0x1C7B320 !
0x1446ed8  addi  a0, s0, -0x148        # a0 = s8+0x20 = LA BORNE (4 itérations)
0x1446ede  addi  t3, zero, 0x30        # le pas des RECORDS (0x30)
0x1446ee2  c.li  a1, -1                # la SENTINELLE
0x1446ee4  addi  t1, zero, 0x64        # /100
0x1446ee8  addi  t4, zero, 0x3e8       # /1000
-- la boucle (4 itérations, k = a4 = 0..3) --
0x1446eec  c.lw  a5, 0(a2)             # a5 = groupe_table[k]  (u32, pas 4)
0x1446eee  and   a5, a5, a7            # & le masque
0x1446ef2  c.beqz a5, 0x5e             # inactif -> le slot reste ZÉRO (s8 += 8 quand même)
0x1446ef4  mul   a5, a4, t3            # a5 = k × 0x30 (le RECORD)
0x1446ef8  sext.w t5, a4
0x1446efc  c.add a5, s5                # a5 = obj + k*0x30
0x1446efe  c.lw  a3, 0x18(a5)          # record[k].f18 — c.lw SIGNÉ
0x1446f00  beq   a3, a1, 0x20          # f18 == -1  -> saute À 0x1446f20 :
                                     #   sw a3 (-1), 8(s8) = le marqueur ILLIMITÉ
0x1446f04-0a  t6 = (k+0x60)*0x10 + s5  # obj + 0x600 + k*0x10
0x1446f0c  lwu   t6, 0x18(t6)          # base[k].D = obj+0x618+k*0x10 — lwu ZÉRO
0x1446f10  c.slli a3, 0x20 ; c.srli a3, 0x20   # f18 -> u32 (le signe ANNULÉ)
0x1446f14  mul   a3, t6, a3            # u32 × u32 (le produit 64-bit)
0x1446f18  divu  a3, a3, t1            # /100
0x1446f1c  divuw a3, a3, t4            # /1000 (u32)
0x1446f20  sw    a3, 8(s8)             # le slot k+1, u32 @+0 = la LIMITE
0x1446f24  c.lw  a3, 0x14(a5)          # record[k].f14 — c.lw SIGNÉ
0x1446f26  beq   a3, a1, 0x20          # f14 == -1 -> saute À 0x1446f46 : le
                                     #   store @0x1446f48 SAUTÉ = le slot @+0xc reste 0
0x1446f2a-32  a5 = obj+0x600+k*0x10 ; lwu a5, 0x18(a5)   # base[k].D encore
0x1446f36  c.slli a3, 0x20 ; c.srli a3, 0x20   # f14 -> u32
0x1446f3a  mul   a5, a5, a3
0x1446f3e  divu  a5, a5, t1            # /100 SEULEMENT (le gap 4.43 = ceci :
0x1446f42  sext.w a3, a5               #   sext.w AVANT le store)
0x1446f46  c.addiw a4, 1               # k++
0x1446f48  sw    a3, 0xc(s8)           # le slot k+1, u32 @+4 = la 2e valeur
0x1446f4c  andi  a4, a4, 0xff
0x1446f50  c.addi s8, 8                # le slot suivant (AVANCÉ même si sauté)
0x1446f52  c.addi a2, 4                # le pointeur de table += 4
0x1446f54  bne   a0, s8, -0x68         # tant que s8 != la borne
```

**Les faits nouveaux vs 4.43** : (a) la table de match = **0x1C7B320**
(u32 {0x1, 0x4, 0x8, 0x2, …}, le pas 4, 4 entrées consommées) — la
cite 4.43 « {0x1024, 0x1026} @0x1C7B450 » = une glissade d'arithmétique
PIC (0x1446ed0 + 0x834000 + 0x450 = 0x1C7B**320** ; la table 0x1C7B450
= stride 0x10, NON référencée dans la boucle) ; (b) les sentinelles
**−1** : f18 = −1 → le marqueur 0xFFFFFFFF STOCKÉ (illimité), f14 = −1
→ le store sauté (le slot reste 0) — asymétrique, byte-provable ; (c)
les loads = `c.lw` signé + la normalisation u32 immédiate → le produit
= **u32 × u32** ; (d) la borne = **4 itérations** (a0 = s8+0x20), le
5e slot = zéros de memset.

### 1.3 La destination exacte de la sortie 0x28 — PROUVÉ

```
0x1446f58  lw    a5, 8(s5)             # obj->0x8
0x1446f5c  bne   a5, a4, 0xe20         # obj->0x8 != 4 -> lointain (0x1447D7C)
0x1446f60  ld    a3, -0x1d8(s0)        # a3 = l'arg1 (l'objet source)
0x1446f64  addi  a2, zero, 0x28
0x1446f68  c.mv  a1, s9                # a1 = a2obj+0x48
0x1446f6a  addi  a0, s0, -0x160        # a0 = sp+0x90 = le slot 1 du buffer
0x1446f6e  auipc ra, 0xffff9 ; jalr -0x4c2   # -> 0x143FAAC
```

0x143FAAC décodé : `sd a4(-1), 0(a1)` ; puis `portMemCopy(dst=a1+8,
dstSize=0x20, src=a0, srcSize=0x20)` — **0x18BDA10 = portMemCopy
(dst, dstSize, src, srcSize)**, PROUVÉ par son corps (les checks
d'overlap `bltu`, l'alignement `or/andi 7`, la copie `c.ld/c.sd`) ;
puis `(*(s2+0x1a0))(s2, buf)` — un VMETHOD de l'arg1 — et `[a1] = le
résultat`. **Donc : les 4 paires (32 B = les slots 1..4) = copiées à
obj2+0x50, et obj2+0x48 = le résultat u64 du vmethod +0x1a0 de l'arg1.**
La lecture 4.43 « stockée à +0x48/+0x7F8/+0x8E8/+0x958 » = corrigée :
les ZÉROS u64 = {+0x48 (@0x1446e1e), +0x7F8 (@0x1446fa4), +0x8F8
(@0x1446fe8 — 4.43 disait 0x8E8), +0x958 (@0x144700c), +0x7C8
(@0x14470dc), +0x9B8 (@0x144724a)} ; **+0x8E8 = l'ARGUMENT a2 du call
0x1440944 (@0x1446fb6 = c.add a2, s4), PAS un store**.

## 2. TÂCHE A2 — le remplissage des bases et les descripteurs

### 2.1 La recompute 0x143fdbc : le WRITE SET complet — PROUVÉ (nouveau)

```
0x143fe1c  lui a3, 0x20809 ; c.addi a3, 9      # l'événement 0x20809009
0x143fe2a  c.jalr a6                           # via *(state2+0x4000+0x138)
0x143fe34  lw  a5, -0x5c(s0)                   # buf+4 = le masque
0x143fe3e  sw  a5, 0x65c(s1)                   # obj->0x65c = le masque
0x143fe4a  memset(list_buf, 0, 0x208)          # s8 = sp-0x210
0x143fe52  auipc s7, 0x83b ; addi 0x4ce        # s7 = 0x1C7B320 (LA MÊME TABLE)
0x143fe5a  auipc a1, 0x83b ; addi 0x4d6        # a1 = 0x1C7B330 = table+0x10
                                               #   = 4 ENTRÉES (pas {0x1,0x4} !
                                               #   la cite 4.43 = 2 sur 4)
0x143fe66-80  la boucle de match : list[k*0x10+8] = table[i] (les bits actifs)
0x143fe94  lui a3, 0x20809 ; addi a3, 0x64     # l'événement 0x20809064
0x143fe98  sw  a6, 4(s8)                       # list[4] = le compte
0x143fea8  c.jalr a7                           # LE REMPLISSEUR des valeurs
-- la boucle d'écriture (4 itérations, les groupements actifs) --
0x143feb6  addi a1, s1, 0x64c                  # le miroir : obj+0x64c+k*4
0x143fec0  addi t3, zero, 0x30                 # le pas 0x30 ICI AUSSI
0x143fece  mul  a4, a3, t3                     # k × 0x30
0x143fed8  c.lw a0, 0xc(a2)                    # list[k]+0xc
0x143fee0  c.sw a0, 0(a1)                      # miroir[k] = list[+0xc]
0x143fee2-ee  t5=list+8, t4=list+0xc, a6=list+0x10, a0=list+0x14
0x143fef0  c.add a5, s1                        # a5 = obj + 0x600 + k*0x10
0x143fef2  sw  t4, 0x10(a5)                    # B[k] @obj+0x610+0x10k <- list+0xc
0x143fef6  sw  t5, 0xc(a5)                     # A[k] @obj+0x60c+0x10k <- list+8
0x143fefa  sw  a6, 0x14(a5)                    # C[k] @obj+0x614+0x10k <- list+0x10
0x143fefe  c.sw a0, 0x18(a5)                   # D[k] @obj+0x618+0x10k <- list+0x14
0x143ff00  add a5, s1, a4                      # a5 = obj + k*0x30 (LE RECORD)
0x143ff04  sw  zero, 0x1c(a5)                  # record[k].+0x1c = 0
0x143ff10  c.sw a4, 0x10(a5)                   # record[k].+0x10 = list[+0xc]
0x143ff1a  c.sw a3, 8(s1)                      # obj->0x8 = le compte
```

**Le write set de la recompute = {0x65c (le masque), 0x60c-0x658 (les
quatre tableaux A/B/C/D, le pas 0x10), le miroir 0x64c-0x658 (le pas 4,
= la copie de B), record[k].{+0x10, +0x1c}, obj->0x8 (le compte)} — et
NE TOUCHE JAMAIS record[k].{+0x14, +0x18} (f14/f18)** — les deux champs
que la formule multiplie. C'est LA preuve de persistance de la route
f18. (La lecture 4.43 « le match contre {0x1, 0x4} » = la moitié : la
recompute matche les MÊMES 4 entrées que l'évaluateur.)

**Les valeurs = pures runtime** : les A/B/C/D = les u32 du RÉSULTAT du
vmethod 0x20809064 (la liste 0x208), pas de constante, pas de
descripteur.

### 2.2 Les descripteurs allocateurs — file-backed OUI, porteurs de valeurs NON — PROUVÉ

v444b : les phdrs du conteneur relus (4 phdrs, le data LOAD @0x4000000)
; 0x4190DC0 et 0x4190DE8 = **dans filesz** (offsets fichier 0x102BDC0 /
0x102BDE8) — et les 0x80 octets dumpés = **TOUT ZÉRO** (u32x32 = 0). La
cellule de re-check 0x4190FA0 (le xor final de l'évaluateur
@0x1446e4e-e5a) = **zéro aussi**. Lecture : les SLOTS descripteurs
existent dans le fichier (le modèle descriptor-linked de 4.37) mais les
POINTEURS de ctor/refs = écrits au runtime par l'init RM (l'allocateur
0x18C373C fait `ld a5, 0(s2) ; c.jalr a5` @0x18c3844-4a — le premier
u64 du descripteur = un pointeur de fonction APPELÉ — il ne peut pas
être zéro à l'exécution). **L'objet naît memset-zéro** (0x1458d08-d12 :
a2=0x6d0, a1=0 → 0x1BE4224). **La voie descriptor pour les valeurs =
MORTE ; les graines = pures runtime.**

Correction au passage : les DEUX calls de création (@0x1458cf8 et
@0x1458d20) ciblent **tous deux 0x18C373C** (0x18C3CF8−0x5BC et
0x18C3D20−0x5E4) — la cite 4.43 « 0x18C3734 » = une glissade
d'arithmétique (0x18C3734 = l'épilogue du voisin, `c.ldsp s3, 8(sp) ;
c.addi16sp sp, 0x30 ; c.jr ra`). Le compagnon = le MÊME allocateur avec
(desc 0x4190DC0, taille 8). Et 0x18C3F80 = le RELEASE (le décrément de
refcount `c.lw a4, 0x18(a5) ; addiw a4,-1 ; c.sw` @0x18c3f9c-fac), pas
un second allocateur.

### 2.3 Les écrivains de record.f14/f18 — le négatif borné — PROUVÉ (négatif)

La chasse (v444c, [0x143f000-0x1448000)) : le pas ×0x30 (t3=0x30
matérialisé, l'encodage exact 0x03000E13) = **2 sites dans toute
l'image** (la recompute 0x143fece + l'évaluateur 0x1446ef4). Les stores
{+0x14,+0x18} de la famille (0x14407f8/fc, 0x144083a, 0x1440882,
0x1440d12) = des compteurs **0xc-stride sur d'autres objets** (les
sous-objets de phase), pas les records ×0x30. **Aucun écrivain de
f14/f18 nommable statiquement** — le négatif = borné à la fenêtre et à
la méthode (le mur runtime-bind 4.16 prédit le reste : les vmethods /
le chemin RPC object-create 4.37).

## 3. TÂCHE A3 — le croisement avec les captures : INDECIDABLE-BY-BYTES

- **edpp_payload_1616.bin** : 9 u32 non-nuls = 4 header {hClient,
  hObject, cmd 0x2080d031, paramsSize 1544} + les 5 params bancés 4.24
  {255, 3, 257, 257, 250000@104}. Le solveur de paires (tout {x, y}
  dans une fenêtre ±32 B, x×y divisible par 100000, le quotient ∈
  {250000, 240000, 100000}) : **0 solutions**. La capture send ne
  contient PAS la sortie de la formule (le handler 0x11267fc ne lit
  même pas les params — 4.24 §5).
- **Les dumps recv** : les hooks 4.25/4.26 = armés, **JAMAIS exécutés**
  — 0 fichiers de capture dans le repo (le négatif borné à ce repo).
- **Le scan d'unités statique** (v444d, rm.elf + conteneur entiers) :
  {250000, 240000, 250000000, 240000000, 100000000} = **0 u32** (les
  formes µW = nouvelles ce pass ; 100000 = 5 hits = les jumeaux de
  temps bancés 4.21/4.32).
- **Verdict** : l'équation ne se résout pas par les données aujourd'hui.
  La famille des paires stock cohérentes avec limit = 250000 :
  **percent (base=250,000,000 µW, f18=100)** — la lecture physiquement
  cohérente (/100 = l'échelle pourcent, /1000 = µW→mW) — et
  **permille (base=25,000,000, f18=1000)** — l'alternative
  arithmétique. **L'expérience qui décide = U2** (le runbook) : écrire
  f18 += 1 et lire nvidia-smi — 252 500 mW → percent ; 250 250 mW →
  permille ; le delta = 2.25 W, lisible, mild, réversible.

## 4. TÂCHE A4 — LA TABLE des valeurs (calculée, jamais devinée)

La structure PROUVÉE par idx (k = 0..3, l'index du groupe) :

| champ | adresse | le load | le rôle |
|---|---|---|---|
| record[k].f14 | obj+0x14+k*0x30 | c.lw (signé, sentinelle −1 = store sauté) | le multiplicande /100 |
| record[k].f18 | obj+0x18+k*0x30 | c.lw (signé, sentinelle −1 = 0xFFFFFFFF stocké) | le multiplicande /100/1000 |
| base[k].D | obj+0x618+k*0x10 | lwu (zéro) | la base multipliée |
| A[k] | obj+0x60c+k*0x10 | (recompute : list+8) | le voisin du D[k] u64 |
| miroir[k] | obj+0x64c+k*4 | (recompute : = B[k]) | le voisin du D[3] u64 |

La sortie par groupe : {D×f18/100/1000, D×f14/100} = les slots 1..4 →
obj2+0x50 (32 B).

**La modification minimale pour 280000** (×28/25 = ×1.12 sur UN
facteur) :

| route | le champ | la valeur (percent) | la valeur (permille) | la persistance |
|---|---|---|---|---|
| **f18** | obj+0x18+k*0x30 ← u64 {112, 0} | 112 = 0x70 | 1120 = 0x460 | **PERSISTANTE** — la recompute ne réécrit jamais f14/f18 (v444c §2.1) ; le voisin +0x1c = le champ que la recompute ZERO à chaque passe (0x143ff04) = le u64 auto-réparé |
| **base** | obj+0x618+k*0x10 ← u64 {0x10B07600, 0} | 280,000,000 µW | 0x1AB3F00 | **VOLATILE** — la recompute réécrit les A/B/C/D depuis les événements ; la fenêtre = entre 0x20809064 et l'évaluateur (4.43 §5) |
| **les deux** | — | **313 600 mW — l'OVERSHOOT** | | **EXCLUSIVES** — le piège que le test TF-C documente (9/9 inclut ce check négatif) |

L'exactitude : f18×28/25 = entier ssi 25 | f18_stock (100 ✓, 1000 ✓) ;
base×28/25 = entier ssi 25 | base_stock (2.5e8/25 = 1e7 ✓, 2.5e7/25 =
1e6 ✓). Les DEUX lectures = exactes — l'U2 décide laquelle.

## 5. TÂCHE B — la chaîne d'écriture concrète

### 5.1 La voie descriptor = MORTE (le verdict)

Le chemin statique→runtime cartographié : les slots descripteurs
(file-backed ZÉRO) → l'init RM écrit les fn-ptrs/refs → l'allocateur
0x18C373C appelle `*(desc)` (le ctor) → l'objet **memset-zéro** → les
phases de l'évaluateur allouent/libèrent les sous-objets → la recompute
remplit les bases depuis les événements. **Patcher les descripteurs
AVANT l'allocation ne peut pas semer 280 : le fichier porte des zéros
et le memset tue tout ce qui viendrait du descripteur.** La recompute
écrase-t-elle les bases ? OUI — PROUVÉ (§2.1 : les 4 tableaux réécrits
à chaque passe depuis l'événement 0x20809064). Les records f14/f18 =
hors du write set (la persistance).

### 5.2 La voie gadget : l'inventaire re-commis et le design honnête

v444e (bootloader.bin, VMA 0x100000, 0x6d000 B) : **84 rets = 84
c.ret** (0x8082, 2 octets — le compte bancé 4.40 reproduit ;
bootloader.asm = 515 auipc, 84 ret ✓) ; **24 chainable** (les
épilogues `c.ldsp ra, off(sp) ; … ; c.addi16sp sp, step ; ret` — les
pas {64, 32, 48, 16, 496}) ; **0 work-gadget** (ld/addi/mv sur a-regs
→ ret, borné ±8 insns branch-free, le scan avant ET arrière) — les
épilogues ne restaurent que s-regs/ra (les a-regs = caller-saved).
**Le design qui découle des octets** :

1. **L'écriture chirurgicale** (l'invocation gadget-mode 0x100b3e,
   a3=1) : write #1 = **[a1-registre]**, puis l'update du slot et le
   compteur [dest] += 1 (les effets de bord du ctx fabriqué — le ctx
   = un bloc scratch, pas l'anneau booter). Le epilogue `addi sp, sp,
   0x50 ; ret` = le pop du lien suivant.
2. **Le scatter consécutif** (a3=N) : les writes #2..N = [ctx.dest +
   slot*8], le slot avance de 1 (le wrap à 1, jamais 0) — **on ne peut
   pas sauter des slots**.
3. **Le a1-refresh entre invocations = PAS constructible** (0
   work-gadget) → les cibles NON-consécutives (les records f18,
   espacés 0x30) = **1 cycle de hijack PAR écriture** (4 cycles pour
   les 4 records ; la ré-entrée = le spin pass-III, non prouvé).
4. **La chaîne D (les 4 bases) = UNE invocation** : dest = obj+0x610,
   a1 = obj+0x618, a3 = 8, la liste [D0, D0, P, D1, P, D2, P, D3] —
   les D u64 = aux slots impairs {dest+8, dest+0x18, dest+0x28,
   dest+0x38}, les P = les clobbers {B[1..3],C[1..3]} (nommés : aucun
   lecteur de A/B/C dans le census 4.43, la recompute les réécrit =
   auto-réparé) + la cellule compteur [dest] = {B[0],C[0]} += 8 (même
   classe).
5. **Le paramètre runtime** : obj = *(state+0x4E98) — l'adresse heap
   n'existe pas statiquement ; le payload = le placeholder, le jour
   capture le résout (le garde dest≠0 du runbook = le TT-D : dest=0 →
   la boucle inerte, l'injection silencieusement morte).

### 5.3 La comparaison honnête des deux voies

| critère | la voie descriptor | la voie gadget (v444) |
|---|---|---|
| le mécanisme | semer les valeurs dans les slots 0x4190DC0/DE8 avant l'alloc | le memdesc signature → la transfer-list → 0x100b3e |
| la couverture signature | les slots = dans le data LOAD file-backed — **la couverture de signature du data LOAD = UNDECIDABLE-BY-BYTES** (le verdict 4.30 tient) | le memdesc = déjà prouvé copié par le driver (kernel_gsp.c:5697, 4.42) |
| l'effet sur l'objet | **NUL** — le fichier = des zéros ET le memset de création | réel (les D ou les f18) |
| la persistance | — | f18 = persistante (la recompute ne touche pas f14/f18) ; base = volatile (la fenêtre) |
| le risque RM-degraded | nul (morte) | le clobber {B,C} = auto-réparé ; l'overshoot si les DEUX routes (le TF-C) ; la sémantique f18/f14 non nommée côté écrivain (le négatif §2.3) — **la leçon FE01 : l'U2 AVANT le 280** |

## 6. TÂCHE C — le payload construit et validé

### 6.1 Le builder v444 + le byte-exact (v444f 3/3 PASS)

`lab/jalon411/v444_transfer_list_build.py` (+ JSON + v444_payload.bin
sha256 85d771149f581225…) : le layout = le ctx {slot0, cap, dest,
magic} @0x488 (l'héritage 4.42) + la liste D (8 u64) @0x500 + la liste
f18 (4 u64) @0x540, le remplissage 0xFF ailleurs. Le C
(`tools/booter-patch/transfer_list_memdesc.c`, tl_build_payload_444)
== le python **BYTE-EXACT sha256 dc0c1b405210419f…** (la config dest
0x12345678) ; le C 4.42 = 4/4 intact ; la paire bancée e85c14d5…
reproduite. Le contrat registres (le dump = le plan JSON) : a0=~0,
a3=N, a7=0, a1=la cible, a4=payload, sp+8=&liste.

### 6.2 --test-444 : 9/9 PASS sur l'image RÉELLE

| test | l'oracle | résultat |
|---|---|---|
| TF-A le scatter D E2E (a3=8, le payload commis pilote la vraie boucle) | les 4 D u64 = 0x0000000010B07600 aux champs exacts obj+0x618/0x628/0x638/0x648 ; les clobbers {B,C} = 0 ; [dest] = 8 ; le ctx slot = 8 ; ret propre | **PASS ×4** |
| TF-B le f18 (a3=1) | obj+0x18 = 0x0000000000000070 {112, 0}, ret propre | **PASS ×2** |
| TF-C la formule re-vérifiée | la route f18 SEULE = 280000 ; la route base SEULE = 280000 ; **les DEUX = 313600 (l'exclusivité — le check négatif)** | **PASS ×3** |

La non-régression : selftest **5/5**, TT **11/11**. Le test a ATTRAPÉ
une vraie erreur de design pendant le développement (l'application des
deux routes = l'overshoot 313.6 W) — l'émulateur = l'oracle qui tient.

### 6.3 runbook-444.sh : le jour du break, gaté

Les étapes {prereq, resolve, payload, patch, restore, u2, apply280,
observe} ; les **7/7 checks** avec le refus automatique (le stock sha,
le payload byte-exact, les batteries émulateur 5/5+11/11+9/9, le C
3/3, **le garde dest≠0**, **la route UNIQUE**, **l'unité U2-décidée**)
; les gates RUNBOOK_444_ACK=1 sur u2 ET apply280 (le refus testé :
sans l'ACK = REFUSÉ immédiatement) ; les observables = nvidia-smi -q
-d POWER + nvidia-smi -pl 280 + RPCRECV + dmesg ; le rollback = le
revert driver (le firmware JAMAIS touché par ce runbook).

## 7. La réconciliation avec les passes précédentes

- **4.43** : la formule tient (mul/divu/divuw re-cités byte-exact par
  v444a) ; trois corrections de résumé (la leçon 4.42-L3 encore) : la
  table de match = 0x1C7B320 {0x1,0x4,0x8,0x2} (pas {0x1024,0x1026} @
  0x1C7B450), les itérations = 4 groupes (pas 5 vPstates), le second
  allocateur = 0x18C373C deux fois (pas 0x18C3734), les stores u64
  zéro = {0x48, 0x7F8, 0x8F8, 0x958, 0x7C8, 0x9B8} (0x8E8 = un
  argument).
- **4.42** : le format plat u64 + le gadget = confirmés et EXTENDUS
  (le mode gadget = l'écriture chirurgicale + le scatter consécutif) ;
  la table E1/E2 = remplacée par les cibles PROUVÉES de 4.44 (les
  records f18 = la cible persistante, les bases D = la cible fenêtre —
  E2 obj+0x660 = le champ du worker 0x14400c6, PAS un champ de la
  formule).
- **4.40** : le write-primitive = le cœur de la chaîne ; l'inventaire
  « 84 rets, 515 auipc » reproduit et la classification ajoutée (24
  chainable, 0 work-gadget — le négatif qui borne le design).
- **4.20/4.21/4.38** : « les limites = runtime data » — maintenant
  PROUVÉ avec le mécanisme complet ET le write set exact de la
  recompute ; la voie host-régkey (4.35/4.36) reste la lane SAFE
  complémentaire.
- **4.24/4.25** : la capture recv reste LE instrument de résolution du
  paramètre obj (et de l'U1) — le runbook-444 l'appelle.

## 8. Les leçons d'instrument

1. **Le résumé d'un pass ≠ le substrat** (la 3e occurrence) : les trois
   corrections 4.43 (la table, le compte d'itérations, l'allocateur)
   venaient de la relecture complète des fenêtres, pas des résumés.
2. **L'arithmétique PIC se fait par le code, jamais à la main** : les
   glissades 0x1C7B450/0x18C3734 = des additions mentales ; les
   instruments calculent les cibles auipc+addi (v444a pic_pairs).
3. **Le scan d'octets ≠ le compte d'instructions** : 84 c.ret (0x8082)
   byte-exact mais 515 auipc = le compte du LISTING asm (le scan d'octets
   seul lit aussi les données) — citer l'univers du compte.
4. **L'émulateur attrape les erreurs de SÉMANTIQUE, pas seulement de
   mécanisme** : le TF-C a converti l'overshoot 313.6 W (les deux
   routes ensemble) en un check négatif permanent.
5. **Le backward decode RVC = approximatif** : les fenêtres = les
   candidats ; tout gadget utilisé dans une chaîne = re-vérifié dans
   l'émulateur avant d'être cité.

## 9. La queue

1. **La résolution du paramètre obj** (le jour capture) : la capture
   4.26 + l'observation du heap ; le garde dest≠0 du runbook refuse
   l'injection non résolue.
2. **L'U2** (le f18 += 1) = la décision d'unité — le premier geste
   d'écriture de la campagne, gated ACK=1.
3. Le **a1-refresh** : si un jour le scan trouve un work-gadget (ou la
   ré-entrée pass-III = prouvée répétable), les 4 écritures f18
   deviennent UNE chaîne.
4. Les écrivains runtime de f14/f18 (le mur) : la capture les nommera
   (les records = le chemin RPC object-create, 4.37).
5. La lecture « 5 paires » du RatedTdp GET (4.21 §4) vs les 4 groupes +
   le slot zéro : la capture du response = l'arbitre.

## Discipline

Chaque hop = PROUVÉ (les octets cités : l'instruction, le VA, le JSON
de l'instrument) ou HYPOTHÈSE (le raisonnement étiqueté). Les comptes
bankés reproduits AVANT de produire (le tableau en tête). Les négatifs
bornés à leur méthode et leur périmètre (le work-gadget ±8 insns
branch-free ; les captures = ce repo ; l'unité = les octets
disponibles). Zéro résultat inventé : les valeurs 112/0x10B07600 =
calculées (×28/25), l'expérience U2 nommée pour le reste. Pas de
merge : branche `pass/4.44-runtime-values`, push, PR ouverte.
