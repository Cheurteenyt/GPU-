# 4.42 — the transfer-list built: the flat u64 format proven, the
# {value, target} table, the C memdesc patch, the emulator validation 11/11

Substrates: tools/analysis/gsp-extract/bootloader.asm (le booter
plaintext, NOTRE build — les lignes 976-1042 relues ce pass) ;
bootloader.elf (les phdrs + les octets) ; artifacts/pkg/firmware/
gsp_ga10x.bin (la section .fwsignature_ga10x, mesurée) ; le driver
ouvert 610.57.04 (kernel_gsp.c:5666-5713, fetché et cité) ;
tools/booter_emu.py (l'émulateur RV64, le 4.31, étendu ce pass).

## 0. The overall verdict

Le gadget 0x100b48 (`sd a5, 0x0(a1)`) = l'écriture d'une boucle
PLUS GRANDE que le résumé 4.41 : la fonction complète 0x100aec-0x100ba6
= l'EVENT LOGGER du booter, appelé 21 fois (le scan PIC ce pass), qui
copie une liste plate u64 depuis SA PROPRE PILE vers un ring buffer
persistant. La source n'est PAS "0x498(a4)" ; la destination n'est PAS
"0x498(a4)" non plus — 0x498(a4) = le POINTEUR du ring (la config).
Le format des entrées attendu par la boucle = **8 octets PLATS, PAS de
{valeur, next-ptr}** — l'hypothèse 16 octets du brief est FALSIFIÉE par
les octets. La capacité du memdesc signature = **512 entrées u64**
(4096 B / 8 B), pas 256.

## 1. TASK 1 — the transfer-list architecture (PROVEN, byte by byte)

### 1.1 Le décodage complet de la boucle (bootloader.asm l.976-1042)

```
100aec  addi  sp, sp, -0x50        ; frame 0x50
100aee..afa  sd a4/a1/a2/a3/a5/a6/a7, 0x30/0x18/0x20/0x28/0x38/0x40/0x48(sp)
          ; a1..a7 SAUVEGARDÉS — sp+0x18 = &a1 sauvé = LA TÊTE de source
100afc  auipc a4, 0x23
100b00  addi  a4, a4, 0x504        ; a4 = 0x124000 = le CONTEXTE GLOBAL
100b04  ld    a5, 0x490(a4)        ; la CAPACITÉ (slots u64)
100b08  beqz  a5, 0x100b78         ; cap==0 -> INERT (ret)
100b0a  ld    a5, 0x498(a4)        ; la DEST BASE (pointeur)
100b0e  beqz  a5, 0x100b78         ; dest==0 -> INERT
100b10  addi  a3, a0, 0x1          ; n = a0+1 = le nombre d'entrées
100b14  addi  a5, sp, 0x18         ; a5 = &a1 sauvé
100b18  sd    a5, 0x8(sp)          ; LA CELLULE DE MARCHE = sp+0x8 (init sp+0x18)
100b1e  li    a7, 0x0              ; i = 0
100b20  li    a5, 0x0
100b22  addi  a0, a0, -0x1         ; la borne du chemin spécial = a0-1
100b24/28  t3 = 0x16d000          ; le soustracteur de la signature
100b2c  srli a2, a2, 0x10          ; a2 = 0xFFFF (le masque)
-- la tête de boucle (par itération) --
100b2e  ld    a6, 0x488(a4)        ; le SLOT courant
100b32  ld    a1, 0x498(a4)        ; la dest base
100b36  slli  a6, a6, 0x3          ; slot*8
100b38  add   a1, a1, a6           ; a1 = dest + slot*8  (RECALCULÉ chaque tour)
100b3a  bgeu  a5, a0, 0x100b7c     ; i >= a0-1 -> le chemin spécial
-- le corps (le gadget 4.40) --
100b3e  ld    a5, 0x8(sp)          ; la marche
100b40  addi  a6, a5, 0x8          ; +8  <- LE PAS FIXE (pas de next-ptr lu)
100b44  ld    a5, 0x0(a5)          ; la charge = 1 u64
100b46  sd    a6, 0x8(sp)          ; la marche avancée
100b48  sd    a5, 0x0(a1)          ; L'ÉCRITURE
-- la mise à jour du slot (le wrap) --
100b4a  ld    a5, 0x488(a4)        ; slot
100b4e  ld    a1, 0x490(a4)        ; capacité
100b52  addi  a5, a5, 0x1          ; slot+1
100b54  bltu  a5, a1, 0x100b5a
100b58  li    a5, 0x1              ; slot = 1 (JAMAIS 0 — le slot 0 = le compteur)
100b5a  sd    a5, 0x488(a4)
-- le compteur d'itérations --
100b5e..b68  a5 = (a7+1) & 0xFFFFFFFF
100b6a  bltu  a5, a3, 0x100b2e     ; i+1 < n -> boucler
-- l'épilogue : le compteur persistant --
100b6e  ld    a4, 0x498(a4)        ; la dest base
100b72  ld    a5, 0x0(a4)          ; [dest] = LE COMPTEUR slot-0
100b74  add   a5, a5, a3           ; += n
100b76  sd    a5, 0x0(a4)          ; le compteur persiste entre les boots
100b78  addi  sp, sp, 0x50 ; ret
-- le chemin spécial (les 2 dernières entrées) --
100b7c  bne   a0, a5, 0x100ba0     ; i > a0-1 -> RDTIME
100b80..b88  (la charge suivante lue comme au corps)
100b8a  lbu   a6, 0x4a0(a4)        ; le MAGIC BYTE (le setup écrit 0x8)
100b8e  sub   a5, a5, t3           ; charge - 0x16d000
100b92  and   a5, a5, a2           ; & 0xFFFF
100b94  slli  a6, a6, 0x38         ; magic << 56
100b96  or    a5, a5, a6
100b9a  or    a5, a5, t1           ; | n << 48
100b9e  j     0x100b48             ; l'écriture SIGNATURE
100ba0  rdtime a5                  ; 1 tick = 1 ns (4.34)
100ba4  j     0x100b48             ; l'écriture TIMESTAMP
```

### 1.2 Les réponses aux questions du brief

- **Entrées de 8 octets, combien ?** Le memdesc signature = 0x1000 =
  4096 B (PROUVÉ : `.fwsignature_ga10x` = size 0x1000 dans NOTRE
  gsp_ga10x.bin, section table mesurée ce pass ; le driver alloue
  `NV_ALIGN_UP(signatureSize, 256)` = 0x1000) → **512 entrées u64 max**
  (chaque itération consomme 8 B). L'hypothèse {valeur, next-ptr} 16 B
  donnerait 256 — FALSIFIÉE : le pas = `addi a6, a5, 0x8` fixe, aucune
  seconde charge par entrée, aucun branchement sur un next lu.
- **Chaîne (self-walk) ou tableau plat ?** **TABLEAU PLAT.** Le
  "pointeur self-walk" = UNE cellule à sp+0x8 du frame (pas sp+0x18 —
  sp+0x18 = la VALEUR INITIALE de la marche = &a1 sauvé). Il avance de
  +8 par itération, mécaniquement. Les données = une suite de u64 sans
  structure liée.
- **La structure réelle par appel** : n = a0+1 entrées = (n−2) RAW +
  1 SIGNATURE `((dernier_raw − 0x16d000) & 0xFFFF) | magic<<56 | n<<48`
  + 1 TIMESTAMP `rdtime`. Le slot-0 de la dest = un COMPTEUR PERSISTANT
  (bumpé de n à chaque appel) ; le setup calcule le slot de reprise
  `([dest] % (cap−1)) + 1` — le ring SURVIT aux reboots.

### 1.3 Le contexte a4 = 0x124000, et le SETUP (l'appelant réel)

v442d : 74 accès mémoire dans [0x124400, 0x124500) ; les ÉCRIVAINS de
la config = la fonction setup @0x101e58-0x102302 (s0 = 0x124000, LE
MÊME bloc que le a4 de la boucle) :

```
1022ca  sb   a2(=0x8), 0x4a0(s0)   ; MAGIC = 0x8
1022ce  ld   a3, 0x20(a5)          ; [desc+0x20] = la taille du buffer
1022d0  ld   a4, 0x28(a5)          ; [desc+0x28] = le POINTEUR du buffer
1022d4  srli a5, a3, 0x3           ; capacité = taille >> 3
1022d8  sd   a5, 0x490(s0)
1022dc  sd   a4, 0x498(s0)
1022e4  ld   s2, 0x0(a4)           ; le compteur persistant
1022ea  remu s2, s2, a5-1          ; (0x102f97933 = remu s2,s2,a5)
1022ee  addi s2, s2, 0x1           ; slot = (count % (cap-1)) + 1
1022fa  sd   s2, 0x488(s0)
1022fe/02 jalr -> 0x100aec avec a0=1 (n=2), a1=0x16DFB0 (le label)
```

**21 sites d'appel** de 0x100aec (v442a, les paires auipc+jalr PIC,
imm20 SIGNÉ — le fix de la leçon 4.31-L7 re-bancé ce pass) : le booter
logge ses étapes de boot. Les labels pointent la région post-image
(0x16DFB0, 0x16E298 — au-delà de filesz 0x6d000, remplie au runtime).
Les cellules statiques (0x124488/90/98/4a0, 0x16C088) = ZÉRO dans
l'image → la boucle = INERTE sans le setup runtime (v442c).

## 2. TASK 2 — the {value, target} table for limitMax=280000

### 2.1 La correction de prémisse (les findings bancés)

Les offsets {limitMin@0x104, limitRated@0x108, limitMax@0x10c,
limitCurr@0x110, limitBattRated@0x114, limitBattMax@0x118} = les champs
des **params INTERNES 1544 B du RPC 0x2080d031** (4.38 §1.3), PAS de
l'objet EDPp 0x6d0. Le verdict 4.38 : cette lane = un template
userspace **jamais rempli** par ce build. L'objet policy (0x6d0,
pointeur à state+0x4E98) : le SEUL champ policy à offset statiquement
prouvé = **obj+0x660** (le résultat de la recomputation,
`sw a5, 0x660(s6)`, 4.20 §4). Les offsets des 6 limites DANS l'objet =
NON bancés (la queue 4.20 reste ouverte).

### 2.2 Les cibles : ni "depuis a4" ni absolues-dans-la-liste

- Le a4 de la boucle = le contexte du RING booter (0x124000), un autre
  univers que la policy RM.
- Le gadget écrit à **[a1] = une adresse ABSOLUE** (mode gadget) ou
  **[ctx+0x498] + slot*8** (le scatter, la base absolue portée par le
  ctx fabriqué). La liste ne porte QUE des valeurs ; les cibles = les
  registres/ctx ROP-résolus AU RUNTIME.
- **L'alignement** : le pas du scatter = slot*8 → toujours aligné 8 par
  rapport à la base ; c'est la BASE qui porte la phase. limitMax@+0x10c
  = 4 mod 8 : l'écriture u64 alignée = +0x108
  `{limitRated, limitMax}`. Une u64 à +0x104 = MISALIGNED (le risque
  trap RV64, nommé).

### 2.3 La table (l'encodage PROUVÉ : mW u32 LE — le transport
clientLimit mW 4.24 §2.2 ; le triplet {100000,240000,250000} capté,
runbook-426 §7.2 ; 280000 = 0x000445C0, 240000 = 0x0003A980)

| id | cible (runtime) | valeur u64 | le split u32 | la classe d'évidence |
|----|-----------------|-----------|--------------|----------------------|
| **E1** | params+0x108 | `0x000445C00003A980` | limitRated=240000 (conservé), limitMax=**280000** | l'alignement PROUVÉ ; l'EFFET policy = HYPOTHÈSE (la lane 4.38 = jamais remplie) |
| **E2** | obj+0x660 | u32 `0x000445C0` (l'u64 couvre {0x660,0x664} — le voisin +0x664 = INCONNU, risque nommé) | le résultat de recomputation = 280000 | le champ policy à offset PROUVÉ (4.20 §4) ; l'écriture = VOLATILE (le worker le réécrit) |
| **E3** | params+0x100/+0x108/+0x110/+0x118 | `0x????????000186A0` / `0x000445C00003A980` / RUNTIME / RUNTIME | la carte template complète | seul E3[1] est constructible statiquement — le reste exige la lecture runtime |

**La résolution runtime** (l'adresse du buffer params, le pointeur
[state+0x4E98] → obj) = le travail du chain ROP AVANT le gadget (les
gadgets ld de l'inventaire 4.40 = la suite nommée). La transfer-list ne
déréférence pas.

### 2.4 Les risques nommés

1. **obj+0x664 voisin** (E2) : inconnu, clobber par l'u64.
2. **La volatilité** : le worker de recomputation réécrit obj+0x660 ;
   l'écriture tient tant que la recompute n'est pas déclenchée/neutré.
3. **Le clamp réel** (4.38) = le heap x86 (le parse VBIOS) : l'écriture
   GSP-side = la surface policy RM, PAS le clamp host — la frontière
   4.38 tient.
4. **Le timing** : la policy object n'existe pas au stade booter ; la
   write-list E1/E2 suppose l'exécution AU STADE RM (le hijack
   persistant ou le gadget du RM = la suite).

## 3. TASK 3 — the memdesc patch kernel_gsp.c (the C + the test)

`tools/booter-patch/transfer_list_memdesc.c` :
- `tl_build_payload()` — le payload 4096 B : 0xFF (le pattern stock)
  hors [0x488]=slot0, [0x490]=capacité, [0x498]=dest, [0x4A0]=magic 0x8,
  la LISTE @0x500 (les u64 plats).
- `tl_patch_signature_memdesc(pSignatureVa)` — le drop-in appelé après
  le `portMemCopy` de `_kgspCreateSignatureMemdesc` (cité :
  kernel_gsp.c:5666-5713, le memdesc = `NV_ALIGN_UP(signatureSize,256)`,
  la source = `pGspFw->pSignatureData`) : écrase le contenu par la
  transfer-list (la liste E1 x3, la dest = runtime).
- Le test unitaire C (`-DTL_SELFTEST`) : 4 groupes d'invariants.
- **v442f_c_payload_test.py : 4/4 PASS** — gcc -Wall -Wextra propre ;
  le dump C == le builder python BYTE-EXACT (sha256 e85c14d5ccbeabfd…) ;
  les invariants indépendants.

La note 0xF800 : le nom historique du memdesc signature (STATE.md, les
7+ runs) ; la constante 0xF800 = ABSENTE du booter plaintext (le grep
ce pass) et la taille byte-prouvée du memdesc = 4096 B (0x1000). La
sémantique exacte du 0xF800 (la longueur DMA du metadata WPR ?) =
INDECIDABLE ce pass (les logs day0 hors workspace).

## 4. TASK 4 — the emulator validation (11/11 PASS)

`tools/booter_emu.py --test-transfer` (le mode ajouté ; rdtime
modélisé = le compteur déterministe, 1 tick = 1 ns 4.34) :

| test | l'oracle | résultat |
|------|----------|----------|
| TT-A le mode gadget (entrée 0x100b3e, a0=~0, a3=3) | [a1]=v1 puis le scatter [ctx.dest+(slot+k)*8] = v2,v3 dans l'ordre ; slot 2→5 ; [dest] += 3 | PASS ×3 |
| TT-B la boucle complète n=2 (la forme du setup, le ctx RÉEL 0x124000) | sig = `0802_0000_0000_0FB0` (le label 0x16DFB0 : (label−0x16d000)&0xFFFF \| 8<<56 \| 2<<48) ; rdtime = la valeur posée ; [dest] 6800→6802 ; slot 7→9 ; ret propre | PASS ×5 |
| TT-C le wrap | slot=cap → 1 (jamais 0) ; les écritures sautent au slot 1 | PASS |
| TT-D les gardes | capacité=0 → INERT, ret, [dest] intact | PASS |
| TT-E **E2E** : le PAYLOAD CONSTRUIT (le layout C/v442e) pilote la vraie boucle | E1=`0x000445C00003A980` aux 3 slots de dest, le ctx lu DANS le payload | PASS |

La non-régression : `--selftest` = **5/5 PASS** (la batterie 4.31
intacte).

## 5. Instrument lessons (banked)

1. **L'imm20 signé, DEUXIÈME leçon** : v442a a raté les 21 appelants
   (0xffffe = −2) jusqu'au fix — la leçon 4.31-L7 s'applique aux
   SCANS, pas seulement à l'émulation.
2. **Le mnemonique dans le regex des opérandes** (deux fois : v442a,
   v442d) : le split objdump = {mnemonic, operands} — les ancres
   d'opérandes n'incluent JAMAIS le mnemonique.
3. **Le résumé d'un pass précédent n'est pas le substrat** : le 4.41
   (6 lignes) appelait "flag=succès" le store du SLOT (0x488) et
   inversait source/dest — la relecture complète de la boucle a
   corrigé les deux.
4. **La capacité = une mesure, pas un souvenir** : le "4096" du brief
   a tenu (mesuré dans la section table), le "0xF800" du nom = resté
   non résolu — les deux traits séparés.

## 6. Next (the queue)

1. Les gadgets ld (le déréférencement) de l'inventaire 4.40 → la
   résolution runtime de [state+0x4E98] et de la base params.
2. La queue 4.20 : les offsets des 6 limites DANS l'objet 0x6d0 (le
   maréchal 0x14581f0 = la piste).
3. Le jour hardware : le payload v442e à la place du stall (le runbook
   existant, le rollback byte-exact).
4. La capture 4.26 (le recv hook) reste la route des données réelles.
