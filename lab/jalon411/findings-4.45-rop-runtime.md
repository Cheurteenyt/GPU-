# 4.45 — la lane ROP runtime : le débordement du memdesc vers le contrôle
# du booter — la chaîne conçue, les murs nommés, la validation émulateur

Mission : prouver CHEZ NOUS le mécanisme du paper (Zenodo 20916112,
prouvé en silicium sur CETTE carte, le spin 0x4a7) — le memdesc copié
sur la pile du booter par un DMA non borné, le canari vaincu par
l'uniformité, le retour détourné vers notre chaîne ROP, le
write-primitive — et construire le payload + la validation émulateur +
le runbook gaté. Substrats : `bootloader.asm` (le booter plaintext,
NOTRE build), `booter_emu.py` (selftest 5/5, TT 11/11, TF 9/9),
`findings-4.40` (les gadgets), `findings-4.42` (le format plat u64, le
ctx), `findings-4.43/4.44` (les cibles runtime), `findings-444machine`
(le 0x1d = le memdesc = consommé au Booter Load). Instruments : v445a
(le scan du site de copie), v445b (la provenance des arguments), v444e
re-commis (les gadgets), v445_rop_payload_build (le builder), --test-rop
(TR 18/18), runbook-445.sh.

## La reproduction des comptes bankés (avant de produire)

| compte | bancé | reproduit ce pass |
|---|---|---|
| le census auipc rm.elf | 416,206 | **416,206 exactement** (v4440 re-run) |
| la loi de coordonnées | 512/512 | **512/512** |
| le census EDPp (v420) | 17/17 | **17/17, missing=[], extra=[]** (v443b re-run) |
| les WRITE-FIELD | 34/34 | **READ=20, WRITE=34, PASS=0** |
| booter_emu --selftest | 5/5 | **5/5** |
| booter_emu --test-transfer | 11/11 | **11/11** |
| booter_emu --test-444 | 9/9 | **9/9** |
| les gadgets du booter | 84 c.ret, 515 auipc | **84 (0x8082 bytes) + 515 re-assert (v445a) ; 24 chainable, 0 work-gadget (v444e re-run)** |

## Verdict first

| question du brief | ce que les octets disent | verdict |
|---|---|---|
| le site de copie memdesc→pile dans bootloader.asm ? | **ABSENT.** Le négatif quantitatif : 44 fonctions à frame, la plus grande = 0x620 (main) < 0x1000 (le memdesc n'entre dans AUCUNE pile du booter) ; **0 écritures pile dans les boucles** (le croisement écritures×boucles de v445a) ; les 10 appels du wrapper SBI {fn 0x20,0x21,0x22,0x23,0x25,0x2a,0x2b,0x2d,0x2e} = AUCUN bloc avec une destination pile (v445b) ; les memcpys internes = les destinations pile à taille LITTÉRALE (0x288), les tailles runtime = vers le WPR (les segments ELF) ou les globales DMEM fixes | **PROUVÉ (négatif borné)** : la copie = dans le BOOT ROM (fermé, immuable) — le consommateur identifié par le 0x1d (le stade s_executeBooterUcode = AVANT que le libos ne tourne) |
| le canari ? | le booter = compilé **SANS stack-protector** (0 suspect réel sur 4 flagués — les 4 = les stores de blocs d'args) ; le canari du paper = celui du ROM | le canari ROM = **INDECIDABLE-BY-BYTES** ; l'expérience = r0/r1 (le runbook) |
| l'ordre copie vs verify ? | notre image = muette sur le ROM ; le 0x1d de 4.44-machine = la compare a RUNT avec la pile intacte ; le spin 0x4a7 du paper = le hijack AVANT la compare | **INDECIDABLE-BY-BYTES** — l'expérience r0 (le mode de panne différentiel) décide |
| la chaîne ROP constructible ? | l'épine = PROUVÉE émulateur (les épilogues réels G40 @0x10022A, les pas 0x40 exacts) ; **trois murs structurels nommés** : W1 = 0 work-gadget → a1/a4 = le résidu ROM ; W2 = le 1er write = [a1] = SAUVAGE ; W3 = le ret du primitive = ré-entrée = le SPIN (l'état final du paper lui-même) | **Lane B = PROUVÉE en mécanique (TR 18/18) GIVEN le bloc de registres assumé ; Lane G (les gadgets ROM du paper @0xf754/0xf76c) = la lane constructible au stade ROM, silicon-prouvée sur CETTE carte** |
| la cible f18 ? | le mur du timing : l'objet 0x6d0 = alloué PAR LE RM après le boot ; au stade ROM la f18 = inexistante ; 5 options analysées (§2.3) — 4 mortes, 1 survivante (les registres MMIO, la route du paper) | **PROUVÉ (l'analyse)** : la lane ROP au stade ROM = n'atteint PAS la f18 — la cible survivante = la classe MMIO |
| le payload + la validation ? | le builder v445 (le layout calculé : la fill uniforme + l'épine à pas 0x40 + la walk-cell à l'index EXACT calculé + le ctx clone 0x488 + la liste 0x500) ; **--test-rop = 18/18 PASS sur l'image réelle** (la fill avale le canari, l'épine marche, les writes atterrissent, W3 démontré par le test lui-même) ; selftest 5/5 + TT 11/11 + TF 9/9 intacts | **PROUVÉ dans l'émulateur** — le jour machine = le runbook gaté |

## 1. TÂCHE A — le chemin de copie : le négatif borné et le consommateur

### 1.1 Le scan quantitatif (v445a)

Le substrat = bootloader.asm (l'image complète, 446,464 B, sha
ab90560bad520e65…). Les faits, machine-lisibles dans
`v445a_booter_copy.json` :

1. **44 fonctions à frame** ; les frames ≥ 0xa0 : {0x100c14: 0xc0,
   0x1011ba: 0x1f0, **0x101e0a: 0x620 (main)**, 0x10277a: 0xa0,
   0x102ce6: 0xb0}. La plus grande = 1568 B — **le memdesc (4096 B)
   n'entre dans aucune pile du booter** : aucun buffer pile ne peut
   contenir la copie entière.
2. **166 écritures pile hors frame-saves**, et **0 à l'intérieur des
   boucles** (le croisement write×loop) : AUCUNE boucle de copie ne
   cible la pile. La seule boucle d'écriture de l'image = la
   transfer-list (0x100aec, l'écrivain du ring, le ctx — PAS la pile).
3. **Le canari = ABSENT du booter** : le pattern stack-protector (le
   load d'un garde global + le store adjacent à ra + la compare
   d'épilogue) = 0 fonction réelle ; les 4 suspects = les stores des
   blocs d'args SBI (faux positifs inspectés un à un).

### 1.2 La provenance des appels privilégiés (v445b)

Les 10 sites du wrapper SBI (0x10045e) = les services {0x20, 0x21,
0x22, 0x23, 0x25, 0x2a, 0x2b, 0x2d, 0x2e} + les stubs directs
{a6=7/8/9/A}. Les blocs d'args = {fn, arg1..arg4} avec les valeurs =
les littéraux (0x1000000/0x200000 = les tailles WPR), les loads
d'objets ([s1+0x100/0x108/0x140/0x148] = les paires {addr, taille} du
bloc de boot — le fn 0x2a = la vérification par paires de régions),
**jamais une adresse pile destination**. Le memcpy interne
(0x1029f6) : (sp+0x328, sp+0x68, 0x288) = le ramassage interne à
taille littérale ; les copies à taille runtime ([a0+0x20] = le
p_filesz ELF) = le parseur ELF (la magie 0x464C457F @0x103720) vers
les adresses de chargement WPR — pas la pile.

### 1.3 Le consommateur du memdesc = le BOOT ROM

La chaîne des preuves : (a) le memdesc = la signature du booter (la
section .fwsignature_ga10x, le driver la copie à kernel_gsp.c:5697) ;
(b) le 0x1d de 4.44-machine = rapporté par
`s_executeBooterUcode_TU102` = l'étape de boot de l'UCODE du booter —
le libos n'a JAMAIS tourné dans ce boot ; (c) la vérification
cryptographique = absente de l'ELF (le verdict 4.31 re-confirmé : 0
constante crypto) ; (d) la copie = absente de l'ELF (§1.1). ⇒ Le
consommateur = le nvriscv BOOT ROM (fermé, immuable, mappé aux basses
adresses — le spin 0x4a7 du paper = DANS cette région). Le « booter »
du paper = le bloc de boot GSP (ROM + libos). La copie du memdesc sur
« SA PROPRE PILE » = le DMA du ROM pendant le Booter Load, AVANT
crt0. **L'adresse, la taille source, la destination et la borne = dans
le ROM = hors de portée des octets.**

### 1.4 Le canari et la distance — INDECIDABLE-BY-BYTES

Le canari = celui du ROM (le booter = sans — §1.1.3). Son emplacement,
sa valeur, la distance du débordement (le nombre de u64 du payload
jusqu'à l'adresse de retour) = les paramètres du paper, non
re-dérivables de nos octets. **L'expérience qui décide = r1** (le
runbook) : l'échelle du fill — la balayage de fill_len par pas de 8
u64, le critère = le changement de mode de panne. L'hypothèse de
travail = le canari-zéro (le ROM freestanding = pas de RNG au boot →
le canari = la valeur statique, probablement 0) — la fill uniforme à
0 = le candidat par défaut, ACK-gaté.

### 1.5 L'ordre copie/verify — INDECIDABLE-BY-BYTES

Deux observables bornent : (i) 4.44-machine = la pile intacte → la
compare a couru → 0x1d ; (ii) le paper = le débordement → le hijack →
le spin 0x4a7 → PAS de 0x1d. L'ordre compatible = la copie (le DMA)
d'abord, la compare à la fin, la fenêtre de hijack = entre les deux.
**L'expérience qui décide = r0** : le débordement bénin (le fill seul +
l'épine inerte 0x100aec avec le ctx zéro = INERT — le TT-D prouvé) —
si le mode de panne ≠ 0x1d, le verify = contourné = le hijack
confirmé ; si = 0x1d, **la lane = morte avant de coder** (le verdict
honnête de r0, la lane ne coûte qu'un boot).

## 2. TÂCHE B — la chaîne ROP, maillon par maillon, et les murs

### 2.1 L'épine (byte-proven, émulateur-proven)

Le retour détourné → les épilogues chainables (l'inventaire v444e
re-commis : 84 c.ret, 24 chainables, les pas {64,32,48,16,496}) → le
write-primitive 0x100b3e/0x100b48 → les écritures. L'épine retenue =
le MÊME épilogue répété : **G40 = 0x10022A** (l'ENTRÉE de l'épilogue
dont le ret = 0x10023a — le v444e banque les ret_va ; le slot de
chaîne = l'entrée, la leçon du premier run --test-rop : entrer au ret
= pc = ra = le résidu = le crash) :

```
0x10022a  c.ldsp    ra, 0x38(sp)   # le maillon suivant
0x10022c..36           s0..s5    # les pops des s-regs (le fill = le garbage inoffensif)
0x100238  c.addi16sp sp, 0x40      # le pas EXACT
0x10023a  ret                      # -> le slot suivant (0x38 = 7 u64 après l'entrée)
```

La math de l'épine (le modèle du hijack : pc = le slot de hijack, sp =
le slot d'après) : les slots de chaîne = fill_len, fill_len+8k
(0x40 = 8 u64) ; la walk-cell = **l'index calculé fill_len +
8·hops + 2** (= [sp+8] à l'entrée du terminal, EXACT — le builder le
calcule, jamais deviné).

### 2.2 Les trois murs structurels de Lane B (le cœur honnête du pass)

- **W1 — les registres.** 0 work-gadget (v444e re-run : ld/addi sur
  a-regs → ret, ±8 insns branch-free, les deux directions = 0). Les
  épilogues ne restaurent QUE ra + les s-regs. a1 (la cible) et a4 (le
  ctx) à l'entrée du terminal = **le résidu du ROM** — non
  constructibles dans le booter.
- **W2 — le write sauvage.** L'entrée gadget (0x100b3e) saute la tête
  de boucle : le corps écrit **[a1] D'ABORD** — a1 = le résidu = le
  write sauvage inhérent à Lane B. Le scatter (les itérations 2+) =
  contrôlé par le ctx (a4) — lui aussi le résidu.
- **W3 — le spin.** Le ret du primitive (0x100b7a) = pc = ra = le
  dernier pop = **le primitive lui-même** : la ré-entrée = la marche
  de la walk-cell sur notre pile = les écritures qui continuent puis
  le chaos — **l'état final que le paper OBSERVE (le spin 0x4a7)**.
  Le boot est déjà hijacké : le spin = accepté par le design (le reset
  = le chemin du driver, le timeout GSP).

⇒ **La lane constructible au stade ROM = Lane G : les gadgets du ROM
(@0xf754 write_value / @0xf76c write_addr dans le paper) — silicon-
prouvés sur CETTE carte, cités, non byte-vérifiables ici (le ROM
fermé).** Lane B = la mécanique byte-proven (TR 18/18) pour le jour J
SI le résidu R0 s'avère favorable — le runbook le teste d'abord.

### 2.3 LE problème central : le timing du write ROP vs l'allocation RM

La cible du brief = la route f18 (PERSISTANTE, 4.44 : 100 → 112 = 280
W) à obj+0x18+idx*0x30. **Au stade ROM, l'objet n'existe pas** (le RM
l'alloue après son boot ; la lane ROP = one-shot au Booter Load).
Les cinq options analysées :

| option | mécanisme | verdict |
|---|---|---|
| O1 le write f18 direct | [obj+0x18+k*0x30] = 112 | **MORT** — l'objet = le heap RM, post-boot ; le hijack = one-shot |
| O2 les adresses qui survivent à l'allocation | pré-semer le heap/l'image | **MORT** — l'objet naît memset-zéro (4.44 v444b PROUVÉ) ; aucun champ statique ne nourrit f18 (le négatif borné 4.44) ; la DMEM du booter = réinitialisée par le RM |
| O3 patcher les descripteurs/le code du RM (le WPR) | le write du ROM-stage dans l'image RM | **REFUSÉ** — la verify RM du booter l'attrape (le 0xb, prouvé 4.38) ; la couverture de la verify = le SBI = non démontrable par nos octets ; le risque RM-degraded = la leçon FE01 |
| O4 la graine dans les boot-params DMEM (0x16D000+) | survivre au stade booter | **MORT** — les params = consommés par le booter ; le RM = ses propres args (le WPR) ; aucun champ statique f18 |
| O5 les registres MMIO (la route du paper) | les PLM/FEAT via le write-primitive | **LE SEUL SURVIVANT byte-cohérent** — les registres = immédiatement atteignables au stade ROM, l'effet = l'application hardware qui survit à tout le boot ; le paper = la preuve silicium |

⇒ **La chaîne v445 = construite pour la classe MMIO (O5, la route du
paper). La f18 = le mur du timing : la lane ROP au stade ROM ne
l'atteint PAS** — la route f18 reste la lane RM-runtime (4.44), dont
le véhicule memdesc-replacement = falsifié (4.44-machine) et dont la
ré-entrée ROP = non prouvée. Les {valeur, cible} du payload v445 = les
placeholders (l'héritage 4.44 : la config = résolue au jour capture),
la mécanique = validée indépendamment des valeurs.

## 3. TÂCHE C — le payload et la validation émulateur

### 3.1 Le layout du payload débordant (v445_rop_payload_build.py)

4096 B = le memdesc (le DMA le copie ENTIER sur la pile — le
débordement = la partie au-delà du buffer ROM) :

```
u64 [0 .. fill_len)         la FILL UNIFORME (fill_value répété) — avale
                            le buffer ROM ET le slot canari (l'uniformité)
u64 [fill_len]              le slot de HIJACK = G40 (0x10022A)
u64 [fill_len + 8k]         les slots d'épine = G40 (les pas 0x40 exacts)
u64 [fill_len + 8·hops]     le TERMINAL = 0x100b3e (le write-primitive)
u64 [fill_len + 8·hops + 2] la WALK-CELL = &list[0] (l'index calculé)
u64 [0x91]                  le ctx clone {slot0=1, cap, dest, magic=8}
                            (l'octet 0x488 — l'héritage 4.42/4.44)
u64 [0xA0]                  la liste plate {valeurs} (l'octet 0x500)
```

Le sha commis = 4ee1f9737004f5cd… ; les paramètres = le bloc
d'assomptions EXPLICITE (A1 fill_len, A2 fill_value, A3 le bloc de
registres, A4 la base) — chaque assomption = l'expérience qui la
décide (le JSON).

### 3.2 --test-rop : 18/18 PASS sur l'image réelle

| test | l'oracle | résultat |
|---|---|---|
| TR-A la fill uniforme | [0, fill_len) = uniforme ; le slot canari (modèle u64 32) = avalé ; la taille = 0x1000 | PASS ×3 |
| TR-B l'épine | les OCTETS RÉELS G40 ×3 → le terminal ; les pas 0x40 EXACTS (sp final = 0x16a2c8) ; la walk-cell = [sp+8] = &list[0] | PASS ×3 |
| TR-C le primitive (a3=1) | [a1] = la valeur #1 (le sauvage = le scratch modélisé) ; le compteur [dest] += 1 ; le slot = slot0+1 ; **W3 : l'arrêt = la ré-entrée** (le primitive est retourné DANS lui-même) | PASS ×4 |
| TR-D le scatter (a3=3) | le sauvage #1 + le scatter #2/#3 = les valeurs aux [dest+(slot0+k)*8] (le ring avance) ; le compteur += 3 | PASS ×4 |
| TR-E E2E | le payload COMMIS (le sha du repo) pilote la chaîne entière ; le write atterrit ; la walk-cell avance | PASS ×4 |

La non-régression : selftest **5/5**, TT **11/11**, TF **9/9**. Les
deux leçons d'exécution attrapées PAR l'émulateur pendant le
développement : (i) le slot de chaîne = l'ENTRÉE de l'épilogue, pas
son ret (entrer au ret = pc = ra = le résidu = le crash) ; (ii) le
stop à la ré-entrée exige un prédicat sémantique (le compteur bumpé) —
le pc seul ne distingue pas la ré-entrée d'une itération de boucle
(l'émulateur a gagné un mode rearm_stop + stop_pred).

### 3.3 runbook-445.sh : le jour du break, gaté

Les étapes {prereq, payload, patch, restore, r0, r1, r2, observe} ; les
**8/8 checks** avec le refus automatique (les 4 batteries émulateur
5/5+11/11+9/9+**18/18**, le payload byte-exact vs le builder, les
comptes bankés 84/515, le garde dest≠0 + slot0≥1, la route unique) ;
les gates **RUNBOOK_445_ACK=1** sur r0/r1/r2 (le refus testé) ; les
chaînages : r1 exige r0 ≠ 0x1d (sinon LA LANE = MORTE — le refus
automatique), r2 exige la distance r1 ; les observables = nvidia-smi
-q -d POWER + nvidia-smi -pl 280 + dmesg (les codes booter) + RPCRECV
(le flux SBI) ; le rollback = le revert driver SEUL (le memdesc =
réécrit stock par le driver au boot suivant — le cycle ~10 min
prouvé 4.44-machine).

## 4. La réconciliation avec les passes précédentes

- **4.40** : l'inventaire = confirmé (84/24/0 re-commits) ; le
  write-primitive = le terminal de la chaîne ; la leçon d'EXÉCUTION
  nouvelle : les ret_va du scan = les rets, PAS les entrées — les
  slots de chaîne = les entrées d'épilogue.
- **4.42** : le format plat u64 + le ctx @0x488/0x490/0x498/0x4A0 =
  l'héritage direct du layout v445 (le ctx clone = DANS le payload) ;
  le ring-slot avance APRÈS le write (le TR-D documente la sémantique
  exacte du scatter : les #2+ = aux slots slot0+1..).
- **4.44** : la chaîne du transfer-list = la mécanique prouvée qui
  DEVIENT l'arme du débordement ; la table {valeur, cible} = les
  placeholders du payload ; la leçon FE01 = honnorée (O3 REFUSÉ).
- **4.44-machine** : le 0x1d = RE-INTERPRÉTÉ par ce pass avec les
  octets : le consommateur = le BOOT ROM (le stade s_executeBooterUcode
  = avant le libos), pas le libos lui-même — le « booter » du paper = le
  bloc de boot (ROM + libos). La lane falsifiée (le remplacement) et la
  lane ouverte (le débordement) = cohérentes avec CE consommateur.

## 5. Les leçons d'instrument

1. **Le scan banque les rets, la chaîne consomme les entrées** — les
   inventaires de gadgets = par VA de ret ; l'assemblage = par VA
   d'entrée. Le premier run --test-rop a crashé sur la confusion
   (l'émulateur l'a attrapé : pc = ra = le résidu = 0).
2. **La ré-entrée et l'itération = le même pc** — le stop d'émulateur
   par adresse est insuffisant quand la cible = une boucle : le stop
   sémantique (le prédicat d'état) = le seul oracle correct.
3. **Le négatif quantitatif exige le croisement, pas le décompte** —
   « 166 écritures pile » sans le croisement avec les boucles = rien ;
   le verdict = venu du croisement (0 écritures pile dans les
   boucles) + la borne des frames (0x620 < 0x1000).
4. **Le résumé d'un pass ≠ le substrat (4e fois)** — le « booter » du
   brief = le ROM + le libos ; le consommateur réel du memdesc =
   identifié par le stade dmesg (s_executeBooterUcode) et l'absence de
   la copie dans l'image, pas par l'intitulé de la lane.
5. **L'assomption explicite = le contrat du test** — le bloc de
   registres (W1), le fill_len (A1), le fill_value (A2) = modélisés
   dans l'émulateur et nommés dans le JSON : la validation = de la
   mécanique, jamais de l'innamé.

## 6. La queue

1. r0/r1/r2 (le runbook, le jour machine) : le mode de panne, la
   distance, les writes — les trois INDECIDABLE-BY-BYTES de ce pass.
2. Le résidu ROM (W1) : si r0/r1 prouvent le hijack, l'étape suivante =
   la découverte du bloc {a0, a1, a3, a4, a7} — le design = la sonde
   à ajouter au runbook (le write sauvage modélisé = le scratch).
3. Lane G : les adresses des gadgets ROM = à extraire du paper
   (silicon-prouvées sur CETTE carte) et à croiser avec nos cibles.
4. La route f18 = toujours la lane RM-runtime ; le véhicule =
   à ré-ouvrir (la ré-entrée ROP = non prouvée ; les surfaces
   post-verify = la leçon 4.44-machine #2).

## Discipline

L'evidence obligatoire (chaque claim = instrument-reproductible : les
JSON v445a/v445b/v445e + le TR 18/18 + les shas) ; les négatifs bornés
(§1 : la copie, le canari, l'ordre — chaque négatif = sa portée et son
expérience) ; les comptes bankés reproduits AVANT de produire (le
tableau en tête) ; l'exécution/machine = PAS notre terrain (le runbook
= gaté, ACK=1, le refus testé) ; PR sans merge, branche
pass/4.45-rop-runtime.
