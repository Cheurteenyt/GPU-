# findings — PASS 4.31 : le hunt de la vérification de signatures dans NOTRE booter

Date : 2026-09-23. Mission : localiser l'équivalent de `booterVerifyLsSignatures_TU10X`
(paper « A Canary in the Crypto Mine », Zenodo 20916112 — LEUR build, @IMEM 0x29C4)
dans NOTRE booter 610.57.04, calculer les bytes patchés (NOP-safe) et préparer la
validation sans risque. Branche `pass/4.31-booter-verify-hunt`, PR ouverte, JAMAIS mergée.

Matériaux (committés, sha256 vérifiés en-session) :
- `tools/analysis/gsp-extract/binaries/bootloader.bin` — 446 464 o = 0x6D000,
  sha256 `ab90560bad520e65…` — le booter libos PLAINTEXT (= boot area de gsp_ga10x.bin).
- `tools/analysis/gsp-extract/bootloader.asm` — 5 397 lignes, objdump RV64
  (5 370 insns parsées), wrapper synthétique : header 64 o + 1 phdr 56 o,
  PT_LOAD#0 vaddr **0x100000** filesz 0x6D000 flags 5 (R-X), entry 0x100000,
  shnum=0 (aucun symbole). Coordonnées : VMA = 0x100000 + file offset.
- `tools/analysis/x86-rm/binaries/nv-kernel.o_binary` — 19 233 368 o,
  sha256 `48096db0…` (le substrat .ko 4.28).

Instruments livrés : `lab/jalon411/v431_booter_hunt.py` (+json, selftest **17/17**),
`lab/jalon411/v431b_capstone_relist.py` (+json), `tools/booter-patch/patch_booter.py`
(selftest **5/5**), `tools/booter_emu.py` (selftest **5/5**).

## 1. VERDICT T1 (la réponse directe à la mission)

**L'équivalent de `booterVerifyLsSignatures` N'EXISTE PAS comme routine
logicielle dans notre bootloader.bin — PROUVÉ par census exhaustif négatif.**
Le pattern du paper décrit une AUTRE couche de la chaîne. Evidence :

1. **Pas de primitive crypto logicielle** : tables SHA-256 (K, IV) absentes,
   SHA-1/MD5 IV absent, exposant RSA 0x10001 absent (scan byte-exact du binaire,
   v431_booter_hunt.json). Aucune boucle de comparaison de blobs 0x100/0x180.
2. **Pas de littéral canary 0xc0deca7e** (LE ni BE) dans le binaire ni dans l'asm.
3. **Les CSRs « primitives crypto Falcon » 0x7d5-0x7d9 du paper = ABSENTS de
   notre build.** Census CSR complet (v431, 26 lignes `csr*` parsées dont 20
   valides numérotées + 2 satp + 2 sscratch ; les 4 restantes = bytes de
   STRINGS désalignés `csrrci tp,0x2f6,0x6`@0x103c32 = '/src', `csrrsi`@0x103c5e
   = 'set ' — artefacts objdump nommés) : nos CSRs = **0x5ca/0x5cb/0x5cc/0x5ce/
   0x5cf/0x5d0/0x5d1/0x8d0** = le bloc de configuration de régions du core
   nvriscv-2.0 (voir §3.3), PAS de la crypto.
4. **L'interface sécurisée de NOTRE build = les ECALLS SBI** (a7=extension,
   a6=primitive, retour a0/a1-a3, convention SBI). Census exhaustif (8 ecalls) :
   `a7=0x900001EB` avec `a6∈{0=get-base, 7=report, 8, 9, 0xa=configure(ptr,0x40,
   0x200000, perms)}` + `a7=8` = le stub FAIL universel. **Aucune primitive
   hash/AES/RSA parmi elles.**
5. **Les adresses du paper sont toutes < 0x8000 = dans la BROM** (32 Ko) de
   LEUR carte : verify 0x29C4, dma_copy_block 0x4d4, image_auth_decrypt 0x2e80,
   __stack_chk_fail 0x7dd9/0x7de9. Leurs propres gadgets le confirment :
   0xcbd/0x1fbd/0x7f2f < 0x8000 (BROM), 0x815a/0x8e18 > 0x8000 (booter_load).
   La vérification LS vit dans la BROM (et/ou le BooterLoad chiffré, §4) —
   **pas dans l'ELF libos que nous détenons**.

## 2. Ce que notre booter EST (carte structurelle, tout PROUVÉ)

- **crt0 @0x100000** : `auipc t0,0x6c; addi t0,t0,0x80; lb t0,0(t0)` — lit le
  byte config @**0x16C080** (= file 0x6C080) ; non-nul → `j 0x1004d6` (path
  erreur/trap). Puis sp = 0x120000, `j 0x101e0a` (main).
- **Trap/fail @0x1004b2-0x1004d6** : gp = 0x1246B0 (init ×2 : 0x10048a,
  0x1004d6), sauvegarde s0-s11/ra/sp/sscratch sur [gp+…], `ecall` @0x1004d2.
- **main @0x101e0a** (frame 0x620, 3 804 o — TOUTE l'orchestration) :
  - byte build-flag @**0x121014** (statique = 0x01) → branche du flow ;
  - globals : struct dispatch **s0 = 0x124000**, config **s3 = 0x16C088**,
    **s5 = 0x16C090**, **s6 = 0x16C098** (bss, remplis au runtime par le
    loader — l'image statique y est tout-zéro, PROUVÉ par dump) ;
  - le contrat loader→booter : `[0x103F78]` = pointeur fourni au runtime
    (placeholder statique 0x2000000000000a00 — c'est la FRONTIÈRE du modèle
    émulateur, ST-B) ;
  - checks de fenêtres FB inline (0x10222a-0x1023c0) : l'adresse testée doit
    être dans **{0x55800000 exact} ∪ [0x24300000,0x44300000] ∪
    [0x05600000,0x11600000]** sinon saut vers le fail @0x101ea4 ;
  - **memmove @0x1029f6** (implémenté : copies à décalage par octets) appelé
    avec (sp+0x328, sp+0x68, **0x288**) = copie de la struct meta de 648 o ;
  - **recherche de composants par nom @0x10006e** (walk de liste chaînée) :
    3 appels aux sites `rm.bindata.bin` (@0x102618, fmt 0x103C78) et
    `rm.elf` (@0x102634, fmt 0x103C88) ;
  - **mapping de régions @0x100578** avec permissions **a3=3 (RW) ou 7 (RWX)**
    — les paires (offset,taille) de la meta aux champs +0x48/0x50, +0x58/0x60,
    +0xa0/0xa8, +0xd0/0xd8, +0x110/0x118, +0x140/0x148 ; le byte
    **[meta+0x198]** décide RWX vs RW (la région exécutable) ;
  - borne de taille : `[found+0x20] <= 0x400000` (4 Mo) @0x102660, et
    `[sp+0x58] = 0x200000` (2 Mo) @0x102676 ;
  - **appel par pointeur @0x1026c0** : `fptr([meta+0xE0], u32[meta+0xE8], meta)`
    où le fptr = **[OS_struct+0x4D8] = 0x1244D8 = 0x1014DC** (dernière écriture
    @0x10220a ; init @0x1013a4) — STRUCTURELLEMENT l'analogue du couple
    (signature buffer, sizeOfSignature) du paper, MAIS la fonction cible =
    un **range-check** (§3.2), pas de la crypto ;
  - **boot-params @0x168000** remplis @0x1026e0-0x102736 ([0x168448]=meta,
    [0x168460]=-1, [0x1684a0]=0xf, flags…) = le handoff vers le RM.
- **Les strings du booter** (8 seulement, '\n'-terminées) : la table
  `kernel_{gr10x,gb10y,gb20y,gb20x,gh100,ga10x,gb10x}.elf` @0x103B38 —
  les noms des RMs par famille, LE MÊME namespace que les records GFW de la
  carte 4.30 (`kernel_ga10x.elf` @record abs 0x6D030 !) ; le getter
  @0x1001c0 renvoie **'kernel_ga10x.elf'** (notre chip) ; `(null)`, l'assert
  libos `Runtime failure: a0 == 0 @ /gpu_drv/uproc/os/libos-v3.1.0/src/common/
  nvriscv-2.0/sbi.c:%d` @0x103BF8 (xrefs 0x102fd4/0x103a9e/0x103ada/0x103b16),
  `FB offset %llx fwWprStart %llx` @0x103C58 (xref 0x10227e — le print WPR),
  `rm.bindata.bin`/`rm.elf` @0x103C78/0x103C88, `0123456789ABCDEF` @0x103F28,
  `TOORGOL` @0x103F58 (non-xreffé).

## 3. La machinerie sécurisée RÉELLE de notre booter

### 3.1 Les stubs SBI (le remplaçant des CSRs crypto du paper)
- **0x103A70** : `ecall 0x900001EB, a6=0` → retourne la base (lue en a3 par
  le caller, convention SBI a0=err/a1-a3=valeurs) — appelé @0x1023a2 juste
  avant les checks de fenêtres FB.
- **0x103A7E** : `ecall a7=8` = **FAIL/halt** (l'oracle universel ; cible de
  tous les chemins d'échec : 0x101ea4, 0x1013aa, 0x1014e8…).
- **0x103A86** : `ecall 0x900001EB, a6=7` = **report/assert** (→ print via
  0x1011ba si l'ecall ne consomme pas l'événement).
- **0x103AC0-ish/0x103AF0-ish** : variantes a6=8/9 avec a1=t1.

### 3.2 Le dispatcher de handlers @0x1244A0-0x1244E8 (init @0x10134C)
La fonction @0x10134C : (1) set bit0 de [**0x145C400**] et compose
[**0x145C600**] |= 0x40000 (les regs de contrôle du core, accessibles via la
fenêtre mappée) ; (2) installe la table : [0x1244C0]=0x1014FA,
[0x1244C8]=0x10037A, [0x1244D0]=0x1000F0, **[0x1244D8]=0x1014DC**,
[0x1244A8]=0x101798, [0x1244B0]=0x1018C6… ; (3) range-check l'argument
contre [ctx+0xC0]/[ctx+0xC8].
**0x1014DC = le range-check** (cité : `ld a4,0x58(a2); ld a5,0x60(a2); add a0,a0,a4;
add a5,a5,a4; bgeu a0,a4,ok; …fail; 1014f4: bgeu a0,a5,fail; ret`) — valide
(arg+base) < (base+size) avec anti-wrap. C'est LA fonction appelée avec le
couple (buffer,taille) de la meta (§2).

### 3.3 Le bloc CSR région (nvriscv-2.0) — les clusters @0x1000F6-0x100176
(inline, config passée en a0) et @0x100A20-0x100AA2 (fonction, table statique
@0x124200 + count @0x124480, TOUS ZÉROS dans l'image statique → branchement
runtime) : `csrw 0x5d0,idx; csrw 0x5d1,val` (zéro-invalidation), puis par
entrée de 0x28 o {u64×4, u8 sel} : `csrw 0x5ca,idx; csrw 0x5cc,[+0x0];
csrw 0x5cb,[+0x8]; csrw 0x5ce,[+0x10]; csrw 0x5cf,(sel?0xC0003F:0x8003F) |
(([+0x18]<<24)&0x1F000000); csrs 0x5cb,1` — puis `satp=-1<<60; sfence.vma;
fence.i; csrw 0x8d0,0`. Les presets 0x8003F/0xC0003F = les deux attributs
de fenêtre. (Nommage comportemental ; les noms officiels nvriscv = HYPOTHÈSE.)

### 3.4 Le builder du MEMMAP (l'équivalent kgspBuildMemmap / la « WPR meta »)
- **@0x100258** (défauts) : remplit la struct = le champ +0x00=0x94, +0x08=0x40,
  +0x10=0x44, +0x30=0x10, +0x38=0x1280000, +0x40=0x80000, +0x48=0x303<<53,
  +0x58=−0x3FD<<53, +0xA0=1<<61, +0xA8=0x4000000, +0xB0=0x180000,
  +0xC0=0x1200000, +0x100=0x1040000, +0x108=0x120000, +0x140=0x1820000/0x1840000
  (sélecteur = byte config **0x16C081**), +0x148=0x1000, +0x120/0x128=composés,
  fill 0xFF sur [0x70,0x80), [0x70]=0x100, [0x72]=2.
- **Variantes par plateforme @0x101798 + wrappers 0x10182E/0x10184C/0x101872/
  0x1018A4** : +0xE0=0x1500000, +0xE8=0x400000, +0xF0=0x1580000, +0xF8=0x400000,
  +0xA8=0x10000000 (ou 0x4000000), +0x198=1 (RWX), +0x188/0x190…
  **Les champs +0xE0/+0xE8 lus par main comme (buffer,taille) = des constantes
  (offset FB 21 Mo, taille 4 Mo) dans ces variantes.**

## 4. T2 — les DEUX booters et le BINDATA de nvidia.ko (falsification de prémisse)

**La prémisse « patcher bootloader.bin dans nvidia.ko » est FALSIFIÉE** : notre
booter libos n'est PAS dans le .ko. Il y a DEUX binaires distincts :

1. **Le BooterLoad ucode (couche 1)** — embarqué dans nvidia.ko sous les
   symboles `kgspBinArchiveBooterLoadUcode_<chip>_BINDATA_LABEL_*` (anatomie
   extraite du symtab de nv-kernel.o_binary par patch_booter.py locate-ko ;
   valeurs GA102 **PROUVÉES**) : `HEADER` 0x1B o (×2 identiques PROD/DBG),
   **`IMAGE_PROD` 0x87D7 o = 34 775 o CHIFFRÉS** (sha256 609a7b3f…, haute
   entropie, ZÉRO match byte-exact avec notre plaintext : probes head/0x1000/
   strings négatifs), `IMAGE_DBG` 0x87D9 o, **`NUM_SIGS` = 2**, `SIG_PROD`
   0x1A4 o, `SIG_DBG` 0x300 o, `PATCH_LOC`=0x8A10, `PATCH_META` 0xC, `PATCH_SIG`
   4 o ; + le descripteur `__kgspGetBinArchiveBooterLoadUcode_GA102` (0xA8 o,
   {10, 3, …}). GA104 → le blob GA102. **Ce ucode est vérifié par la BROM
   (RSA-3K, clé fuse — le chain du paper §3 de 4.30) : tout patch de l'IMAGE
   exige un re-signing impossible.** Le tool REFUSE par construction.
2. **Le booter libos (couche 2)** — NOTRE bootloader.bin, porté PAR gsp.bin.

**Découverte conteneur (PROUVÉE, selftest ST2 run 1)** : `gsp_ga10x.bin` = un
**ELF64 RISC-V** (e_machine=0xF3, e_type=1, phnum=0, 19 shdrs @0x50673D8) et
le booter = **la première section : contenu bootloader.bin à l'offset conteneur
0x40** (byte-exact : b[:64]@0x40, b[0x21014]@0x21054 ; sha256 du boot area
0x40..0x6D040 = ab90560b… = la référence). Le répertoire GFW suit @0x6D040
(magic 4de1105c706ab281 = 0x81b26a705c10e14d LE, conforme à la carte 4.30).
**La prémisse 4.30 « boot area = [0,0x6D000) » était donc en coordonnées
de contenu, pas de conteneur — corrigée et documentée.**

**Livraison T2** : `tools/booter-patch/patch_booter.py` — locate-ko (anatomie
BINDATA du .ko installé, offsets fichier = la recette pour le .ko cible),
locate-gsp (vérification byte-exact du boot area), patch-gsp (sites
{offset fichier booter, old, new} avec refus si old-bytes ne matchent pas,
diff exacte rapportée), selftest 5/5. Les sites de check de CETTE image
sont exprimables en NOP-safe RISC-V : ex. le bgeu du range-check
**0x1014F4** (`fef57ae3` → NOP `13000000`, 4 o → 4 o, démontré §5) — en
coordonnées conteneur = **0x14F8**. NB honnête : ce sont des checks de
validation, pas la vérification cryptographique (absente de cet ELF, §1).

## 5. T3 — l'émulateur et la validation sans risque

`tools/booter_emu.py` : interpréteur RV64IMC (capstone 5.0.7 pour le décodage),
mémoire [0x100000,0x170000), sp=0x120000, CSRs capturés (0x140/0x180/0x5ca-0x5d1/
0x8d0), modèle SBI ecall (a7=0x900001EB a6=0 → a3=base modélisable --sbi-base ;
a6∈{7,8,9,0xa} loggés ; **a7=8 = l'oracle FAIL**), fence/sfence nop.

Selftest **5/5 PASS** (détails dans la sortie du tool) :
- **ST-A** : la trace PC des 10 premières instructions == l'objdump
  (avec la leçon : 0x100010 — le `j 0x1004d6` du path d'erreur — n'est PAS
  exécuté car le `beqz` @0x10000C est pris sur l'image statique) ;
- **ST-B** : crt0 + entrée de main exécutés (39 insns), frontière nommée =
  le contrat loader→booter ([0x103F78] fourni au runtime) ;
- **ST-C** : le path d'erreur du crt0 (byte config 0x16C081 forcé) atteint
  le trap @0x1004d2/0x10052a ;
- **ST-D — LE DÉMONSTRATEUR DE PATCH** : le range-check @0x1014DC dirigé avec
  a0=size (cas limite) : **ORIGINAL → oracle FAIL (ecall a7=8 via 0x103A7E)** ;
  **PATCHÉ (bgeu @0x1014F4 → NOP) → ret propre (ra sentinelle atteinte)** ;
- **ST-E** : le patch est NOP-safe et minimal : exactement les 4 octets
  0x14F4-0x14F7 diffèrent.

La méthodo de validation d'un patch, démontrée : (1) choisir le site check
prouvé, (2) exprimer le NOP à longueur d'instruction préservée (RISC-V :
remplacement 4→4 o ou 2→2 o), (3) émuler original vs patché sur les cas
acceptés ET rejetés, (4) exiger l'oracle FAIL sur l'original et le ret propre
sur le patché, (5) vérifier la diff minimale. **Application à la vérification
de signatures : BLOQUÉE en amont** — la fonction cible n'est pas dans cet ELF
(§1) et la couche qui la porte (BooterLoad chiffré) est couverte par la BROM.

## 6. Conséquences pour la campagne (le arbre de décision mis à jour)

1. Le **bypass driver-patch PROUVÉ sur cette GA104** (4.30 : _kgspCreateSignatureMemdesc,
   7+ runs) reste LE chemin de production — inchangé par ce pass.
2. Le patch du **booter libos plaintext** (couche 2, gsp.bin) est TECHNIQUEMENT
  _possible (l'outil + l'émulateur le permettent) mais sa cible utile serait
   la validation-layer, pas la crypto LS — et la couverture par signature du
   conteneur reste UNDECIDABLE-BY-BYTES (4.30 T3) → l'expérience one-boot
   tranchera avant toute campagne de patch booter.
3. Le patch du **BooterLoad chiffré** (couche 1, .ko) = hors de portée par
   construction (re-signing BROM impossible) — documenté, tool en REFUS.
4. La question du paper (« où est le test que l'on veut NOPer ? ») a sa
   réponse pour NOTRE stack : **dans la BROM** (non acquise) et/ou le
   BooterLoad (illisible sans la clé fuse) — les offsets du paper (0x29C4…)
   ne s'appliquent à aucun binaire que nous détenons.

## 7. Leçons bancées (bugs d'instrument attrapés et nommés)

1. **v431 run 1** : strings libos terminées par `\n` (pas NUL) + tables sans
   terminateur → double mécanisme d'acceptation.
2. **v431 run 1** : groupes regex non-capturants (REG) → group(1)=l'immédiat
   → xrefs vides ; groupes explicites requis.
3. **v431 run 1** : clusters CSR = proximité (gap ≤ 0x60), pas contiguïté ;
   ancre `$` invalide sur ops contenant des registres finaux.
4. **v431 run 2** : objdump `ld a5, -0x1da(a5)` — le displacement est
   PRÉCÉDÉ du registre : l'ancre de fin, pas du début.
5. **v431b** : capstone décode ~toute la mémoire (220 k insns) — usage
   dirigé uniquement.
6. **patch_booter run 1** : le conteneur gsp = ELF et le booter @0x40 —
   ST2 l'a attrapé avant tout patch.
7. **booter_emu runs 1-4** : capstone imprime les cibles de branchement
   RELATIVES (j/beqz/jalr = pc+imm) ; `c.addi` = 2 tokens ; `jalr` = 3
   tokens [rd,rs1,imm] ; lui/auipc = imm20 SIGNÉ en RV64 ; le path d'erreur
   de l'attendu ST-A (branch taken) — chaque correction nommée en code.
