# 4.43 — the power-enforcement map inside GSP-RM: where the 250 W is
# read, compared, and enforced — and the falsification of the
# "the GSP reads the VBIOS itself" hypothesis

Mission: cartographier l'application de la limite power dans le
firmware GSP-RM (`rm-full.elf`, le GA104 610.57.04) — où la valeur
250 W est lue, comparée, enforcee. Les trois tâches du brief : (1) le
désassemblage du chemin de lecture (le GSP lit-il le VBIOS lui-même ?),
(2) la cartographie des consommateurs de la politique (l'objet 0x6d0 :
qui le remplit, qui consomme, où est le clamp), (3) le contrôleur
d'état power (le throttle). Substrats : `tools/analysis/gsp-extract/
rm-full.elf` (le code image 0x1000000+0xE9B000, VA = off + 0x1000000)
et `binaries/gsp-rm-17MB.bin` (le conteneur 2-LOADs, la loi
`B_file = A_img − 0x38` re-vérifiée 512/512 fenêtres par les trois
instruments). Instruments : `v443a_vbios_lane.py`, `v443b_edpp_
consumers.py`, `v443c_enforcement_anchors.py` (+ JSONs). Le census
auipc reproduit le compte bancé 4.35b **exactement (416,206)** ; le
census EDPp reproduit v420 **17/17** et les WRITE-FIELD de 4.38a
**34/34** — la loi de carte tient sur cette machine.

## Verdict first

| question du brief | ce que les octets disent | verdict |
|---|---|---|
| le GSP lit-il le VBIOS lui-même ? | la machinerie FWSECLIC **VBIOS VERIFY** existe (les arms de report 0x11bf000-0x11c0a00, les codes 0x25-0x2e, les name-strings @0x1E30158-0x1E30348) MAIS **zéro constante crypto** (SHA-256 IV ×8, SHA-1 IV ×5, RSA e=0x10001 = **0 sites**) dans le code RM couvert — le RM ne fait que REPORTER des codes reçus du domaine sécurisé | **PROUVÉ : le RM rapporte, il ne vérifie pas** — le verify s'exécute dans le domaine FWSEC/SEC2 (le 4.31 : le crypto vit dans le BROM/le BooterLoad chiffré) |
| le GSP parse-t-il les tables power du VBIOS ? | le négatif 4.22 re-bancé (pas de `BIT\0`, pas de 0x00544942) + ce pass : **aucun driver SPI** (pas de cluster JEDEC-0x9F sur 3,400,949 insns décodées ; `RMDisableSpi` = 0 xrefs sous les deux mécanismes ; pas de nom de fonction SPI/I2C) ; pas d'accès config PCIe | **PROUVÉ (négatif) : non** — l'hypothèse « GSP = maître PCIe lisant le VBIOS pour sa politique power » est **falsifiée** |
| où le 250 W est-il lu/comparé/enforcee dans le RM ? | **jamais une constante** (4.21/4.32/4.38 re-bancés) ; la formule d'application trouvée DANS l'objet 0x6d0 : `limite = base[obj+0x618+idx*0x10] × record[obj+0x18+idx*0x30].f18 / 100 / 1000` (mul/divu/divuw cités 0x1446f14-f1c) — sortie = **5 paires {u32,u32} = les limites par vPstate** | **PROUVÉ : la formule** — les deux entrées = runtime (les bases = les résultats d'événements internes ; les records = les champs de l'objet) ; la comparaison finale vs la puissance mesurée = dans les vmethods runtime-dispatchées (le mur 4.16) |
| les cibles patchables ? | toutes RUNTIME-FED (§5) : les bases obj+0x600-0x660, les records obj+0x18+idx*0x30, le masque obj+0x65c, la table 4×8B B+0x8D9DC | **le verdict 4.38 tient, prouvé maintenant DEPUIS L'INTÉRIEUR du firmware** : aucun octet du rm.elf ne porte la limite |

## 1. TÂCHE 1 — le chemin de lecture VBIOS : le GSP rapporte, il ne lit pas

### 1.1 La machinerie FWSECLIC VBIOS-VERIFY — PROUVÉ

Le census des strings (v443a, 281 strings des familles power/VBIOS sur
le conteneur) expose la famille `NV_FWSECLIC_ERR_CODE_CMD_VBIOS_
VERIFY_*` (11 noms @0x1E30158-0x1E30348) et `NV_UDE_ERR_VBIOS_VERIF_
COMPLETED_AND_FAILED` @0x1E2B798. Leurs xrefs PIC exactes (121 xrefs
au total sur les 281) montrent le mécanisme : chaque nom est passé
comme a2 à un tail-call de report, avec a0 = 3 (le module), a1 = le
CODE numérique de l'erreur, a3 = une format-string. La fenêtre citée
(les arms se suivent, code DÉCROISSANT quand l'adresse monte) :

```
0x11c08ea: addi  a2, a2, -0x5d6      # a2 = 0x1E30348 "...HULK_SIG_INVALID"
0x11c08ee: addi  a1, zero, 0x2e      # le code 0x2e
0x11c08f2: c.li  a0, 3               # le module 3
0x11c08f4: c.addi sp, 0x10
0x11c08f6: auipc t1, 0x8de
0x11c08fa: jalr  zero, t1, -0x2d2    # tail-call → 0x1A9E624
```

Le bloc des arms s'étend sur [0x11bf000-0x11c0a00] (les codes 0x1b
jusqu'à ≥0x50) ; les codes VBIOS y sont contigus : 0x27 =
CERT_PARSE_FAIL (@0x11c09d8), 0x28 = CERT_VERIFY_FAIL (@0x11c09ba),
0x29 = HAT_FAIL (@0x11c0994), 0x2c = HULK_KA_NOT_FOUND (@0x11c092e),
0x2d = HULK_TYPE_INVALID (@0x11c090c), 0x2e = HULK_SIG_INVALID
(@0x11c08ea). La cible du tail-call **0x1A9E624** = un logger
variadique (les args a0-a7 empilés, la marche va_list, l'état
**thread-local lu via tp+0x88** — `lui a5,0 ; add a5,a5,tp ;
addi a4,a5,0x88` cité) : le RM journalise les résultats de
vérification VBIOS.

### 1.2 LA DÉCOUVERTE STRUCTURELLE : la région runtime 0x20000000+ — PROUVÉ, le backing = HYPOTHÈSE

Les format-strings a3 des arms composent **hors de notre extraction** :

```
0x11c0900: auipc a3, 0x1f0d0 ; addi a3, a3, -0x10   # a3 = 0x202908F0
0x11c07ac: auipc a3, 0x1f0d0 ; addi a3, a3, 0x234   # a3 = 0x202909E0
```

Le conteneur réel (`gsp-rm-17MB.bin`, phdrs relus ce pass) a **4
phdrs** : ph0 = PT_LOAD code @0x1000000 (0xE9B000), ph1 = PT_LOAD
data @0x4000000 (0x1D5000), **ph2 = PT_TLS @0x203C6000 (memsz
0x1000)**, ph3 = PT_LOOS @0x20000000 (filesz 0). Donc : la carte
runtime inclut une région ≥0x20000000 que le TLS prouve (le template
TLS y vit) mais qui n'est PAS file-backed dans notre extraction. Les
format-strings du logger y pointent (0x2029xxxx). Lecture : la région
= les données runtime mappées par le loader (le backing candidat = le
rodata décompressé LZ — le 4.29 — ou un blob voisin du conteneur
gsp.bin) — **HYPOTHÈSE** sur le mécanisme, PROUVÉ sur l'existence.

**La leçon de portée** : tout négatif « X n'existe pas dans l'image »
est dorénavant borné aux LOADs file-backed. Le négatif crypto ci-
dessous couvre le CODE ; la région 0x20000000 = données (aucune
évidence de code exécutable dedans — les seuls pointeurs observés y
sont des strings de format).

### 1.3 Le négatif crypto : le RM n'exécute pas le verify — PROUVÉ

Le census v443c sur les régions couvertes (3.4M insns) : **SHA-256 IV
{0x6A09E667...0x5BE0CD19} = 0 sites, SHA-1 IV = 0 sites, RSA e
0x10001 = 0 sites** (les formes li et lui+addi). Avec le 4.31 (le
crypto du boot vit dans le BROM/le BooterLoad chiffré, RSA-3K) : la
vérification du VBIOS s'exécute dans le domaine sécurisé (FWSEC/SEC2),
le noyau RM en reçoit les codes et les journalise (§1.1). La chaîne :
FWSEC vérifie l'image VBIOS (staged par le driver en RAM hôte) → les
codes remontent au RM → les arms de report. **Le RM lit le VBIOS
comme IMAGE VÉRIFIÉE, jamais comme tables parsées.**

### 1.4 Le négatif SPI/I2C/PCIe — PROUVÉ (négatif), la méthode citée

- **Opcodes SPI flash** : le fingerprint (les clusters ≤0x400 avec ≥4
  opcodes distincts parmi {06,05,03,0B,9F,02,D8,52,6B,EB,B7,E9,66,99})
  sur 3,400,949 insns décodées = 547 clusters, tous du bruit à petits
  immédiats {2,3,5,6} ; **aucun cluster ne contient le JEDEC-ID 0x9F**
  (le marqueur le plus spécifique d'un driver flash) — lisible dans
  `v443a_vbios_lane.json.spi_opcode_clusters`.
- **`RMDisableSpi`** (la regkey qui prouverait un driver SPI) : 0 xref
  PIC addi (v443a) ET 0 xref par l'idiome %lo-on-the-load (v443b, le
  census auipc+ld/addi étendu) ET 0 pointeur u64 brut. Les 864 regkeys
  du 4.35b vivent dans un pool packé (16-B aligné, cité) consommé par
  un autre mécanisme (le même source RM compilé deux fois, 4.38 §2.2 —
  la moitié sans xref = x86-side ou hashed). Le négatif est HONNÊTE :
  l'absence de xref ≠ l'absence de feature, mais AUCUN pointeur de
  code ne touche la porte SPI dans le RM.
- **I2C** : le seul marqueur = la regkey `RMI2cPmgrMutexTimeoutus`
  (le PMGR synchronise un bus I2C — les moniteurs de puissance) : 0
  xref dans les deux mécanismes. Le framework PMGR I2C existe par ses
  asserts (§3), le driver physique n'est pas xref-able statiquement.
- **Config PCIe** : aucun accès — cohérent avec le 4.22 (le GSP
  reçoit ses infos PCI via GSP_SET_SYSTEM_INFO).

**Verdict TÂCHE 1** : l'hypothèse du brief (« le GSP construit sa
politique power depuis le VBIOS lu lui-même via SPI/PCIe ») =
**FALSIFIÉE** au niveau de la politique power. Le GSP-RM : (a) vérifie
le VBIOS via le domaine sécurisé et en rapporte les codes, (b) ne
parse pas les tables power, (c) tient sa politique power en données
runtime (§2). La 4.38 reste LA réponse : les valeurs naissent du parse
x86 fermé ; le RM les reçoit par un canal runtime non-observé (la lane
4.26).

## 2. TÂCHE 2 — l'objet 0x6d0 : création, remplissage, la FORMULE du clamp

### 2.1 Le census et les usages — PROUVÉ, tout reproduit

v443b reproduit le census v420 **17/17** (zéro missing/extra) et
trace les usages avec la copy-chain de 4.38a : **READ = 20,
WRITE = 34 (le compte bancé reproduit exactement), PASS = 0**. La
carte des READ-FIELD par champ (le détail JSON) :

| champ | lectures | sites |
|---|---|---|
| 0x0 (le type/valide, lbu) | 4 | 0x1446dba, 0x145841c, 0x14584d8, 0x145901a |
| 0x10/0x12/0x13/0x14 (lbu) | 4 | 0x14584d8 (l'init) |
| 0x158 (ld) | 1 | 0x1458bfc (la fenêtre GET-handler) |
| **0x65c (lw — le masque de politique)** | **3** | **0x143fde2 ×2, 0x1446dba** |
| 0x6c4 (lw) | 1 | 0x145884e |
| 0x6c8 (lw — les change-flags) | 7 | 0x143fde2, 0x14400c6, 0x14405f0, 0x1440a22, 0x1440dbc, 0x1446dba, 0x14584d8 |
| **0x660 (lw — le dword rafraîchi par le worker)** | **0** | — (aucun lecteur dans les fenêtres du census) |

### 2.2 La création — PROUVÉ, l'allocateur bancé re-cité

La fenêtre 0x1458cf8 re-décodée (v443b) :

```
0x1458cec: addi  a1, zero, 0x6d0          # la taille 0x6d0
0x1458cf0: auipc a0, 0x2d38 ; addi a0, a0, 0xf8   # a0 = 0x4190DE8 (data LOAD)
0x1458cf8: auipc ra, 0x46b ; jalr ra, ra, -0x5bc  # → 0x18C373C (l'allocateur bancé 4.20)
0x1458d00: sd    a0, -0x168(s1)           # state+0x4E98 = l'objet
0x1458d08: addi  a2, zero, 0x6d0 ; c.li a1, 0     # memset(obj, 0, 0x6d0)
0x1458d16: c.li  a1, 8 ; auipc a0, 0x2d38 ; addi a0, a0, 0xd0  # le descripteur 0x4190DC0
0x1458d20: auipc ra, 0x46b ; jalr ra, ra, -0x5e4  # → 0x18C3734 (le compagnon)
0x1458d28: sd    a0, -0x160(s1)           # state+0x4EA0 = le compagnon
```

L'objet = alloué à l'init par **0x18C373C** avec le descripteur data
**0x4190DE8**, mis à zéro (0x6d0), stocké à state+0x4E98 ; le
compagnon par **0x18C3734** / descripteur **0x4190DC0** à state+0x4EA0.
Les descripteurs = data LOAD (le modèle descriptor-linked-instance-
state du 4.37 : les VA statiques, les VALEURS runtime).

### 2.3 La recompute (0x143fdbc) — PROUVÉ, le masque et les bases

La fonction (prologue `c.addi16sp sp, -0x60` @0x143fdbc) charge
s1 = *(state+0x4E98) (l'objet) et s3 = *(state+0x4EA0) (le compagnon),
puis :

1. **l'événement interne 0x20809009** (`lui a3, 0x20809 ; c.addi a3, 9`
   @0x143fe1c-26) via la vmethod *(state2+0x138) avec les slots
   +0xdc/+0xe4 — LA MÊME forme d'appel que le worker bancé 4.20 §4 ;
   le résultat (buf+4) est stocké : **`sw a5, 0x65c(s1)`** @0x143fe3e —
   le champ 0x65c = un masque reçu d'un événement interne.
2. Le masque est matché contre la table de constantes **{0x1, 0x4}**
   @0x1C7B320 (lue `c.lw a2, 0(a5)` / `lw a3, 0x65c(s1)` /
   `c.and a3, a2` — la fenêtre citée @0x143fe66-e6) ; les bits actifs
   construisent une liste dans un buffer 0x208.
3. **l'événement interne 0x20809064** (@0x143fe94-a2) porte la liste ;
   les résultats sont écrits dans la table de bases de l'objet :
   **obj + (idx+0x60)*0x10 + {0xc, 0x10, 0x14, 0x18}** (la fenêtre
   0x143fece-fefe : `c.add a5, s1` après `addi a5, a3, 0x60 ;
   c.slli a5, 4`).

**La chaîne de remplissage est donc : événements internes
0x20809009/0x20809064 → obj+0x65c (masque) + obj+0x600-0x660 (les
bases)** — runtime de bout en bout, aucune constante power.

### 2.4 L'évaluateur (0x1446d98) — PROUVÉ, LA FORMULE

La fonction (frame 0x1f0, prologue @0x1446d98) = la machine à états de
consommation : byte *(state+0x4EA8) ∈ {1..4} sélectionne la phase
(beq 0x1446e2a-3c), les flags obj->0x6c8 gates chaque branche (bit0 →
le masque 0x65c @0x1446dfe-e06 ; bit5 → obj+0x6c0 @0x1446f8c-92 ;
bit4 → obj+0x664 vs 0xFF @0x1446fc6-d0 ; bit6 → obj+0x688
@0x144702c-38), puis pour chaque idx du masque (match contre la table
{0x1024, 0x1026} @0x1C7B450, fenêtre 0x1446ecc-f12) :

```
0x1446ef4: mul    a5, a4, t3        # idx × 0x30
0x1446efc: c.add  a5, s5            # a5 = obj + idx*0x30
0x1446efe: c.lw   a3, 0x18(a5)      # record[idx].f18
0x1446f04: addi   t6, t5, 0x60 ; c.slli t6, 4 ; c.add t6, s5
0x1446f0c: lwu    t6, 0x18(t6)      # base[idx] = obj[0x618 + idx*0x10]
0x1446f14: mul    a3, t6, a3        # base × record
0x1446f18: divu   a3, a3, t1        # / 100   (t1 = 0x64 @0x1446ee4)
0x1446f1c: divuw  a3, a3, t4        # / 1000  (t4 = 0x3E8 @0x1446ee8)
0x1446f20: sw     a3, 8(s8)         # → la paire de sortie
0x1446f24: c.lw   a3, 0x14(a5)      # record[idx].f14
0x1446f3a: mul    a5, a5, a3 ; divu a5, a5, t1   # / 100 seulement
0x1446f48: sw     a3, 0xc(s8)       # → la 2e moitié de la paire
```

**LA FORMULE D'APPLICATION : `limite = base × record / 100 / 1000`**
(avec la seconde sortie `base × record / 100`). Le buffer de sortie =
memset 0x28 (0x1446ebc) = **5 paires {u32,u32}** (s8 marche de 8 en 8,
borne 0x28) — **la structure 5×{u32,u32} des limites par vPstate,
exactement la table que le handler RatedTdp construit en réponse**
(4.21 §4). Les résultats sont écrits dans l'objet état passé en a2
(s4+0x48 @0x1446e1e, s4+0x7F8 @0x1446fa4, s4+0x8E8 @0x1446fb6,
s4+0x958 @0x144700c).

C'est le cœur de la TÂCHE 2 : **le clamp EDPp du GSP = une
multiplication runtime par un pourcentage**, pas une comparaison à une
constante. La comparaison contre la puissance MESURÉE (le throttle)
n'est PAS dans cette fonction — elle est en aval (§3).

### 2.5 Les limites honnêtes de la TÂCHE 2

- **0x660 = 0 lecteur** dans toutes les fenêtres du census : le dword
  rafraîchi par le worker (0x14400c6) est consommé HORS d'atteinte du
  trace 160-insns (par les vmethods/notifs) — HYPOTHÈSE : alimente la
  chaîne de notification, pas un clamp statique.
- **0 appelant direct** (jal/c.jal) vers 0x1446d98 / 0x143fdbc /
  0x14400c6 sur 3.4M insns : les trois = runtime-dispatchés (vtables/
  task-queue — le mur 4.16/4.19). La phase 1-4 (state+0x4EA8) et
  l'objet a2 restent non-nommables statiquement.
- L'outlier **0x15fbad6** décodé (v443b) : `lw a5, -0x168(s10)` puis
  un call avec format-string — un consommateur périphérique
  (log/télémétrie), pas le clamp.

## 3. TÂCHE 3 — le contrôleur d'état power : le framework PMGR et le mur

### 3.1 Le framework PMGR — PROUVÉ par ses asserts (les régions nommées)

Le census v443a extrait les asserts source-embeddés du module PMGR
(power manager) du RM — le framework complet existe dans le firmware :

- **les devices/providers** : `(PMGR_PWR_DEVICE_IDX_IS_VALID(pPmgr,
  pSensor->pwrDevIdx))` @0x1E88100, `(pSensor->pwrDevProvIdx <
  pDev->provNumGet(pGpu, pPmgr, pDev))` — les capteurs de puissance
  = des DEVICES à PROVIDERS (les moniteurs I2C — cf.
  `RMI2cPmgrMutexTimeoutus`) ;
- **les channels/relationships** : `PMGR_PWR_MONITOR_PWR_CHANNEL_IS_
  VALID` @0x1E87F10, `PWR_CHRELATIONSHIP_IS_VALID` (dont la variante
  PstateEstLUT `lutEntry[i].data.dynChRelIdx` — xref PROUVÉE
  @0x177d59c, la région **0x177D5xx** = le module) ;
- **les policies = BOARDOBJs** : `NV2080_CTRL_PMGR_PWR_POLICY_TYPE_
  WORKLOAD_DIE_2X` / `WORKLOAD_PHYSICAL_SINGLE_2X` @0x1E886A0-0x1E88B48,
  l'interface TGP (`pTgpIface->fbPolicyRelIdx / corePolicyRelIdx`
  @0x1E88238/0x1E882D0), les relations **tgt/floor/ceiling** (@0x1E88908/
  0x1E889A0/0x1E889F0) — le plafond/plancher power par politique ;
- **les controllers perf-cf** : `pSingle1x->softFloor.clkPropTopIdx !=
  NV2080_CTRL_CLK_CLK_PROP_TOP_ID_INVALID`,
  `perfCfControllerClkIdx != NV2080_CTRL_CLK_CLK_DOMAIN_INDEX_INVALID`,
  `perfCfControllerIdx != NV2080_CTRL_PERF_PERF_CF_CONTROLLER_INDEX_
  INVALID` — les contrôleurs de clocks avec planchers doux ;
- **la tension** : `(pOutputVoltage1x->voltMode <
  NV2080_CTRL_PMGR_PWR_CHANNEL_OUTPUT_VOLTAGE_1X_VOLT_MODE_NUM)` —
  xref PROUVÉE @0x17822f8, la région **0x1782xxx** = le module VOLT
  (`lhu a1, 0x260(a5)` cité dans la fenêtre).

Honnêteté : la majorité des asserts = 0 xrefs (les deux mécanismes de
census) — soit compilés-out avec strings résiduelles, soit référencés
via la table d'asserts non-file-backed (§1.2). Les DEUX xrefs prouvées
(0x177d59c PstateEstLUT, 0x17822f8 OutputVoltage1x) nomment les
régions modules ; les autres cadres = PROUVÉS comme textes, HYPOTHÈSE
comme sites d'exécution.

### 3.2 Les tables thermiques — PROUVÉ (les 4 pointeurs)

`THERM_POLICY_GPC` (et ses sœurs DRAM/XBAR/NVVDD @0x1E8D0C8...) =
référencées par **4 pointeurs u64 bruts** @0x1E15D38, 0x1E17958,
0x1E22EC8, 0x1E24E48 (v443a ptr_table_refs) : les tables de noms des
politiques thermiques, la matière du framework THERM côté RM.

### 3.3 Les anchors de contrôle — PROUVÉS (les fenêtres citées)

- **RatedTdp (0x163c42c dispatch-VA = tail ; prologue 0x163c478)**
  re-décodé : le builder de la réponse 5×{u32,u32} (le compteur
  s5 = 5, le buffer 0xc, `sw s1, -0x58(s0)` par vPstate) — le GET ;
  le SET + le clamp = la lane 4.38 §2.3 (le relais x86, la valeur
  runtime).
- **PERF_GPU_BOOST_SYNC_SET_LIMITS (0x16e4f20, en queue depuis 4.20)**
  décodé : le cluster tail = des getters bornés (+0x170/+0x20) et un
  getter qui lit les limites via **la MÊME chaîne de base que le
  dispatcher 0x2080A080** (`ld a5, 0x158(a0) ; +0x2000 ; ld -0x68(a5)`
  @0x16e4f5e-68 — le 4.38 §1.1), puis `ld a4, 0x198(a4)` (la limite
  u64 stockée) + les bytes 0x2DB/0x2D9. **Les limites du boost vivent
  dans la famille d'état B runtime.**

### 3.4 La carte complète du chemin power dans le GSP-RM

```
[les capteurs] PMGR pwr devices/providers (I2C)          — le cadre PROUVÉ (asserts),
                                                           le chemin physique = HYPOTHÈSE
      │  (les lectures → les channels)
      ▼
[les canaux] PMGR pwr channels + relationships           — PROUVÉ (asserts + xref 0x177d59c)
      │
      ▼
[la politique] l'objet EDPp 0x6d0 @state+0x4E98          — PROUVÉ (4.20 + ce pass)
   création 0x18C373C/desc 0x4190DE8 (§2.2)
   masque 0x65c ← événement interne 0x20809009            — PROUVÉ (§2.3)
   bases 0x600-0x660 ← événement interne 0x20809064       — PROUVÉ (§2.3)
   worker 0x14400c6 : 0x2080A080 → obj+0x660              — PROUVÉ (4.20/4.38)
      │  l'évaluateur 0x1446d98 (phase 1-4 @state+0x4EA8)
      │  LIMITE = base × record / 100 / 1000              — PROUVÉ (§2.4)
      ▼
[les limites par vPstate] 5 × {u32,u32}                  — PROUVÉ (le buffer 0x28)
   → l'objet état (a2 : +0x48/+0x7F8/+0x8E8/+0x958)       — PROUVÉ (les stores cités)
      │  (consommés par les controllers)
      ▼
[les controllers] perf-cf / softFloor / THERM / VOLT     — le cadre PROUVÉ (asserts + tables),
   GPU_BOOST_SYNC lit les limites (état B)                 le TRIGGER du throttle
      │                                                     = HYPOTHÈSE (runtime-bound)
      ▼
[le throttle] la comparaison puissance-mesurée vs limite
   → la réduction de clock                                — NON NAMMABLE STATIQUEMENT
                                                           (0 appelant direct ; le mur 4.16)
```

Le dernier hop = honnêtement fermé par le mur runtime-bind : la
comparaison finale s'exécute dans une vmethod dispatchée, comme
prédit par la cartographie 4.14-4.19. Ce qui est PROUVÉ : la SOURCE
de la limite appliquée (la formule §2.4) et le fait qu'elle n'existe
nulle part comme constante.

## 4. La réconciliation avec les passes précédentes

- **4.20** (l'objet 0x6d0, le worker) : intégré — le worker 0x14400c6
  = LE MÊME appel de vmethod que la recompute 0x143fdbc ; la famille
  0x1440xxx-0x1446xxx = le module de politique complet.
- **4.21** (le mW-scan, « les limites sont runtime data ») : PROUVÉ
  maintenant avec le MÉCANISME (la formule ×/100/1000 sur des bases
  d'événements).
- **4.22/4.38** (le parse VBIOS = x86 fermé ; le clamp -pl = x86) :
  renforcé — le GSP n'a NI parse NI source VBIOS power ; sa politique
  = le reflet runtime d'un canal non-observé (la lane 4.26).
- **4.30/4.32/4.34** (la lane rm.elf CLOSED) : la fermeture est
  maintenant justifiée DE L'INTÉRIEUR : même en réécrivant le noyau
  RM, la limite = base × pourcentage avec les deux opérandes runtime —
  il n'y a rien à patcher sans re-fournir les données (le memdesc/
  transfer-list 4.41/4.42 = le seul canal d'injection prouvé).

## 5. Les cibles patchables (nommées, avec les offsets)

Toutes runtime-fed — aucun octet statique du rm.elf ne porte la
limite (le verdict 4.38 tient, prouvé de l'intérieur). Les cibles
d'une injection (le canal 4.42 : le memdesc signature → la
transfer-list → les gadgets ld 4.40) :

| # | cible | offset | contenu | la preuve |
|---|---|---|---|---|
| 1 | les bases de politique | obj+0x600..0x660 (stride 0x10, champ +0x18) | les valeurs multipliées (÷100÷1000) par l'évaluateur | §2.3-2.4 |
| 2 | les records de politique | obj+0x18+idx*0x30 (champs +0x14/+0x18) | les pourcentages | §2.4 |
| 3 | le masque actif | obj+0x65c | les bits de politique actifs (des événements 0x20809009) | §2.3 |
| 4 | la table 4×8B runtime | B+0x8D9DC (+ le byte B+0x8D9CC) | la source des getters 0x2080A080 (le remplissage = la lane RPC object-create, le 4.37/4.38) | 4.38 §1.1 |
| 5 | les limites boost | l'état B (via *(a0+0x158)+0x2000-0x68), champ +0x198 | les limites u64 du boost sync | §3.3 |

**La conséquence opérationnelle** : une injection E1/E2 du 4.42 qui
voudrait poser 280000 mW doit viser les BASES (cible 1) APRÈS le
remplissage runtime mais AVANT l'évaluation — le timing = la fenêtre
entre les événements 0x20809064 et l'évaluateur, non contrôlée
statiquement (HYPOTHÈSE, la recompute est volatile — le risque déjà
bancé 4.42). La re-dérivation périodique écraserait l'injection : la
voiture = les RECORDS (cible 2, les pourcentages) ou le masque
(cible 3), plus persistants dans l'objet.

## 6. Les leçons d'instrument

1. **La région 0x20000000+** : les paires auipc statiques composent
   hors des LOADs file-backed (PT_TLS @0x203C6000 + PT_LOOS
   @0x20000000 = la classe de région prouvée). Tout négatif statique
   est borné au file-backed ; les strings de format du logger y
   vivent (0x2029xxxx cités).
2. **L'architecture tail-entry** (la 3e confirmation indépendante) :
   les VAs de dispatch-table (0x163c42c, 0x16e4f20, comme 0x16502d0
   au 4.38) = des TAILS dans des corps partagés — décoder le
   prologue + le cluster, jamais le VA seul.
3. **Le census %lo-idiome** (auipc + ld/addi gap ≤16) : fermé pour
   les strings de regkeys/asserts (v443b) — 0 hit au-delà des paires
   addi connues ; le piège 4.37 est maintenant aussi testé sur le
   pool de strings.
4. **capstone detail-mode** : `ins.operands` sans `md.detail=True`
   lève CS_ERR_DETAIL (le patch v443c) — la règle : detail on dès
   qu'une trace lit les opérandes.

## 7. La queue

1. La lane 4.26 (le recv-hook capture) reste LA route vers les
   valeurs live — elle nommerait aussi l'objet a2 de l'évaluateur
   (les limites par vPstate) pour la Lane T du 4.38.
2. Le backing de la région 0x20000000 : une passe conteneur (le
   gsp_ga10x.bin brut, la recette sha256 du 4.30) peut la retrouver
   file-backed — les format-strings FWSECLIC sont le traceur.
3. L'idiome d'appel 0x20809009/0x20809064 → les handlers internes
   (la famille 0x2080_9xxx, le complément 0x2080_Axxx du 4.21 §6) :
   nommer les sources des bases (le remplissage réel).
4. La comparaison finale puissance-vs-limite : inatteignable
   statiquement (le mur) — la seule route = la capture live ou
   l'émulateur booter (les instruments 4.31/4.42) sur une trace
   d'exécution.

## Discipline

Chaque hop = PROUVÉ (les octets cités : l'instruction, le VA, le
JSON de l'instrument) ou HYPOTHÈSE (le raisonnement étiqueté). Les
trois instruments reproduisent les comptes bancés avant de produire
(416,206 auipc ; 17/17 census ; 34/34 WRITE-FIELD ; la loi de
coordonnes 512/512 ×3). Les négatifs (crypto 0, SPI 0, xrefs 0) sont
bornés à leur méthode et à leur périmètre (§1.2). Zéro résultat
inventé : la formule, les tables, les descripteurs, les régions —
tout relisible par les commandes des instruments. Pas de merge :
branche `pass/4.43-power-map`, push, PR ouverte.
