# ROADMAP 600 GB/s — la grosse tâche post-4.49 (le plan d'escalade complet)

Pass: 4.50-planning (branché sur 4.49 `39c7881`). Date: 2026-09-24.
Trigger: « je me lance pas tout de suite — prévoie une grosse tâche sur ce
qu'on peut encore améliorer/trouvé d'intéressant, soit ingénieux, pour la
suite — vise la possibilité d'avoir 600 GB/s voir + ».
État d'entrée: la file statique est DRAINÉE (4.49: la chaîne
RML2MaxWaysSysmem nommée bout-en-bout, la chasse timing épuisée avec
preuve). Ce qui reste se joue sur la machine, par paliers. Ce document
est le plan; chaque tier = un ou deux jours machine, chaque palier a son
gate go/no-go chiffré.

---

## §0 La cible, décodée honnêtement — les QUATRE sens de « 600 GB/s »

La carte: RTX 3070, GA104, GDDR6 Hynix 256-bit, 14 Gbps stock =
**448 GB/s théorique**. L'escalier (256-bit → GB/s = Gbps × 32; l'effectif
= théorique × l'efficacité, la référence 0xSero = 91.3 %, un bon Ampere
D2D tourne ~85-88 % tant que personne n'a optimisé les noyaux):

| GDDR6 | MCLK (readout) | Théorique | Effectif @88 % | Effectif @91.3 % |
|---|---|---|---|---|
| 14.0 (stock) | 6801 MHz | 448 | 394 | 409 |
| 15.0 | 7501 | 480 | 422 | 438 |
| 15.6 (+1000 LACT) | 7801 | 499 | 439 | 456 |
| 16.0 | 8001 | 512 | 451 | 467 |
| 16.6 (+1500 LACT) | 8301 | 531 | 467 | 485 |
| 17.0 | 8501 | 544 | 479 | 497 |
| 18.0 | 9001 | 576 | 507 | 526 |
| 18.75 | 9376 | **600 (théo)** | 528 | 548 |
| 20.6 | 10301 | 659 | **580** | **601 = le 600 effectif** |

Les quatre jalons, du plus atteignable au plus dur:

- **M1 — le % de la référence (la métrique 0xSero)**: 91.3 % de 448 =
  **~409 GB/s effectif à clock stock**. 100 % logiciel, aucune prise de
  risque. C'est le jalon que le plan garantit quasi-mathématiquement.
- **M2 — l'OC mémoire**: 15.6-16.6 Gbps via LACT (+1000/+1500, la marge
  typique du GDDR6 Hynix) → **~440-485 GB/s effectif**. Logiciel, réversible
  par un offset à zéro. Le produit du Tier 1 + Tier 3.
- **M3 — le 600+ PAR RÉSIDENCE L2**: pour tout workload dont l'empreinte
  tient dans le L2 (~4 MB sur la 3070), le débit mesuré dépasse
  **largement 600 GB/s** dès aujourd'hui, en logiciel pur, zéro risque.
  C'est le premier « 600+ » atteignable du plan (Tier 1d) — honnête pour
  les workloads cache-friendly (inférence de petits modèles, kernels
  persistants, données de travail compactes).
- **M4 — le 600 effectif en STREAMING DRAM**: exige ~20.5-21.5 Gbps/pin,
  soit **+47-54 % sur le Hynix stock** — le mur matériel (vddq + cooling).
  Le plan le documente (Tier 4) mais le respect de la décision
  2026-09-21 (PC-only, aucun achat hardware) le laisse HORS PÉRIMÈTRE.

**La ligne directrice: grimper M1 → M2 → M3 en logiciel, mesurer le mur
M4 avec précision, et ne jamais confondre les quatre dans un verdict.**

## §1 L'actif en main (l'inventaire des leviers déjà PROUVÉS)

| Actif | État | Où |
|---|---|---|
| La métrique % du plafond (Pillar B) | armée, jamais mesurée | runbook-447 §1 (torch, 2 GiB, médianes, % de 448) |
| Le sweep LACT mclk {0,+500,+1000,+1500} jugé par la batterie | armé | runbook-447 §2 (la leçon vram-ab: glmark2 ne voit PAS la bande passante) |
| La clé regkey dégagée RmClk2Enable=1 | cartée (8 xrefs) | runbook-447 §3 |
| La chaîne L2 ways NOMMÉE BOUT-EN-BOUT (ingestion 0x1307AFC → fetch 0x103c08c → registre 0x1a93218 → config+0x3D84 → consommateur 0x1318d4a → reg 0x2AC ways<<8, domaine {0}∪{7}) | PROUVÉ 4.49 | findings-4.49 §1 — l'expérience nommée: RML2MaxWaysSysmem=0 son propre jour |
| Les timings LHR décodés (rc 76→70, rfc 210→175, ras 49→44, faw 28→20, rrd 7→5) | PROUVÉ gx4/gx5 | la preuve constructeur que la marge existe |
| Les fingerprints DMEM des records timing | bankés | v448c_stride_timing.json → runbook-447 §5 (l'expérience décisionnaire de TÂCHE B) |
| Le write-primitive runtime (transfer-list) PROUVÉ EN BOOT + l'émulateur | prouvé 4.42/4.45 | le f18-analog (250→280 W) est le gabarit du payload timing |
| Le trace-ring par-tâche du RM (0x1a9e624, 61,339 sites, 1 ns rdtime) | décodé 4.48 | l'observateur runtime (les valeurs MclkProg passent dans le ring) |
| La capture recv-hook 4.26 | armée (runbook-426.sh) | partager le jour machine pour observer le vrai programmé MCLK |
| La batterie émulateur (--test-444 / --test-rop) | 11/11 + 18/18 | le futur --test-timings de TÂCHE D |
| Le patch 280 W + le firmware patché préservés | prouvé, stock restauré | la machinerie d'écriture réutilisable |
| ReBAR 8192 MiB + undervolt 1995@987 mV + core +225 MHz | actifs | le socle perf déjà en place |
| Le chemin hardware CH341A | documenté, NON choisi (décision 2026-09-21) | docs/hardware-path-ch341a.md |

## §2 TIER 0 — LA MESURE (le jour machine, TÂCHE A du runbook-447)

Objectif unique: transformer les INDECIDABLE en nombres. Aucun changement
de comportement ce jour-là, le firmware ne touche à rien.

1. **§0-§1 du runbook** — la baseline stock: copy/read/write GB/s + % de
   448. C'est LA réponse jamais mesurée (le % d'aujourd'hui est
   INDECIDABLE — c'est le seul nombre qui décide de la suite).
   Livrable: `~/bandwidth-447/pillarB-stock.json`.
2. **La sonde thermique/refresh (NOUVEAU, gratuit)**: re-courir §1 à froid
   (<45 °C VRAM) puis en boucle jusqu'à saturation thermique (>80 °C).
   Le GDDR6 double son taux de refresh au-delà du seuil thermique —
   l'effectif peut chuter de 3-8 %. Le delta froid/chaud chiffre le gain
   « refroidissement = bande passante gratuite » (HYPOTHÈSE à mesurer;
   loggez `nvidia-smi --query-gpu=temperature.memory` à chaque rep).
3. **La sonde ncu (NOUVEAU, si installable)**: Nsight Compute lit
   `dram__throughput.avg.pct_of_peak_sustained_elapsed` — le % du plafond
   DIRECTEMENT par kernel, sans hypothèse de batterie. Si `ncu` absent,
   noter dans le verdict et passer (la batterie torch reste le juge).
4. **§2 le sweep** — le premier étage de M2, déjà scripté.
5. **§5 le dump DMEM** — partagé avec le jour 4.44/4.45 si cette boot
   existe; le hit/no-hit DECIDE du Tier 2 (voir §4).

Gate de sortie du Tier 0: le % stock est CONNU (M1 a sa ligne de départ),
le delta thermique est chiffré, le verdict §5 est rendu.

## §3 TIER 1 — les gains 100 % logiciels (aucun firmware, réversible par reboot)

### 1a. Le sweep MCLK jusqu'au plafond stable (M2, premier étage)

Le runbook §2 s'arrête à +1500. Le gain réel se situe au dernier palier
STABLE: prolonger le sweep par pas de +250 tant que (a) la batterie §1
progresse, (b) memtest_vulkan (10 min min.) passe sans erreur, (c) zéro
Xid au journal. Chaque +500 MHz MCLK = +32 GB/s théorique = ~+28 GB/s
effectif. Le palier qui échoue → revenir au dernier bon, le noter
VERROU. Attendu honnête: 440-485 GB/s effectif (HYPOTHÈSE → le sweep le
transforme en nombre).

### 1b. RmClk2Enable=1 (le pack dégagé, runbook §3)

Une clé, un boot, un delta, la règle de la maison inchangée. Gain espéré:
inconnu mais gratuit; la carte 4.35 (8 xrefs) reste la seule clé CLEAR.

### 1c. Pillar B: les NOYAUX (la méthode 0xSero, appliquée à la lettre)

C'est le cœur ingénieux du Tier 1 — la référence (555/608) est un exploit
de KERNELS, pas de firmware. La batterie torch de §1 mesure le torch;
le vrai objectif = des noyaux nvcc maison qui grignotent le % jusqu'à
~91.3 %:

- vectorisation 128-bit (float4/int4), déroulage ×8, grid-stride sur les
  46 SMs, `__restrict__`, launch bounds calibrés;
- lecture en `ld.global.nc` + la politique d'éviction STREAMING
  (`cudaAccessPropertyStreaming`) sur les flux — empêcher le flux
  d'écriture d'écraser les lignes du flux de lecture dans le L2 (le
  piège classique du copy D2D);
- écritures en `st.global.cg` (L2-only);
- l'overlap CE+SM: intercaler les copies des copy-engines et les kernels
  SM sur des streams séparés — le contrôleur mémoire voit un mix plus
  riche et l'effectif monte (HYPOTHÈSE à A/B-er dans la batterie);
- boucler avec ncu (ou la batterie) jusqu'à ce que le % plafonne.

Le produit: M1 = ~409 GB/s effectif à clock stock, mesuré, REPRODUCTIBLE —
et ce même noyau devient le JUGE de tous les paliers suivants (la leçon
vram-ab portée à sa forme finale).

### 1d. La voie L2-résidente (M3 — le premier « 600+ » garanti)

`cudaAccessPolicyWindow` en mode persisting sur une empreinte ≤ ~3 MB:
mesurer le débit effectif du workload résident. Attendu: plusieurs
centaines de GB/s à plus de 1 TB/s selon le pattern — le « 600 GB/s + »
en logiciel pur, zéro firmware, zéro risque. Honnêteté obligatoire dans
le verdict: c'est le débit CACHE-résident, pas le streaming DRAM — mais
pour un workload réel qui tient en L2, c'est un vrai débit utile, et la
famille de knobs L2 (4.49) offre des leviers complémentaires (§7).

### 1e. La sonde compression (gratuite, une heure)

Remplir un buffer avec des données fortement compressibles vs aléatoires,
courir la batterie §1 sur les deux. Si le débit « compressible » dépasse
l'aléatoire de façon reproductible, la compression L2 est ACTIVE sur les
écritures compute → du GB/s gratuit sur tout payload compressible
(HYPOTHÈSE; les knobs RmDisablePostL2Compression/RmDisableDecompOnlyLce
de la carte 4.47 prouvent que la machinerie existe côté RM).

### 1f. Le verrouillage d'état P0 mémoire (gratuit, une ligne)

`nvidia-smi -lmc 6801` (verrou MCLK au max P0, déverrou = `-rmc`): élimine
la montée P-state pendant les reps courtes. Zéro risque, testable en
deux minutes, à intégrer au protocole de mesure si delta mesurable.

## §4 TIER 2 — le retarget runtime des TIMINGS (le f18-analog, TÂCHE B→D)

Le produit du constructeur lui-même (les records LHR resserrés) prouve
que le silicium Hynix tourne plus serré que le stock de la 3070. La voie:

1. **Le verdict §5 décide.** Hit DMEM → les records parsés vivent dans
   l'état RM-reachable → l'étape 2 s'ouvre. No-hit (et aucun consommateur
   FB-Falcon nommé) → la lane meurt HONNÊTEMENT, le poids passe sur le
   Tier 1c/3 (et A2 se ferme comme runtime-unreachable).
2. **La table {value, target} des timings** (le gabarit 4.42 qui a fait
   250→280 W): appliquer les valeurs LHR une à une — rc 70, rfc 175,
   ras 44, faw 20, rrd 5 — JAMAIS en bloc: un champ, un boot, la batterie
   §1 + memtest_vulkan + le compteur Xid. Le gain à clock égale est
   modeste (~1-3 %, HYPOTHÈSE — l'essentiel du produit = la STABILITÉ aux
   clocks du Tier 3: des timings resserrés sont souvent la condition
   d'un OC stable, pas l'inverse).
3. **Le payload par la machinerie prouvée**: transfer-list (4.42) →
   validation émulateur (`--test-timings` à écrire, le gabarit TT 11/11)
   → le jour machine. Le rollback = reboot (l'état RM se re-parse du
   VBIOS stock à chaque boot — le risque permanent est NUL).
4. **Le trace-ring MclkProg** (4.49 §2): le producteur de la valeur =
   la vtable méthode (+0x68) — INDECIDABLE-BY-BYTES; le dump du ring de
   trace (les valeurs passent dans le ring, l'API 4.48) le nomme au
   runtime. Partager le jour de capture.
5. **RML2MaxWaysSysmem=0, son propre jour** (l'expérience nommée 4.49):
   le domaine prouvé = {0}∪{7}, 0 = honored (ways→0). Jugé par la
   batterie §1. Si 0 = décloisonner le partitionnement sysmem au profit
   de la bande passante locale, c'est un gain D2D; si l'inverse, NO-EFFECT
   ou régression — dans les deux cas la carte 4.49 se complète par une
   mesure, pas une hypothèse.

## §5 TIER 3 — pousser le PLAFOND (14 → 16+ Gbps, la question RM)

LACT plafonne à +1500 offset. Au-delà, la question = qui tient le plafond:

1. **Les 4 tables MCLK_LIMIT** ({name-ptr,…} @0xe15c78/0xe17918/0xe22e88/
   0xe24e08) + **RmClkMclkProg** (la fenêtre latch 4.49 §2): le RM porte
   sa propre table de limites; la marge du bin gx4 (6301-16383 MHz) montre
   que le décodeur de straps sert déjà des valeurs bien au-delà de 8001 —
   le lié probable = la table de limites + le training GDDR6.
2. **Le training** (les indices nommés: RmMClkP5LinkTrainingWckStopClks,
   RMDisableFbAddressRetraining): à chaque palier +250, surveiller le
   re-training (les temps de switch MCLK dans le trace-ring, la capture
   4.26 partagée). Un palier qui re-train en boucle = le mur du training,
   pas celui des timings.
3. **La condition préalable = le Tier 2** (les timings LHR en runtime):
   c'est le pack constructeur pour la stabilité haute fréquence.
4. **Le thermique decide du dernier palier** (la sonde §2.1): si l'effectif
   chute au-delà de ~80 °C VRAM, le plafond pratique vient du refresh
   thermique — le Tier 4 (hardware) OU la gestion du flux d'air du boîtier
   (gratuit, si un ventilo existant peut être repositionné — à statuer
   dans les contraintes PC-only).
5. **Gate par palier**: batterie §1 (médianes ×3) + memtest_vulkan 10 min +
   zéro Xid + le rollback offset=0 confirmé. Un palier sans le quadruple
   n'existe pas.

Attendu honnête: 15.6-16.6 Gbps (M2 complet, ~440-485 effectif) est le
domaine typique du Hynix GDDR6 en air; 17+ = la zone des bons bins,
palier par palier, sans promesse.

## §6 TIER 4 — le mur du 600 streaming (ROUGE, hors périmètre actuel)

Le calcul est sans appel: 600 GB/s effectif en streaming = ~20.5-21.5
Gbps/pin = +47-54 % sur le stock. Le Hynix GDDR6 8 Gb n'y arrive pas en
air, ni avec des timings parfaits. Le chemin documenté (pas planifié):
vddq mod + refroidissement direct VRAM (le wiki cmp170hx connaît la
famille de manœuvre; le CH341A reste documenté dans
docs/hardware-path-ch341a.md). **La décision 2026-09-21 (PC-only) tient;
ce tier ne s'ouvre que sur une décision contraire explicite du founder.**
En attendant, le « 600+ » honnête de cette carte = M3 (la voie L2-résidente,
§3-1d) — et le plan le livre dès le Tier 1.

## §7 Le parking lot ingénieux (idées non assignées, taggées)

| Idée | Ce que ça pourrait donner | Tag |
|---|---|---|
| CE+SM overlap dans la batterie (§3-1c) | +3-8 % effectif sur les copies mixtes | HYPOTHÈSE, test gratuit |
| La sonde compression (§3-1e) | gros sur payload compressible, sinon 0 | HYPOTHÈSE, test gratuit |
| RMG5xL2VidmemPromote=1 | le voisin bit1 du flag word 4.49 (+0x3D68) — la promotion L2 côté vidmem; une clé, un boot, un delta | CARTE À ÉCRIRE (le mécanisme du store est prouvé, l'effet inconnu) |
| La famille FB/L2 de 4.49 en pack futur (RML2PreFill, RMAltL2ArbCYA, RMDisableLRCCoalescing… ~24 clés cartées) | le stock de futurs jours « une clé, un boot, un delta » | CARTE (ingestion prouvée 4.49) |
| Le verrou P0 mémoire (§3-1f) | élimine la variance P-state des mesures | trivial |
| L'accounting refresh/rfc (le delta rfc 210→175 chiffré en downtime) | ~0.5-1 % d'effectif, la compréhension fine du cout refresh | HYPOTHÈSE chiffrable au Tier 0 (le froid/chaud + la literature) |
| La capture 4.26 partagée (observer le MCLK réellement programmé) | nomme le producteur MclkProg + valide les tables MCLK_LIMIT | INDECIDABLE-BY-BYTES → runtime |
| RmIsoHubMCLKSwitch / RmOptp2LowerMclk (×2/×1) | la politique de switch MCLK (maintenir le P0 mémoire sous charge mixte) | CARTE 4.47, sémantique à éclaircir |
| Le harness nvbandwidth (au lieu de torch) | le harness professionnel de NVIDIA (CE/SM/DP4A) — la probe order du runbook §1 le liste déjà | trivial si installable |

## §8 La gouvernance (les règles qui ne bougent pas)

- **Une clé, un boot, un delta, un mécanisme nommé** — sinon NO-EFFECT ou
  UNPROVEN (la règle 4.35-4.47, inchangée).
- **REFUSÉ-BY-CARD, inchangés**: RMClkVfOverride (le précédent 4.23 — la
  table clock dégradée à 240/245), RMUseTc0NonCoherent (cohérence), les
  familles time-math à l'aveugle (4.32/4.35), tout flash EEPROM (CERT20).
- **Le quadruple gate par palier OC**: batterie §1 ×3 + memtest_vulkan
  10 min + zéro Xid + rollback confirmé.
- **Le sha firmware §0 du runbook** = la garde de chaque jour machine:
  le jour stock ne touche RIEN au firmware; les jours payload passent
  par l'émulateur AVANT la machine.
- **Le journal Xid systématique** (`journalctl -k | grep -iE 'NVRM|Xid'`)
  après chaque étape — le compteur de la maison.

## §9 Le calendrier des jours machine (la séquence recommandée)

| Jour | Contenu | Produit | Gate |
|---|---|---|---|
| **J1** | runbook-447 §0→§1 + la sonde thermique + la sonde ncu + §2 (sweep complet prolongé) + §5 (dump DMEM si la boot partagée a lieu) | le % stock (M1 ligne de départ), le delta thermique, le verdict §5 | — |
| **J2** | §3 regkey RmClk2Enable=1 + le dernier palier OC stable du J1 verrouillé + memtest | M2 premier étage + la clé cartée | le quadruple gate |
| **J3** | la voie meurt ou s'ouvre: si §5 hit → la table {value,target} LHR + `--test-timings` (émulateur) puis le payload machine; si no-hit → J3 = Pillar B noyaux (§3-1c) + L2 persisting (§3-1d) | le payload timing OU le M1/M3 mesuré | émulateur 100 % AVANT la machine |
| **J4** | RML2MaxWaysSysmem=0 (son propre jour) + le trace-ring/capture 4.26 partagée (MclkProg) | la carte L2 complétée par une mesure + le producteur MclkProg nommé | le quadruple gate |
| **J5+** | le pack FB/L2 du parking lot, un par jour, + la boucle noyaux jusqu'au plafond du % | l'escalade M2 vers 15.6-16.6+ | le quadruple gate |

Le travail sans machine (entre les jours): écrire les noyaux nvcc du
§3-1c, écrire `--test-timings` pour l'émulateur, rédiger les cartes RMG5xL2VidmemPromote
et la famille FB/L2, prolonger le runbook (§6: la sonde thermique/ncu
formalisée, §7: le protocole L2 persisting).

## §10 Le ledger d'honnêteté

- PROUVÉ: la référence (91.3 % par des noyaux, pas un hack); la chaîne
  L2 ways bout-en-bout; les timings LHR (la marge constructeur); le
  write-primitive en boot; l'escalier de chiffres de §0 (arithmétique).
- HYPOTHÈSE: +1000-1500 MHz = le gain M2 (jamais mesuré avec un juge
  bande passante); le gain des timings à clock égale (~1-3 %); le
  thermique/refresh (3-8 %); l'overlap CE+SM; la compression compute;
  le % d'aujourd'hui lui-même (INDECIDABLE jusqu'au J1).
- INDECIDABLE-BY-BYTES: la résidence runtime des records timing (le §5
  décide); le producteur MclkProg (le trace-ring décide); le % stock.
- REFUSÉ-BY-CARD: RMClkVfOverride, RMUseTc0NonCoherent, time-math à
  l'aveugle, tout flash (CERT20), le Tier 4 tant que la décision
  PC-only tient.
- La projection finale honnête: M1 ~409 (quasi-certain, logiciel pur) →
  M2 ~440-485 (probable, le sweep décide) → M3 600+ L2-résident (certain
  pour les patterns qui tiennent en L2, dès le Tier 1) → M4 le 600
  streaming = le mur matériel, documenté, hors périmètre.
