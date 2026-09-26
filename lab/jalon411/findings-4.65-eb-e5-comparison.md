# 4.65 — La comparaison EB ↔ E5 (l'audit externe exécuté, offline, zéro boot)

Date : 2026-09-27. Déclencheur : l'audit stratégique externe (GPT-5.6,
`GPU_280W_AUDIT_4.59_4.64_PLAN.md`) qui exigeait la Phase 1 (le dump ×2) et
la Phase 2 (la comparaison structurelle) AVANT toute écriture.

## Résultat exécutif

La comparaison structurelle EB ↔ E5 est **exécutée offline, en une passe,
sans un seul boot** :

- **455 octets différents sur 962 048 = 0,047 %** entre le raw .EB (le
  sibling `_1`, même board que notre puce) et le raw .E5 cible — même
  taille, mêmes tables aux mêmes offsets.
- **Le board marker = IDENTIQUE** : `MSINV390MH` / `0V39020` porté par
  notre propre puce (@0x80), le sibling ET l'E5 — la famille board MSI
  3070 = une seule référence board.
- **La mémoire = SAMSUNG des deux côtés** : `SAMSUNG-SNTBVV-11` (EB) vs
  `SAMSUNG-SA1KY4-24` (E5) = deux lots Samsung 8Gb (la gx16 ~85 %Samsung
  confirmée par le construit .E5 lui-même).
- **La puissance = des deltas in-place** : le cluster
  {100000, 240000, 250000} → {100000, 280000, 300000} au MÊME offset
  0x86a04, les quatre hits au MÊMES offsets {0x86a08, 0x87491, 0x874c4,
  0x874f7}, le 220000 commun @0x33f04.
- Les deltas restants = les bins clock autour des états power (la classe
  1760→1920 = les bins Suprim, attendu pour le construit 280 W) et
  **UNE région inconnue 326 B @0xe8e12–0xe8f57** (dense, à classifier —
  l'unique rangée UNKNOWN du gate).

## Les corrections de provenance que cette passe a dû faire (l'honnêteté du ledger)

1. **`vbios-stock.rom` N'EST PAS « partiel »** (le libellé erroné de
   4.64, corrigé) : sha256 `135b215313fa4d1e…` = **exactement le dump
   double-lecture du 2026-09-17** (rom-read-20260917 : deux lectures
   byte-identiques, la chaîne PCI de la puce auto-cohérente : 65 024 B
   x86 @0 + 92 672 B EFI @0xFE00 = 157 696 B). C'est la **chaîne
   complète et auto-cohérente** de notre puce — l'identité fiable
   (PCI 10de:2488, subsystem 0000:0300, MSINV390MH, version .EB).
2. **Mais ce n'est PAS le contenu SPI intégral** : le sysfs ne sert que
   la chaîne legacy ; la lecture in-session du SPI complet = **fermée
   par mesure** (le registre day-0 : le BAR d'expansion ne sert pas le
   SPI à l'hôte ; les dumps « BAR window » = des lectures ratées — la
   v1 = la RAM d'un autre périphérique). La ferme de tables (le cluster
   power, les strings SAMSUNG, les tables fan/thermal) vit AU-DELÀ de
   157 696 B.
3. **Conséquence pour la loi §2** : le chip-before réel (l'image SPI
   ~1 Mo, ce que nvflash efface/écrit) = à lire **×2 dans le guest**
   (nvflash --save) — PREMIER geste du jour flash, avant toute écriture.
   Le dump chaîne 157 696 B = le pré-check d'identité, pas l'image de
   rollback complète.
4. **Le proxy de la ferme EB** : le sibling `_1` (TPU, même board
   MSINV390MH, les couches BIT+mémoire byte-égales à notre puce — le
   registre acquisitions ; les diffs connues = le head 23 B + la région
   0x7e00–0xf400) = la source honnête de la ferme EB tant que le SPI
   complet de notre puce n'est pas lu. La comparaison ci-dessous =
   sibling-EB ↔ E5.

## La table de comparaison (la A4 de l'audit, remplie)

| champ | EB (notre puce + sibling) | E5 cible | verdict |
|---|---|---|---|
| taille image | 962 048 B | 962 048 B | SAFE (identique) |
| PCI vendor/device | 10de:2488 | 10de:2488 | SAFE |
| subsystem in-image | 0000:0300 (norme MSI) | 0000:0300 | SAFE |
| board marker | MSINV390MH / 0V39020 (@0x80, notre puce) | MSINV390MH / 0V39020 | SAFE (identique) |
| mémoire | SAMSUNG-SNTBVV-11_x-2_y6 (8Gb) | SAMSUNG-SA1KY4-24_x0_y4 (8Gb) | SAFE (même vendor, lot différent) |
| cluster power | {100000, 240000, 250000} @0x86a04 | {100000, 280000, 300000} @0x86a04 | DIFF in-place (L'OBJET) |
| offsets des hits power | 0x33f04, 0x86a08, 0x87491, 0x874c4, 0x874f7 | LES MÊMES | SAFE (structure commune) |
| bins clock aux états power | classe 0x06e0 (1760) | classe 0x0780 (1920) | WARN (les bins Suprim — le runtime gère) |
| tables périphériques (0x3446x, 0x80aex, 0x88exx, 0xb7exx) | petits deltas u16 | petits deltas u16 | WARN (fan/thermal/clock — non bloquant attendu) |
| région 0xe8e12–0xe8f57 (326 B) | dense | dense | **UNKNOWN — à classifier avant l'écriture** |
| SPI intégral de notre puce | non capturé in-session | — | le chip read ×2 GUEST = prérequis |

**La classification du gate : ZÉRO INCOMPATIBLE connu ; UNE UNKNOWN
(326 B) ; le cross-flash = admissible sous réserve du chip read ×2
guest + la classification de 0xe8e12.** Le précédent communautaire
(kuiwbg : le même cross-flash Gaming X Trio → Suprim X = daily driver)
et l'enveloppe officielle MSI (280 W 2×8-pin sur la famille) = la couche
empirique convergente.

## Les instruments

- `v463a_vbios_decode.py` (le décodeur du repo, selftest 29/29) sur les
  trois images : notre chaîne (erreur attendue « no budget cluster » =
  la preuve structurelle que la ferme vit au-delà de 157 696 B), le
  raw _1 (cluster {100000, 240000, 250000}), le raw .E5 (cluster
  {100000, 280000, 300000}).
- le diff byte inline (50 plages, listées dans la passe) — à
  intégrer en instrument rangé `v465a_eb_e5_diff.py` au prochain
  tour si le gate doit être re-joué.

## Le prochain geste (l'ordre inchangé, maintenant informé)

1. `bash -n flash-day-v7.sh` ; l'installation v7 (un sudo) ;
2. le boot Flash463 → **le chip read ×2 COMPLET dans le guest** (le
   vrai chip-before ~1 Mo, cmp + sha256) ;
3. la classification de la région 0xe8e12 (offline, sur les raws) ;
4. SEULEMENT ENSUITE : l'écriture .E5 ou l'arrêt honnête — le verdict
   appartient au gate, pas à l'élan.

## Addendum (le même jour) — la région 0xe8e12 CLASSIFIÉE : le bloc BIT compressé

L'UNKNOWN du gate est levée offline : le contexte avant la région =
`42 49 00 10 00 00 01 01 78 da` = **le token BIT (id 0x4942, taille
0x1000) portant un flux ZLIB** (`78 da`). Décompression des deux côtés :

- les deux flux décompressent en **4 080 B, structure identique** (l'en-tête
  `ROM\x01\x02\x70…`, les tokens `IMGD/BOBD/…`) ;
- la diff décompressée = **169 octets**, trois familles : (1) la tête
  power/clock (@0x000a), (2) **les chaînes OEM/mémoire** (les mêmes
  SAMSUNG-SNTBVV-11 vs SAMSUNG-SA1KY4-24 que la copie non-compressée
  @0xb8219 — le bloc = la copie compressée des mêmes données), (3)
  **une table à stride 8 remplie dans l'E5 et à ZÉRO dans l'EB**
  (@0x0560+, la classe fan/thermique — le radiateur Suprim ≠ le Trio).

**La classification : tables périphériques par-board compressées — PAS
des signatures, PAS du cryptographique. WARN (le flash = adopter la
politique fan/thermique Suprim sur notre radiateur Trio — le tradeoff
connu du précédent kuiwbg), NON bloquant.** Le gate final : ZÉRO
INCOMPATIBLE, ZÉRO UNKNOWN bloquant — reste uniquement le chip read ×2
guest (le rollback physique).
