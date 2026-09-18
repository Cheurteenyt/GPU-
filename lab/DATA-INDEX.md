# DATA-INDEX — le catalogue maître des données de reverse engineering

Chaque adresse, structure, table et artefact décodé par les 40 rings,
avec sa localisation et l'instrument qui le reproduit. **La data se trouve
ici d'abord.**

## 1. La carte d'adresses rm.elf (build 610.57.04, 16 912 384 B)

VA = file_offset + 0x1000000 (code, file 0x0-0xe9b000) ; VA = file_offset
- 0xe9b000 + 0x4000000 (data, file 0xe9b000-0x1070000).

| Adresse | Quoi | Source |
|---|---|---|
| `0x1631010` | **Vraie entrée du grand parseur perf** (appelle le capability setter à l'entrée) | vague 4.9 |
| `0x1631300-0x1632790` | Le grand parseur perf (UNE fonction) | vague 4.6 |
| `0x1631e02` | Dial `RMDisablePStates` (consommateur) | vague 4.6 |
| `0x1631e28` | Dial `AllowMaxPerf` (consommateur) | vague 4.6 |
| `0x16322c6` | Dial `RMDisablePerfIntersect` (consommateur — notre dial 2) | vague 4.6 |
| `0x1632714` | Dial `PerfPmaControlReg` (consommateur) | vague 4.6 |
| `0x1630c48` | Le setter (requestCapabilityChange) | vague 4.4 |
| `0x1631010` | Handler de capacité (parseur) | vague 4.4 |
| `0x1634bc2` | Lecteur bit 0 (le court-circuit VF) | vague 4.4 |
| `0x1634ff8 / 0x1635286` | Lecteurs bit 8 | vague 4.4 |
| `0x1634a38` | Le moteur (requête type 0xc) | vague 4.4 |
| `0x1684880` | Callback du bit 0 (tail-call de chaînage) | vague 4.4 |
| `0x16844bc/0x1684880/0x1684330/0x16745b8/0x1674f0c` | Les 5 vtables-texte | vague 4.4 |
| `0x1457440` | Le chercheur BOARDOBJ (hash +0x48, clé 64 o) | vague 4.7 |
| `0x14571b8` | Le fallback 0xf de PerfPmaControlReg | vague 4.7 |
| `0x164b388-0x164c7c8` | Le destructeur perf-state (libère types 0xf et 0x16) | vague 4.9 |
| `0x1915574 / 0x193cc44` | Stubs no-op (les « vtables » 4.7 corrigées) | vague 4.9 |
| `0x1b3c2xx-0x1b3cxxx` | Le cluster mappers strap→code | vague 4.9 |
| `0x1DEB210 / 0x1DEB280` | Décodeurs 5-bit packed-field (rodata jump tables) | vague 4.9 |
| `0x68A00C / 0x68A01C` | Registres matériels lus par les mappers (straps) | vague 4.9 |
| `0x1e83d38` | Le bitmap de whitelist des séquences (0x0001000100210001 : IDs 0x20/0x30/0x35/0x40) | vague 4.8 |
| `0x164a1c4` | Secondaire 100 appelants — **ambiguïté publiée** | vague 4.5 |

## 2. La machinerie de capacité (l'objet d'état +0x324/+0x328)

| Bit | Qui le pose | Sémantique |
|---|---|---|
| 0 | dial `RmVFPointCheckIgnore=1` → SET 0x1631366 | Court-circuit de validation VF (notre levier) |
| 1 | SET 0x1631310 | Re-séquençage de la chaîne VF (posé avec le bit 0) |
| 8 | **FORCÉ par le dispatcher** à l'entrée des requêtes (a3=1 codé en dur) + dial `RmPerfChangeSeqOverride` | « Second check désactivé » — armé par ClkAdc, lu par le moteur |
| 9 | **corrigé** : sortie de revalidation P-state — PAS un dial | vague 4.6 |
| 2,3,5,6,7,10,11 | attribués par région, libellés ouverts | vague 4.5 |

Le state root : `[state+0x3CD0]` (holder PMA-fallback, double-prouvé 4.9).

## 3. La chasse VMIN (rings 38-40 — junction avec les straps)

| Élément | Valeur |
|---|---|
| Dial | `RmSramVminCheckIgnore` — string VA 0x1e871b0 |
| Consommateurs | 2 sites : 0x6b98c4, 0x6ba30c |
| Le champ checké | u16 à +0x53a de l'objet de capacités |
| Lecteurs +0x53a | 0x6b381c, 0x6b9848, 0x6b9948 |
| Écrivains +0x53a | **0x161114, 0x9f4874** (l'initialiseur de l'objet — ring 40) |
| Les noms VMIN | pool MODS debug (VMIN_NVVDD/MSVDD/LOGIC/SRAM/IODVDD) — file 0xe8d308+ |
| Les seuils | **dérivés des straps** (hypothèse vague 4.9 : mappers 0x1b3c lisent 0x68A00C/0x68A01C) — pas de constantes mV en clair (ring 39) |

## 4. Les tables VBIOS (build 210519_1, offsets fichier MSI ; notre puce = identique décalée 0x9200)

| Table | Offset MSI | Structure | Contenu clé |
|---|---|---|---|
| BIT | 432 (legacy @0) | v1.0 | tokens, dont P @ +736/38,112 |
| Power budget (P+0x2C) | 588,616 | ver 0x30, 20×0x47B | **cap entry 2 : 100/240/250 W** |
| Power sense (P+0x28) | 585,871 | — | — |
| Fan coolers (P+0x58) | 591,405 | ver 0x10, 2×0x1A | duty 17-100 %, PWM 27 kHz, 1000-3250 RPM |
| Fan policy (P+0x5C) | 591,463 | ver 0x20, 8×51B | **17/45/100 % @ 55/75/80 °C → 1000/2100/3250 RPM** |
| Memory timings map | 564,474 | ver 0x11 | 7 bins actifs, monotone |
| Memory timings table | 571,520 | ver 0x20, **65×76 B = 19 FBPA regs/bin** | le bin 6801 : records [6,16,26,8,18,8,38,19,8,8] |
| vP-states | 563,764 (+header 22) | 7 profils × 65 B chaînés | IDs 0xF/0xD/0xC/0xA/0x7 — 2100/7001 → 420/405 |
| VF curve | — | **construite à l'exécution** | 127 points interpolés, PAS stockée (ring 37) |

## 5. Les artefacts day0 (les lectures de la vraie puce)

| Fichier | Quoi |
|---|---|
| `day0/rom-read-20260917/vbios-sysfs.rom` (+ -2) | La chaîne PCI complète, 157 696 B, double lecture identique |
| `day0/rom-bar-window.bin` | La fenêtre BAR 512 KiB, préfixe identique au sysfs |
| `day0/genshin-session-dial2.csv` | La première télémétrie de jeu réel (3 193 échantillons, 214 W médian) |
| `acquisitions/MSI.RTX3070.8192.210519_1.rom` | **Le build de la puce** (identité prouvée 512 Ko, décalage 0x9200) |
| `acquisitions/MSI.RTX3070.8192.210519_1-mod-280W.rom` | Le mod 280 W (6 octets, vérifié) |
| `acquisitions/MSI.RTX3070.8192.200923.rom` | Le build frère 200923 |

## 6. Les instruments (reproductibilité)

| Famille | Où | Quoi |
|---|---|---|
| gx1-gx15 | `lab/gx*.py` | Les décodeurs VBIOS (BIT, perf, clocks, timings, fan, vP-states) |
| v42-v45 | `tools/gsp-extract/v4*.py` | L'indexation/désassemblage/xref d'rm.elf (la campagne cloud) |
| wave2/xref | `tools/gsp-extract/wave2_*, xref_dials.py` | Le census des 881 dials + le xref des consommateurs |
| ROM reads | `tools/read-rom-bar.py`, `hwtruth/rom.py` | Les lectures doubles (sysfs + BAR) |
| Dials | `campagne-dial-gate.sh`, `tools/apply-dials.py` | Le gate de sécurité + l'application |
| Flash | `tools/usb-flash-session.sh`, `tools/vbios-power-mod.py` | La session flash (gates) + le constructeur de mod |
| Scans | `tools/scan-kcore-vbios.py`, `scan-bar1-vbios.py` | Les scans mémoire (kcore, BAR1) |

## 7. Les frontières (ce qui est muré, avec preuve)

- **La bindata GSP** : chiffrée (entropie 8.0000, zéro autocorrélation — ring 29). Clés en fuses/SE. **On n'entre pas.**
- **Le patch rm.elf** : le bootloader vérifie chaque section signée (directory 0x170/0x188/0x1f8 — ring 33). Le bypass sanctionné = les dials.
- **La courbe VF en clair** : absente du VBIOS (construite à l'exécution — ring 37).
- **LHR** : zéro string ethash dans le RM — côté driver hôte (vague 2).
