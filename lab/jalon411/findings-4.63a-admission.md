# 4.63a — L'admission du ROM réel (the founder day)

Date : 2026-09-26.

## Résultat exécutif

Le ROM cible identifié en 4.63 (MSI Suprim X 94.04.46.00.E5, TPU 277875) a été
téléchargé par le fondateur et soumis aux portes v463a. Le refus initial a
enseigné **trois lois**, toutes désormais en code dans le décodeur. À la sortie :
le fichier est **admis**, l'identité = OK (10de:2488, version .E5), et le
**cluster de budget = {100000, 280000, 300000} mW @0x86A04 → la porte 280 W
est passée sur le fichier réel**. Le jour flash (runbook-463 §2, le transport
VFIO) est admissible.

## Les empreintes (l'admission ring-12/14)

| artefact | taille | md5 | sha1 |
|---|---|---|---|
| le fichier TPU téléchargé (le conteneur NVGI) | 999424 | `54968a598b4f8479bc597b63033e6e11` | `dc517d1ad5baad7a926e2913c72b2fc9ce7097a1` |
| le ROM brut extrait (LE FICHIER FLASH) | 962048 (0xEAE00, aligné 512) | `ccabe841014d92d5fad82472ff820541` | `95b3624ac00f5ecb3e77fb648ab03b304b0f6b1b` |

La comparaison avec les valeurs publiées par la page TPU = le geste du
fondateur dans son navigateur (les pages .rom = bot-checkées pour nous).

## Les trois lois

### 1. Le conteneur NVGI

TPU sert les .rom enveloppés dans le conteneur de flash-image NVIDIA
(`NVGI` en tête). L'image active = le premier 55AA dont la chaîne PCI
parse — @0x9200 pour le .E5. La disposition GA10x (PCIR à image_start+0x170)
est vérifiée sur **deux sources genuines indépendantes** : le dump de notre
propre puce (.EB) et l'archive TPU (.E5). v463a écrit le brut à côté du
fichier (`*.rom.raw.rom`) ; **le fichier flash = le brut**, le NVGI = le
transport.

### 2. La porte subsystem corrigée

Le .E5 genuin = subsystem `0000:0300` — **et notre propre puce .EB lit la
même chose**. Le subsystem zéroré = la norme de la famille MSI dans l'IMAGE
du ROM ; le 1462:3904 vivant = chargé depuis la région strap, pas cuit dans
l'image. L'autopsie day-0 est précisée : les 35 sessions VFIO sont mortes
sur le **Device ID** zéroré (« Firmware image PCI Device ID (0000) …
mismatch »), pas sur le subsystem. La loi du verdict : vendor != 10de ou
device zero → REFUS ; subsystem zero → OK avec la note nommée. Le mismatch
subsystem au flash = le travail du binaire patché 2 octets, inchangé.

### 3. Le fallback cluster v0x4D

La table P du .E5 = version 0x4D (la grammaire ring-3 nommait v2 + budget
v0x30). Fallback : le budget = le triplet u32 consécutif aligné-4
{min ≤ 150000, cap, max}, les trois dans le filet du census mW. Sur le .E5
réel : **exactement un** triplet — @0x86A04 = {100000, 280000, 300000}. Les
trois autres hits 280000 échouent à la forme (non-alignés, ou max hors
filet) : le census EST la grammaire quand la grammaire nommée ne parse pas.
Notre dump .EB partiel (157696 B) = tronqué avant la table-ferme (0x8FB48
au-delà) : la loi full-dump est rappelée pour CHIP_REF.

## Selftest

29/29 (contre 20/20 en 4.63) : les checks NVGI (l'enveloppement, le
passthrough du non-NVGI), la norme subsystem (le fixture zéro-subsystem-seul
= OK avec la note), le cluster v0x4D (le fixture aligné, l'ambiguïté
impossible), la garde de bornes du reader.

## L'état du jour flash

- le fichier flash = `~/dmem-451/vbios-flash/MSI.RTX3070.8192.210519.rom.raw.rom`
- les portes §0 du runbook-463 : l'instrument OK (selftest 29/29, le patch
  2-octets vérifié @0x18460B 75 18 → 90 90), l'admission = la comparaison
  TPU par le fondateur, l'identité = OK, le peak = 280000 mW
- le prochain geste = **§2 le jour VM** (le transport VFIO day-0, le chip
  read ×2 + cmp AVANT toute écriture, RUNBOOK_463_FLASH_ACK)
- le rollback = le re-flash de chip-before.rom (pas de switch dual-BIOS sur
  cette board)
