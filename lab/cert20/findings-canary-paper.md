# findings — "A Canary in the Crypto Mine" : l'analyse complète et le plan GA104

Date : 2026-09-20. Source : Jon Pry, « A Canary in the Crypto Mine: Defeating
Stack Protection in a GPU Secure Coprocessor », juin 2026, 16 pages, Zenodo
record `20916112` (PDF : `../canary-crypto-mine.pdf`, le texte extrait
`.txt`, 965 lignes). ResearchGate 408132536. Disclosure publique
simultanée — le vendor notifié, sans embargo, **parce que le remède du
vendor (la révocation par fusibles) frappe le propriétaire, pas un
attaquant** : « in the inverted threat model of this paper, where the
defender is the device and the adversary is its owner, declining the
embargo is the user-protective choice ».

## 1. Le cadre qui légitime notre usage

Le paper frame le travail comme « legitimate security research and as an
interoperability and right-to-repair investigation », sur du matériel
possédé, sans changement persistant du silicium, sans clé extraite, sans
signature forgée. Notre situation = exactement la même classe : la RTX 3070
nous appartient, la limite que nous levons = une décision commerciale
logicielle, et la méthode = publique, publiée, éthiquement défendue par son
auteur contre l'objection « mais c'est du contournement ».

## 2. La chaîne de la vulnérabilité (au niveau instruction)

Le booter_load du SEC2 (uCode Falcon, AES-chiffré au repos, déchiffré
in-Falcon en HS) contient :

- `booterVerifyLsSignatures_TU10X` @IMEM **0x29C4** — la vérification des
  signatures LS du GSP-RM.
- `booterIssueDma_HAL` (lcall 0x0601) et `dma_copy_block` @IMEM **0x4d4**,
  appelé @**0x37b3** — le DMA : destination fixe **DMEM 0x800**, longueur =
  **WprMeta.sizeOfSignature** — un champ du WprMeta, structure DMA-ée depuis
  la mémoire système **contrôlée par le host**. Aucune borne.
- L'arithmétique exacte : 0x800 + 0xF800 = 0x10000 = le haut du DMEM. Le
  canary global @DMEM **0x6340** (payload offset 0x5b40) + les copies
  sauvegardées @0xFF58/0xFF94/0xFFA0/0xFFC4 = tous écrasés par le fill
  uniforme V.
- `image_auth_decrypt` @IMEM **0x2e80** (AES+MAC, les valeurs WprMeta en
  r2..r7) : le check de longueur passe naturellement (0xF800 copiés =
  0xF800 déclarés — « the oversized signature is self-consistent »).
- `__stack_chk_fail` @IMEM **0x7dd9** (le spin) ; **0x7de9** = la variante
  debug (imprime $r15 sur MAILBOX0 — « the basis of every debug ROP built
  during the project »).

## 3. Le mécanisme de victoire du canary

« Defeat by uniformity, not by prediction » : le fill uniforme V écrase le
guard global ET toutes les copies sauvegardées — chaque épilogue compare
V==V, passe, et retourne dans la chaîne. La valeur = arbitraire ; l'entropie,
le secret et la fraîcheur par boot = irrelévants. La mitigation entière se
réduit à « le mot de référence est-il immuable ? » — et le placement de
l'outil répond non.

Le fill V = **aussi l'adresse de retour** : le PC détourné vers V = un
point du code du booter. Le payload = une « continuation image » valide —
construite par émulation (voir §5).

## 4. La structure du ROP (le vocabulaire des gadgets)

Le chain du cmpunlocker (24 dwords, validé sur le silicium A100/CMP) :

| Slot (payload offset) | Contenu |
|---|---|
| 0x1100 | header 0x7 |
| 0x5b40 | canary (→ DMEM 0x6340, le guard global) |
| 0xf754 | write_value (runtime) |
| 0xf75c | gadget_1 = 0xcbd (charge write_value) |
| 0xf76c | write_addr (runtime) |
| 0xf774 | gadget_2 = 0x1fbd (le commit) |
| 0xf780 | zero |
| 0xf788-0xf7b8 | gadgets 3-9 (0x10aa, 0x815a, 0x8e18, 0x815a, 0x1fbd, 0xffbc, 0x582d) |
| 0xf7c4-0xf7f8 | canary + gadgets 10-14 (0xcbd, 3, 0x1fbd, 0xccb, 0x7f2f) |

**Notre booter contient ces adresses comme du code valide** (le test
d'aujourd'hui : 0x8e18 = `auipc ra, 0x5; jalr` = un appel réel ;
0x815a = dans le texte). **La base IMEM du texte = 0x8000** (au-dessus de
la BROM 32 Ko @0x0). Les gadgets > 0x4414 (0x815a exclu) = au-delà du texte
— dans le resident ou la BROM — le mapping précis = le prochain pas.

## 5. L'émulateur = l'oracle et le décrypteur

Le paper : « deterministic microcode is fully emulatable, so the payload is
a valid continuation image ». L'émulateur du paper (jamais publié, mais le
méthode = documentée §7) : l'exécution cycle-fidèle inclut **le
déchiffrement AES du booter_load** — l'IMEM déchiffré = récupérable par
l'émulation. Pour NOTRE booter (le 610.57.04's TU10X booter_load, dans
`g_bindata_kgspGetBinArchiveBooterLoadUcode_GA102.c` du DKMS tree — 459 Ko
de C, les sections IMAGE/HEADER/SIG/PATCH) : le même chemin = extraction →
l'émulation avec le déchiffrement → l'IMEM déchiffré → les gadgets.

L'émulateur du cmpunlocker (booter_emu.py + booter_secure.py) modélise déjà
: les CSR Falcon (0x7c8/0x7cc = BAR0, 0x7ca = fuse, 0x7d0-4 = DMA,
0x7d5-9 = AES, **0x7da = le bypass HMAC**), le DMEM, l'IMEM — l'extension =
le déchiffrement réel du uCode (l'AES key = modélisée — la source = le
BROM/le header du uCode).

## 6. Le static checker (§8) — la méthode pour OUR booter

Le paper implémente « a small static checker over the booter's instruction
stream » : (A) le DMA = un copy sink (l'idiome : la destination latched +
l'appel dans la routine de transfert), (B) le taint = le DMA depuis la
mémoire host, (C) l'obligation bounded-write (L ≤ S − o), (D) l'escalade
par layout (le guard → les canaries → les return addresses), (E) les
contrats HAL. **Le checker a couru sur le corpus** : il marque
« l'open-kernel-era booter's signature-read transfer » comme le seul sink
non borné, et passe les booters anciens sans faux positifs.

Pour nous : le checker appliqué à NOTRE booter_load (déchiffré par
l'émulation) = l'inventaire des gadgets ET la validation que notre version
a la même régression.

## 7. La persistance : l'always-on island

« The override values we write through the opened PLMs are held in an
always-on island and survive the reset » — **les overrides écrits en PLM
ouvert persistent à travers le FLR et le reload du driver stock** ; les
PLM se re-verrouillent, les valeurs restent. L'exploit = transient, le
résultat = durable. Pour nous : le write du power limit (280000 mW) dans
le registre EDPp = persistant après le FLR — pas de daemon nécessaire (au
contraire du cmpunlocker dont les writes = les registres qui se
re-verrouillent).

## 8. La taxonomie et notre position

Le paper : defeated-in-firmware = les shadow registers des fusibles (le SM
rate, la capacité, le PCIe Gen2) ; defeated-only-in-hardware = le lane
width (les condensateurs AC dépopulés — la soudure !) ; not-defeated =
PCIe Gen3, l'ECC on-die, le HBM MRS (source-ID-locked, hypothèses de
travail).

**Notre RTX 3070** : les limites = PAS des shadow registers de fusibles
(nos SMs = pleine vitesse, notre VRAM = pleine) — les nôtres = la **table
EDPp du VBIOS** (le power budget 100/240/250 W @0x8fc04, appliquée par le
GSP-RM comme limitMax) et les **caps vP-state** (2100 MHz). Le mécanisme du
paper (le PLM ouvert = les writes BAR0 arbitraires) s'applique au registre
EDPp de la GA104 **si** nous trouvons son adresse : la trace NVML (le
driver écrit la limite !) + les register maps du paper + le RM émulé. Le
280 W = un write — mais le registre = à trouver, et la persistance EDPp =
à vérifier (le GSP-RM peut re-clamper depuis sa table interne à chaque
init — le test le dira).

## 9. Le plan d'adaptation GA104 (l'ordre d'exécution)

1. **Extraire booter_load** du BINDATA GA102 de notre driver (le DKMS
   tree, `g_bindata_kgspGetBinArchiveBooterLoadUcode_GA102.c` — les
   sections IMAGE/HEADER/SIG/PATCH en C arrays).
2. **L'émulation avec déchiffrement** (étendre booter_emu/secure : l'AES
   key + le flux HS) → l'IMEM déchiffré de NOTRE booter.
3. **Le static checker** (le port du §8 du paper) sur notre IMEM → les
   gadgets (les write-to-BAR0 + les slots de la stack) + la validation de
   la régression.
4. **Le patch driver** : kgspPopulateWprMeta — sizeOfSignature = 0xF800 +
   le buffer = le payload avec NOS gadgets et NOTRE cible (le registre
   EDPp power).
5. **Le DKMS build + le test hardware** : le fire, le MAILBOX0 oracle, le
   PLM FEAT vérifié, puis le power write, puis nvidia-smi -pl 280.

## 10. Les références du paper à exploiter

- P2IM / HALucinator / Fuzzware / DICE : les modèles périphériques pour
  l'émulation (la référence DICE = le DMA input modeling !).
- Xing, arXiv:2505.03782 : l'autre étude CMP 170HX (le contournement
  applicatif — le FMA routing — ×15 FP32 sur le firmware stock ; notre voie =
  en dessous, le firmware lui-même).
- gpu-burn : le stress test de validation.
- Le dual-BIOS : le filet permanent (jamais requis — les 4 récupérations
  étaient toutes logicielles).
