# 4.59 — audit profond du repo et fermeture de la piste 280 W

Date de l'audit : 2026-09-25.

## Résultat exécutif

Le repo a fait un vrai travail d'investigation : la limite de puissance a été ramenée d'une recherche VBIOS très large vers un chemin runtime dans GSP-RM, puis vers une primitive de contrôle au stade Booter. Le point 280 W est lui-même déjà matérialisé comme forme µW exacte (`0x10B07600 = 280000000`), mais le blocage actuel n'est plus « trouver 280 W » : c'est **obtenir un contrôle fiable du `ra` de la frame GA104 avec le payload POSTBL**, puis seulement exploiter le registre déjà identifié.

Le pass 4.58 contient quatre problèmes de reproductibilité/correction qui doivent être traités avant d'interpréter un nouveau boot :

1. **Le flush du WPR_META est absent du helper v448**, alors que le journal 4.58 affirme qu'il a été ajouté et que le transpose 4.57/référence le fait explicitement. Le helper réécrit `sysmemAddrOfSignature` et `sizeOfSignature` après le flush du memdesc, puis s'arrête sans `memdescFlushCpuCaches()` sur le descripteur WPR_META.
2. **`patch448.py` est annoncé comme commité, mais n'est pas présent dans `main`**. Le dernier commit 4.58 ne contient que `STATE.md`, `INDEX.md`, `findings-4.58-machine-day.md` et `tools/booter-patch/v448_tail_write.c`.
3. **`v448_patch_signature_tail()` n'est pas relié à un chemin d'intégration visible dans le dépôt** : la recherche de code ne renvoie pas d'appel au symbole. Le fichier ressemble donc à un drop-in, pas à un patch exécutable/reproductible.
4. **Le sweep d'offsets 4.58 n'est pas cohérent avec les faits 4.45 si on suppose `payload_offset == stack_offset`** : la frame `main` fait `0x620`, et le `ra` sauvegardé est à `0x618`. La chaîne v448 fait `0xa8` octets (`0xf754..0xf7f8`). Dans ce modèle, `0x300/0x400/0x480/0x500` ne peuvent pas toucher le `ra`; `0x580` touche bien le `ra`, mais la valeur présente à la position correspondante de la chaîne est `0x00000000`.

La conséquence pratique est importante : **le prochain travail utile est un problème de géométrie de stack/chaîne, pas une nouvelle recherche aléatoire d'offsets**.

## Chaîne de preuve 4.21 → 4.58

### 1. Le chemin de puissance est runtime

Les passes 4.43/4.44 ont fermé la voie d'une constante statique simple dans le VBIOS et ont établi une formule runtime dans GSP-RM : une base par groupe/pstate est multipliée par un facteur de record (`f18`), avec plusieurs valeurs alimentées dynamiquement.

Deux formes 280 W sont documentées dans le dépôt :

- base µW : `0x10B07600` = `280000000` µW ;
- route `f18` : facteur 112 % / 1120 ‰, par rapport à la base 250 W.

Le pass 4.54 a ensuite posé une discipline claire : un écriture future n'est acceptable que si une lecture réelle produit d'abord une ligne `POWER-BASE-MATCH`. Le `v454d_write_plan.py` reste volontairement un plan, pas une écriture.

### 2. Le contrôle par overflow POSTBL est distinct de la lane transfer-list

Le pass 4.44 a falsifié la lane « remplacement libre du memdesc de signature » : le Booter vérifie bien cette zone et renvoie `0x1d` quand elle est altérée de manière incompatible.

Le pass 4.45 a ensuite caractérisé une lane différente : le memdesc sert de **véhicule d'overflow du Booter**, avec la possibilité de reprendre le contrôle via la pile du Booter. L'analyse `v445a_booter_copy.json` donne 44 frames analysées ; la plus grande est `0x620`, sur `main @ 0x101e0a`, et le `ra` est sauvegardé à `0x618`.

### 3. Le transpose cmpunlocker est bien la bonne famille de mécanisme, mais son placement n'est pas transposable tel quel

Le pass 4.57 transpose sur GA104 le mécanisme de référence : memdesc `0xf800`, remplissage uniforme `0x4a7`, chaîne `0xf754..0xf7f8`, refill, re-point du WPR_META, puis ré-exécution du Booter.

Le dépôt documente explicitement deux différences majeures : le chemin du `dmem.bin` n'est pas repris, et le mapping des gadgets GA100 n'est pas prouvé par les octets du Booter GA104.

### 4. Le pass 4.58 apporte le bon post-mortem, mais son helper contient une erreur de cohérence

Le journal 4.58 dit : « re-point WPR_META + flush descriptor ».

Le `tools/booter-patch/v448_tail_write.c` réel fait :

```c
memdescFlushCpuCaches(pGpu, pMemdesc);

if (pKernelGsp != NULL && pKernelGsp->pWprMeta != NULL)
{
    pKernelGsp->pWprMeta->sysmemAddrOfSignature =
        memdescGetPhysAddr(pMemdesc, AT_GPU, 0);
    pKernelGsp->pWprMeta->sizeOfSignature = memdescGetSize(pMemdesc);
}
```

Il manque le flush du **descripteur** WPR_META après cette mutation. Le patch de référence `imports/cmpunlocker/sec2-postbl.patch`, ainsi que le transpose 4.57, font explicitement ce second flush.

Ce point est particulièrement intéressant parce qu'il explique à lui seul pourquoi la conclusion « v448b a bien repointé la taille, mais le Booter a continué à se comporter comme v448a » ne peut pas être considérée comme preuve propre tant que la cohérence cache n'est pas réparée.

## Re-déduction de la géométrie v448

Faits d'entrée :

- frame `main` = `0x620` octets ;
- `ra_slot = 0x618` ;
- chaîne = `0xf754..0xf7f8` ;
- longueur = `0xf7f8 - 0xf754 + 4 = 0xa8` octets ;
- chaîne = 42 dwords.

### Le sweep 4.58 actuel

Sous le modèle direct `payload_offset == stack_offset` :

| Start | Fin excl. | `ra` touché ? | dword injecté au `ra` | Lecture géométrique |
|---|---:|---|---|---|
| `0x300` | `0x3a8` | Non | — | trop bas pour toucher `0x618` |
| `0x400` | `0x4a8` | Non | — | trop bas pour toucher `0x618` |
| `0x480` | `0x528` | Non | — | trop bas pour toucher `0x618` |
| `0x500` | `0x5a8` | Non | — | trop bas pour toucher `0x618` |
| `0x580` | `0x628` | Oui | `0x00000000` | le `ra` reçoit le dword à la position `0xf7ec` |

Donc les quatre premiers points sont des tests de présence de chaîne, mais **pas des tests directs de prise du `ra`** sous ce modèle. `0x580` est le seul des cinq à atteindre `0x618`, mais la valeur correspondante dans la chaîne est zéro.

### Le cas `0x578`

La recherche ciblée des dwords qui sont déjà connus comme gadgets donne quatre starts 8-alignés possibles sous le modèle direct :

- `0x610` → `ra = 0x0cbd` ;
- `0x5f8` → `ra = 0x1fbd` ;
- `0x5c8` → `ra = 0x1fbd` ;
- `0x578` → `ra = 0x0ccb`.

Le point remarquable est `0x578` :

- `0x578 + 0xa8 = 0x620` exactement ;
- le `ra` à `0x618` reçoit alors le dword `0x00000ccb` ;
- la chaîne complète reste dans la frame `0x620`.

**C'est un cas discriminant propre pour le modèle direct.** Ce n'est pas encore une preuve d'exécution : le dépôt lui-même classe les gadgets GA100/BROM comme indécidables par les octets du Booter GA104. Il faut donc garder `0x578` dans la catégorie « hypothèse à falsifier/confirmer », pas « solution ».

## Le vrai blocage restant : le biais de destination

Toute la déduction ci-dessus suppose que l'octet 0 du memdesc copié devient l'octet 0 de la frame de `main`.

C'est précisément le point qui n'est pas encore prouvé dans les éléments 4.45/4.58 consultés. Tant que le **biais `copy_dst - sp`** n'est pas connu, un start payload `S` correspond en réalité à :

`stack_offset = S + bias`

et le test du `ra` devient :

`S + bias = 0x618`.

La prochaine instrumentation utile doit donc sortir une table `start × bias × ra_value`, au lieu d'un simple sweep de starts choisis à la main.

## Travail effectué dans cette passe

J'ai préparé trois artefacts offline :

1. `v459_frame_audit.py` — rederive la frame, le `ra`, la longueur de la chaîne et le sweep ; il calcule aussi les starts qui placent exactement un dword gadget connu sur le `ra`.
2. `v459_frame_audit.json` — matrice calculée sur ces faits.
3. `v448_tail_write.fix.patch` — correction ciblée du helper 4.58 : garde de taille, usage du couple WPR_META/WPR_META_DESC comme dans la référence et flush du descripteur après re-point.

Le selftest du nouvel analyseur passe `8/8`.

## Ordre de travail proposé pour 4.59 machine day

### A. Corriger la cohérence v448

Avant de tirer une conclusion sur les boots 4.58 : intégrer le second flush WPR_META exactement après la réécriture de `sysmemAddrOfSignature` et `sizeOfSignature`.

### B. Remplacer le sweep empirique par un sweep géométrique

Faire produire au builder les candidats correspondant à :

- `ra_slot = 0x618` ;
- starts 8-alignés ;
- éventuellement biais de destination variable ;
- valeur exacte écrite au `ra` ;
- drapeau « chaîne complète dans la frame ».

Le premier discriminant du modèle direct est `0x578`.

### C. Vérifier la cible de puissance avant toute écriture

La chaîne de preuve 4.54 reste valable : lire d'abord, classifier ensuite. Le `280 W` exact est `0x10B07600`, mais la correspondance entre un offset GA104 précis et cette forme doit rester une propriété mesurée, pas déduite d'un offset GA100.

### D. Garder la réversibilité totale

Aucune modification de firmware ; restaurer le module/driver seul ; conserver un observable binaire post-boot pour chaque position ; refuser tout write quand l'ACK de l'étape précédente manque.

## Limites de cet audit

Je n'ai pas touché à la carte et je n'ai pas lancé de boot matériel. Le connecteur GitHub a refusé la création de branche par `403`, et l'environnement local n'a pas d'accès réseau à GitHub ; je n'ai donc pas poussé une modification sur `main`.

Les conclusions ci-dessus sont établies à partir des fichiers et commits présents dans le dépôt au moment de l'audit, notamment `41146409cdb51b84f8d90778d826295bab9fbef1` et son parent `6354c3a58fd242024f61f987cdf19d97f67e6b1c`.
