# 4.59 machine day — La clôture de la lane boot 280 W (the founder day)

Date : 2026-09-26.

## Résultat exécutif

Le plan de l'audit 4.59 a été exécuté sur la machine : le fix flush
(`v448b`) intégré, puis le sweep géométrique lancé par son premier
discriminant **`0x578`** — la chaîne placée à la position géométrique
EXACTE (le ra @0x618 reçoit notre gadget `0x00000ccb`, vérifié au niveau
octet dans le module par le python regex — l'od grep simple = l'artefact
de split de ligne).

**LE WRITE N'A PAS TIRÉ.** Le post-mortem PLM : le WPR = `0x4cb8f` = le
stock. Le modèle direct (payload offset == stack offset) =
**falsifié par son propre discriminant** — le biais de destination
(copy_dst − sp) = la traduction manquante confirmée.

## Le verdict structurel

1. **Le mur RSA** — le memdesc = l'entrée de vérification ; toute
   modification = l'échec cryptographique. Aucun contenu modifié ne passe.
2. **Le mur falcon** — le gestionnaire d'erreur du GA104 = la boucle
   sécurisée SANS RETOUR (pas de ROP, pas de contrôle). Le CMP 170HX
   (GA100) = le gestionnaire exploitable = la différence architecturale
   CMP-vs-consumer.

**LA LANE BOOT 280 W = FERMÉE PAR DESIGN SUR CETTE CARTE** — 8 variantes,
15+ boots, la réponse = structurelle. Les rollbacks = définitifs (0
strings v448 dans le module stock, le firmware sha c0156954 intact, zéro
Xid sur les boots du jour).

## Les routes nommées restantes (long-terme, non ouvertes)

- l'O5 par les 20 leads ;
- la route W (exécutée en 4.62 — la lecture seule) ;
- le Boot ROM fermé (le reverse).

## La valeur bankée

La méthode complète (le post-mortem PLM = l'observable binaire par boot),
les instruments réutilisables, et la preuve que le mur = le design du
silicium — pas la compétence. **Le pivot : la passe 4.63 = le chemin
matériel (le cross-flash vBIOS), la seule route restante.**
