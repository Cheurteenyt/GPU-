# 4.66 — La dig kernel-side du 0x1F : FERMÉE (l'enforcement = GSP-closed, la surface EDPp = ACPI/VBIOS)

Date : 2026-10-01. La mission 4.60's « the kernel-side validation = the wall
to study — the NVPCF headers = the next dig » exécutée par l'assistant externe
(Claude, les citations vérifiées fichier:ligne), auditée contre le ledger.

## Résultat exécutif

La question « où le SET 280000 = rejeté 0x1F côté kernel, et un regkey peut-il
élever le max ? » = **tranchée : NON, et rien de légitime ne l'élève.**

1. **Le contrôle FINN 0x2080e61e = ABSENT de l'open source** — la recherche
   littérale + le décodage FINN (0x2080 + interface + message) sur toute
   l'arborescence `ctrl2080/` = rien. `ctrl2080pmgr.h` = une seule macro
   (GET_MODULE_INFO). Aucune structure PWR_POLICY/SET_POWER_LIMIT.
   → la confirmation du 4.60 (« FINN closed-only ») au niveau du tree.
2. **La seule surface EDPp kernel-visible = la lane ACPI/plateforme**
   (`src/nvidia/src/kernel/platform/platform_request_handler_ctrl.c`) :
   - `pfmreqhndlrHandlePlatformGetEdppLimit_IMPL` (:1697) → l'ACPI
     (`NV0000_CTRL_PFM_REQ_HNDLR_CALL_ACPI_CMD_GETEDPPLIMIT` :1709) —
     **le max = servi par le firmware ACPI**, pas un parse kernel ni un regkey ;
   - `pfmreqhndlrHandlePlatformSetEdppLimitInfo_IMPL` (:1738) lit
     limitMin/limitRated/limitMax/limitCurr via
     `NV2080_CTRL_CMD_INTERNAL_PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO`
     (:1757) = un RPC vers le GSP fermé ;
   - `pfmreqhndlrHandlePlatformEdppLimitUpdate_IMPL` (:1647, le SET :1672) —
     tout le calcul/clamp = côté GSP.
3. **Zéro regkey** autour de l'EDPp (`grep REG_STR|regkey` = rien).

## La lecture stratégique (l'audit de l'assistant local)

Cette fermeture = **l'argument le plus fort POUR la voie 4.63/4.64 (le
cross-flash)** : le système est conçu pour prendre sa policy des tables
SIGNÉES — le parse VBIOS (4.38 : la source du limitMax) et la surface ACPI
EDPp, dont les méthodes _DSM de la carte = DANS le VBIOS. Le .E5 = cette
policy à 280 W, signée MSI/NVIDIA. **Le flash = nourrir le tuyau avec la
configuration signée qu'il est conçu pour recevoir — pas un bypass.** La lane
bypass = de toute façon morte (le 4.59-machine : le mur RSA + le falcon
sans retour).

## La nuance à vérifier un jour (optionnel, offline)

Le diff des tables ACPI embarquées (.EB vs .E5) — si le .E5 porte une surface
EDPp ACPI différente, le cross-flash = la livraison DOUBLE de la policy 280 W
(les tables power + l'ACPI). Un chapitre naturel de v465a (l'instrument du
diff, la passe 4.65).

host-only, zéro boot. Les citations = de l'assistant externe, vérifiées
sur le tree 610.57.04 public.
