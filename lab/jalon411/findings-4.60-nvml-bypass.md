# 4.60 — le NVML bypass : le contrôle direct par ioctl — le frame
# userspace→kernel PROUVÉ sur l'arbre exact, le SET décodé par la
# machine, le GSP = le juge final

Mission : reproduire la séquence SET de `nvidia-smi -pl` en userspace
pur (ctypes + /dev/nvidiactl) avec 280000 mW, sans le fetch/check de la
NVML. Zéro boot, zéro patch driver, réversible par construction. Les
cinq tâches : T1 le décode des ioctls, T2 l'outil bypass (v460a), T3 le
jardin d'honnêteté (le GSP = le juge), T4 la contingence (le code =
l'emplacement du mur), T5 la doc + l'intégration runbook-457 §5.

Substrats : **le tag GitHub EXACT 610.57.04 de
NVIDIA/open-gpu-kernel-modules** (fetché et committé dans
`imports/open-gpu-kernel-modules-610.57.04/` — nvos.h, nv-ioctl.h,
nv-ioctl-numbers.h, nv_escape.h, **escape_610.57.04.c** (le dispatcher
RM complet, open), nvstatuscodes.h, cl0000/cl0080/cl2080,
ctrl0080base/ctrl0080gpu, ctrl2080pmgr, ctrl2080perf (cité),
ctrlxxxx, nvlimits) ; les verdicts 4.21/4.22/4.23/4.24/4.38/4.43 du
repo ; les captures 4.23 restent sur le SSD (le rpcdump76 = la famille
d'analyseur, PAS les octets eux-mêmes — l'honnêteté du brief ajustée :
les dumps bruts fn=76 n'étaient PAS committés ; ce pass livre
l'instrument qui capture l'équivalent userspace).

## Verdict first

| question du brief | ce que les octets disent | verdict |
|---|---|---|
| la séquence ioctl du -pl est-elle décodable ? | le FRAME complet = prouvé sur l'arbre exact : CHECK_VERSION_STR → ALLOC ROOT → ALLOC DEVICE_0 → ALLOC SUBDEVICE_0 → CONTROL GET → CONTROL SET → les FREE ; chaque ESC, chaque struct, chaque taille validée par la table kernel (escape.c RmValidateIoctl + nv.c nv_validate_ioctl_data, lus) | **PROUVÉ (le frame)** |
| quel ioctl = le SET de la limite ? | la FAMILLE = NV_ESC_RM_CONTROL (0x2A) sur hDevice/hSubdevice ; l'ID exact du cmd mW = **ABSENT du SDK public** (grep zéro `POWER_MANAGEMENT_LIMIT` sur tout inc/ de 610.57.04 ET 550.54.14 — closed-only FINN) | **INDECIDABLE-BY-BYTES ici — DÉCIDÉ SUR LA MACHINE par v460b** (le shim capture le -pl 250 qui a réussi) |
| quel ioctl = le fetch min/max ? | idem famille CONTROL ; le nommage par le census mW (l'OUT porte {min,default,max}) = codé dans v460b_analyze.py (la loi rpcdump76) | **PROUVÉ (la méthode), la valeur = machine** |
| quel champ = la valeur mW ? | l'u32 mW dans les params (250000 = 0x3D090 LE — le format bancarisé 4.23/4.24), l'offset = sorti par le census de la capture | **PROUVÉ (le format), l'offset = machine** |
| le bypass peut-il marcher ? | la NVML check = userspace (le -pl 250 a RÉUSSI sur CETTE machine = la séquence SET passe le kernel ; seul le CHECK du 280 bloque côté NVML) ; l'application effective = le x86-RM/GSP (4.38/4.43 : la formule, la valeur runtime) | **EXPÉRIENCE ARMÉE (T3/T4 = la matrice de verdict)** |
| le côté kernel accepte-t-il n'importe quel struct ? | la validation kernel = les tailles EXACTES (lire §1.3) ; nos structs ctypes = TOUT VERT 24/24 vs les tailles du C | **PROUVÉ** |

## 1. T1 — le décode : la table des appels (le frame prouvé)

### 1.1 Le transport : deux familles d'ESC, deux magies

- Les RM ioctls (NV_ESC_RM_*) = les numéros 0x20-0x5F, type **'U'
  (0x55)**, encodés _IOWR('U', esc, sizeof(struct)) — le kernel décode
  `_IOC_NR(cmd)` (nv.c:2497 `arg_cmd = _IOC_NR(cmd)`) et valide
  `_IOC_SIZE(cmd)` contre la table (nv.c:2403 nv_validate_ioctl_data →
  osapi.c:2905 rm_validate_ioctls → escape.c:295 RmValidateIoctl).
- Les ioctls UNIX (CHECK_VERSION_STR=210, REGISTER_FD=201,
  CARD_INFO=200) = type **'F'** (NV_IOCTL_MAGIC,
  kernel-open/common/inc/nv-ioctl-numbers.h).

### 1.2 LA TABLE (chaque ligne = citée du tree 610.57.04)

| # | appel | ioctl (encodé) | struct (taille) | le contenu |
|---|---|---|---|---|
| 1 | open | — | — | /dev/nvidiactl (le ctl, O_RDWR) + /dev/nvidiaN (+ REGISTER_FD(ctl_fd) sur le fd GPU — nv_ioctl_register_fd_t, 4 B) |
| 2 | version check | `0xC04846D2` = _IOWR('F',210,72) | `nv_ioctl_rm_api_version_t` (72 B : cmd, reply, versionString[64]) | cmd=STRICT(0)/RELAXED('1'), la chaîne "610.57.04" ; reply=1 = RECOGNIZED (nv-ioctl.h:100-112) |
| 3 | alloc client | `0xC030552B` = _IOWR('U',0x2B,48) | `NVOS64_PARAMETERS` (48 B, pad 4) | hClass=**NV01_ROOT (0x0)**, hNew=0→OUT ; params=`NV0000_ALLOC_PARAMETERS` (120 B : hClient, processID, processName[100], pOsPidInfo) ; le kernel FORCE NV01_ROOT_CLIENT (escape.c:484-489) |
| 4 | alloc device | `0xC030552B` | NVOS64 | hClass=**NV01_DEVICE_0 (0x80)**, hParent=hClient ; params=`NV0080_ALLOC_PARAMETERS` (56 B : deviceId, hClientShare, hTargetClient, hTargetDevice, flags, vaSpaceSize/8, vaStartInternal/8, vaLimitInternal/8, vaMode) |
| 5 | alloc subdevice | `0xC030552B` | NVOS64 | hClass=**NV20_SUBDEVICE_0 (0x2080)**, hParent=hDevice ; params=`NV2080_ALLOC_PARAMETERS` (4 B : subDeviceId=1) |
| 6 | GET limites | `0xC020552A` = _IOWR('U',0x2A,32) | `NVOS54_PARAMETERS` (32 B) | cmd=**l'ID GET** (table v460b), hObject=hDevice/hSubdevice, params=le buffer IN→OUT ; l'OUT porte {min, default, max, current} en mW |
| 7 | SET limite | `0xC020552A` | NVOS54 | cmd=**l'ID SET**, params=le buffer avec **l'u32 mW** (280000 = 0x0004465C LE) |
| 8 | free | `0xC00C5529` = _IOWR('U',0x29,12) | `NVOS00_PARAMETERS` (12 B) | les handles en ordre inverse |

NVOS54_PARAMETERS (nvos.h:2227-2239) : hClient@0x00, hObject@0x04,
cmd@0x08, flags@0x0C (NONE=0), params@0x10 (NvP64), paramsSize@0x18,
status@0x1C — **32 octets**. NVOS64 : hRoot@0, hObjectParent@4,
hObjectNew@8, hClass@0xC, pAllocParms@0x10, pRightsRequested@0x18,
paramsSize@0x20, flags@0x24, status@0x28 — 44 champs, **sizeof 48**
(pad) : la taille = ce que la validation kernel exige.

### 1.3 La preuve côté kernel (les tailles = la loi)

`RmValidateIoctl` (escape_610.57.04.c:295-345) : NV_ESC_RM_CONTROL →
sizeof(NVOS54_PARAMETERS) ; NV_ESC_RM_ALLOC → **la double acceptation**
sizeof(NVOS64) OU sizeof(NVOS21) (l.331) ; FREE → NVOS00. Le handler
CONTROL (l.789+) : `NV_CTL_DEVICE_ONLY` (= l'ioctl sur le ctl fd) +
`RmGetDeviceFd` = gate seulement pour NV00FD/NV00E0 — **le CONTROL
normal n'exige pas de fd GPU** (le §1.2 #1 minimal = le ctl seul).
Toute taille fausse = NV_ERR_INVALID_ARGUMENT AVANT le RM — le selftest
v460a (24/24 VERT) verrouille nos ctypes contre ces tailles.

### 1.4 LA DÉCOUVERTE : les cmds power-limit = closed-only FINN

`grep -r POWER_MANAGEMENT_LIMIT src/common/sdk/nvidia/inc/` = **zéro
hit** sur 610.57.04 ET sur 550.54.14 (vérifié les deux par le fetch).
Les NV0080_CTRL_CMD_GPU_* publics = l'encodage FINN 0x8002xx
(GET_CLASSLIST = 0x800201, ctrl0080gpu.h:70) — la famille 0x208013xx =
**FB** (preuve maison : v420_resolve.json, les handlers 0x1301430
(FB_GET_INFO_V2) etc. boundary-verifiés dans NOTRE rm.elf — l'ancienne
rumeur "0x20801314 = SET_POWER_MANAGEMENT_LIMIT" = FALSIFIÉE pour
l'encodage FINN). La famille publique qui existe = **RatedTdp** :
`NV2080_CTRL_CMD_PERF_RATED_TDP_GET_CONTROL = 0x2080206e` /
`SET_CONTROL = 0x2080206f` (ctrl2080perf.h:399/438, le struct 12 B
{client, input, vPstateType}) — **résolue dans NOTRE rm.elf par 4.21**
(handler 0x163c42c boundary-verified, `subdeviceCtrlCmdPerfRatedTdp
SetControl_KERNEL` = kern_perf_pwr.c:53, le redirect GSP). C'est la
sonde de lisibilité publique de v460a (--probe-ratedtdp) — PAS le SET
mW (le struct = un arbitrage d'action, pas un u32 mW).

**La conséquence de méthode** : les IDs exacts du GET/SET mW ne
peuvent pas être décidés ici (closed-only) — et n'ont pas BESOIN de
l'être : la mission affirme que le strace du -pl 250 (qui a réussi)
existe sur le SSD. v460b capture la séquence RÉELLE au-dessus du
kernel ; le census mW nomme le GET (l'OUT porte les limites) et le SET
(l'IN porte 250000) ; v460a rejoue le SET avec 280000. **Les octets de
la machine décident** — la même loi que le RPCDUMP76, une couche
plus haut.

### 1.5 La réconciliation avec les falsifications 4.23/4.24

4.24 a prouvé : la valeur power **ne voyage pas le transport fn=76**
(GSP_RM_CONTROL RPC) — le -pl = x86-side. Cohérent : le bypass ici =
AU-DESSUS du kernel (userspace→kernel), là où 4.22/4.38 placent le
parse et l'application (le x86 fermé). Le 84-B fn=76 de 4.23 (0xFE01
@40) = réattribué NV00FE (le memory-mapper) — v460b le VERRA s'il
existe un écho GSP ; sinon zéro : le ledger tranche. Le SET accepté
mais non appliqué (T3) = le scénario où le x86-RM relaie au GSP et le
GSP clamp (la formule 4.43 : base × record/100/1000, la valeur runtime).

## 2. T2 — v460a_nvml_bypass.py : l'outil

La chaîne complète en ctypes (le §1.2, la fidélité NVML : REGISTER_FD
inclus, le root alloc avec processID/processName) + :

- **--table v460-decode.json** : le contrat v460b — le GET et le SET
  avec leurs templates hex capturés et les value_offsets de l'u32 mW ;
  le replay = les octets de la machine, la valeur patchée (280000).
- **--set-cmd / --set-size / --set-offsets / --set-hobject** : le mode
  manuel (sans capture — pour les variations).
- **--arm** = LE GATE (la loi de la maison : pas d'écriture sans ACK) ;
  le dry-run par défaut = la chaîne alloc + les GET + le plan, zéro
  écriture.
- **--probe-ratedtdp** : la sonde publique (0x2080206e, lecture
  seule) = le contrôle de lisibilité du subdevice avant tout geste.
- **--restore MW** : le SET-back (le retour en arrière = un ioctl).
- le ledger JSON de chaque étape (les params hex avant/après, les
  status, les errno) — la preuve contre l'arbre exact.

## 3. T3/T4 — le jardin d'honnêteté + la matrice de contingence (codée)

L'observable binaire = le GET avant/après + `nvidia-smi -q -d POWER`.
La matrice (le code de sortie + le verdict imprimé) :

| résultat du SET | signification | la localisation du mur |
|---|---|---|
| status != NV_OK | le kernel/x86-RM rejette | **LE MUR = KERNEL** — le NVstatus nomme : 0x2E INVALID_LIMIT, 0x1B INSUFFICIENT_PERMISSIONS, 0x56 NOT_SUPPORTED, 0x3B INVALID_PARAMETER... (la table nvstatuscodes.h committée) |
| NV_OK, GET/smi inchangés | accepté mais non appliqué | **LE MUR = GSP** (le check effectif = firmware-side — le négatif DÉFINITIF et propre : le bypass userspace ne peut pas suffire, la lane = le PLM/write-primitive 4.57) |
| NV_OK + GET/smi = 280 + la charge tient | appliqué | **LE BREAK** — la NVML-check = le seul mur ; le -pl 280 direct devient accepté (le cross-check T5.2 du runbook-460) |

La réversibilité = par construction : un ioctl = un appel ; --restore
250000 = l'état d'avant (le ledger prouve la valeur d'origine). Zéro
écriture firmware, zéro patch driver, le driver/le boot intacts.

## 4. T5 — les livrables du jour + l'intégration

- `tools/edpp/v460b_ioctl_trace.c` — le shim LD_PRELOAD (la capture
  passive, le format 460TRACE grep-able, la loi RPCDUMP76).
- `tools/edpp/v460b_analyze.py` — l'analyseur (le census mW, le
  nommage GET/SET, la table JSON) + le fixture `v460_fixture_pl250.log`
  (la séquence synthétique complète, testée — voir §6).
- `tools/edpp/v460a_nvml_bypass.py` — l'outil (le §2) avec le selftest
  intégré (--selftest).
- `tools/edpp/runbook-460.sh` — le jour (ACK-gaté RUNBOOK_460_ACK=1 :
  §0 guards+selftest → §1 capture → §2 analyse → §3 dry-run → §4 SET →
  §5 verdict/charge/restore).
- `tools/edpp/runbook-457.sh` §5.1b — **le double-couvert** : si le
  PLM s'ouvre (4.57) mais que le -pl reste bloqué au check NVML, la
  ligne bypass = la contingence userspace ; les deux lanes = indépendantes
  (le bypass n'exige PAS le PLM ouvert).
- la méthode générique : TOUTE limite future = la même recette — (1)
  v460b capture le geste qui réussit, (2) l'analyseur nomme le cmd et
  les offsets, (3) v460a rejoue avec la nouvelle valeur. L'outil = le
  tournevis, pas la cible.

## 5. La carte du mur (mise à jour par ce pass)

| couche | état après 4.60 |
|---|---|
| le check NVML (userspace) | **contournable par construction** (la séquence = un replay d'ioctl ; le -pl 250 = la preuve que le SET passe) |
| la validation kernel (les tailles/droites RM) | PAS un mur pour nous : les structs = byte-exact (selftest 24/24) ; les droits = NV01_ROOT non-priv... l'expérience dira (le status nommera) |
| l'application x86-RM | le juge T4a — le NVstatus = le nom du refus |
| la politique GSP (la formule 4.43) | le juge T4b — accepté-non-appliqué = le négatif définitif du bypass, la lane 4.57 (le PLM) = la seule restante |
| le firmware | JAMAIS touché (la discipline tient) |

## 6. Les tests (la discipline selftest-d'abord)

- v460a --selftest : **24 PASS / 0 FAIL** (les tailles NVOS54=32,
  NVOS64=48, NVOS21=32, NVOS00=12, verchk=72, NV0000=120, NV0080=56,
  NV2080=4, RatedTdp=12 ; les offsets NVOS54 {cmd@8, params@0x10,
  paramsSize@0x18, status@0x1C} et NVOS64 {pAllocParms@0x10,
  paramsSize@0x20} ; les encodages 0xC020552A/0xC030552B/0xC00C5529/
  0xC04846D2 ; le patch_mW ; les NVstatus).
- v460b_analyze sur le fixture `v460_fixture_pl250.log` : la séquence
  complète (version → 3 allocs → 5 controls → 3 frees) reconstruite ;
  le GET nommé (l'OUT {100000, 240000, 250000}), le SET nommé (l'IN
  250000 @0 et @4), la table JSON produite avec template+offsets — la
  chaîne v460b→v460a = verte bout en bout.
- le shim compile propre (gcc -Wall, zéro warning) ; zéro device
  requis pour tout ce qui précède.

## Discipline

Chaque constante = citée du tree committé
(imports/open-gpu-kernel-modules-610.57.04/, le fichier + la ligne) ou
du repo (v420_resolve.json, findings-4.21). Les IDs exacts du SET/GET
mW = étiquetés INDECIDABLE-BY-BYTES avec l'instrument qui les décide
(v460b sur la machine) — zéro invention, zéro valeur choisie au
hasard. Le gate --arm partout. Pas de merge : branche
`pass/4.60-nvml-bypass`, push, PR ouverte.
