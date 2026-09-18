# CAMPAGNE RTX 3070 — Carte d'optimisation & directives
**Task 61 · session cloud du 18/09/2026 · Super Z · pour le chat machine de Cheurteenyt**
*(re-constitué après rotation d'environnement — Task 64)*

> Directive fondatrice : « nous on vise les optimisations de la rtx 3070, on a toute la data
> maintenant, on doit y travailler profondément » — renforcée par « c'était que le début ».
> Cette carte est produite SANS accès GPU : elle mine les 31 rings de GPU-, corrige ce qui
> doit l'être, et transforme chaque levier en directive exécutable côté machine.

---

## 0. Les trois vérités nouvelles de cette session

**V1 — Le ring 31 a mal lu sa propre télémétrie.** Les droops à 1770 MHz du rapport
Genshin ne sont PAS des événements de power-cap : la timeline des 7 événements (3 193
échantillons re-analysés) montre qu'ils arrivent tous à **62 W médian / 16 % de load**
(menus, chargements, transitions) — jamais sous charge. Ce sont des downclocks de
transition du jeu, pas de la carte.

**V2 — En vrai gameplay, la carte est VOLTAGE-LIMITÉE, pas power-limited.** Sous-ensemble
« vrai gameplay » (load ≥ 90 % & puissance ≥ 150 W = 72,7 % de la session) :

| Métrique | Valeur mesurée | Lecture |
|---|---|---|
| Horloge core | **épinglée à 1890 MHz (99,8 % des échantillons)**, min 1884 | le plafond de la courbe V/F est atteint |
| Puissance | médiane 218 W, p95 227, p99 232, **max 235 W** | **0 échantillon ≥ 245 W** — le plafond 250 n'est jamais touché (gap 15 W) |
| Fenêtres 3 s | maxima : médiane 219 W, p95 229 W | même en transitoire soutenu, 21 W sous le cap |
| Température | médiane 62 °C, max 64 °C | 19 °C sous le throttle (83 °C) — axe thermique fermé |
| vRAM | 6801 MHz constant (100 %) | profil 0xD stable |

Conséquences en cascade : dans CE workload, **le mod 280 W = 0 gain attendu** (zéro
échantillon à moins de 15 W du plafond), **le dial-2 `RMDisablePerfIntersect` = 0 gain
attendu** (aucune intersection de limites ne se produit jamais), et la seule famille de
leviers qui peut monter les FPS est celle qui **déplace la courbe V/F elle-même**.

**V3 — La mesure décisive de toute la campagne n'a jamais été prise :** les
*Clocks Event Reasons* pendant le vrai jeu. Une seule lecture tranche quel levier existe
physiquement par workload. C'est la **Phase V** ci-dessous — ce soir, zéro risque, avant
tout flash.

---

## 1. Fondation consolidée (ce qui est prouvé, ring par ring)

| Axe | Verdict | Ring |
|---|---|---|
| ReBAR | **8192 MiB BAR1, actif** (CSM tuait Above-4G ; fix = 1 toggle) | 18 |
| Budget puissance ROM | 100 / 240 / 250 W, triple-cross (3 grammaires), = NVML live | 3, 16, 23 |
| vP-states | 0xF=2100/7001 · 0xD=2100/6801 (live) · 0xC=2100/5001 · 0xA=2100/810 · 0x7=420/405 | 15 |
| Courbes ventilateur | opérative 17/45/100 % @ 55/75/80 °C ; urgence 95–103 °C ; panique 133–139 °C ; déjà battue par la courbe LACT du fondateur | 14, 25 |
| PERF v0x60 | constante de génération (3 planches byte-identiques) — **layout pas encore craqué** | 16, 17 |
| Timings vRAM | 7 bins monotones couvrant 6801 ; 1 landmine zero-record d'usine | 5 |
| Identité chip | build `MSI.RTX3070.8192.210519_1` shifté 0x9200 ; 512 KiB byte-exact | 20, 21, 23 |
| GSP bindata | **chiffré** (entropie 8.000, autocorrélation nulle) — piste LZ close honnêtement | 28, 29 |
| rm.elf | **17,2 Mo plaintext RISC-V** — 881 dials registre + `CUSTOMER_BOOST_MAX` etc. | 30 |
| Kit flash 280 W | mod construit + vérifié offline (6 octets, entrée cap) ; session USB scriptée + gate identité | 26, 31 |

---

## 2. La matrice des leviers, requalifiée par régime de contrainte

La leçon centrale de V2 : **un levier ne vaut que dans le régime où sa contrainte lie.**

| Régime | Signature mesurable | Leviers vivants | Leviers morts |
|---|---|---|---|
| **A. Power-limited** (jeux lourds type Cyberpunk/Steel Nomad) | `SW Power Cap` actif ; draw ≥ cap ; clock < 1890 | **mod 280 W** (flash) ; dial-2 ; `RmPerfLimitsOverride` ; `RmPerfRatedTdpLimit` | offset core (déplace V/F, pas le cap) |
| **B. Voltage-limited** (Genshin **prouvé**) | reasons = NONE ; clock = 1890 ; draw < cap | **offset core LACT** (shift V/F) ; `RMClkVfOverride` ; `CUSTOMER_BOOST_MAX` ; `RMProgrammableClkMask` | mod 280 W ; dial-2 ; ventilateurs (19 °C de marge) |
| **C. Bandwidth-bound** (à qualifier par A/B) | fps insensible à l'offset core, sensible au mclk | **vRAM 6801→7001** (état 0xF firmware-blessed, = LACT +400) | tout le reste |

Genshin classé **B pur**. Le classement des autres jeux = la Phase V.

---

## 3. Cohérence rails du mod 280 W (le v1 six-octets est le bon — avec un point de veille)

Dump complet des 20 entrées (registre gx3, planche `210519_1`) :

| Entrée | min/avg/peak (W) | Lecture |
|---|---|---|
| **2 = cap** | 100/240/250 → **modifié 100/265/280** | l'entrée d'enforcement (NVML la reflète) — triple-cross |
| 5 | 66/78 | rail auxiliaire |
| 6, 7 | 150/175, 150/175 | domaines de puissance majeurs (sense/enforcement candidats) |
| 8, 9, 10 | 11,35/12,39 · 22,75/24,82 · 28/30,8 | petits rails |
| **13** | **226,8/252** | seconde définition board-total — **point de veille** (voir ci-dessous) |
| 16 | 85/92,8 (unkn12=3277) | rail non nommé |
| 17 | 66/72 | rail auxiliaire |

Le v1 du mod (6 octets d'entrée 2 seulement) est le bon choix : la table est non-signée
(scan ASN.1/RSA = zéro hit, ring 26), l'entrée 2 est l'entrée d'enforcement prouvée, et
toucher les rails sans connaître leur sémantique exacte serait mentir au VRM. **Point de
veille** : l'entrée 13 déclare un board-total sense à 252 W peak ; si le RM l'utilise
comme alarme, un tirage 280 W coexistera avec un sense d'usine à 252 — surveiller les
premières sessions lourdes (Xid, télémétrie rails via `nvidia-smi -q -d POWER`), le
dual-BIOS restant le filet à tout instant.

---

## 4. Le séquençage v2 — directives pour le chat machine

### Phase V — LE VERDICT (ce soir, zéro risque, avant tout flash)
Instrumenter un vrai jeu (le jeu du fondateur) **et** un jeu lourd cap-touchant :
```bash
# 1) pendant le jeu, log 1 Hz (terminal séparé) :
nvidia-smi --query-gpu=timestamp,pstate,power.draw,clocks.current.graphics,\
clocks.current.memory,temperature.gpu,utilization.gpu --format=csv -l 1 > phaseV-games.csv
# 2) toutes les 30 s, le verdict :
nvidia-smi -q -d PERFORMANCE     # section "Clocks Event Reasons"
# 3) MangoHud : AJOUTER gpu_voltage aux champs de log (absent de la CSV dial-2 !)
```
Lecture : `SW Power Cap` actif sous charge → régime A (le flash a un sens).
Reasons = NONE avec clock 1890 et draw < cap → régime B (offset core / dials VF).
Faire le double classement (jeu léger / jeu lourd). **C'est cette mesure qui décide
si le flash de demain vaut quoi que ce soit, et où.**

### Phase M — le flash 280 W (demain, kit inchangé, attentes corrigées)
- Kit ring 31 tel quel : `usb-flash-session.sh` (gate identité byte-exact → protectoff
  → flash → re-verify, dual-BIOS sur SECONDARY). Aucune modification du protocole.
- **Ne pas attendre de gain dans Genshin** (V2 le prouve). Le gain — s'il existe — se
  mesurera exclusivement sur les workloads classés A en Phase V : baseline 250 W (sans
  dial) vs 280 W, même protocole paired, MangoHud auto-log.
- Post-flash immédiat : `hwtruth rebar-check` + `hwtruth tables` (lire 100/265/280 sur la
  carte réelle) + session de surveillance Xid.

### Phase D — les dials RM, re-séquencés par le verdict V
Protocole ring 31 inchangé (1 dial/reboot, `apply-dials.py`, keep/kill en jeu réel) mais
l'ordre dépend de la Phase V :
- régime A dominant → 1) `RMDisablePerfIntersect=1` 2) `RmPerfLimitsOverride=1`
  3) `RmBootGspRmWithBoostClocks=1`
- régime B dominant → 1) `RMClkVfOverride` (exploration prudente de valeurs) 2) `CUSTOMER_BOOST_MAX`
  3) `RmBootGspRmWithBoostClocks=1` — dial-2 dépriorisé (mort en B).
- Dans tous les cas : `RMBug*` intouchés ; `RMEnablePowerSupplyCapacity`/`RmPerfRatedTdpLimit`
  = comptabilité de second ordre, après les premiers.

### Phase O — offsets core/vRAM, le terrain enfin valide (rouvrir la porte verrouillée)
Les verdicts « no gain » des rings 19/25 portent tous l'astérisque glmark2 (workload
draw-call-bound à 92–109 W — disqualifié par gx25 lui-même). Le terrain valide = jeu réel :
- **core** : +75 LACT puis +150, paired A/B en jeu (l'infrastructure
  `fan-boost-experiment.py` est réutilisable telle quelle), watchdog stabilité ;
- **vRAM** : +400 LACT (= +200 readout) → **7001 MHz, l'état 0xF du propre firmware** ;
  A/B en jeu + première vraie boucle de stabilité (ring 19 : « no artifacts test
  performed » — dette ouverte) ;
- keep/kill : keep seulement si médiane core-clock ou fps progresse hors bruit démontré
  (les paliers de 15 MHz du GPU Boost servent de règle).

### Phase X — le dernier objet innommé : PERF v0x60 (multi-session, offline)
Cette session a extrait les 20 octets portés par les registres, renforcé les corrélations
(u16 420→210→105 = chaîne ÷2 aux offsets impairs ; 600×2 ; 150/405 ; record 0 = `07 00 00 00 ff`
dont 0x07 = l'ID d'ouverture de la liste vP-state) — **et falsifié la classe de lecture
« u32 /2^15 propre » de gx16** : les valeurs 842/1200/810 sont des artefacts de
recouvrement (420 décalé ×2 + octet voisin), démontrée par l'instrument.
Outil prêt : **`gx32-perf-v0x60.py`** (joint) — à exécuter sur `chip-full.rom` (lu au
ring 31) ou l'acquisition 999 424 B : corrélations gate → 4 hypothèses de layout →
verdict. Le re-téléchargement TPU depuis le cloud est muré (403 datacenter, conforme au
registre) ; côté machine, le fichier existe déjà.

---

## 5. Registre d'honnêteté

- **Prouvé** (cette session, sur les 3 193 échantillons) : la timeline des droops
  (62 W/16 % load), l'épinglage 1890 MHz à 99,8 % en charge, le gap 15 W au cap,
  zéro hitch in-game (les 143 spikes frametime > 100 ms = tous menus/chargements).
- **Inféré** : le régime voltage-limited (signature forte : clock plafonnée + power sous
  le cap + reasons à lire pour sceller).
- **Corrigé** : la lecture du ring 31 attribuant les p1 dips au power-cap — datée,
  sourcée, falsifiable (la CSV est la preuve des deux côtés).
- **Muré** : re-téléchargement TPU depuis ce cloud (403) ; bindata GSP (chiffré, hors
  ligue anti-tamper — l'exclusion tient).
- **Inconnu, instrumenté** : layout v0x60 (gx32 prêt) ; sémantique des valeurs de dials
  (canal host→GSP confirmé fonctionnel, valeurs host-side non documentées).

*Note Task 64 : le fichier `gx32-perf-v0x60.py` et les scripts `campaign_genshin_*.py`
n'ont pas survécu à la rotation d'environnement et ne sont pas re-transcriptibles
octet-pour-octet depuis le contexte ; leurs méthodes et résultats sont intégralement
conservés dans cette carte et le worklog — réengénérables à la demande.*
