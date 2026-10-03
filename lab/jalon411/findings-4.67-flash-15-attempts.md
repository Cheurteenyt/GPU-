# 4.67 — Le transport flash v7 : les 15 tentatives, la cause racine prouvée, l'état exact

Date : 2026-10-03 (les essais 1-10 du 26/09, les 11-15 du 03/10).
Le contexte : la lane boot 280 W = fermée par design (4.59-machine) ; la seule
route = le cross-flash du ROM genuine signé (4.63/4.63a/4.65). Ce document =
le ledger complet des tentatives du transport v7 — chaque essai, chaque bug,
chaque fix, chaque preuve — et l'état exact au moment du merge.

## L'état de la carte : INTACTE à chaque essai

`.EB`, 250 W, zéro écriture EEPROM sur les 15 tentatives. Le rollback
permanent hors ligne = `~/dmem-451/vbios-flash/chip-before.rom`
(999 424 B, md5 `858094b3dbfb0e54855973a88df7330e`, vérifié — extrait du
base64 du guest.log du 21h09).

## La cible et le format (les lois bankées)

- **LE FICHIER À FLASHER = LE CONTENEUR NVGI** (999 424 B, md5
  `54968a598b4f8479bc597b63033e6e11`, TPU-vérifié) — prouvé par la puce
  elle-même : `chip-before.rom` = `"NVGI"` @0, la disposition
  [en-tête NVGI 0x9200][image 0xEAE00]. Le raw (962 048) = 0x9200 trop court
  (le verify size-fail, l'essai 21h09).
- **Le chemin d'écriture prouvé** = `nvflash -6 <fichier>` (le 21h09 : le
  WARNING subsystem + le prompt atteints). La lore `-4 -5 -6` = FAUSSE pour
  nvflash 5.867 (`-4` = option inconnue → le help affiché, l'essai 16h24).
- **Le flag officiel découvert** : `--overridesysid` (« Allow the system ID
  mismatch » — dans le help complet, paginé par le pty le 17h25) + les
  voisins `overrideaddrid`/`overriderefdes`.
- **Le gate backup** = le chip read ×2 + LE HASH SEUL (la sortie complète de
  md5sum porte le nom du fichier = le faux FAIL du 20h36). L'empreinte
  `858094b3` ×3 boots = la puce stable et saine.

## La cause racine du blocage clavier — PROUVÉE PAR OBSERVATION (le 17h30)

Le spy `LD_PRELOAD` (open/fopen/openat interceptés, `nvflash --help` sous pty
en root, la sortie bornée) = la capture :

```
[spy] open("/dev/tty", 0x2)     ← O_RDWR : LE TERMINAL CONTRÔLANT
```

nvflash ouvre **`/dev/tty`** — pas le pty-stdin, pas le VGA, pas /dev/console
en direct. Un process = un ctty seulement si un parent le réclame
(`TIOCSCTTY`) ; **l'init busybox minimaliste n'en réclame JAMAIS** →
`open("/dev/tty")` = ENXIO → fd −1 → `read(−1)` = EBADF = le message exact
des essais (« console read: Bad file descriptor »).

Cette capture raccorde TOUTES les observations :
- le pty de `script` fonctionnait parce que **script crée un ctty** (le pty
  = le ctty) — le flood y = arrivé (mais géant ≠ « y ») ;
- le pipe stdin (`yes | nvflash`) = mort parce que **isatty(stdin) = faux** →
  nvflash n'utilise pas stdin pour les prompts ;
- le VGA, /dev/pts, les modules atkbd/evdev = hors de cause (built-in ou
  sans rapport) ;
- `-serial file:` = la sortie seule : le problème n'a jamais été le
  transport du log mais l'absence de ctty.

## Le ledger des 15 tentatives (chaque essai : la version, le bug, la preuve)

| # | horodatage | version du transport | le résultat | la leçon → le fix |
|---|---|---|---|---|
| 1 | 26/09 20h36 | v6-unit + init raw | le gate = FAUX FAIL | le md5sum vs le nom de fichier → **le hash seul** |
| 2 | 26/09 20h52 | initcpio busybox | **le kernel panic guest** (libcrypt) → l'écran noir | le busybox STATIQUE + multi-user (pas de sddm) + les timeouts |
| 3 | 26/09 21h09 | v6-unit, init raw | le gate PASS ✓ ; FLASH-RC=2 keyboard ; le verify size-fail | **la découverte du conteneur** ; l'unité v6 = le reboot-always |
| 4 | 26/09 21h47 | v6-unit (BANNÉ) | la garde = exit 1, rien ne tourne | le BANNÉ guard prouvé |
| 5 | 26/09 22h40 | — | idem + le cleanup a effacé les unités | le déclencheur sans unité |
| 6 | 26/09 23h01 | l'entrée ✓ le journal ✓, rc.local effacé | rien n'a tourné | le cleanup du fondateur = le vecteur |
| 7 | 03/10 16h05 | sans unité, la course | 2 QEMU (le vfio busy) | **le verrou atomique mkdir** |
| 8 | 03/10 16h24 | l'atome ✓ | `-4` = inconnu → le help paginé par le flood | **-6 seul** (notre preuve 21h09) |
| 9 | 03/10 17h00 | le conteneur ✓ | le chardev `path:` = invalide → QEMU exit 1 | `path=$SER` + le feeder robuste |
| 10 | 03/10 17h11 | le conteneur ✓ le gate ✓ | le prompt ATTEINT ; le flood = une ligne géante ≠ « y » → abort | le feeder = **y\n propre** sur le série bidirectionnel |
| 11 | 03/10 17h31 | sans sendkey (l'édition = après le boot) | « keyboard failed » malgré le VGA | le sendkey (la ceinture) |
| 12 | 03/10 16h49 | le chardev | `path:` → exit 1 (le doublon = inerté ✓ à l'écran) | la syntaxe + le feeder attend le socket |
| 13 | 03/10 16h59 | le série bidirectionnel ✓ | le guest = le TARGET-MD5 ✓ puis le dump base64 (~2 min à 115200 bauds) AVANT le flash → le reboot « trop tôt » | **l'ordre : le flash → le verdict → le copy-out** |
| 14 | 03/10 17h11 | l'ordre ✓ | « console read: Bad file descriptor » — **le spy = la capture /dev/tty** | **cttyhack + --overridesysid** (f4daf8d9) |
| 15 | 03/10 17h31 | **l'initramfs PRÉCÉDENT (le boot = 4 min avant le rebuild)** | le même EBADF (les fixes = jamais chargés) | **le 15e = PAS un test de f4daf8d9** |

## Ce qui est PROUVÉ chaîne par chaîne (les observations directes)

1. **Le déclencheur** : `flash463=1` dans la cmdline (le journal le 23h01 et
   16h36 ✓) + l'essaim (rc-local + vbios-transport) + **le verrou atomique
   mkdir** (les 16h24 et 16h36 = « déjà lancé » ✓ un seul QEMU).
2. **Le VFIO** : le bind 2/2 à chaque essai ✓.
3. **La cible** : le conteneur NVGI, le md5 vérifié dans le guest ✓ (3 essais).
4. **Le gate** : `858094b3` ×3 boots = la double lecture stable ✓.
5. **Le chemin d'écriture** : `-6` = le prompt atteint (21h09, 16h36, 17h11) ✓.
6. **La sortie nvflash** : le série bidirectionnel = le tee hôte ✓ (17h00+).
7. **La sécurité** : les BANNÉ guards ×3 dans le journal ✓ ; la carte intacte ×15 ✓.
8. **LE SEUL maillon jamais testé avec ses fixes** : l'entrée du confirm
   (`cttyhack` + `--overridesysid` + le feeder y\n) — l'initramfs
   **f4daf8d9** = le premier à les porter.

## L'architecture finale (le déploiement actuel)

- **Le déclencheur** : l'entrée Limine « FLASH 463 » (`flash463=1` +
  `module_blacklist=nvidia,...` + `systemd.unit=multi-user.target` +
  `loglevel=3`) → `/etc/rc.local` + `rc-local.service` +
  `vbios-transport.service` (l'essaim) → `flash-day-v7.sh` (le verrou
  atomique `/run/flash463-inflight`).
- **L'hôte** : QEMU/KVM, le GPU+audio en VFIO, `-device VGA` (le boot du
  ROM de la carte dans le guest), **le série = le socket unix bidirectionnel**
  (chardev ser0), **le feeder hôte** : le tee (la sortie → guest.log) +
  `y\n` toutes les 3 s + `sendkey y` toutes les 3 s (le moniteur). Le cap
  QEMU = 900 s.
- **Le guest** : busybox statique (le selftest = le pipeline fonctionnel),
  devpts monté, le md5 cible, le chip read ×2 = le gate hash-seul, le
  protectoff, `nvflash -6 --overridesysid` sous **cttyhack**, le verify, le
  rollback auto (cb1.rom), le verdict, puis le copy-out base64 (~2 min,
  APRÈS le verdict), poweroff. Le v7 hôte = le verdict → l'auto-reboot
  (OK) ou la machine reste (tout autre verdict).

## Le prochain geste

**Le reboot sur FLASH 463 avec l'initramfs f4daf8d9 = le PREMIER test réel
des fixes /dev/tty.** Le rituel inchangé :
`sudo bash ~/dmem-451/vbios-flash/install-v7.sh && sudo reboot` → FLASH 463
→ ~8 min (ne pas juger avant) → le verdict dans le log + à l'écran.

host-only. La carte = intacte à travers les 15 tentatives. Aucune écriture
EEPROM n'a jamais été initiée (le gate = avant, toujours).
