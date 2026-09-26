# 4.64 — Le jour flash : le transport VFIO exécuté, v7 armé non posé (the founder day)

Date : 2026-09-26 (soir).

## Résultat exécutif

Le runbook-463 §2 (le transport VFIO) a été exécuté en six tentatives
v1→v6 : **ZÉRO écriture EEPROM, la carte intacte après chaque** (le `.EB`
re-vérifié par nvidia-smi à chaque retour). Le transport = **fail-safe
prouvé en conditions réelles**, pas seulement par l'autopsie day-0. Les
échecs = TOUS dans la préparation de l'isolation côté hôte, jamais dans le
transport lui-même. L'architecture v7 = écrite, **non installée** — le
prochain geste.

## Les pièces du transport (`~/dmem-451/vbios-flash/`)

| artefact | preuve |
|---|---|
| le fichier flash = le raw .E5 admis | `MSI.RTX3070.SuprimX.raw.rom` ≡ `MSI.RTX3070.8192.210519.rom.raw.rom` (962048 B, md5 `ccabe841…`) — `55AA` en tête |
| le conteneur TPU .E5 | `MSI.RTX3070.8192.210519.rom` (999424 B, md5 `54968a59…`) — `NVGI` en tête (la loi 1 de 4.63a) |
| la page bot-check | `MSI.RTX3070.SuprimX.8192.210519.rom` (118041 B, md5 `6e86484f…`) = `<!doctype html` — la première fetch bloquée, gardée comme preuve de la leçon admission |
| le noyau guest | `vmlinuz-guest` (17277440 B, md5 `2534dc1c…`) — 7.2.5-3-omarchy extrait de l'UKI |
| l'initramfs guest | `initramfs.img` (9891987 B, md5 `c46614f4…`) — busybox + nvflash 5.867 patché + le raw ROM ; la répétition SANS GPU = l'ABORT propre |
| les scripts | `build-guest.sh`, `flash-day.sh` v1→v7, `session-VtFFDY/` (host.log, v6.log) |
| le dump stock existant | `~/dmem-451/vbios-stock.rom` = PARTIEL (157696 B sur ~962048 attendus, `55AA`, md5 `38782a40…`) — un pré-check d'identité, PAS le rollback |

**Le chip read ×2 COMPLET (l'image entière, le chip-before.rom) = le
PREMIER geste du jour §2, avant toute écriture** — la loi runbook-463 (le
999424 B = le conteneur .E5, PAS un backup stock ; le partiel 157696 B ne
suffit pas au rollback).

## Les six tentatives — chaque échec nommé

- **v1→v3** : les itérations du transport en machine vivante (le rmmod
  direct, la session graphique tuée) — avortées avant toute écriture.
- **v4** : le rmmod pendu — **nvidia_drm tient la console framebuffer**.
- **v5** : le kill de la session graphique = **le gel noyau (vtcon)**.
- **v6** : la voie initramfs — **nvidia est DANS l'image UKI** : dix
  boucles d'abort propres 19h02–19h13 (`ERREUR: nvidia est chargé — le
  blacklist n'a pas été appliqué`, v6.log) → la snapshot Omarchy
  restaurée par le fondateur (la blacklist + le service supprimés,
  l'entrée normale intacte).

**LA LEÇON STRUCTURELLE : l'isolation du GPU doit vivre au niveau cmdline
noyau (`module_blacklist`), pas au niveau fichiers** — le blacklist
fichier arrive trop tard : l'initramfs et l'UKI chargent le driver avant
que quoi que ce soit ne puisse le retirer.

## v7 — l'architecture du fondateur (écrite, non posée)

`flash-day-v7.sh` + l'installation prévue :

1. l'entrée Limine **« Flash463 » à usage unique** (la cmdline copiée +
   `module_blacklist=nvidia,nvidia_drm,nvidia_modeset,nvidia_uvm`) —
   l'entrée normale `linux-omarchy` = INTACTE, backup `limine.conf`
   avant ;
2. le service `flash463.service` (le blindage VFIO + le QEMU flash) ;
3. le drapeau d'armement `/etc/flash463-armed` ;
4. **les 3 verrous anti-boucle** : le drapeau = consommé dès le boot sans
   driver ; **l'abort ne reboot JAMAIS** (la machine reste au tty,
   lisible) ; le trap cleanup (drapeau + unité désactivée) — la boucle =
   structurellement impossible.

**L'état à l'instant** : installation NON exécutée (le sudo refusé 2×) —
l'entrée Flash463 absente de limine.conf, le backup absent, le service
not-found, le drapeau absent, l'entrée normale intacte. La carte = `.EB`,
250 W max, nvidia en place.

## Le prochain geste (l'ordre exact)

1. `bash -n flash-day-v7.sh` (la syntaxe jamais validée) ;
2. l'installation v7 en UN SEUL appel sudo (`bash -c` avec `set -e`) :
   backup limine.conf → le bloc `//Flash463` (assert cryptdevice présent,
   pas de double insertion) → le service → le drapeau ;
3. le reboot sur **Flash463** → le blindage VFIO → le QEMU flash
   (~3 min, écran texte, les bannières — **ne jamais couper
   l'alimentation pendant la fenêtre d'écriture**) ;
4. le verdict : `.E5` = succès (valider 280 W, le chip-after v463a, les
   benchs) ; `.EB` = abort/rollback, la carte intacte ;
5. le cleanup : l'entrée, le service, le drapeau — le chip-before
   conservé pour le rollback.
