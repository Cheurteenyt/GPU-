#!/bin/bash
# Remplace les XML SystemInfo produits sous Wine par notre template exact.
# EasyFMSI (5.93) écrit parfois un XML complet mais faux sous Wine (DDR3, RAM
# incomplète) : on écrase TOUT fichier fm-si-*.xml qui n'a pas notre marqueur,
# à chaque événement inotify + à chaque passage de poll.
TMPDIRW="/home/cheurteen/proton-3dmark/pfx/drive_c/ProgramData/UL/3DMark/tmp"
TPL="/home/cheurteen/.local/share/3dmark/SystemInfo_template.xml"
MARK="49152"
mkdir -p "$TMPDIRW"
[ -f "$TPL" ] || exit 1

fix_all() {
  local f sz
  for f in "$TMPDIRW"/fm-si-*.xml "$TMPDIRW"/tmp[0-9]*.tmp; do
    [ -f "$f" ] || continue
    sz=$(stat -c%s "$f" 2>/dev/null) || continue
    if [ "$sz" = "0" ] || [ "$sz" -lt 1000 ] || ! grep -q "$MARK" "$f" 2>/dev/null; then
      cp "$TPL" "$f"
      echo "$(date +%H:%M:%S) injecté ($(basename "$f"), était $sz o)" >> /tmp/si_watcher.log
    fi
  done
}

while true; do
  fix_all
  # garde le template du shim EasyFMSI synchronisé
  cp -f "$TPL" "$TMPDIRW/si_template.xml" 2>/dev/null
  if command -v inotifywait >/dev/null; then
    inotifywait -q -e create,close_write,moved_to --timeout 2 "$TMPDIRW" >/dev/null 2>&1
  else
    sleep 1
  fi
done
