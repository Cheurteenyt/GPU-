#!/usr/bin/env python3
"""Vague 2 — taxonomie des strings du GSP-RM (rm-strings.txt, 9 054 lignes).
(re-constitué après rotation d'environnement — Task 64)

Objectifs (directive fondateur : « plein de choses qui nous punissent…
qui n'améliorent pas la sécurité… le code du firmware est à chier ») :
  1. Valider le census 881 dials registre (Rm*/RM* names).
  2. Construire la taxonomie des FAMILLES de contrôle : power, clocks, VF,
     fan, idle, sécurité/signatures, bugs, debug/cru.
  3. Chercher les « punitions » : limites perf, intersection de limites,
     throttles, LHR/ethash (attendu : ABSENT du RM — pilote hôte), télémétrie.
  4. Extraire des EXEMPLAIRES concrets pour la critique du code firmware.

Sortie : rapport markdown imprimé sur stdout.
Usage : python3 wave2_strings_taxonomy.py [chemin rm-strings.txt]
"""

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

STRINGS = Path(sys.argv[1] if len(sys.argv) > 1 else
               "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-strings.txt")

FAMILIES = [
    ("dial_registre",        re.compile(r"^(Rm|RM)[A-Z][A-Za-z0-9_]*$")),
    ("bug_workaround",       re.compile(r"(Bug|BUG)")),
    ("power_limit",          re.compile(r"(Power|Tdp|TDP|Watt|PowerSupply|RatedTdp|PowerSteering|PowerBudget)", re.I)),
    ("clock_vf_boost",       re.compile(r"(Clk|Clock|VfOverride|CfOverride|Boost|PState|Freq)", re.I)),
    ("fan_cooler",           re.compile(r"(Fan|Cooler|Cooling)", re.I)),
    ("thermal",              re.compile(r"(Thermal|Temp|Slowdown)", re.I)),
    ("idle_lpwr",            re.compile(r"(Lpwr|Idle|Sleep|Slumber)", re.I)),
    ("security_signature",   re.compile(r"(Sign|Secure|Verify|Auth|Fuse|Tamper|Lockdown|Decrypt|Crypto|Secret)", re.I)),
    ("telemetry_debug",      re.compile(r"(Telemetr|Dbg|Debug|Trace|Assert|Perfmon|EventLog)", re.I)),
    ("gc6_suspend",          re.compile(r"(Gc6|Suspend|Resume)", re.I)),
    ("mem_vram",             re.compile(r"(Mem|Vram|Bar1|Bar0|Framebuffer|Fb)", re.I)),
]

NOTABLE_PATTERNS = {
    "limite/perf/punition attendue": re.compile(
        r"(PerfLimit|LimitsOverride|PerfIntersect|Slowdown|Throttle|Clamp|Cap|Restrict|Block|Deny|Forbid|Punish|Enforce)", re.I),
    "boost/ouverture": re.compile(
        r"(BoostClock|Overclock|CustomerBoost|PriorityBoost|Unlock|Exceed)", re.I),
    "sécurité/verrou": re.compile(
        r"(SecureBoot|SignedFirmware|BootVerify|AntiTamper|Fused|Rollback)", re.I),
    "cru/debug en prod": re.compile(
        r"(XXX|FIXME|TODO|HACK|WTF|Uh oh|Shouldn.t happen|Impossible|Bad bad|panic|PANIC)", re.I),
}

def is_plausible_string(line: str) -> bool:
    if len(line) < 4:
        return False
    printable = sum(1 for c in line if c.isprintable())
    return printable / len(line) > 0.95

def main() -> None:
    lines = STRINGS.read_text(errors="replace").splitlines()
    clean = [l.strip() for l in lines if is_plausible_string(l.strip())]

    fam_count = Counter()
    dial_names = []
    for s in clean:
        for fam, rx in FAMILIES:
            if rx.search(s):
                fam_count[fam] += 1
                if fam == "dial_registre":
                    dial_names.append(s)
                break

    print("# Taxonomie rm-strings.txt (census GSP-RM 31 rings)")
    print(f"Lignes totales : {len(lines)} · lignes plausibles-texte : {len(clean)}")
    print()
    print("## Comptage par famille (premier match gagne)")
    for fam, _ in FAMILIES:
        print(f"- {fam}: {fam_count[fam]}")
    print(f"- dials uniques (dial_registre) : {len(set(dial_names))}")
    print()
    for label, rx in NOTABLE_PATTERNS.items():
        hits = [s for s in clean if rx.search(s)]
        print(f"## {label} — {len(hits)} hits")
        for h in hits[:40]:
            print(f"  {h}")
        print()
    out = Path(__file__).parent / "wave2_dial_names.txt"
    out.write_text("\n".join(sorted(set(dial_names))) + "\n")
    print(f"[dials uniques écrits -> {out}]")

if __name__ == "__main__":
    main()
