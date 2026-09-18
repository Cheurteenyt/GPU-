#!/usr/bin/env python3
"""v47-resolve — résout TOUTES les cibles auipc+jalr (et les jalrs via registre
précédés d'un auipc sur le même registre) dans les fenêtres v47.

Fenêtres : dispatcher 0x1634a38..0x1635700, boucle P-states 0x1631840..0x1631a80.
Sortie : pour chaque site d'appel, cible résolue + contexte immédiat (li a1/…)
→ v47_targets.json + résumé stdout groupé par cible.
"""
import json
from collections import defaultdict
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v47")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
idx = {a: i for i, (a, s, m, o) in enumerate(rows)}
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def resolve_window(lo, hi):
    """Résout les appels dans la fenêtre. Retourne liste d'événements."""
    events = []
    i = idx[lo]
    pending_auipc = {}  # reg -> (base, auipc_addr)
    while i < n and rows[i][0] <= hi:
        a, s, m, o = rows[i]
        if m == "auipc":
            p = parse(o)
            if len(p) == 2:
                try:
                    hi12 = int(p[1], 0) << 12
                except ValueError:
                    hi12 = None
                if hi12 is not None:
                    base = a + hi12
                    if base >= 0x80000000:
                        base -= 0x100000000
                    pending_auipc[p[0]] = (base, a)
        elif m == "jalr":
            p = parse(o)
            # forme 1 : jalr ra, ra, lo (auipc juste avant)
            if len(p) == 3 and p[0] == p[1] and p[1] in pending_auipc:
                base, auipc_a = pending_auipc[p[1]]
                try:
                    lo12 = int(p[2], 0)
                except ValueError:
                    lo12 = 0
                events.append({"site": hex(a), "target": hex(base + lo12),
                               "kind": "auipc+jalr", "auipc": hex(auipc_a)})
                pending_auipc.pop(p[1])
            # forme 2 : c.jalr / jalr rd, rs (appel via pointeur de registre)
            elif len(p) == 2 and p[1] not in ("zero",):
                events.append({"site": hex(a), "target": None, "kind": f"indirect:{p[1]}"})
            elif len(p) == 1:
                events.append({"site": hex(a), "target": None, "kind": "indirect:jr"})
        elif m == "c.jalr":
            p = parse(o)
            if len(p) == 1:
                events.append({"site": hex(a), "target": None, "kind": f"indirect:{p[0]}"})
        elif m in ("c.li", "li", "addi", "c.addi", "lui", "c.lui"):
            # on garde les li a1/a2/a3 récents pour le contexte (5 insns)
            pass
        i += 1
    return events


def context_types(lo, hi):
    """Pour chaque appel auipc+jalr, capture le dernier a1/a2/a3 immédiat."""
    events = resolve_window(lo, hi)
    out = []
    for ev in events:
        site = int(ev["site"], 16)
        i = idx[site]
        regs = {}
        for j in range(max(0, i - 14), i):
            aa, ss, mm, oo = rows[j]
            p = parse(oo)
            if mm in ("li", "c.li") and len(p) == 2:
                try:
                    regs[p[0]] = int(p[1], 0)
                except ValueError:
                    regs[p[0]] = None
            elif mm in ("addi", "c.addi") and len(p) == 3 and p[1] == "zero":
                try:
                    regs[p[0]] = int(p[2], 0)
                except ValueError:
                    regs[p[0]] = None
        ev["a1"] = regs.get("a1")
        ev["a2"] = regs.get("a2")
        ev["a3"] = regs.get("a3")
        out.append(ev)
    return out


WINDOWS = {
    "dispatcher": (0x1634A38, 0x1635700),
    "loop_pstate": (0x1631840, 0x1631A80),
}

all_events = {}
for name, (lo, hi) in WINDOWS.items():
    evs = context_types(lo, hi)
    all_events[name] = evs
    print(f"\n=== {name} {lo:#x}..{hi:#x} : {len(evs)} appels ===")
    by_target = defaultdict(list)
    for ev in evs:
        key = ev["target"] or ev["kind"]
        by_target[key].append(ev)
    for tgt in sorted(by_target, key=lambda k: (by_target[k][0]["site"])):
        lst = by_target[tgt]
        print(f"  cible {tgt} : {len(lst)} appel(s)")
        for ev in lst:
            print(f"    site {ev['site']}  a1={ev['a1'] if ev['a1'] is not None else '-'}"
                  f" a2={ev['a2'] if ev['a2'] is not None else '-'}"
                  f" a3={ev['a3'] if ev['a3'] is not None else '-'}  [{ev['kind']}]")

json.dump(all_events, (OUT / "v47_targets.json").open("w"), indent=1)
print(f"\n-> {OUT / 'v47_targets.json'}")
