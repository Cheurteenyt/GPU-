#!/usr/bin/env python3
"""v48-pass — vague 4.8, chantier 2 : la grammaire de la passe 0x1b3c4f0.

1. Déroulé de la fonction (fenêtre 0x1b3c4f0 + 0x500) avec cibles de branches.
2. Tests sur a1 (le sélecteur) : andi/srl/beq/bgeu/li — la grammaire des passes.
3. Census des a1 des 52 appelants (regard arrière ≤ 14 insns, li/addi sur a1).
4. Appels internes résolus (auipc+jalr) pour nommer les sous-opérations.
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v48")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


BR = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez", "bgez",
      "blez", "bltz", "bgtz", "j", "c.j", "c.bnez", "c.beqz", "jal"}


def branch_target(m, o, a):
    if m not in BR:
        return None
    last = parse(o)[-1]
    try:
        val = int(last, 16) if last.startswith("0x") else int(last)
    except ValueError:
        return None
    return a + val if -0x100000 < val < 0x100000 else None


def resolve_auipc_jalr(i):
    """Résout auipc+jalr à l'index i (le jalr)."""
    a, s, m, o = rows[i]
    p = parse(o)
    if m == "jalr" and len(p) == 3 and p[0] == p[1]:
        for k in (i - 1, i - 2):
            if k < 0:
                break
            ka, ks, km, ko = rows[k]
            kp = parse(ko)
            if km == "auipc" and len(kp) == 2 and kp[0] == p[1]:
                base = ka + (int(kp[1], 0) << 12)
                if base >= 0x80000000:
                    base -= 0x100000000
                return base + int(p[2], 0)
    return None


# ------------------------------------------------ 1 : déroulé
F = 0x1B3C4F0
i0 = bisect.bisect_left(addrs, F)
print(f"=== 1. déroulé de la passe {F:#x} (0x500 octets) ===")
lines = []
calls_in = []
while i0 < n and rows[i0][0] < F + 0x500:
    a, s, m, o = rows[i0]
    t = branch_target(m, o, a)
    tgt = f"   → {t:#x}" if t else ""
    if m == "jalr":
        r = resolve_auipc_jalr(i0)
        if r:
            tgt = f"   → {r:#x}"
            calls_in.append((a, r))
    lines.append(f"  {a:#08x}  {m:10} {o}{tgt}")
    i0 += 1
(OUT / "v48_pass.dump").write_text("\n".join(lines) + "\n")
print(f"  {len(lines)} instructions → v48_pass.dump")
print(f"  appels internes résolus : {[hex(c[1]) for c in calls_in]}")

# ------------------------------------------------ 2 : tests sur a1/a2 (args)
print("\n=== 2. usage des registres d'arguments a0/a1 dans la fenêtre ===")
i0 = bisect.bisect_left(addrs, F)
uses = []
while i0 < n and rows[i0][0] < F + 0x500:
    a, s, m, o = rows[i0]
    if m in ("andi", "slli", "srli", "sraiw", "srlw", "addiw", "beq", "bne",
             "bltu", "bgeu", "beqz", "bnez") :
        p = parse(o)
        if p and p[0] in ("a1", "a0") or (len(p) > 1 and p[1] in ("a1", "a0")):
            uses.append(f"  {a:#08x}  {m:10} {o}")
    i0 += 1
print("\n".join(uses) if uses else "  (aucun)")

# ------------------------------------------------ 3 : census des a1 des appelants
print("\n=== 3. census des a1 aux 52 sites d'appel ===")
SITES = [0x10da2da, 0x11a6d4a, 0x1257ffa, 0x162a382, 0x162f6f0, 0x162ff1e,
         0x1631568, 0x16315b8, 0x163197e, 0x16319c6, 0x16325d6, 0x16378e6,
         0x1637958, 0x16379d4, 0x1637a2e, 0x1637b4c, 0x1637c92, 0x1637d96,
         0x16383b4, 0x1639a74, 0x1645b46, 0x16494de, 0x164d1d8, 0x16798a6,
         0x1679cfa, 0x167ae90, 0x167c0b0, 0x167fd6a, 0x167ff84, 0x167ffec,
         0x16951fe, 0x16ec394, 0x16ec3d0, 0x16ff7ee, 0x16ff960, 0x16ffb5e,
         0x16ffed8, 0x17000a6, 0x17028a4, 0x1702b84, 0x1767796, 0x17677c2,
         0x17677e8, 0x1767812, 0x1767836, 0x1767860, 0x1767886, 0x17b749c,
         0x17b8e32, 0x1ad0cb4, 0x1b9ea72, 0x1bd4230]
from collections import Counter
census = Counter()
detail = []
for site in SITES:
    i = bisect.bisect_left(addrs, site)
    found = None
    for j in range(i - 1, max(0, i - 14) - 1, -1):
        aa, ss, mm, oo = rows[j]
        p = parse(oo)
        if mm in ("li", "c.li") and len(p) == 2 and p[0] == "a1":
            found = ("li", aa, int(p[1], 0))
            break
        if mm in ("addi", "c.addi") and len(p) == 3 and p[0] == "a1" and p[1] == "zero":
            found = ("addi", aa, int(p[2], 0))
            break
        if mm in ("mv", "c.mv") and len(p) == 2 and p[0] == "a1":
            found = (f"mv←{p[1]}", aa, None)
            break
        if mm in ("auipc", "lui") and p and p[0] == "a1":
            found = ("other", aa, None)
            break
    if found:
        census[found[2] if found[2] is not None else found[0]] += 1
        detail.append({"site": hex(site), "kind": found[0],
                       "li_site": hex(found[1]), "a1": found[2]})
    else:
        census["?"] += 1
        detail.append({"site": hex(site), "kind": "none"})
print("  distribution :")
for k, c in sorted(census.items(), key=lambda x: -x[1]):
    print(f"    a1={k if isinstance(k, str) else hex(k)} : {c} site(s)")
(OUT / "v48_pass_a1.json").open("w").write(json.dumps(detail, indent=1))
print(f"\n  détail → v48_pass_a1.json")
print("\nv48-pass terminé.")
