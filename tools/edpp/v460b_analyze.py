#!/usr/bin/env python3
"""v460b_analyze.py — l'analyseur de la capture 4.60 (la famille
rpcdump76_analyze.py, le transport userspace cette fois).

Input  : le ledger du shim v460b_ioctl_trace.so (les lignes 460TRACE)
Output : (1) la table des appels rendue (stdout)
         (2) la table de décode JSON (--out v460-decode.json) — le
             contrat d'entrée de v460a_nvml_bypass.py --table

La règle de nommage (la loi mW, héritée de rpcdump76) :
  - le SET   = le CONTROL dont les IN params portent la valeur mW du -pl
    (ex. 250000 = 0x3D090) — la valeur qu'on sait qu'on a demandée ;
  - le GET   = les CONTROLs dont les OUT params portent les valeurs
    min/default/max (ex. {100000, 240000, 250000}) — le fetch des limites ;
  - les cmd répétés identiques sans valeur mW = le bruit NVML (caps, etc.).

Usage :
  python3 v460b_analyze.py capture.log [--pl 250] [--out v460-decode.json]
"""
import argparse
import json
import re
import struct
import sys

MW_CENSUS_MIN, MW_CENSUS_MAX = 50000, 500000

NVSTATUS = {
    0x00000000: "NV_OK",
    0x0000001B: "NV_ERR_INSUFFICIENT_PERMISSIONS",
    0x0000001F: "NV_ERR_INVALID_ARGUMENT",
    0x00000023: "NV_ERR_INVALID_CLIENT",
    0x00000026: "NV_ERR_INVALID_DEVICE",
    0x00000029: "NV_ERR_INVALID_FLAGS",
    0x0000002E: "NV_ERR_INVALID_LIMIT",
    0x00000031: "NV_ERR_INVALID_OBJECT",
    0x00000033: "NV_ERR_INVALID_OBJECT_HANDLE",
    0x00000036: "NV_ERR_INVALID_OBJECT_PARENT",
    0x0000003B: "NV_ERR_INVALID_PARAMETER",
    0x00000056: "NV_ERR_NOT_SUPPORTED",
    0x00000063: "NV_ERR_STATE_IN_USE",
    0x0000FFFF: "NV_ERR_GENERIC",
}


def parse_ledger(text):
    calls = []
    for ln in text.splitlines():
        if not ln.startswith("460TRACE "):
            continue
        rec = dict(re.findall(r"(\w+)=(\"[^\"]*\"|\S+)", ln))
        rec["raw"] = ln
        for k in ("fd", "paramsSize", "cmd", "reply"):
            if k in rec:
                rec[k] = int(rec[k], 0)
        for k in ("hClient", "hObject", "hRoot", "hParent", "hNew", "hClass",
                  "hObjectOld", "flags", "status"):
            if k in rec:
                rec[k] = int(rec[k], 16)
        rec["params_hex"] = rec.get("params", "(null)")
        calls.append(rec)
    return calls


def mw_scan(hexstr):
    """les valeurs mW-like dans un hexdump (u32 LE, pas à pas de 1)."""
    out = []
    try:
        data = bytes.fromhex(hexstr)
    except ValueError:
        return out
    for off in range(0, max(0, len(data) - 3)):
        v = struct.unpack_from("<I", data, off)[0]
        if MW_CENSUS_MIN <= v <= MW_CENSUS_MAX and v % 500 == 0:
            out.append((off, v))
    return out


def u32_at(hexstr, off):
    data = bytes.fromhex(hexstr)
    if off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ledger")
    ap.add_argument("--pl", type=int, default=250,
                    help="la valeur W passée au -pl capturé (250 par défaut)")
    ap.add_argument("--out", default=None, help="la table JSON pour v460a")
    args = ap.parse_args()

    calls = parse_ledger(open(args.ledger, encoding="utf-8", errors="replace").read())
    if not calls:
        print("ERREUR : aucune ligne 460TRACE — le shim était-il chargé ?",
              file=sys.stderr)
        return 2

    pl_mw = args.pl * 1000
    print(f"== la capture 4.60 : {len(calls)} appels tracés, la cible -pl {args.pl} ({pl_mw} mW) ==\n")

    handles = {}
    version = None
    alloc_chain = []
    controls = []

    for i, c in enumerate(calls):
        op = c.get("op", "")
        if op == "VERSION":
            version = c
            print(f"[version] reply={c.get('reply')} version={c.get('version')}")
        elif op == "ALLOC":
            # merger le ALLOC_RET suivant (le hObjectNew OUT + le status réel)
            ret = None
            if i + 1 < len(calls) and calls[i + 1].get("op") == "ALLOC_RET" \
                    and calls[i + 1].get("hClass") == c.get("hClass"):
                ret = calls[i + 1]
            h = {"hClass": c.get("hClass"), "hParent": c.get("hParent"),
                 "hNew": (ret or {}).get("hNew", c.get("hNew")),
                 "paramsSize": c.get("paramsSize", 0),
                 "status": (ret or {}).get("status", c.get("status")),
                 "params": c.get("params_hex")}
            alloc_chain.append(h)
            nm = {0x0: "NV01_ROOT", 0x80: "NV01_DEVICE_0",
                  0x2080: "NV20_SUBDEVICE_0"}.get(c.get("hClass"), "?")
            print(f"[alloc]   {nm} hClass=0x{c.get('hClass', 0):x} "
                  f"hNew=0x{h['hNew']:08x} status=0x{h['status']:08x} "
                  f"({NVSTATUS.get(h['status'], '?')})")
            if c.get("hClass") == 0x80:
                handles["hDevice"] = h["hNew"]
            elif c.get("hClass") == 0x2080:
                handles["hSubdevice"] = h["hNew"]
        elif op == "CONTROL":
            controls.append(c)
        elif op == "CONTROL_RET":
            if controls:
                controls[-1]["ret_params"] = c.get("params_hex", "(null)")
                controls[-1]["status"] = c.get("status")

    if handles.get("hDevice") and handles.get("hSubdevice"):
        handles["hClient"] = next((a.get("hParent") for a in alloc_chain
                                   if a.get("hClass") == 0x80), None)

    print(f"\n== les {len(controls)} CONTROLs (cmd, taille, les mW vus) ==")
    get_cands, set_cands = [], []
    for i, c in enumerate(controls):
        ins, outs = mw_scan(c.get("params_hex", "")), mw_scan(c.get("ret_params", ""))
        tag = ""
        if any(v == pl_mw for _, v in ins):
            tag += f"  <<< SET-candidat (l'IN porte {pl_mw})"
            set_cands.append(i)
        if outs and not tag:
            tag += f"  <<< GET-candidat (l'OUT porte les mW)"
            get_cands.append(i)
        st = c.get("status")
        print(f"[{i:3d}] cmd=0x{c.get('cmd', 0):08x} size={c.get('paramsSize', 0):5d} "
              f"hObj=0x{c.get('hObject', 0):08x} st=0x{st:08x}" if st is not None else
              f"[{i:3d}] cmd=0x{c.get('cmd', 0):08x} size={c.get('paramsSize', 0)}")
        if ins:
            print(f"      IN  mW: " + ", ".join(f"@{o}:{v}" for o, v in ins))
        if outs:
            print(f"      OUT mW: " + ", ".join(f"@{o}:{v}" for o, v in outs))
        if tag:
            print("     " + tag)

    if not set_cands:
        print(f"\nATTENTION : aucun CONTROL IN ne porte {pl_mw} mW — soit le "
              f"-pl {args.pl} n'a pas été capturé jusqu'au SET, soit la valeur "
              f"voyage dans une autre forme (mW/1000 ? l'encodage diffère ?). "
              f"Le census complet ci-dessus = le ledger honnête.")

    if args.out:
        tbl = {
            "source": args.ledger,
            "pl_w": args.pl,
            "version_check": {"reply": (version or {}).get("reply"),
                              "version": (version or {}).get("version")},
            "handles": handles,
            "alloc_chain": alloc_chain,
            "controls": [{"i": i, "cmd": controls[i].get("cmd"),
                          "paramsSize": controls[i].get("paramsSize"),
                          "hObject": controls[i].get("hObject"),
                          "flags": controls[i].get("flags"),
                          "params": controls[i].get("params_hex"),
                          "ret_params": controls[i].get("ret_params"),
                          "status": controls[i].get("status")}
                         for i in range(len(controls))],
            "set_candidates": set_cands,
            "get_candidates": get_cands,
        }
        if set_cands:
            sc = controls[set_cands[0]]
            offs = sorted({o for o, v in mw_scan(sc.get("params_hex", "")) if v == pl_mw})
            tbl["set"] = {"cmd": sc.get("cmd"), "paramsSize": sc.get("paramsSize"),
                          "hObject": sc.get("hObject"), "flags": sc.get("flags"),
                          "template_hex": sc.get("params_hex"),
                          "value_offsets": offs}
        if get_cands:
            gc = controls[get_cands[0]]
            tbl["get"] = {"cmd": gc.get("cmd"), "paramsSize": gc.get("paramsSize"),
                          "hObject": gc.get("hObject"), "flags": gc.get("flags"),
                          "template_hex": gc.get("params_hex"),
                          "ret_hex": gc.get("ret_params")}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(tbl, f, indent=1)
        print(f"\nla table de décode écrite : {args.out}")
        print(f"le replay : python3 v460a_nvml_bypass.py --table {args.out} --mw 280000 --arm")
    return 0


if __name__ == "__main__":
    sys.exit(main())
