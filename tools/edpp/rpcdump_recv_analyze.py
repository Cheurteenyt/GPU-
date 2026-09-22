#!/usr/bin/env python3
"""L'analyseur receveur 4.25 : réassemble les réponses fn=76 (RPCRECVINFO +
RPCRECV76, le patch tools/edpp/patch_rpc_recv.py) et teste la prédiction §7.2
(findings-4.24-edpp-flow.md) : dump 96 B = préfixe 40 + params 24 + résidu 32,
le triplet {100000, 240000, 250000} à poff {0,4,8} (dump {40,44,48}).

LOI DE LONGUEUR (findings-4.24-payload-fieldmap.md §2, PROUVÉE) : le hook
imprime rpc_len octets depuis rpc_message_data (le DÉBUT du corps) ; le résidu
de 32 octets en fin n'est PAS le message → vérifié nul puis tronqué.

Usage:
  journalctl -b -k | grep -E 'RPCRECV' | python3 rpcdump_recv_analyze.py
  python3 rpcdump_recv_analyze.py --predict    # la table prédite §7.2 (sans capture)
  python3 rpcdump_recv_analyze.py --selftest   # valide le décodeur sur un buffer SYNTHÉTIQUE

Layouts (PROUVÉS par le source, tag 610.57.04) :
  corps réponse fn=76 = rpc_gsp_rm_control_v03_00 (g_rpc-structures.h:1423-1435)
    0x00 hClient, 0x04 hObject, 0x08 cmd, 0x0C status, 0x10 paramsSize,
    0x14 rmapiRpcFlags, 0x18 rmctrlFlags, 0x1C rmctrlAccessRight,
    0x20 reserved0 (u64), 0x28 params[]
  GET_EDPP_LIMIT_INFO (0x20800afd) params 24 B (ctrl2080internal.h:3988-3995) :
    poff 0 limitMin, 4 limitRated, 8 limitMax, 12 limitCurr,
    16 limitBattRated, 20 limitBattMax
  UPDATE_EDPP_LIMIT (0x20800ad0) params 8 B (ctrl2080internal.h:3238-3241) :
    poff 0 bEnable, 4 clientLimit
"""
import re
import struct
import sys

POWER_MW = {100000: "100 W (le min prédit)", 120000: "120 W", 210000: "210 W",
            220000: "220 W", 240000: "240 W (le default prédit)",
            250000: "250 W (le max VBIOS)", 265000: "265 W", 280000: "280 W (LA CIBLE)"}

CMD_GET_EDPP = 0x20800afd
CMD_UPD_EDPP = 0x20800ad0
RESIDUE = 32          # la loi de longueur 4.24

RE_INFO = re.compile(
    r"RPCRECVINFO seq=(\d+) fn=(\d+) cmd=0x([0-9a-fA-F]{8}) status=0x([0-9a-fA-F]{8}) "
    r"psz=(\d+) rres=0x([0-9a-fA-F]{8}) rpriv=0x([0-9a-fA-F]{8}) len=(\d+) dump=(\d+)")
RE_CHUNK = re.compile(r"RPCRECV76 seq=(\d+) off=(\d+) len=(\d+):\s*((?:[0-9a-fA-F]{2}\s*)*)$")


def parse_lines(lines):
    """[(seq, info_dict, bytes)] — réassemblage par seq (le tag anti-interleave)."""
    infos, chunks = {}, {}
    for ln in lines:
        m = RE_INFO.search(ln)
        if m:
            seq = int(m.group(1))
            infos[seq] = {"fn": int(m.group(2)), "cmd": int(m.group(3), 16),
                          "status": int(m.group(4), 16), "psz": int(m.group(5)),
                          "rres": int(m.group(6), 16), "rpriv": int(m.group(7), 16),
                          "len": int(m.group(8)), "dump": int(m.group(9))}
            chunks.setdefault(seq, bytearray())
            continue
        m = RE_CHUNK.search(ln.strip())
        if m:
            seq, off = int(m.group(1)), int(m.group(2))
            hx = bytes(int(x, 16) for x in m.group(4).split())
            buf = chunks.setdefault(seq, bytearray())
            if len(buf) < off + len(hx):
                buf.extend(bytes(off + len(hx) - len(buf)))
            buf[off:off + len(hx)] = hx
    out = []
    for seq in sorted(infos):
        if seq in chunks and infos[seq]["dump"] == len(chunks[seq]):
            out.append((seq, infos[seq], bytes(chunks[seq])))
        elif seq in chunks:
            out.append((seq, infos[seq], bytes(chunks[seq])))   # incomplet : décodé, signalé
    return out


def apply_length_law(cap):
    """Le résidu 32 B : vérifié nul, puis tronqué (findings-4.24 §2)."""
    seq, info, buf = cap
    if info["dump"] != len(buf):
        print("  [seq %u] INCOMPLET : dump déclaré %u, réassemblé %u — décodage partiel, HONNÊTE"
              % (seq, info["dump"], len(buf)))
    n = len(buf)
    if n < RESIDUE:
        return buf, None, "trop court (< 32) — pas de troncature applicable"
    residue = buf[n - RESIDUE:]
    if any(residue):
        return buf, residue, "RÉSIDU NON NUL — la loi de longueur ne s'applique PAS telle quelle"
    return buf[:n - RESIDUE], residue, "résidu 32 B tout-zéro vérifié, tronqué"


def decode(seq, info, body, synth=False):
    """Décode une réponse fn=76 ; rend la table (off, poff, champ, valeur, statut)."""
    tag = "PRÉDICTION" if synth else ("PROUVÉ capture" if info.get("captured") else "HYPOTHÈSE")
    rows = []
    if len(body) >= 40:
        hClient, hObject, cmd, status, psz, f1, f2, f3 = struct.unpack_from("<8I", body, 0)
        reserved0 = struct.unpack_from("<Q", body, 32)[0]
        rows += [(0x00, None, "hClient", "0x%08x" % hClient, "layout PROUVÉ (g_rpc-structures.h:1425)"),
                 (0x04, None, "hObject", "0x%08x" % hObject, "layout PROUVÉ (:1426)"),
                 (0x08, None, "cmd", "0x%08x" % cmd, "layout PROUVÉ (:1427) — %s" % tag),
                 (0x0C, None, "status (rmctrl)", "0x%08x" % status, "layout PROUVÉ (:1428) — valeur %s" % tag),
                 (0x10, None, "paramsSize", "%u" % psz, "layout PROUVÉ (:1429) — valeur %s" % tag),
                 (0x14, None, "rmapiRpcFlags", "0x%08x" % f1, "layout PROUVÉ (:1430)"),
                 (0x18, None, "rmctrlFlags", "0x%08x" % f2, "layout PROUVÉ (:1431)"),
                 (0x1C, None, "rmctrlAccessRight", "0x%08x" % f3, "layout PROUVÉ (:1432)"),
                 (0x20, None, "reserved0 (u64)", "0x%016x" % reserved0, "layout PROUVÉ (:1433)")]
        info["dec_cmd"], info["dec_status"], info["dec_psz"] = cmd, status, psz
    else:
        info["dec_cmd"] = info.get("cmd")
        print("  [seq %u] corps %d < 40 : préfixe incomplet" % (seq, len(body)))
        return rows
    params = body[40:]
    if cmd == CMD_GET_EDPP:
        names = ["limitMin", "limitRated", "limitMax", "limitCurr", "limitBattRated", "limitBattMax"]
        for i, nm in enumerate(names):
            poff = 4 * i
            if len(params) < poff + 4:
                break
            v = struct.unpack_from("<I", params, poff)[0]
            lbl = POWER_MW.get(v, "")
            rows.append((0x28 + poff, poff, nm, "%d (0x%08x) %s" % (v, v, lbl),
                         "ordre PROUVÉ (ctrl2080internal.h:3989-3994) — valeur %s" % tag))
        info["edpp"] = {nm: struct.unpack_from("<I", params, 4 * i)[0]
                        for i, nm in enumerate(names) if len(params) >= 4 * i + 4}
    elif cmd == CMD_UPD_EDPP:
        if len(params) >= 8:
            b, cl = struct.unpack_from("<II", params, 0)
            rows.append((0x28, 0, "bEnable", "%u" % b, "ordre PROUVÉ (ctrl2080internal.h:3239-3240)"))
            rows.append((0x2C, 4, "clientLimit", "%d (0x%08x)" % (cl, cl), "ordre PROUVÉ (:3240)"))
    else:
        rows.append((0x28, 0, "params[%u]" % len(params), "(contrôle non-EDPp — voir le dump brut)", ""))
    return rows


def print_table(rows, title):
    print("\n=== %s ===" % title)
    print("| off (dump) | poff | champ            | valeur                      | statut |")
    print("|------------|------|------------------|-----------------------------|--------|")
    for off, poff, nm, val, st in rows:
        print("| 0x%04x      | %s | %-16s | %-27s | %s |" % (
            off, ("%-4d" % poff) if poff is not None else " —  ", nm, val, st))


def verdict_72(info, body_len, residue_zero):
    """La comparaison à la prédiction §7.2 (96 B, triplet à poff 0/4/8)."""
    print("\n--- le test de la prédiction §7.2 (seq %u) ---" % info.get("seq", -1))
    checks = []
    checks.append(("len (header) = 96 = 40 préfixe + 24 params + 32 résidu", info["len"] == 96))
    checks.append(("corps décodé + résidu = 64 + 32 (la loi 4.24 s'applique)",
                   residue_zero and body_len == 64))
    e = info.get("edpp", {})
    if e:
        checks.append(("limitMin @40 (poff 0) = 100000", e.get("limitMin") == 100000))
        checks.append(("limitRated @44 (poff 4) = 240000", e.get("limitRated") == 240000))
        checks.append(("limitMax @48 (poff 8) = 250000", e.get("limitMax") == 250000))
        checks.append(("paramsSize = 24", info.get("dec_psz") == 24))
    for name, ok in checks:
        print("  [%s] %s" % ("CONFORME" if ok else "NON-CONFORME", name))
    return all(ok for _, ok in checks)


def predict_table():
    """La table §7.2 telle que prédite — SANS capture (tout est HYPOTHÈSE valeur)."""
    info = {"seq": -1, "len": 96, "psz": 24, "cmd": CMD_GET_EDPP, "captured": False}
    prefix = struct.pack("<8I", 0, 0, CMD_GET_EDPP, 0, 24, 0, 0, 0) + struct.pack("<Q", 0)
    params = struct.pack("<6I", 100000, 240000, 250000, 0, 0, 0)
    rows = decode(-1, info, prefix + params, synth=True)
    print_table(rows, "la table PRÉDITE (§7.2 — 96 B dumpés : 40 préfixe + 24 params + 32 résidu)")
    print("\n  (valeurs 100000/240000/250000 = la prédiction §7.2 ; limitCurr/Batt* = inconnues)")
    print("  (le résidu 32 B tout-zéro = la loi de longueur 4.24, à revérifier sur la capture)")


def selftest():
    """Valide le PIPELINE de décodage sur un buffer SYNTHÉTIQUE conforme à §7.2.
    Instrument-check uniquement — JAMAIS une capture (interdiction de fabriquer)."""
    prefix = struct.pack("<8I", 0xc1d0004c, 0xa55a0030, CMD_GET_EDPP, 0, 24, 0, 0, 0) + struct.pack("<Q", 0)
    params = struct.pack("<6I", 100000, 240000, 250000, 245000, 0, 0)
    dump = prefix + params + bytes(RESIDUE)          # 96 B, la forme prédite
    lines = ["NVRM: RPCRECVINFO seq=42 fn=76 cmd=0x%08x status=0x00000000 psz=24 "
             "rres=0x00000000 rpriv=0x00000000 len=96 dump=96" % CMD_GET_EDPP]
    for off in range(0, len(dump), 512):
        chunk = " ".join("%02x" % b for b in dump[off:off + 512])
        lines.append("NVRM: RPCRECV76 seq=42 off=%u len=96: %s" % (off, chunk))
    caps = parse_lines(lines)
    assert len(caps) == 1, "selftest : 1 capture attendue"
    seq, info, buf = caps[0]
    assert info["cmd"] == CMD_GET_EDPP and len(buf) == 96, "selftest : header/lueur"
    body, residue, msg = apply_length_law((seq, info, buf))
    assert len(body) == 64 and any(residue) is False, "selftest : loi de longueur"
    info["captured"] = True                            # le décodeur croit à une capture SYNTHÉTIQUE
    rows = decode(seq, info, body)
    e = info["edpp"]
    assert e["limitMin"] == 100000 and e["limitRated"] == 240000 and e["limitMax"] == 250000
    assert e["limitCurr"] == 245000, "selftest : limitCurr"
    assert info["dec_psz"] == 24 and info["dec_cmd"] == CMD_GET_EDPP
    assert verdict_72(info, len(body), True)
    print_table(rows, "SELFTEST — buffer SYNTHÉTIQUE §7.2 (validation du décodeur, PAS une capture)")
    print("\nSELFTEST OK : réassemblage + loi 32 B + décodage préfixe/params + verdict §7.2 opèrent")
    print("  (ce buffer est FABRIQUÉ pour valider l'instrument ; aucune valeur n'est bankée)")


def main():
    if "--selftest" in sys.argv:
        selftest()
        return
    if "--predict" in sys.argv:
        predict_table()
        return
    caps = parse_lines(sys.stdin.read().splitlines())
    print("réponses fn=76 réassemblées : %d" % len(caps))
    if not caps:
        print("aucune capture receveuse en entrée — rien n'est décodé (journal honnête).")
        print("usage : journalctl -b -k | grep RPCRECV | python3 rpcdump_recv_analyze.py")
        sys.exit(1)
    edpp_seen = False
    for cap in caps:
        seq, info, buf = cap
        info["seq"] = seq
        info["captured"] = True
        body, residue, msg = apply_length_law(cap)
        print("\n=== seq %u : cmd=0x%08x fn=%u status=0x%08x psz=%u rres=0x%08x rpriv=0x%08x len=%u ==="
              % (seq, info["cmd"], info["fn"], info["status"], info["psz"],
                 info["rres"], info["rpriv"], info["len"]))
        print("  loi de longueur : %s" % msg)
        rows = decode(seq, info, body)
        print_table(rows, "seq %u — la réponse décodée (offsets dans le DUMP de %u B)"
                    % (seq, len(buf)))
        if info["cmd"] == CMD_GET_EDPP:
            edpp_seen = True
            verdict_72(info, len(body), residue is not None and not any(residue))
        elif info["dec_cmd"] == CMD_GET_EDPP if "dec_cmd" in info else False:
            edpp_seen = True
            verdict_72(info, len(body), residue is not None and not any(residue))
    if not edpp_seen:
        print("\nAUCUNE réponse GET_EDPP_LIMIT_INFO (0x20800afd) dans ce journal — verdict §7.2 :")
        print("  NON-TESTÉ (le GET n'a pas été émis, ou RpcRecvMode ≠ 1/2, ou le hook est absent)")
        print("  → le fallback : EdppForceGet=1 (findings-4.25 §3)")
        sys.exit(1)


if __name__ == "__main__":
    main()
