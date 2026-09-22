#!/usr/bin/env python3
"""recv76_analyze (4.29) — le réassembleur send↔recv + la chasse aux champs
de réponse.

Entrée : UN journal contenant les DEUX familles de lignes de capture :

  send : RPCDUMP76 seq=.. off=.. len=..: hex      (patch_rpc_final.py, 4.23 —
         le seq est le COMPTEUR du hook, PAS la séquence du header RPC ;
         findings-4.25-recv-edpp.md §2, l'avertissement de corrélation)
  recv : RPCRECVINFO seq=.. fn=.. cmd=.. status=.. psz=.. rres=.. rpriv=..
         len=.. dump=..  +  RPCRECV76 seq=.. off=.. len=..: hex
         (patch_rpc_recv.py, 4.25 — le seq EST la séquence du header,
         l'identifiant de corrélation faisant autorité)

Ce que l'outil fait :
  1. RÉASSEMBLAGE par (côté, seq) : affectation sparse par offset (chunks
     hors-ordre OK, doublons idempotents, trous détectés et signalés),
     indexation par dict (un seq hostile géant ne doit PAS allouer).
  2. CORRÉLATION send↔recv — P1 : égalité seq+cmd (« seq-consistent », mais
     étiqueté HYPOTHÈSE tant que le hook send 4.23 imprime son propre
     compteur — le raffinement §6.4 de 4.25 n'est pas embarqué) ;
     P2 (défaut) : appariement cmd + ordre du journal (le k-ième recv de la
     cmd X répond au k-ième send de la cmd X) — HYPOTHÈSE, étiqueté.
  3. CHASSE AUX CHAMPS DE RÉPONSE — par paire : la carte des deltas
     send→recv (ce que le GSP a écrasé, en runs contigus + échantillons
     u32), nommée là où le source le permet : le préfixe 40 B
     rpc_gsp_rm_control_v03_00 (g_rpc-structures.h:1423-1435), les params
     EDPp GET (ctrl2080internal.h:3988-3995) / UPDATE (:3238-3241), la
     struct 0x2080d031 = header 8 B {flags, domain-bitmask} + 32 entrées
     × 48 B (findings-4.28-x86-substrate.md §7) ; + le recensement des
     valeurs mW-like (les étiquettes 4.23 ; pour 0x2080d031 la
     ré-attribution 4.28 = table clock-VF, PAS des watts) ; + la loi de
     longueur (résidu 32 B vérifié nul puis tronqué, findings-4.24 §2).

Usage :
  journalctl -b -k | grep -E 'RPC(DUMP|RECV)' | python3 recv76_analyze.py
  python3 recv76_analyze.py --selftest    # la batterie de robustesse

AUCUN tool offline ne fabrique une capture : le selftest valide le
pipeline sur le corpus send RÉEL (tools/edpp/edpp_payload_1616.bin,
les octets de la capture 4.23) + des cas de bordure SYNTHÉTIQUES
étiquetés comme tels (instrument-check, jamais banké comme capture).
"""
import os
import re
import struct
import sys

RE_INFO = re.compile(
    r"RPCRECVINFO seq=(\d+) fn=(\d+) cmd=0x([0-9a-fA-F]{8}) "
    r"status=0x([0-9a-fA-F]{8}) psz=(\d+) rres=0x([0-9a-fA-F]{8}) "
    r"rpriv=0x([0-9a-fA-F]{8}) len=(\d+) dump=(\d+)")
RE_RECV = re.compile(
    r"RPCRECV76 seq=(\d+) off=(\d+) len=(\d+):\s*((?:[0-9a-fA-F]{2}\s*)*)$")
RE_SEND = re.compile(
    r"RPCDUMP76 seq=(\d+) off=(\d+) len=(\d+):\s*((?:[0-9a-fA-F]{2}\s*)*)$")
RE_SEND_OTHER = re.compile(r"RPCDUMP fn=(\d+) len=(\d+)")

POWER_MW = {100000: "100 W (étiquette 4.23 ; d031 = clock-VF 4.28)",
            120000: "120 W (idem)", 210000: "210 W", 220000: "220 W",
            240000: "240 W (idem)", 250000: "250 W (étiquette 4.23 ; "
            "ré-attribuée clock-VF par 4.28 pour d031)",
            265000: "265 W", 280000: "280 W (LA CIBLE)"}
CMD_GET_EDPP = 0x20800afd
CMD_UPD_EDPP = 0x20800ad0
CMD_D031 = 0x2080d031
RESIDUE = 32          # la loi de longueur 4.24

PREFIX_FIELDS = [(0x00, "hClient"), (0x04, "hObject"), (0x08, "cmd"),
                 (0x0C, "status (rmctrl)"), (0x10, "paramsSize"),
                 (0x14, "rmapiRpcFlags"), (0x18, "rmctrlFlags"),
                 (0x1C, "rmctrlAccessRight"), (0x20, "reserved0 (u64)")]


# ---------------------------------------------------------------- réassemblage
class Capture(object):
    """Un message réassemblé d'un côté (send ou recv)."""

    def __init__(self, side, seq):
        self.side = side
        self.seq = seq
        self.buf = bytearray()
        self.declared = None          # le len= total (toute ligne le porte)
        self.written = []             # [(start, end)] pour la détection de trous
        self.info = {}                # recv : la ligne RPCRECVINFO

    def put(self, off, hx, declared):
        if self.declared is None:
            self.declared = declared
        elif self.declared != declared:
            self.info.setdefault("len_conflicts", []).append(declared)
        need = off + len(hx)
        if len(self.buf) < need:
            self.buf.extend(bytes(need - len(self.buf)))
        if hx:
            self.buf[off:need] = hx
        self.written.append((off, need))

    def holes(self):
        """Les intervalles non couverts dans [0, declared)."""
        if self.declared is None:
            return []
        iv = sorted(self.written)
        merged = []
        for s, e in iv:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        holes, cur = [], 0
        for s, e in merged:
            if s > cur:
                holes.append((cur, s))
            cur = max(cur, e)
        if cur < self.declared:
            holes.append((cur, self.declared))
        return holes


def _hexbytes(s):
    """La chaîne hex -> octets, ESPACÉ OU NON (la leçon du selftest : le
    parseur des frères faisait group(4).split() et explosait sur l'hex
    collé 'deadbeef' — int('deadbeef',16) déborde). Un demi-octet final
    orphelin est tronqué (le journal est corrompu à cet endroit)."""
    h = re.sub(r"\s+", "", s)
    if len(h) % 2:
        h = h[:-1]
    return bytes(int(h[i:i + 2], 16) for i in range(0, len(h), 2))


def parse_lines(lines):
    """{(side, seq): Capture} — les deux familles, index dict (pas de
    préallocation : un seq hostile géant ne coûte rien)."""
    caps = {}
    other_fn = 0
    junk = 0
    for ln in lines:
        m = RE_INFO.search(ln)
        if m:
            seq = int(m.group(1))
            c = caps.setdefault(("recv", seq), Capture("recv", seq))
            c.info = {"fn": int(m.group(2)), "cmd": int(m.group(3), 16),
                      "status": int(m.group(4), 16), "psz": int(m.group(5)),
                      "rres": int(m.group(6), 16),
                      "rpriv": int(m.group(7), 16),
                      "len": int(m.group(8)), "dump": int(m.group(9))}
            continue
        m = RE_RECV.search(ln.strip())
        if m:
            seq, off, declared = int(m.group(1)), int(m.group(2)), int(m.group(3))
            hx = _hexbytes(m.group(4))
            caps.setdefault(("recv", seq),
                            Capture("recv", seq)).put(off, hx, declared)
            continue
        m = RE_SEND.search(ln.strip())
        if m:
            seq, off, declared = int(m.group(1)), int(m.group(2)), int(m.group(3))
            hx = _hexbytes(m.group(4))
            caps.setdefault(("send", seq),
                            Capture("send", seq)).put(off, hx, declared)
            continue
        if RE_SEND_OTHER.search(ln):
            other_fn += 1
            continue
        if ln.strip():
            junk += 1
    for c in caps.values():
        if c.buf and c.info:
            c.info["reasm"] = len(c.buf)
    return caps, {"non_fn76_sends": other_fn, "junk_lines": junk}


# ---------------------------------------------------------------- corrélation
def cmd_of(cap):
    """La cmd : la ligne INFO fait autorité (recv), sinon l'offset 0x08."""
    if cap.info.get("cmd") is not None:
        return cap.info["cmd"]
    if len(cap.buf) >= 12:
        return struct.unpack_from("<I", cap.buf, 8)[0]
    return None


def correlate(caps):
    """[(send_cap, recv_cap, mode)] + les orphelins. P1 = seq+cmd égaux
    (HYPOTHÈSE : le seq send 4.23 est un compteur privé) ;
    P2 = cmd + ordre du journal (HYPOTHÈSE, étiqueté)."""
    sends = sorted((c for (s, _), c in caps.items() if s == "send"),
                   key=lambda c: c.seq)
    recvs = sorted((c for (s, _), c in caps.items() if s == "recv"),
                   key=lambda c: c.seq)
    pairs, used_r = [], set()

    # P1 : la cohérence seq+cmd
    by_seq = {c.seq: c for c in recvs}
    for s in sends:
        r = by_seq.get(s.seq)
        if r is not None and id(r) not in used_r and \
                cmd_of(s) is not None and cmd_of(s) == cmd_of(r):
            pairs.append((s, r, "P1 seq+cmd (HYPOTHÈSE — compteur hook 4.23)"))
            used_r.add(id(r))

    # P2 : cmd + ordre du journal
    for s in sends:
        if any(p[0] is s for p in pairs):
            continue
        cs = cmd_of(s)
        for r in recvs:
            if id(r) in used_r:
                continue
            if cmd_of(r) == cs:
                pairs.append((s, r, "P2 cmd+ordre (HYPOTHÈSE)"))
                used_r.add(id(r))
                break
    orphans_s = [s for s in sends if not any(p[0] is s for p in pairs)]
    orphans_r = [r for r in recvs if not any(p[1] is r for p in pairs)]
    return pairs, orphans_s, orphans_r


# ------------------------------------------------- la chasse aux champs (delta)
def name_params(cmd, body, base=40):
    """Les noms de champs params là où le source les donne (citations dans
    la docstring). [(poff, nom)] — vide = non décodé, honnête."""
    names = []
    if cmd == CMD_GET_EDPP:
        names = [(base + 4 * i, nm) for i, nm in enumerate(
            ["limitMin", "limitRated", "limitMax", "limitCurr",
             "limitBattRated", "limitBattMax"])]
    elif cmd == CMD_UPD_EDPP:
        names = [(base, "bEnable"), (base + 4, "clientLimit")]
    elif cmd == CMD_D031:
        names = [(base, "flags"), (base + 4, "domain-bitmask")]
        names += [(base + 8 + 48 * i, "entry[%d].version" % i)
                  for i in range(32)]
    return names


def delta_map(scap, rcap):
    """Ce que le GSP a écrasé : les u32 modifiés (vue champ, alignée 4),
    nommés là où le source le permet, + le total d'octets différents
    (la précision non-alignée). La vue u32 est la bonne granularité ici :
    le transport fn=76 est un champ de u32 (le préfixe, les params)."""
    a, b = scap.buf, rcap.buf
    n = min(len(a), len(b))
    cmd = cmd_of(rcap) or cmd_of(scap)
    named = name_params(cmd, b) + list(PREFIX_FIELDS)
    changed = []
    for o in range(0, max(0, n - 3), 4):
        va = struct.unpack_from("<I", a, o)[0]
        vb = struct.unpack_from("<I", b, o)[0]
        if va != vb:
            nm = next((nm for oo, nm in named if oo == o), None)
            changed.append((o, va, vb, nm))
    byte_diffs = sum(1 for i in range(n) if a[i] != b[i])
    return changed, byte_diffs


def residue_verdict(cap):
    """La loi de longueur : le résidu 32 B vérifié nul (4.24 §2)."""
    n = len(cap.buf)
    if n < RESIDUE:
        return "trop court (<32)"
    res = cap.buf[n - RESIDUE:]
    return "résidu 32 B tout-zéro (tronqué)" if not any(res) else \
        "RÉSIDU NON NUL — la loi ne s'applique pas telle quelle"


def census_mw(cap):
    """Le recensement mW-like (les étiquettes 4.23, la note 4.28)."""
    found = []
    for off in range(0, len(cap.buf) - 3):
        v = struct.unpack_from("<I", cap.buf, off)[0]
        if v in POWER_MW:
            found.append((off, v))
    return found


# ------------------------------------------------------------------ reporting
def report(caps, stats):
    print("captures réassemblées : send=%d recv=%d | lignes hors fn=76 : %d,"
          " lignes non reconnues ignorées : %d" %
          (sum(1 for (s, _), c in caps.items() if s == "send"),
           sum(1 for (s, _), c in caps.items() if s == "recv"),
           stats["non_fn76_sends"], stats["junk_lines"]))
    for (side, seq), c in sorted(caps.items()):
        h = c.holes()
        if h or (c.declared is not None and c.declared != len(c.buf)):
            print("  [%s seq=%d] INCOMPLET : déclaré %s, réassemblé %d, trous %s"
                  % (side, seq, c.declared, len(c.buf), h[:4]))
    pairs, orph_s, orph_r = correlate(caps)
    print("\n=== corrélation send↔recv : %d paire(s) ===" % len(pairs))
    for scap, rcap, mode in pairs:
        print("\n--- send seq=%d (%d B) <-> recv seq=%d (%d B) [%s] ---"
              % (scap.seq, len(scap.buf), rcap.seq, len(rcap.buf), mode))
        print("  loi de longueur recv : %s" % residue_verdict(rcap))
        changed, byte_diffs = delta_map(scap, rcap)
        named = [c for c in changed if c[3]]
        print("  chasse aux champs de réponse : %d u32 modifiés "
              "(%d nommés), %d octets différents" %
              (len(changed), len(named), byte_diffs))
        for o, va, vb, nm in named[:16]:
            print("    @%-4d %-18s : 0x%08x -> 0x%08x" % (o, nm, va, vb))
        unnamed = [c for c in changed if not c[3]][:8]
        for o, va, vb, _ in unnamed:
            print("    @%-4d (non nommé)          : 0x%08x -> 0x%08x"
                  % (o, va, vb))
        for off, v in census_mw(rcap)[:12]:
            print("    valeur mW-like @%d : %d (%s)" % (off, v, POWER_MW[v]))
    for s in orph_s:
        print("\n  send seq=%d cmd=%s (%d B) : AUCUN recv apparié "
              "( réponse non capturée, ou RpcRecvMode ≠ 1/2, ou hook absent)"
              % (s.seq, "0x%08x" % cmd_of(s) if cmd_of(s) else "?",
                 len(s.buf)))
    for r in orph_r:
        print("\n  recv seq=%d cmd=%s (%d B) : AUCUN send apparié "
              "(le hook send 4.23 n'était pas actif, ou la requête précède "
              "la fenêtre du journal)" %
              (r.seq, "0x%08x" % cmd_of(r) if cmd_of(r) else "?", len(r.buf)))
    if not caps:
        print("aucune capture en entrée — rien n'est décodé (journal honnête).")
        return 1
    return 0


def main():
    caps, stats = parse_lines(sys.stdin.read().splitlines())
    sys.exit(report(caps, stats))


# ------------------------------------------------------------------ selftest
def _wrap_send(seq, data, chunk=512):
    """Les lignes RPCDUMP76 comme le hook 4.23 les imprime."""
    lines = []
    for off in range(0, len(data), chunk):
        hx = " ".join("%02x" % b for b in data[off:off + chunk])
        lines.append("NVRM: RPCDUMP76 seq=%d off=%d len=%d: %s"
                     % (seq, off, len(data), hx))
    return lines


def _wrap_recv(seq, data, info, chunk=512):
    lines = ["NVRM: RPCRECVINFO seq=%d fn=76 cmd=0x%08x status=0x%08x "
             "psz=%d rres=0x%08x rpriv=0x%08x len=%d dump=%d"
             % (seq, info["cmd"], info["status"], info["psz"],
                info["rres"], info["rpriv"], len(data), len(data))]
    for off in range(0, len(data), chunk):
        hx = " ".join("%02x" % b for b in data[off:off + chunk])
        lines.append("NVRM: RPCRECV76 seq=%d off=%d len=%d: %s"
                     % (seq, off, len(data), hx))
    return lines


def selftest():
    ok = []

    # 1. le corpus send RÉEL : edpp_payload_1616.bin (capture 4.23, octets
    #    committés) — l'emballage en lignes est un instrument-check.
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "edpp_payload_1616.bin")
    assert os.path.exists(p), "corpus send réel absent"
    real = open(p, "rb").read()
    caps, stats = parse_lines(_wrap_send(0, real))
    c = caps[("send", 0)]
    assert bytes(c.buf) == real, "selftest 1: réassemblage != fichier"
    assert c.holes() == [], "selftest 1: trous"
    assert cmd_of(c) == CMD_D031, "selftest 1: cmd @0x08"
    assert struct.unpack_from("<I", c.buf, 0x10)[0] == 0x608, \
        "selftest 1: paramsSize 1544"
    ok.append("1 corpus réel 1616 B (cmd 0x2080d031, psz 0x608) byte-exact")

    # 2. interleave de deux seqs + 3. hors-ordre + doublons (idempotent)
    a = bytes(range(256)) * 2                     # 512 B
    b = b"\x5a" * 300
    lines = _wrap_send(7, a) + _wrap_send(3, b)
    mixed = lines[1::2] + lines[0::2]             # entrelacé
    caps, _ = parse_lines(mixed)
    assert bytes(caps[("send", 7)].buf) == a and \
        bytes(caps[("send", 3)].buf) == b, "selftest 2: entrelacé"
    caps, _ = parse_lines(_wrap_send(7, a) * 2)   # doublons
    assert bytes(caps[("send", 7)].buf) == a, "selftest 3: doublons"
    rev = sorted(_wrap_send(9, a), key=lambda l: -int(
        re.search(r"off=(\d+)", l).group(1)))     # hors-ordre
    caps, _ = parse_lines(rev)
    assert bytes(caps[("send", 9)].buf) == a, "selftest 3: hors-ordre"
    ok.append("2-3 entrelacé + hors-ordre + doublons idempotents")

    # 4. tronqué : trou détecté, pas de crash
    caps, _ = parse_lines(_wrap_send(1, real)[:-1])
    c = caps[("send", 1)]
    assert c.holes() != [] and c.declared == len(real), "selftest 4: tronqué"
    ok.append("4 tronqué -> trous déclarés [%d,%d)" % c.holes()[0])

    # 5. junk / RPCDUMP fn= / hex court — ignorés proprement
    caps, stats = parse_lines(
        ["systemd[1]: Started X", "NVRM: RPCDUMP fn=77 len=200",
         "NVRM: RPCDUMP76 seq=2 off=0 len=4: deadbeef", "", "  "])
    assert caps[("send", 2)].buf == bytes.fromhex("deadbeef") and \
        stats["non_fn76_sends"] == 1 and stats["junk_lines"] == 1, \
        "selftest 5: junk (1 junk + 1 blanche ignorée)"
    ok.append("5 junk comptée, hex collé ET espacé OK, RPCDUMP fn= compté")

    # 6. seq hostile géant : pas de préallocation (dict-indexé)
    caps, _ = parse_lines(_wrap_recv(4294967295, b"\x00" * 8,
                                     {"cmd": 0, "status": 0, "psz": 0,
                                      "rres": 0, "rpriv": 0}))
    assert ("recv", 4294967295) in caps, "selftest 6: seq géant"
    ok.append("6 seq hostile 2^32-1 sans allocation géante")

    # 7. paire SYNTHÉTIQUE §7.2 : la carte des deltas nomme la réponse.
    #    TOUT est fabriqué ici (instrument-check) — jamais banké comme capture.
    req = struct.pack("<8I", 0xc1d0004c, 0xa55a0030, CMD_GET_EDPP, 0, 24,
                      0, 0, 0) + struct.pack("<Q", 0) + \
        struct.pack("<6I", 0, 0, 0, 0, 0, 0) + bytes(RESIDUE)
    rsp = struct.pack("<8I", 0xc1d0004c, 0xa55a0030, CMD_GET_EDPP, 0, 24,
                      0, 0, 0) + struct.pack("<Q", 0) + \
        struct.pack("<6I", 100000, 240000, 250000, 245000, 0, 0) + bytes(RESIDUE)
    caps, _ = parse_lines(_wrap_send(5, req) + _wrap_recv(
        5, rsp, {"cmd": CMD_GET_EDPP, "status": 0, "psz": 24,
                 "rres": 0, "rpriv": 0}))
    pairs, os_, or_ = correlate(caps)
    assert len(pairs) == 1 and not os_ and not or_, "selftest 7: paire"
    scap, rcap, mode = pairs[0]
    changed, byte_diffs = delta_map(scap, rcap)
    names = [nm for _o, _va, _vb, nm in changed if nm]
    assert "limitMin" in names and "limitRated" in names and \
        "limitMax" in names and "limitCurr" in names, \
        "selftest 7: champs nommés %s" % names
    assert byte_diffs == 12, "selftest 7: 12 octets (le triplet+Curr)"
    assert "tout-zéro" in residue_verdict(rcap), "selftest 7: résidu"
    ok.append("7 paire synthétique §7.2 : P2 appariée, deltas -> "
              "limitMin/Rated/Max/Curr nommés, 12 octets, résidu vérifié")

    print("SELFTEST OK — le pipeline recv76 tient la robustesse :")
    for s in ok:
        print("  [%s]" % s)
    print("  (les cas 1 = octets RÉELS de la capture 4.23 ; les cas 2-7 = "
          "instrument-checks SYNTHÉTIQUES, aucune valeur bankée)")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        main()
