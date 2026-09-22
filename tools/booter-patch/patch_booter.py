#!/usr/bin/env python3
"""
patch_booter.py — PASS 4.31 TÂCHE 2 : localisation et patch du booter.

Deux artefacts, deux vérités (PROUVÉ par le hunt 4.31, voir
lab/jalon411/findings-4.31-booter-verify-hunt.md):

  A. nvidia.ko (nv-kernel.o_binary localement) — embarque le BooterLoad
     ucode CHIFFRÉ (GA102: IMAGE_PROD 0x87D7 o) + NUM_SIGS=2 + SIG_PROD
     0x1A4 + SIG_DBG 0x300 + PATCH_LOC/META/SIG. Le BROM le vérifie
     (RSA-3K, clé fuse) — PATCHER L'IMAGE = RE-SIGNER = HORS DE PORTÉE.
     Le mode locate-ko fait l'ANATOMIE seule (offsets fichier), sans patch.

  B. gsp_ga10x.bin — le booter libos PLAINTEXT (bootloader.bin, 0x6D000 o,
     sha256 ab90560b…) OCCUPE LES OFFSETS [0x0, 0x6D000) DU CONTENEUR
     (prouvé 4.30 + re-vérifié ici). C'est le SEUL booter patchable en
     clair. Mode patch-gsp: application de sites {offset, old, new}
     avec vérification des octets attendus + diff exact.

Sous-commandes:
  locate-ko  <nvidia.ko>            anatomie BINDATA BooterLoad (offsets fichier .ko)
  locate-gsp <gsp_ga10x.bin>        vérifie le boot area vs la référence + sha256
  patch-gsp  <gsp.bin> --sites S.json --out O.bin
                                    applique les sites (old-bytes check), refuse
                                    tout site dont les octets ne matchent pas
  selftest                          battery sur les fichiers locaux du repo

Règles campagne: PROUVÉ vs HYPOTHÈSE; aucun octet patché sans old-bytes
match; aucun re-signing fabriqué; gros binaires hors repo.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
REF_BOOTER = REPO / "tools/analysis/gsp-extract/binaries/bootloader.bin"
REF_KO = REPO / "tools/analysis/x86-rm/binaries/nv-kernel.o_binary"
REF_GSP = Path("/home/z/my-project/work/downloads/extracted/firmware/gsp_ga10x.bin")

BOOT_AREA = 0x6D000
# PROUVE 4.31 (selftest ST2 run 1): gsp_ga10x.bin = un ELF64 RISC-V
# (e_machine=0xf3, e_type=1, phnum=0, 19 shdrs @0x50673d8) et le booter
# libos = la PREMIERE section: contenu bootloader.bin a l'offset conteneur
# 0x40 (= juste apres le header ELF 64 o; b[:64] @0x40, b[0x21014] @0x21054).
BOOT_OFF = 0x40


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- ELF symtab
def elf64_symbols(k):
    e_shoff = struct.unpack("<Q", k[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", k[0x3A:0x40])
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack(
            "<IIQQQQIIQQ", k[o : o + 64]
        )
        secs.append(dict(name=name, typ=typ, off=off, size=size, link=link, entsize=entsize))
    shstr = secs[e_shstrndx]

    def sname(n):
        e = k.index(b"\0", shstr["off"] + n)
        return k[shstr["off"] + n : e].decode(errors="replace")

    for s in secs:
        s["nm"] = sname(s["name"])
    out = []
    for st in [s for s in secs if s["nm"] == ".symtab"]:
        strtab = secs[st["link"]]
        n = st["size"] // 24
        for i in range(n):
            o = st["off"] + i * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(
                "<IBBHQQ", k[o : o + 24]
            )
            e = k.index(b"\0", strtab["off"] + st_name)
            nm = k[strtab["off"] + st_name : e].decode(errors="replace")
            if 0 < st_shndx < len(secs):
                sec = secs[st_shndx]
                file_off = sec["off"] + st_value
                out.append((nm, sec["nm"], file_off, st_size))
    return out


def cmd_locate_ko(path):
    k = Path(path).read_bytes()
    print(f"== {path} ({len(k)} o, sha256 {sha(k)[:16]}...) ==")
    rows = []
    for nm, sec, off, size in elf64_symbols(k):
        if "_BINDATA_LABEL_" in nm or nm.startswith("__kgspGetBinArchiveBooterLoadUcode"):
            rows.append((nm, sec, off, size))
    ga102 = [r for r in rows if "GA102" in r[0]]
    print("\n-- BooterLoad BINDATA GA102 (utilisé par GA104/RTX 3070) --")
    for nm, sec, off, size in sorted(ga102, key=lambda r: r[2]):
        data = k[off : off + size]
        print(f"{off:#010x} size={size:#7x} sha={sha(data)[:16]}  {nm}")
    print("\n-- autres chips (même structure, IMAGE+NUM_SIGS seulement) --")
    for nm, sec, off, size in sorted(rows, key=lambda r: r[2]):
        if "GA102" in nm or "_BINDATA_LABEL_" not in nm:
            continue
        if "IMAGE_PROD" in nm or "NUM_SIGS" in nm:
            print(f"{off:#010x} size={size:#7x}  {nm}")
    img = [r for r in ga102 if "IMAGE_PROD" in r[0]]
    ns = [r for r in ga102 if "NUM_SIGS" in r[0]]
    if img and ns:
        nsval = struct.unpack("<I", k[ns[0][2] : ns[0][2] + 4])[0]
        print(
            f"\nVERDICT: IMAGE chiffree ({img[0][3]} o) + NUM_SIGS={nsval} + blobs SIG "
            f"-> tout patch de l'IMAGE exige un re-signing par la cle BROM (fuse). "
            f"REFUS de patch ici par construction."
        )
    return 0


def cmd_locate_gsp(path):
    g = Path(path).read_bytes()
    ref = REF_BOOTER.read_bytes()
    ok = g[BOOT_OFF : BOOT_OFF + BOOT_AREA] == ref
    print(f"== {path} ({len(g)} o) ==")
    print(f"conteneur = ELF64 RISC-V: e_machine={g[0x12]:#04x} e_type={g[0x10]:#04x} "
          f"phnum={g[0x38]:#04x} (bytes bruts), shoff+shnum a parser si requis")
    print(f"boot area [0x{BOOT_OFF:x},0x{BOOT_OFF+BOOT_AREA:x}) == bootloader.bin reference: {ok}")
    print(f"  conteneur boot area sha256 = {sha(g[BOOT_OFF:BOOT_OFF+BOOT_AREA])[:32]}...")
    print(f"  reference  bootloader.bin sha256 = {sha(ref)[:32]}...")
    print(f"  repertoire GFW juste apres (magic head @0x{BOOT_OFF+BOOT_AREA:x}: "
          f"{g[BOOT_OFF+BOOT_AREA:BOOT_OFF+BOOT_AREA+8].hex()})")
    return 0 if ok else 1


def cmd_patch_gsp(path, sites_path, out_path):
    src = Path(path).read_bytes()
    g = bytearray(src)
    sites = json.loads(Path(sites_path).read_text())
    ref = REF_BOOTER.read_bytes()
    if bytes(g[BOOT_OFF : BOOT_OFF + BOOT_AREA]) != ref:
        print("REFUS: le boot area du conteneur != bootloader.bin reference (loi 1: rien a l'aveugle)")
        return 1
    applied = []
    for s in sites["sites"]:
        off = int(s["offset"], 16)  # coordonnées fichier booter (VMA-0x100000)
        coff = off + BOOT_OFF       # offset conteneur réel
        old = bytes.fromhex(s["old"])
        new = bytes.fromhex(s["new"])
        cur = bytes(g[coff : coff + len(old)])
        if cur != old:
            print(f"REFUS site @0x{off:x} (conteneur 0x{coff:x}): octets courants {cur.hex()} != attendus {old.hex()} ({s.get('why','')})")
            return 1
        applied.append((off, coff, old, new, s.get("why", "")))
    for off, coff, old, new, why in applied:
        g[coff : coff + len(old)] = new
        print(f"PATCH booter@0x{off:x} (conteneur 0x{coff:x}): {old.hex()} -> {new.hex()}  ({why})")
    diff = sum(1 for a, b in zip(bytes(g), src) if a != b)
    Path(out_path).write_bytes(bytes(g))
    print(f"ecrit {out_path}: {diff} octets differents; boot area sha256 {sha(bytes(g[BOOT_OFF:BOOT_OFF+BOOT_AREA]))[:16]}...")
    return 0


def cmd_selftest():
    fails = []
    ref = REF_BOOTER.read_bytes()
    # ST1: reference stable
    if len(ref) != BOOT_AREA or sha(ref)[:16] != "ab90560bad520e65":
        fails.append("ST1 reference booter changed")
    # ST2: locate-gsp sur le conteneur local (booter = section @0x40)
    if REF_GSP.exists():
        g = REF_GSP.read_bytes()
        if g[BOOT_OFF : BOOT_OFF + BOOT_AREA] != ref:
            fails.append("ST2 gsp boot area mismatch")
        if g[:4] != b"\x7fELF" or g[0x12] != 0xF3:
            fails.append("ST2 gsp container not RISC-V ELF")
    else:
        print("ST2 skip (gsp_ga10x.bin local absent)")
    # ST3: locate-ko trouve la structure GA102 attendue (valeurs PROUVEES au hunt)
    if REF_KO.exists():
        k = REF_KO.read_bytes()
        syms = dict((nm, (off, size)) for nm, sec, off, size in elf64_symbols(k))
        key = "kgspBinArchiveBooterLoadUcode_GA102_BINDATA_LABEL_IMAGE_PROD_data"
        if key not in syms:
            fails.append("ST3 IMAGE_PROD symbol missing")
        else:
            off, size = syms[key]
            if size != 0x87D7:
                fails.append(f"ST3 IMAGE_PROD size {size:#x} != 0x87d7")
            data = k[off : off + size]
            if sha(data)[:16] != "609a7b3f09675384":
                fails.append("ST3 IMAGE_PROD sha mismatch")
        ns = syms.get("kgspBinArchiveBooterLoadUcode_GA102_BINDATA_LABEL_NUM_SIGS_data")
        if not ns or struct.unpack("<I", k[ns[0] : ns[0] + 4])[0] != 2:
            fails.append("ST3 NUM_SIGS != 2")
    else:
        print("ST3 skip (nv-kernel.o_binary absent)")
    # ST4: refus de patch site errone
    if REF_GSP.exists():
        bad = {"sites": [{"offset": "0x14f4", "old": "00" * 4, "new": "11" * 4, "why": "negative test"}]}
        p = Path(tempfile.mkstemp(suffix=".json")[1])
        p.write_text(json.dumps(bad))
        r = subprocess.run(
            [sys.executable, __file__, "patch-gsp", str(REF_GSP), "--sites", str(p), "--out", "/tmp/_v431_out.bin"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            fails.append("ST4 bad-site patch NOT refused")
        p.unlink(missing_ok=True)
    # ST5: patch nominal sur copie (no-op @0x14f4, coordonnée booter)
    if REF_GSP.exists():
        site = {"sites": [{"offset": "0x14f4", "old": ref[0x14F4:0x14F8].hex(),
                           "new": ref[0x14F4:0x14F8].hex(), "why": "selftest no-op"}]}
        p2 = Path(tempfile.mkstemp(suffix=".json")[1])
        p2.write_text(json.dumps(site))
        o2 = Path(tempfile.mkstemp(suffix=".bin")[1])
        r = subprocess.run(
            [sys.executable, __file__, "patch-gsp", str(REF_GSP), "--sites", str(p2), "--out", str(o2)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            fails.append("ST5 nominal patch failed: " + r.stdout[-200:])
        elif o2.stat().st_size != REF_GSP.stat().st_size:
            fails.append("ST5 size mismatch")
        o2.unlink(missing_ok=True)
        p2.unlink(missing_ok=True)
    print(f"selftest: {5 - len(fails)}/5 PASS")
    for f in fails:
        print("  FAIL:", f)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("locate-ko"); s.add_argument("ko")
    s = sub.add_parser("locate-gsp"); s.add_argument("gsp")
    s = sub.add_parser("patch-gsp"); s.add_argument("gsp"); s.add_argument("--sites", required=True); s.add_argument("--out", required=True)
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "locate-ko":
        return cmd_locate_ko(a.ko)
    if a.cmd == "locate-gsp":
        return cmd_locate_gsp(a.gsp)
    if a.cmd == "patch-gsp":
        return cmd_patch_gsp(a.gsp, a.sites, a.out)
    if a.cmd == "selftest":
        return cmd_selftest()
    return 2


if __name__ == "__main__":
    sys.exit(main())
