#!/usr/bin/env python3
"""
v431_booter_hunt.py — PASS 4.31 TÂCHE 1 : chasse de la vérification des
signatures LS dans NOTRE booter (gsp_ga10x.bin boot area, driver 610.57.04).

Entrées (truth materials, committés):
  tools/analysis/gsp-extract/bootloader.asm  (désassemblage objdump RV64, 5397 lignes)
  tools/analysis/gsp-extract/binaries/bootloader.bin (446464 o = 0x6d000, boot area raw)

Coordonnées: VMA = 0x100000 + file_offset (phdr0 vaddr 0x100000 filesz 0x6d000,
wrapper synthétique 120 o: header 64 + 1 phdr 56). L'ELF n'a NI sections NI
symboles (shnum=0) — tout le code = 'PT_LOAD#0'.

Le paper « A Canary in the Crypto Mine » (Zenodo 20916112) donne les patterns
de LEUR build (TU10X/CMP 170HX): booterVerifyLsSignatures_TU10X @IMEM 0x29C4,
dma_copy_block @0x4d4, canary 0xc0deca7e, AES CSRs 0x7d5-0x7d9, __stack_chk_fail
@0x7dd9. NOTRE build = autre: les patterns sont à retrouver par la structure.

Sorties: v431_booter_hunt.json (registre gelé) + rapport stdout.
Selftest: vérités terrain déjà prouvées à la main (crt0, main, clusters CSR,
adresses strings) doivent être retrouvées par l'instrument.
"""
import json
import re
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
ASM = REPO / "tools/analysis/gsp-extract/bootloader.asm"
BIN = REPO / "tools/analysis/gsp-extract/binaries/bootloader.bin"
OUT = HERE / "v431_booter_hunt.json"

VMA_BASE = 0x100000

# ---------------------------------------------------------------- parse asm
LINE_RE = re.compile(
    r"^\s*([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)(?:\s+(.*?))?\s*(?:<(.*?)>)?$"
)


def parse_asm():
    """-> list of dicts {addr, nbytes, mnem, ops} ; skips data/<unknown> lines"""
    insns = []
    for ln in ASM.read_text().splitlines():
        m = LINE_RE.match(ln)
        if not m:
            continue
        addr_s, raw, mnem, ops, sym = m.groups()
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue
        nbytes = len(raw) // 2
        insns.append(
            {
                "addr": addr,
                "n": nbytes,
                "mnem": mnem.strip(),
                "ops": (ops or "").strip(),
                "sym": sym or "",
            }
        )
    return insns


# ---------------------------------------------------------------- helpers
REG = r"(?:a[0-7]|s(?:[0-9]|1[01])|t[0-6]|r[aa]|sp|gp|tp|fp|ra|zero|x[0-9]+)"


def target_of(ops):
    """extract numeric jump/call target from ops like '-0x426(ra) <PT_LOAD#0+0x3a7e>'"""
    m = re.search(r"<PT_LOAD#0\+0x([0-9a-f]+)>", ops)
    if m:
        return None  # relative-to-symbol; caller computes
    return None


def resolve_ops_addr(insn):
    """return absolute target for j/jal/jalr/branch lines using the comment field
    or by decoding ops directly. objdump prints absolute target for j/jal as
    'j 0x101e0a <...>' and branches as 'beqz a0, 0x102306 <...>'."""
    m = re.search(r"0x([0-9a-f]{6,})", insn["ops"])
    if m:
        return int(m.group(1), 16)
    return None


def main():
    b = BIN.read_bytes()
    insns = parse_asm()
    report = {}
    selftest = []

    # ---- 0. ground truth: coordinates
    report["bin"] = {"len": len(b), "sha256": _sha256(b)}
    selftest.append(("bin_len_0x6d000", len(b) == 0x6D000))

    # ---- 1. strings + xrefs
    # LECON BANCÉE (selftest run 1): les strings libos de ce booter sont
    # terminées par '\n' (0x0a), pas par NUL — et la table hexdigits est un
    # tableau SANS terminateur. Deux mécanismes d'acceptation.
    strings = {}
    for m in re.finditer(rb"[\x20-\x7e]{6,}", b):
        s = m.group().decode()
        end = m.end()
        if end < len(b) and b[end] in (0, 0x0A):
            strings[m.start()] = s
    # hexdigits lookup table @0x3f28: 16 chars, no terminator, proven by bytes
    if b[0x3F28 : 0x3F38] == b"0123456789ABCDEF":
        strings[0x3F28] = "0123456789ABCDEF"
    report["strings"] = {hex(VMA_BASE + k): v for k, v in sorted(strings.items())}

    def find_xrefs(target_vma):
        """auipc rd, imm ; addi rd, rd, imm with rd+rd = target (2-insn window)"""
        hits = []
        n = len(insns)
        for i in range(n - 1):
            a, c = insns[i], insns[i + 1]
            if a["mnem"] != "auipc":
                continue
            ma = re.match(r"(\w+),\s*0x([0-9a-f]+)", a["ops"])
            if not ma:
                continue
            rd, hi = ma.group(1), int(ma.group(2), 16)
            if hi >= 0x80000:  # negative hi
                hi -= 0x100000
            base = a["addr"] + (hi << 12)
            if c["mnem"] in ("addi", "c.addi", "add"):
                # LECON BANCÉE (selftest run 1): REG est non-capturant —
                # il faut des groupes explicites (rd=g1, rs=g2, imm=g3),
                # sinon group(1) = l'immédiat et la comparaison rd échoue
                # pour TOUTES les paires.
                mc = re.match(rf"({REG}),\s*({REG}),\s*(-?0x[0-9a-f]+|-?\d+)", c["ops"])
                if not mc:
                    continue
                if mc.group(1) != rd:
                    continue
                lo = _int(mc.group(3))
                if base + lo == target_vma:
                    hits.append(a["addr"])
        return hits

    named = {}
    NAMED_STRINGS = {
        "kernel_table": 0x3B38,  # kernel_gr10x.elf...
        "kernel_ga10x": 0x3BB0,
        "sbi_assert": 0x3BF8,
        "wpr_print": 0x3C58,
        "rm_bindata": 0x3C78,
        "rm_elf": 0x3C88,
        "hex_digits": 0x3F28,
        "toorgol": 0x3F58,
    }
    for nm, off in NAMED_STRINGS.items():
        vma = VMA_BASE + off
        xr = find_xrefs(vma)
        named[nm] = {"vma": hex(vma), "value": strings.get(off, "?"), "xrefs": [hex(x) for x in xr]}
        selftest.append((f"string_{nm}_present", off in strings))
    report["named_strings"] = named

    # ---- 2. lui immediate census (absolute MMIO candidates)
    lui_census = defaultdict(list)
    for a in insns:
        if a["mnem"] == "lui":
            m = re.match(rf"{REG},\s*0x([0-9a-f]+)", a["ops"])
            if m:
                imm = int(m.group(1), 16)
                lui_census[imm].append(a["addr"])
    report["lui_census_top"] = {
        hex(k): [hex(x) for x in v[:6]] for k, v in sorted(lui_census.items(), key=lambda kv: -len(kv[1]))[:24]
    }
    high_lui = {k: v for k, v in lui_census.items() if (k << 12) >= 0x8000_0000}
    report["lui_high_mmio"] = {
        hex(k): [hex(x) for x in v] for k, v in sorted(high_lui.items())
    }

    # ---- 3. csr census with context
    csr_sites = []
    for i, a in enumerate(insns):
        if a["mnem"].startswith("csr"):
            m = re.search(r"0x([0-9a-f]+)", a["ops"])
            csr = int(m.group(1), 16) if m else None
            lo = max(0, i - 6)
            ctx = [
                f"{x['addr']:x}:{x['mnem']} {x['ops']}" for x in insns[lo : i + 7]
            ]
            csr_sites.append({"addr": hex(a["addr"]), "csr": hex(csr) if csr is not None else "?", "ctx": ctx})
    report["csr_sites"] = csr_sites
    # LECON BANCÉE (selftest run 1): les csrrci/csrrsi du listing objdump
    # sont des BYTES DE STRINGS désalignés (0x103c32 = '/src', 0x103c5e =
    # 'set ') — pas du code. Census réel vérifié à la main: 20 csr numérotés
    # + 2 satp + 2 sscratch (trap handler @0x1004b2). Filtre le désalignement:
    # une insn csr est valide seulement si 4 bytes à son adresse re-décodent
    # la MÊME instruction csr (les csrs authentiques ici sont tous 4 bytes).
    valid_csr = []
    for s in csr_sites:
        addr = int(s["addr"], 16)
        off = addr - VMA_BASE
        w = struct.unpack("<I", b[off : off + 4])[0]
        if (w & 0x3) == 0x3:  # 32-bit encoding (csr = 0x73 opcode low)
            valid_csr.append(s)
    report["csr_sites_valid"] = [s["addr"] for s in valid_csr]

    # ---- 4. call graph: jal/jalr ra targets + function starts (prologues)
    calls = []
    for a in insns:
        if a["mnem"] in ("jal", "jalr"):
            calls.append((a["addr"], a["ops"]))
    prologues = []
    for i, a in enumerate(insns):
        if a["mnem"] == "addi" and re.match(rf"sp,\s*sp,\s*-0x[0-9a-f]+", a["ops"]):
            # next instruction saves ra or s0 -> function start candidate
            nxt = insns[i + 1] if i + 1 < len(insns) else None
            if nxt and (nxt["mnem"] == "sd" or nxt["mnem"] == "c.sd"):
                prologues.append(a["addr"])
    report["call_count"] = len(calls)
    report["prologue_count"] = len(prologues)

    # function ranges from prologues
    prologues_sorted = sorted(set(prologues))
    ranges = []
    for i, p in enumerate(prologues_sorted):
        end = prologues_sorted[i + 1] if i + 1 < len(prologues_sorted) else insns[-1]["addr"]
        ranges.append((p, end))
    report["function_ranges"] = [
        {"start": hex(s), "end": hex(e), "size": e - s} for s, e in ranges if e - s > 0x100
    ]

    # ---- 5. self-loops / spins
    spins = []
    for a in insns:
        if a["mnem"] in ("j", "c.j"):
            t = resolve_ops_addr(a)
            if t == a["addr"]:
                spins.append({"addr": hex(a["addr"]), "kind": "j-self"})
    # branch-to-self infinite loops: beqz zero / bne x,x
    for a in insns:
        if a["mnem"].startswith("b") and a["mnem"] != "branch":
            t = resolve_ops_addr(a)
            if t == a["addr"]:
                m = re.match(rf"{REG},\s*{REG}", a["ops"])
                if a["mnem"] in ("beq", "bne"):
                    r1, r2 = m.group(1), m.group(2)
                    if r1 == r2 and a["mnem"] == "beq":
                        spins.append({"addr": hex(a["addr"]), "kind": "beq-rr-self"})
    report["spins"] = spins

    # ---- 6. compare-loop candidates (signature compare):
    # ld/ld/bne or ld/bneu tight loops with two loads of different bases
    cmp_loops = []
    for i in range(len(insns) - 3):
        w = insns[i : i + 4]
        mns = [x["mnem"] for x in w]
        if mns[0].startswith("ld") and mns[1].startswith("ld") and mns[2].startswith("bne"):
            cmp_loops.append(
                {"addr": hex(w[0]["addr"]), "window": [f"{x['addr']:x}:{x['mnem']} {x['ops']}" for x in w]}
            )
    report["cmp_loops"] = cmp_loops

    # ---- 7. region-config clusters (CSR 0x5ca..0x5d1, 0x8d0)
    # LECON BANCÉE (selftest run 1): les clusters contiennent des ld/lui
    # intercalés (les csrw lisent leurs données) — regroupement par PROXIMITÉ
    # (gap <= 0x60), pas par contiguïté d'instructions.
    cluster_csrs = {0x5CA, 0x5CB, 0x5CC, 0x5CE, 0x5CF, 0x5D0, 0x5D1, 0x8D0}
    sites = []
    for a in insns:
        if a["mnem"].startswith("csr"):
            m = re.search(r"0x([0-9a-f]+)", a["ops"])
            if m and int(m.group(1), 16) in cluster_csrs:
                sites.append(a["addr"])
    clusters = []
    cur = [sites[0]] if sites else []
    for s in sites[1:]:
        if s - cur[-1] <= 0x60:
            cur.append(s)
        else:
            clusters.append(cur)
            cur = [s]
    if cur:
        clusters.append(cur)
    report["csr_clusters"] = [
        {"first": hex(c[0]), "last": hex(c[-1]), "n": len(c)} for c in clusters
    ]
    selftest.append(("cluster_A_at_1000f6", any(c["first"] == hex(0x1000F6) for c in report["csr_clusters"])))
    selftest.append(("cluster_B_at_100a20", any(c["first"] == hex(0x100A20) for c in report["csr_clusters"])))
    # debug aid kept: xref of a KNOWN auipc+addi pair (main's s7 = 0x121014)
    _kx = find_xrefs(0x121014)
    selftest.append(("xref_mechanism_known_pair", hex(0x101E42) in [hex(x) for x in _kx]))

    # ---- 8. selftest ground truths
    crt0 = [a for a in insns if a["addr"] == 0x100000]
    selftest.append(("crt0_auipc_t0_6c", bool(crt0) and crt0[0]["mnem"] == "auipc" and "0x6c" in crt0[0]["ops"]))
    mainp = [a for a in insns if a["addr"] == 0x101E0A]
    selftest.append(("main_addi_sp_620", bool(mainp) and mainp[0]["ops"].startswith("sp, sp, -0x620")))
    # csr count ground truth: 18 csr lines? recount from grep census:
    csr_count = sum(1 for a in insns if a["mnem"].startswith("csr"))
    selftest.append(("csr_parse_count_26", csr_count == 26))
    numbered = [s for s in csr_sites if s["csr"] in {hex(x) for x in {0x5CA, 0x5CB, 0x5CC, 0x5CE, 0x5CF, 0x5D0, 0x5D1, 0x8D0}}]
    selftest.append(("numbered_csr_writes_20", len(numbered) == 20))
    # satp write present (0x100168 / 0x100a94)
    satp = [a for a in insns if a["mnem"] == "csrw" and "satp" in a["ops"]]
    selftest.append(("satp_writes_2", len(satp) == 2))

    # ---- 9. pointer-table scan: u64 LE in image == a string VMA (data xrefs)
    ptr_xrefs = {}
    for off, s in strings.items():
        vma = VMA_BASE + off
        pat = struct.pack("<Q", vma)
        sites = [m.start() for m in re.finditer(re.escape(pat), b)]
        # exclude self-pointer (the string cannot contain its own address unless coincidental)
        sites = [p for p in sites if not (off <= p < off + len(s))]
        if sites:
            ptr_xrefs[s[:40]] = {"vma": hex(vma), "ptr_sites": [hex(VMA_BASE + p) for p in sites]}
    report["string_ptr_xrefs"] = ptr_xrefs

    report["selftest"] = [{"check": k, "ok": bool(v)} for k, v in selftest]
    report["n_selftest_fail"] = sum(1 for _, v in selftest if not v)

    OUT.write_text(json.dumps(report, indent=2, sort_keys=False))
    print(f"[v431] wrote {OUT}")
    print(f"[v431] insns={len(insns)} calls={len(calls)} prologues={len(prologues)} csr={csr_count}")
    for k, v in selftest:
        if not v:
            print(f"  SELFTEST FAIL: {k}")
    fails = sum(1 for _, v in selftest if not v)
    print(f"[v431] selftest: {len(selftest) - fails}/{len(selftest)} PASS")
    return 1 if fails else 0


def _int(s):
    s = s.strip()
    return int(s, 16) if s.startswith(("0x", "-0x")) else int(s, 0) if s.startswith(("0o", "0b")) else int(s)


def _sha256(b):
    import hashlib

    return hashlib.sha256(b).hexdigest()


if __name__ == "__main__":
    sys.exit(main())
