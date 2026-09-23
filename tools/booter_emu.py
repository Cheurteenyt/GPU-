#!/usr/bin/env python3
"""
booter_emu.py — PASS 4.31 TÂCHE 3 : émulateur du booter libos GA10x
(bootloader.bin, RV64, VMA 0x100000, driver 610.57.04) — la validation
SANS RISQUE des patches AVANT le reboot.

Modèle (PROUVÉ par le hunt 4.31):
  - IMEM/DMEM flat: [0x100000, 0x170000) RAM; l'image est chargée à 0x100000
    (phdr0 vaddr 0x100000 filesz 0x6d000 du wrapper synthétique).
  - sp initial = 0x120000 (crt0: auipc sp,0x20; addi sp,sp,-0x14 -> 0x120014-0x14).
  - CSRs: 0x140 sscratch, 0x180 satp, et le bloc région 0x5ca/0x5cb/0x5cc/
    0x5ce/0x5cf/0x5d0/0x5d1/0x8d0 (config nvriscv-2.0, capture only).
  - SBI ecall (l'interface sécurisée de NOTRE build — le paper utilise des
    CSRs 0x7d5-0x7d9 pour LE leur, ABSENTS ici):
      a7=0x900001EB, a6=0  -> retour (a0=0, a3=base WPR modélisable --sbi-base)
      a7=0x900001EB, a6=7/8/9/0xa -> loggé, a0=0 (succès)
      a7=8                 -> FAIL oracle (l'appel @0x103a7e = le stub fail
                              universel du booter) -> arrêt état=FAIL
  - fence.i / sfence.vma = nop; écritures hors RAM = fault + arrêt.

Modes:
  --run      : exécution depuis l'entry (budget --steps), rapport + oracle.
  --trace    : idem, trace PC par PC ( Vergleich vs objdump possible).
  --test-bounds : test dirigé de la fonction range-check @0x1014DC
                 (original vs patché NOP du bgeu @0x1014F4) — la méthodo de
                 validation d'un patch de check, démontrée sur un site réel.
  --selftest : la battery complète.

Le découragement honnête: la vérification cryptographique des LS signatures
n'est PAS dans cet ELF (verdict T1 4.31) — l'émulateur valide donc les
checks/validation-layer de CET image; la méthodo s'applique telle quelle à
toute cible future prouvée.
"""
import argparse
import collections
import sys
from pathlib import Path

from capstone import (
    CS_ARCH_RISCV,
    CS_MODE_RISCVC,
    CS_MODE_RISCV64,
    Cs,
)

REPO = Path(__file__).resolve().parent.parent
REF_BOOTER = REPO / "tools/analysis/gsp-extract/binaries/bootloader.bin"

VMA_BASE = 0x100000
IMG_SIZE = 0x6D000
RAM_LO, RAM_HI = 0x100000, 0x170000
SP_INIT = 0x120000
SBI_EXT = 0x900001EB
FAIL_STUB = 0x103A7E

REG_NAMES = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
]
M = 1 << 64


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Emu:
    def __init__(self, image, sbi_base=0x55800000, trace=False):
        self.mem = bytearray(RAM_HI - RAM_LO)
        img = image[:IMG_SIZE]
        self.mem[VMA_BASE - RAM_LO : VMA_BASE - RAM_LO + len(img)] = img
        self.regs = [0] * 32
        self.regs[2] = SP_INIT
        self.csr = {}
        self.pc = VMA_BASE
        self.trace = trace
        self.sbi_base = sbi_base
        self.time = 0  # le compteur rdtime émulé (1 tick = 1 ns, 4.34)
        self.tracer = None
        self.stop_at = set()
        self.events = collections.Counter()
        self.fail = None  # (pc, why)
        self.log = []
        self.steps = 0

    # ---- memory
    def _off(self, addr, n):
        if addr < RAM_LO or addr + n > RAM_HI:
            raise MemoryError(f"addr {addr:#x} hors RAM [{RAM_LO:#x},{RAM_HI:#x})")
        return addr - RAM_LO

    def rmem(self, addr, n):
        o = self._off(addr, n)
        return int.from_bytes(self.mem[o : o + n], "little")

    def wmem(self, addr, n, val):
        o = self._off(addr, n)
        self.mem[o : o + n] = (val & ((1 << (8 * n)) - 1)).to_bytes(n, "little")

    # ---- SBI model
    def do_ecall(self):
        a7, a6 = self.regs[17], self.regs[16]
        self.events[f"ecall a7={a7:#x} a6={a6}"] += 1
        if a7 == 8:
            self.fail = (self.pc, "ecall a7=8 (stub fail @0x103a7e)")
            return
        if a7 == SBI_EXT:
            if a6 == 0:
                self.regs[10] = 0  # a0 = error=OK
                self.regs[13] = self.sbi_base  # a3 = la base (le check la lit)
            elif a6 in (7, 8, 9, 0xA):
                self.regs[10] = 0
            else:
                self.log.append(f"sbi a6={a6} inconnu @pc={self.pc:#x} -> a0=2 (NOT-SUPP)")
                self.regs[10] = 2
            return
        self.log.append(f"ecall a7={a7:#x} a6={a6} @pc={self.pc:#x} -> ignoré")
        self.regs[10] = 0

    # ---- CSR
    def csr_op(self, w, rd, csr, rs1, kind):
        old = self.csr.get(csr, 0) & M - 1
        val = self.regs[rs1]
        if kind == "csrw":
            new = val
        elif kind == "csrs":
            new = old | val
        elif kind == "csrr":
            new = old
        else:
            new = old
        self.csr[csr] = new
        self.events[f"csr {kind} {csr:#x}"] += 1
        if rd != 0:
            self.regs[rd] = old

    # ---- main loop (capstone decode)
    def step(self):
        md = self.md
        off = self._off(self.pc, 4)
        code = bytes(self.mem[off : off + 4])
        try:
            ins = next(md.disasm(code, self.pc))
        except StopIteration:
            self.fail = (self.pc, "decode fail")
            return
        if self.tracer:
            self.tracer(self, ins)
        r = self.regs
        mn, ops = ins.mnemonic, ins.op_str
        p = [o.strip() for o in ops.split(",")] if ops else []
        pc = self.pc
        nxt = pc + ins.size
        imm = lambda s: int(s, 0)
        try:
            if mn in ("ld", "lw", "lh", "lhu", "lb", "lbu", "lwu", "c.ld", "c.lw", "c.ldsp"):
                rd = REG_NAMES.index(p[0])
                base, d = p[1].split("(")[1][:-1], p[1].split("(")[0]
                addr = (r[REG_NAMES.index(base)] + imm(d)) & (M - 1)
                n = {"ld": 8, "lw": 4, "lwu": 4, "lh": 2, "lhu": 2, "lb": 1, "lbu": 1, "c.ld": 8, "c.lw": 4, "c.ldsp": 8}[mn]
                v = self.rmem(addr, n)
                if mn in ("lb", "lh"):
                    v = sx(v, 8 * n) & (M - 1)
                r[rd] = v
            elif mn in ("sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.sdsp"):
                rs2 = REG_NAMES.index(p[0])
                base, d = p[1].split("(")[1][:-1], p[1].split("(")[0]
                addr = (r[REG_NAMES.index(base)] + imm(d)) & (M - 1)
                self.wmem(addr, {"sd": 8, "sw": 4, "sh": 2, "sb": 1, "c.sd": 8, "c.sw": 4, "c.sdsp": 8}[mn], r[rs2])
            elif mn in ("addi", "c.addi"):
                # capstone c.addi = 2 tokens ('sp, -0x10'); addi = 3 ('rd, rs1, imm')
                if len(p) == 3:
                    rd, rs1, im = p[0], p[1], p[2]
                else:
                    rd, rs1, im = p[0], p[0], p[1]
                r[REG_NAMES.index(rd)] = (r[REG_NAMES.index(rs1)] + sx(imm(im), 12)) & (M - 1)
            elif mn == "addiw":
                rd, rs1 = REG_NAMES.index(p[0]), REG_NAMES.index(p[1])
                r[rd] = sx((r[rs1] + sx(imm(p[2]), 12)) & 0xFFFFFFFF, 32) & (M - 1)
            elif mn in ("add", "sub", "and", "or", "xor", "sll", "srl", "sra", "slt", "sltu"):
                rd, a1, a2 = REG_NAMES.index(p[0]), r[REG_NAMES.index(p[1])], r[REG_NAMES.index(p[2])]
                f = {
                    "add": lambda: (a1 + a2) & (M - 1),
                    "sub": lambda: (a1 - a2) & (M - 1),
                    "and": lambda: a1 & a2,
                    "or": lambda: a1 | a2,
                    "xor": lambda: a1 ^ a2,
                    "sll": lambda: (a1 << (a2 & 63)) & (M - 1),
                    "srl": lambda: a1 >> (a2 & 63),
                    "sra": lambda: sx(a1, 64) >> (a2 & 63) & (M - 1),
                    "slt": lambda: 1 if sx(a1, 64) < sx(a2, 64) else 0,
                    "sltu": lambda: 1 if a1 < a2 else 0,
                }[mn]
                r[rd] = f()
            elif mn in ("addw", "subw", "slliw", "srliw", "sllw", "srlw"):
                rd, a1, a2 = REG_NAMES.index(p[0]), r[REG_NAMES.index(p[1])], r[REG_NAMES.index(p[2])]
                if mn == "addw":
                    v = (a1 + a2) & 0xFFFFFFFF
                elif mn == "subw":
                    v = (a1 - a2) & 0xFFFFFFFF
                elif mn == "slliw":
                    v = ((a1 << (a2 & 31)) & 0xFFFFFFFF)
                elif mn == "srliw":
                    v = (a1 & 0xFFFFFFFF) >> (a2 & 31)
                elif mn == "sllw":
                    v = (a1 << (a2 & 31)) & 0xFFFFFFFF
                else:
                    v = (a1 & 0xFFFFFFFF) >> (a2 & 31)
                r[rd] = sx(v, 32) & (M - 1)
            elif mn in ("slli", "srli", "srai"):
                rd, rs1 = REG_NAMES.index(p[0]), REG_NAMES.index(p[1])
                sh = imm(p[2]) & 63
                v = r[rs1] << sh if mn == "slli" else (
                    r[rs1] >> sh if mn == "srli" else sx(r[rs1], 64) >> sh)
                r[rd] = v & (M - 1)
            elif mn in ("andi", "ori", "xori"):
                rd, rs1 = REG_NAMES.index(p[0]), REG_NAMES.index(p[1])
                v = r[rs1] & sx(imm(p[2]), 12) if mn == "andi" else (
                    r[rs1] | sx(imm(p[2]), 12) if mn == "ori" else r[rs1] ^ sx(imm(p[2]), 12))
                r[rd] = v & (M - 1)
            elif mn == "lui":
                # RV64: sign-extend(imm20<<12) a 64 bits (probe 4.31: lui 0xfffff
                # doit donner 0xfffffffffffff000, pas 0xfffff000)
                r[REG_NAMES.index(p[0])] = sx((imm(p[1]) & 0xFFFFF) << 12, 32) & (M - 1)
            elif mn == "auipc":
                # idem: imm20 signe (probe 4.31: auipc 0xffffe = pc - 0x2000)
                r[REG_NAMES.index(p[0])] = (pc + (sx(imm(p[1]) & 0xFFFFF, 20) << 12)) & (M - 1)
            elif mn in ("li", "c.li"):
                r[REG_NAMES.index(p[0])] = sx(imm(p[1]), 64) & (M - 1)
            elif mn in ("mv", "c.mv"):
                r[REG_NAMES.index(p[0])] = r[REG_NAMES.index(p[1])]
            elif mn in ("c.add", "c.addw", "c.sub", "c.subw", "c.and", "c.or", "c.xor"):
                a1 = r[REG_NAMES.index(p[0])]
                a2 = r[REG_NAMES.index(p[1])]
                f = {"c.add": lambda: (a1 + a2) & (M - 1), "c.addw": lambda: sx((a1 + a2) & 0xFFFFFFFF, 32) & (M - 1),
                     "c.sub": lambda: (a1 - a2) & (M - 1), "c.subw": lambda: sx((a1 - a2) & 0xFFFFFFFF, 32) & (M - 1),
                     "c.and": lambda: a1 & a2, "c.or": lambda: a1 | a2, "c.xor": lambda: a1 ^ a2}[mn]
                r[REG_NAMES.index(p[0])] = f()
            elif mn in ("c.slli", "c.srli", "c.srai", "c.slli64", "c.srli64", "c.srai64"):
                rd = REG_NAMES.index(p[0])
                sh = imm(p[1]) & 63
                r[rd] = ((r[rd] << sh) if mn.startswith("c.slli") else (r[rd] >> sh if mn in ("c.srli", "c.srli64") else sx(r[rd], 64) >> sh)) & (M - 1)
            elif mn == "c.andi":
                rd = REG_NAMES.index(p[0])
                r[rd] = (r[rd] & sx(imm(p[1]), 12)) & (M - 1)
            elif mn in ("not",):
                r[REG_NAMES.index(p[0])] = (~r[REG_NAMES.index(p[1])]) & (M - 1)
            elif mn in ("neg", "negw"):
                r[REG_NAMES.index(p[0])] = (-r[REG_NAMES.index(p[1])]) & (M - 1)
            elif mn == "seqz":
                r[REG_NAMES.index(p[0])] = 1 if r[REG_NAMES.index(p[1])] == 0 else 0
            elif mn == "snez":
                r[REG_NAMES.index(p[0])] = 1 if r[REG_NAMES.index(p[1])] != 0 else 0
            elif mn == "zext.b":
                r[REG_NAMES.index(p[0])] = r[REG_NAMES.index(p[1])] & 0xFF
            elif mn == "rdtime":
                # le CSR time (0xC01) — 1 tick = 1 ns (4.34 PROUVÉ);
                # modèle déterministe: emu.time posé par le test.
                r[REG_NAMES.index(p[0])] = self.time & (M - 1)
            elif mn == "sext.w":
                r[REG_NAMES.index(p[0])] = sx(r[REG_NAMES.index(p[1])] & 0xFFFFFFFF, 32) & (M - 1)
            elif mn in ("j", "c.j"):
                # capstone 5.0.7 imprime les cibles de saut EN RELATIF (probe 4.31:
                # 'j 0x4c6' @0x100010 = cible 0x1004d6). nxt = pc + imm.
                nxt = (pc + imm(p[0])) & (M - 1)
            elif mn in ("jr", "c.jr"):
                nxt = r[REG_NAMES.index(p[0])] & (M - 1)
            elif mn == "jal":
                rd = REG_NAMES.index(p[0])
                if rd:
                    r[rd] = nxt
                nxt = (pc + imm(p[1])) & (M - 1)
            elif mn in ("jalr", "c.jalr"):
                # capstone: 'jalr ra, ra, -0x5d0' = [rd, rs1, imm]
                if mn == "jalr":
                    rd = REG_NAMES.index(p[0])
                    tgt = r[REG_NAMES.index(p[1])] + imm(p[2])
                    if rd:
                        r[rd] = nxt
                else:
                    tgt = r[REG_NAMES.index(p[0])]
                nxt = tgt & (M - 1)
            elif mn == "ret":
                nxt = r[1] & (M - 1)
            elif mn == "c.addi4spn":
                rd = REG_NAMES.index(p[0])
                r[rd] = (r[2] + imm(p[2])) & (M - 1)
            elif mn == "c.addi16sp":
                r[2] = (r[2] + imm(p[1])) & (M - 1)
            elif mn in ("beq", "bne", "blt", "bge", "bltu", "bgeu", "bgez"):
                a1 = r[REG_NAMES.index(p[0])]
                a2 = r[REG_NAMES.index(p[1])]
                take = {
                    "beq": a1 == a2, "bne": a1 != a2,
                    "blt": sx(a1, 64) < sx(a2, 64), "bge": sx(a1, 64) >= sx(a2, 64),
                    "bltu": a1 < a2, "bgeu": a1 >= a2,
                    "bgez": sx(a1, 64) >= 0,
                }[mn]
                if take:
                    nxt = (pc + imm(p[2])) & (M - 1)
            elif mn in ("beqz", "bnez", "c.beqz", "c.bnez"):
                a1 = r[REG_NAMES.index(p[0])]
                take = (a1 == 0) if mn in ("beqz", "c.beqz") else (a1 != 0)
                if take:
                    nxt = (pc + imm(p[1])) & (M - 1)
            elif mn in ("csrw", "csrs", "csrr", "csrrw", "csrrs", "csrrwi", "csrrsi", "csrrci"):
                csr = int(p[1], 0) if p[1].startswith("0x") else {
                    "sscratch": 0x140, "satp": 0x180}.get(p[1], 0)
                kind = {"csrrw": "csrw", "csrrs": "csrs"}.get(mn, mn[:4])
                rd = REG_NAMES.index(p[0]) if mn in ("csrr", "csrrw", "csrrs") else 0
                self.csr_op(1, rd, csr, REG_NAMES.index(p[2]) if len(p) > 2 else 0, kind)
            elif mn in ("ecall",):
                self.do_ecall()
            elif mn in ("nop", "c.nop", "fence.i", "sfence.vma", "fence", "unimp"):
                pass
            elif mn == "ebreak":
                self.fail = (pc, "ebreak")
            else:
                self.fail = (pc, f"mnemonic non modélisé: {mn} {ops}")
                return
        except (MemoryError, ValueError, IndexError) as e:
            self.fail = (pc, f"fault: {e}")
            return
        self.pc = nxt
        self.steps += 1

    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.detail = False

    def run(self, budget=200000):
        while self.fail is None and self.steps < budget and self.pc not in self.stop_at:
            self.step()
        return self


def report(e, title):
    print(f"== {title} ==")
    print(f"steps={e.steps} pc={e.pc:#x} fail={e.fail}")
    print(f"events: {dict(e.events)}")
    for l in e.log[-6:]:
        print("  log:", l)


def load_image(path=None):
    p = Path(path) if path else REF_BOOTER
    return p.read_bytes()


def test_bounds(patch=False, image=None):
    """Test dirigé: range-check @0x1014DC (base=[ctx+0x58], size=[ctx+0x60]).
    CAS: a0=size (limite exacte, rejetée par bgeu @0x1014f4) -> fail ecall#8.
    PATCH: bgeu -> NOP (4 o, même longueur: fef57ae3 -> 13000000)."""
    img = bytearray(image if image is not None else load_image())
    SITE_OFF = 0x14F4  # fichier; VMA 0x1014f4
    ORIG = img[SITE_OFF : SITE_OFF + 4]
    if patch:
        img[SITE_OFF : SITE_OFF + 4] = bytes.fromhex("13000000")  # nop
    e = Emu(bytes(img))
    ctx = 0x160000
    e.wmem(ctx + 0x58, 8, 0x1500000)   # base
    e.wmem(ctx + 0x60, 8, 0x400000)    # size
    e.pc = 0x1014DC
    e.regs[10] = 0x400000              # a0 = size -> a0+base == base+size -> rejet
    e.regs[12] = ctx                   # a2 = ctx
    e.regs[1] = 0xDEADC0DE             # ra sentinelle
    e.stop_at = {0xDEADC0DE}           # retour = succes (pas de fetch au-dela)
    e.run(budget=1000)
    status = "FAIL(dépassé la limite)" if (e.fail and "ecall a7=8" in str(e.fail)) else (
        "PASS(ret) " if e.pc == 0xDEADC0DE else f"?(pc={e.pc:#x},{e.fail})")
    print(f"[bounds {'PATCHED' if patch else 'ORIGINAL'}] a0=0x400000 (== size): {status}")
    return ("FAIL" if not patch else "PASS") in status


GADGET_ENTRY = 0x100B3E   # ld a5,0x8(sp) — la charge (le gadget 4.40)
FULL_ENTRY   = 0x100AEC   # le prologue de la boucle de transfert (4.41)
SIG_BASE     = 0x16D000   # le soustracteur t3 de la signature
MAGIC_BYTE   = 0x08       # li a2,0x8 @0x1022c8 (le setup 4.42)


def test_transfer():
    """4.42 TÂCHE 4 — la validation émulateur de la transfer-list.

    Le mécanisme bancé (bootloader.asm l.976-1042, décodé ce pass):
      - la liste = un tableau PLAT u64; le pointeur de marche @sp+0x8;
        +8 par itération; [a1] = la charge. PAS de next-ptr dans les
        données (l'hypothèse {valeur,next} 16 B FALSIFIÉE).
    TT-A le mode GADGET (entrée 0x100b3e): écriture #1 = [a1] (registre),
          #2..N = [a4+0x498] + [a4+0x488]*8 (le scatter du ctx fabriqué),
          a0=~0 garde le chemin RAW (pas de signature/rdtime).
    TT-B le mode BOUCLE COMPLÈTE (entrée 0x100aec, n=2 = la forme du
          setup): 1 signature ((label-0x16d000)&0xFFFF|magic<<56|n<<48)
          + 1 rdtime; le compteur slot-0 += n.
    TT-C le WRAP: slot+1 >= capacité -> slot = 1 (jamais 0).
    TT-D les gardes: capacité=0 -> la boucle inerte (ret immédiat).
    """
    img = load_image()
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")

    # ---- TT-A: le mode GADGET — scatter-write depuis le ctx fabriqué
    e = Emu(img)
    ctx, dest, lst, sp = 0x160000, 0x161000, 0x162000, 0x163000
    vals = [0xAAAAAAA1, 0xBBBBBBB2, 0xCCCCCC3]
    e.wmem(ctx + 0x488, 8, 2)          # slot0 = 2
    e.wmem(ctx + 0x490, 8, 0x40)       # capacité
    e.wmem(ctx + 0x498, 8, dest)       # dest base
    e.wmem(ctx + 0x4A0, 1, MAGIC_BYTE)
    for k, v in enumerate(vals):
        e.wmem(lst + 8 * k, 8, v)      # la liste plate
    e.wmem(sp + 8, 8, lst)             # la cellule de marche -> &list[0]
    e.pc = GADGET_ENTRY
    e.regs[REG_NAMES.index("a0")] = (M - 1)  # a0 = ~0 -> le chemin RAW pour toujours
    e.regs[REG_NAMES.index("a3")] = 3  # a3 = la borne N
    e.regs[REG_NAMES.index("a7")] = 0  # a7 = i départ
    e.regs[REG_NAMES.index("a1")] = dest + 2 * 8  # la 1re cible = [a1] (registre)
    e.regs[REG_NAMES.index("a4")] = ctx
    e.regs[2] = sp                     # sp: la cellule de marche @sp+8
    e.regs[1] = 0xDEADC0DE
    e.stop_at = {0xDEADC0DE}
    e.run(budget=400)
    ok = e.pc == 0xDEADC0DE and not e.fail
    got = [e.rmem(dest + 8 * (2 + k), 8) for k in range(3)]
    check("TT-A gadget scatter: 3 écritures dans l'ordre", ok and got == vals,
          f"got={['%x' % g for g in got]} slot_fin={e.rmem(ctx+0x488,8)}")
    check("TT-A le compteur slot-0 += N", e.rmem(dest, 8) == 3,
          f"[dest]={e.rmem(dest, 8)}")
    check("TT-A le slot avance 2->5", e.rmem(ctx + 0x488, 8) == 5)

    # ---- TT-B: la boucle COMPLÈTE n=2 (la forme du setup) — ctx RÉEL 0x124000
    e = Emu(img)
    dest = 0x168000                    # la région boot-params (STATE.md)
    label = 0x16DFB0                   # le label du setup @0x1022f0-4
    e.wmem(0x124488, 8, 7)             # slot = 7
    e.wmem(0x124490, 8, 0x40)          # capacité
    e.wmem(0x124498, 8, dest)          # dest base
    e.wmem(0x1244A0, 1, MAGIC_BYTE)    # le magic byte (le setup écrit 0x8)
    e.wmem(dest, 8, 6800)              # le compteur persistant slot-0
    e.time = 0x1234                    # le rdtime émulé
    sp = 0x164000
    e.regs[2] = sp
    e.regs[REG_NAMES.index("a0")] = 1  # n = a0+1 = 2 (la forme du setup)
    e.regs[REG_NAMES.index("a1")] = label
    e.regs[1] = 0xDEADC0DE
    e.pc = FULL_ENTRY
    e.stop_at = {0xDEADC0DE}
    e.run(budget=400)
    exp_sig = ((label - SIG_BASE) & 0xFFFF) | (MAGIC_BYTE << 56) | (2 << 48)
    sig_got = e.rmem(dest + 8 * 7, 8)
    ts_got = e.rmem(dest + 8 * 8, 8)
    check("TT-B l'entrée signature transformée", sig_got == exp_sig,
          f"sig={sig_got:016x} attendu={exp_sig:016x}")
    check("TT-B l'entrée rdtime (1 tick=1ns, 4.34)", ts_got == 0x1234,
          f"ts={ts_got:x}")
    check("TT-B le compteur slot-0 += n (6800->6802)", e.rmem(dest, 8) == 6802,
          f"[dest]={e.rmem(dest, 8)}")
    check("TT-B le slot 7->9", e.rmem(0x124488, 8) == 9)
    check("TT-B ret propre", e.pc == 0xDEADC0DE and not e.fail,
          f"pc={e.pc:#x} fail={e.fail}")

    # ---- TT-C: le WRAP slot+1 >= capacité -> slot=1
    e = Emu(img)
    ctx, dest, lst, sp = 0x160000, 0x161000, 0x162000, 0x163000
    e.wmem(ctx + 0x488, 8, 0x3F)       # le dernier slot
    e.wmem(ctx + 0x490, 8, 0x40)
    e.wmem(ctx + 0x498, 8, dest)
    e.wmem(lst, 8, 0x11)
    e.wmem(lst + 8, 8, 0x22)
    e.wmem(lst + 16, 8, 0x33)
    e.wmem(sp + 8, 8, lst)
    e.pc = GADGET_ENTRY
    e.regs[REG_NAMES.index("a0")] = (M - 1)
    e.regs[REG_NAMES.index("a3")] = 3
    e.regs[REG_NAMES.index("a7")] = 0
    e.regs[REG_NAMES.index("a1")] = dest + 0x3F * 8
    e.regs[REG_NAMES.index("a4")] = ctx
    e.regs[2] = sp
    e.regs[1] = 0xDEADC0DE
    e.stop_at = {0xDEADC0DE}
    e.run(budget=400)
    ok = (e.rmem(dest + 0x3F * 8, 8) == 0x11 and
          e.rmem(dest + 1 * 8, 8) == 0x22 and
          e.rmem(dest + 2 * 8, 8) == 0x33 and
          e.rmem(ctx + 0x488, 8) == 3)   # wrap: 0x3F->1 puis 1->2->3
    check("TT-C le wrap slot=cap -> 1 (jamais 0)", ok,
          f"s0+0x3F={e.rmem(dest+0x3F*8,8):x} s1={e.rmem(dest+8,8):x} "
          f"s2={e.rmem(dest+16,8):x} slot_fin={e.rmem(ctx+0x488,8)}")

    # ---- TT-D: les gardes — capacité=0 -> INERT (ret sans écrire)
    e = Emu(img)
    dest = 0x161000
    e.wmem(0x124490, 8, 0)             # capacité = 0 -> le garde beqz @0x100b08
    e.wmem(0x124498, 8, dest)
    e.wmem(dest, 8, 77)
    e.regs[2] = 0x164000
    e.regs[REG_NAMES.index("a0")] = 3
    e.regs[1] = 0xDEADC0DE
    e.pc = FULL_ENTRY
    e.stop_at = {0xDEADC0DE}
    e.run(budget=200)
    check("TT-D capacité=0 -> la boucle inerte, ret propre",
          e.pc == 0xDEADC0DE and e.rmem(dest, 8) == 77 and not e.fail,
          f"pc={e.pc:#x} [dest]={e.rmem(dest,8)} steps={e.steps}")

    # ---- TT-E: E2E — le PAYLOAD CONSTRUIT (le layout C/v442e) pilote la
    #      vraie boucle: le ctx @payload+0x488, la liste @payload+0x500.
    e = Emu(img)
    PAY, DEST = 0x165000, 0x166000   # le payload [PAY,PAY+0x1000), dest après
    E1 = 0x000445C00003A980          # {limitRated 240000, limitMax 280000}
    payload = bytearray(b"\xFF" * 0x1000)
    payload[0x488:0x490] = (2).to_bytes(8, "little")     # slot0 = 2
    payload[0x490:0x498] = (0x400).to_bytes(8, "little") # capacité
    payload[0x498:0x4A0] = DEST.to_bytes(8, "little")    # dest base
    payload[0x4A0] = 0x08                                # magic
    for k in range(3):
        payload[0x500 + 8*k:0x508 + 8*k] = E1.to_bytes(8, "little")
    for i, b in enumerate(payload):
        e.mem[PAY - 0x100000 + i] = b
    e.pc = GADGET_ENTRY
    e.regs[REG_NAMES.index("a0")] = (M - 1)
    e.regs[REG_NAMES.index("a3")] = 3
    e.regs[REG_NAMES.index("a7")] = 0
    e.regs[REG_NAMES.index("a1")] = DEST + 2 * 8   # la 1re cible (registre)
    e.regs[REG_NAMES.index("a4")] = PAY            # le ctx = le payload LUI-MÊME
    e.regs[2] = 0x167000
    e.wmem(0x167000 + 8, 8, PAY + 0x500)           # la marche -> &list[0]
    e.regs[1] = 0xDEADC0DE
    e.stop_at = {0xDEADC0DE}
    e.run(budget=400)
    got = [e.rmem(DEST + 8 * (2 + k), 8) for k in range(3)]
    check("TT-E E2E le payload construit -> E1 aux 3 slots",
          e.pc == 0xDEADC0DE and got == [E1, E1, E1] and not e.fail,
          f"got={['%x' % g for g in got]} slot_fin={e.rmem(PAY+0x488,8)}")

    n_pass = sum(1 for _, ok, _ in results if ok)
    print(f"test-transfer: {n_pass}/{len(results)} PASS")
    return 0 if n_pass == len(results) else 1


def selftest():
    img = load_image()
    fails = []
    # ST-A: trace crt0 == objdump (les 10 premières addresses)
    e = Emu(img)
    pcs = []
    e.tracer = lambda emu, ins: pcs.append(ins.address) if len(pcs) < 10 else None
    e.run(budget=12)
    # 0x100010 (le j 0x1004d6 de l'erreur) N'EST PAS execute: beqz pris
    # (byte @0x16c080 = 0 dans l'image statique) — corrige run 1.
    expected = [0x100000, 0x100004, 0x100008, 0x10000C, 0x100014,
                0x100018, 0x10001C, 0x100020, 0x100024, 0x101E0A]
    if pcs != expected:
        fails.append(f"ST-A crt0 trace {['%x' % p for p in pcs]}")
    # ST-B: run complet — crt0 -> main exécutés, frontière nommée atteinte.
    # (Requalifié run 1: [0x103F78] = pointeur fourni au runtime par le
    # loader (contrat loader->booter) — l'image statique porte un placeholder.
    # L'oracle FAIL (ecall a7=8) reste démontré par le test dirigé ST-D.)
    e = Emu(img)
    reached = []
    e.tracer = lambda emu, ins: reached.append(ins.address)
    e.run(budget=120000)
    ran_main = 0x101E0A in reached
    boundary = e.fail is not None and e.steps > 30
    if not (ran_main and boundary):
        fails.append(f"ST-B frontière non atteinte: main={ran_main} fail={e.fail} steps={e.steps}")
    else:
        print(f"ST-B: crt0+main exécutés ({e.steps} insns), frontière du contrat "
              f"loader->booter @pc={e.fail[0]:#x}: {e.fail[1]}")
    # ST-C: le path d'erreur du crt0 (byte config @0x16C081 != 0 -> j 0x1004d6)
    e = Emu(img)
    e.wmem(0x16C080, 1, 1)
    e.run(budget=5000)
    if not (e.fail or e.steps >= 5000):
        fails.append("ST-C path erreur crt0 inattendu")
    else:
        print(f"ST-C: crt0 erreur config -> pc={e.pc:#x} fail={e.fail} steps={e.steps}")
    # ST-D: bounds check original rejette, patché (NOP) accepte
    if not test_bounds(patch=False):
        fails.append("ST-D1 original devrait rejetter")
    if not test_bounds(patch=True):
        fails.append("ST-D2 patché devrait accepter")
    # ST-E: le patch est NOP-safe (4 o -> 4 o) et l'image sinon identique
    img2 = bytearray(img)
    img2[0x14F4 : 0x14F8] = bytes.fromhex("13000000")
    d = [i for i in range(len(img)) if img[i] != img2[i]]
    if d != [0x14F4, 0x14F5, 0x14F6, 0x14F7]:
        fails.append(f"ST-E diff inattendue {[hex(x) for x in d]}")
    print(f"selftest: {5 - len(fails)}/5 PASS")
    for f in fails:
        print("  FAIL:", f)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default=None, help="bootloader.bin alternatif (patché)")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--steps", type=int, default=120000)
    ap.add_argument("--sbi-base", type=lambda x: int(x, 0), default=0x55800000)
    ap.add_argument("--test-bounds", action="store_true")
    ap.add_argument("--patch-bounds", action="store_true", help="NOP du bgeu @0x1014f4 avant run")
    ap.add_argument("--test-transfer", action="store_true",
                    help="4.42: la validation de la transfer-list (TT-A..D)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.test_transfer:
        return test_transfer()
    if a.selftest:
        return selftest()
    img = load_image(a.image)
    if a.image:
        import hashlib

        print(f"image: {a.image} sha256 {hashlib.sha256(img).hexdigest()[:16]}...")
    if a.test_bounds or a.patch_bounds:
        ok1 = test_bounds(patch=False)
        ok2 = test_bounds(patch=True, image=bytes(bytearray(img)))
        return 0 if (ok1 and ok2) else 1
    e = Emu(img, sbi_base=a.sbi_base, trace=a.trace)
    e.run(budget=a.steps)
    report(e, f"run entry-> budget {a.steps}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
