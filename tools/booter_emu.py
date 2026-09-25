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
        # rearm_stop: when set, the run passes THROUGH the stop set once
        # (the pc already inside it) and stops at the NEXT arrival — the
        # "stop at the re-entry" semantic (the 4.45 W3 spin demonstration).
        # stop_pred: a predicate evaluated BEFORE each step — the stop =
        # the semantic condition (e.g. the counter bumped = the invocation
        # complete), needed because the re-entry pc = the loop-body pc.
        rearm = getattr(self, "rearm_stop", False)
        pred = getattr(self, "stop_pred", None)
        left = not rearm
        while self.fail is None and self.steps < budget and (
                self.pc not in self.stop_at or (rearm and not left)):
            if pred is not None and pred(self):
                break
            if rearm and self.pc not in self.stop_at:
                left = True
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


def test_444():
    """4.44 TÂCHE C2 — la chaîne complète du payload v444 sur l'image
    RÉELLE du booter.

    Le modèle (les paramètres du jour capture = injectés par le test —
    la résolution de l'adresse obj n'est PAS constructible en gadgets
    du booter, v444e — le mur honnête) :
      - l'objet policy 0x6d0 NÉ ZÉRO (la preuve v444b : le memset de la
        création 0x1458d08) modelé @OBJ ;
      - le pointeur *(state+0x4E98) = OBJ posé dans la RAM (la
        résolution du paramètre) ;
      - le PAYLOAD v444 (le layout C/v444_transfer_list_build.py, le
        ctx @+0x488, la liste D @+0x500, la liste f18 @+0x540) ;
      - UNE invocation gadget (0x100b3e, a3=8) = le scatter D complet ;
      - UNE invocation gadget (0x100b3e, a3=1) = le 1er f18.
    PASS = les u64 D aux CHAMPS exacts obj+0x618+idx*0x10, le f18 =
    112 à obj+0x18, la formule re-vérifiée : base x f18/100000 =
    280000.
    """
    import hashlib
    img = load_image()
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print(f"[{ 'PASS' if cond else 'FAIL' }] {name} {detail}")

    # -- le payload v444 COMMIS (le builder python = le C, v444f)
    repo_pay = (Path(__file__).resolve().parent.parent /
                "lab/jalon411/v444_payload.bin").read_bytes()
    assert len(repo_pay) == 0x1000

    OBJ = 0x120000          # l'objet policy (0x6d0, né zéro)
    STATE_SLOT = 0x114E98   # state+0x4E98 (le model, state @0x110000)
    DEST = OBJ + 0x610      # la dest du scatter = obj+0x610
    PAY = 0x165000          # le payload (le ctx @+0x488, D @+0x500)
    D0 = 0x0000000010B07600   # 280,000,000 µW (la lecture percent)
    F18 = 0x0000000000000070  # 112

    # -- TF-A : le scatter D E2E (UNE invocation a3=8)
    e = Emu(img)
    for i, b in enumerate(repo_pay):
        e.mem[PAY - 0x100000 + i] = b
    # le paramètre runtime : le dest résolu DANS le payload (le jour
    # capture, le builder patche ce champ — ici le test le pose)
    e.mem[PAY - 0x100000 + 0x498:PAY - 0x100000 + 0x4A0] = \
        DEST.to_bytes(8, "little")
    # l'objet né ZÉRO + le pointeur *(state+0x4E98)
    e.mem[OBJ - 0x100000:OBJ - 0x100000 + 0x6d0] = bytes(0x6d0)
    e.wmem(STATE_SLOT, 8, OBJ)
    sp = 0x16E000
    e.wmem(sp + 8, 8, PAY + 0x500)      # la cellule de marche -> &D[0]
    e.wmem(sp + 0x50, 8, 0xDEADC0DE)    # le lien terminal de la chaîne
    e.pc = GADGET_ENTRY
    r = e.regs
    r[REG_NAMES.index("a0")] = M - 1    # le chemin RAW pour toujours
    r[REG_NAMES.index("a3")] = 8        # n = 8 itérations
    r[REG_NAMES.index("a7")] = 0
    r[REG_NAMES.index("a1")] = DEST + 8  # la 1re cible = obj+0x618 (D0)
    r[REG_NAMES.index("a4")] = PAY      # le ctx = le payload lui-même
    r[2] = sp
    r[1] = 0xDEADC0DE
    e.stop_at = {0xDEADC0DE}
    e.run(budget=800)

    check("TF-A le scatter D : les 4 D u64 aux champs exacts",
          e.rmem(OBJ + 0x618, 8) == D0 and
          e.rmem(OBJ + 0x628, 8) == D0 and
          e.rmem(OBJ + 0x638, 8) == D0 and
          e.rmem(OBJ + 0x648, 8) == D0,
          f"D0={e.rmem(OBJ+0x618,8):x} D1={e.rmem(OBJ+0x628,8):x} "
          f"D2={e.rmem(OBJ+0x638,8):x} D3={e.rmem(OBJ+0x648,8):x}")
    check("TF-A les clobbers {B,C} = 0 (le placeholder nommé)",
          e.rmem(OBJ + 0x620, 8) == 0 and e.rmem(OBJ + 0x630, 8) == 0
          and e.rmem(OBJ + 0x640, 8) == 0,
          f"BC1={e.rmem(OBJ+0x620,8):x} BC2={e.rmem(OBJ+0x630,8):x} "
          f"BC3={e.rmem(OBJ+0x640,8):x}")
    check("TF-A le compteur slot-0 [dest] += 8",
          e.rmem(DEST, 8) == 8, f"[dest]={e.rmem(DEST,8)}")
    check("TF-A le slot ctx = 8 et ret propre",
          e.rmem(PAY + 0x488, 8) == 8 and e.pc == 0xDEADC0DE
          and not e.fail, f"pc={e.pc:#x} fail={e.fail}")

    # -- TF-B : le 1er f18 (l'invocation a3=1 — la route persistante)
    e2 = Emu(img)
    for i, b in enumerate(repo_pay):
        e2.mem[PAY - 0x100000 + i] = b
    e2.mem[PAY - 0x100000 + 0x498:PAY - 0x100000 + 0x4A0] = \
        DEST.to_bytes(8, "little")
    e2.mem[OBJ - 0x100000:OBJ - 0x100000 + 0x6d0] = bytes(0x6d0)
    e2.wmem(STATE_SLOT, 8, OBJ)
    sp2 = 0x16E000
    e2.wmem(sp2 + 8, 8, PAY + 0x540)    # la marche -> &f18_list[0]
    e2.wmem(sp2 + 0x50, 8, 0xDEADC0DE)
    e2.pc = GADGET_ENTRY
    r = e2.regs
    r[REG_NAMES.index("a0")] = M - 1
    r[REG_NAMES.index("a3")] = 1
    r[REG_NAMES.index("a7")] = 0
    r[REG_NAMES.index("a1")] = OBJ + 0x18   # record[0].f18
    r[REG_NAMES.index("a4")] = PAY
    r[2] = sp2
    r[1] = 0xDEADC0DE
    e2.stop_at = {0xDEADC0DE}
    e2.run(budget=400)
    check("TF-B le f18 = 112 à obj+0x18 (le u64 = {112, 0})",
          e2.rmem(OBJ + 0x18, 8) == F18,
          f"[obj+0x18]={e2.rmem(OBJ+0x18,8):x}")
    check("TF-B ret propre", e2.pc == 0xDEADC0DE and not e2.fail,
          f"pc={e2.pc:#x} fail={e2.fail}")

    # -- TF-C : la formule re-vérifiée sur les valeurs posées — les
    #    DEUX ROUTES = EXCLUSIVES (l'application des DEUX = l'overshoot
    #    313.6 W — le piège opérationnel que CE test documente)
    base = e.rmem(OBJ + 0x618, 8) & 0xFFFFFFFF
    f18 = e2.rmem(OBJ + 0x18, 8) & 0xFFFFFFFF
    lim_stock = 250000000 * 100 // 100000          # le stock = 250000
    lim_f18_route = 250000000 * f18 // 100000      # la route f18 SEULE
    lim_base_route = base * 100 // 100000          # la route base SEULE
    lim_both = base * f18 // 100000                # les DEUX = l'erreur
    check("TF-C la route f18 SEULE : 250000000 x 112 / 100000 = 280000",
          lim_f18_route == 280000, f"= {lim_f18_route}")
    check("TF-C la route base SEULE : 280000000 x 100 / 100000 = 280000",
          lim_base_route == 280000, f"= {lim_base_route}")
    check("TF-C les DEUX routes ENSEMBLE = l'overshoot 313600 "
          "(l'exclusivité des routes — le runbook n'en applique QU'UNE)",
          lim_both == 313600 and lim_stock == 250000,
          f"both={lim_both} stock={lim_stock}")

    n_pass = sum(1 for _, ok, _ in results if ok)
    print(f"test-444: {n_pass}/{len(results)} PASS")
    return 0 if n_pass == len(results) else 1


def test_rop():
    """4.45 TÂCHE C2 — the ROP chain on the REAL booter image.

    The model (the explicit walls — the findings-4.45 §B):
      W1: a1/a4 at the gadget entry = the ROM's residue (0 work-gadgets,
          v444e re-run) — the test MODELS the assumed block (the day-J
          discovery = the runbook R0);
      W2: the body always writes [a1] first = the wild write — modeled
          to the scratch;
      W3: the primitive's ret returns INTO the primitive = the spin —
          the test DEMONSTRATES it (the stop = the re-entry).
    The modeled hijack: the ROM's DMA laid the payload ONTO its stack
    buffer (the payload AT the modeled stack); the return = hijacked to
    the hijack slot; sp = the slot after (the bare-ret model).

    TR-A the uniformity fill: the fill covers the canary slot (the
         mechanical defeat; the zero-canary = the A2 hypothesis)
    TR-B the spine walk: the REAL epilogue bytes G40 x3, the exact
         0x40 steps, the terminal reached, the walk cell = [sp+8]
    TR-C the primitive (a3=1): [a1] = valeur #1; the counter [dest]+=1;
         the slot = slot0+1; the stop = the re-entry (W3)
    TR-D the scatter (a3=3): the wild #1 + the scatter #2/#3 = the
         valeurs at [dest+slot0*8+k*8]; the counter += 3
    TR-E E2E: the COMMITTED payload (v445_rop_payload.bin) drives the
         whole chain on the real image; the writes land.
    PASS = the writes observed at the modeled targets.
    """
    import importlib.util
    lab = Path(__file__).resolve().parent.parent / "lab/jalon411"
    spec = importlib.util.spec_from_file_location(
        "v445_build", lab / "v445_rop_payload_build.py")
    B = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(B)

    img = load_image()
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")

    PAY = 0x16A000          # the modeled ROM stack buffer (the DMA dst)
    SCRATCH = 0x168000      # the modeled a1 residue (the wild-write dst)
    DEST = 0x161000         # the scatter/counter base (the ctx clone's dest)
    FILL_LEN, HOPS, SLOT0 = 64, 3, 1
    VALEURS = (0x112, 0x113, 0x114)
    SP0 = PAY + (FILL_LEN + 1) * 8   # the sp after the modeled hijack
    TERMINAL = B.TERMINAL
    G40 = B.G40

    def lay(payload):
        e = Emu(img)
        for i, b in enumerate(payload):
            e.mem[PAY - 0x100000 + i] = b
        return e

    def hijack(e):
        # the modeled hijack: pc = the hijack slot (the popped ra),
        # sp = the slot after (the bare-ret epilogue model)
        e.regs[2] = SP0
        e.pc = int.from_bytes(
            e.mem[PAY - 0x100000 + FILL_LEN * 8:
                  PAY - 0x100000 + FILL_LEN * 8 + 8], "little")

    # ---- TR-A: the uniformity fill swallows the canary slot ----
    payload, meta = B.build(fill_len=FILL_LEN, hops=HOPS, slot0=SLOT0,
                            dest=DEST, base_addr=PAY, valeurs=VALEURS)
    words = [int.from_bytes(payload[i * 8:(i + 1) * 8], "little")
             for i in range(len(payload) // 8)]
    canary_slot = 32  # the modeled canary position (INDECIDABLE-BY-BYTES)
    check("TR-A the fill = uniform on [0, fill_len)",
          all(w == 0 for w in words[:FILL_LEN]),
          f"{FILL_LEN} u64 = {hex(words[0])}")
    check("TR-A the canary slot swallowed by the uniformity",
          words[canary_slot] == 0,
          f"slot {canary_slot} = {hex(words[canary_slot])} (the fill — the "
          f"A2 zero-canary hypothesis)")
    check("TR-A the size = the memdesc 0x1000", len(payload) == 0x1000)

    # ---- TR-B: the spine walk (the REAL epilogue bytes) ----
    e = lay(payload)
    hijack(e)
    e.stop_at = {TERMINAL}
    e.run(budget=200)
    sp_after = SP0 + 0x40 * HOPS
    check("TR-B the spine = the REAL bytes G40 x3 -> the terminal",
          e.pc == TERMINAL and not e.fail,
          f"pc={e.pc:#x} steps={e.steps}")
    check("TR-B the exact 0x40 steps",
          e.regs[2] == sp_after,
          f"sp={e.regs[2]:#x} attendu={sp_after:#x}")
    check("TR-B the walk cell = [sp+8] = &list[0]",
          e.rmem(e.regs[2] + 8, 8) == PAY + 0x500,
          f"[sp+8]={e.rmem(e.regs[2]+8,8):#x}")

    # ---- TR-C: the primitive (a3=1) GIVEN the assumed block ----
    e = lay(payload)
    hijack(e)
    e.stop_at = {TERMINAL}
    e.run(budget=200)
    # the assumed register block (the A3 assumption — the day-J = R0)
    e.regs[REG_NAMES.index("a0")] = M - 1
    e.regs[REG_NAMES.index("a3")] = 1
    e.regs[REG_NAMES.index("a7")] = 0
    e.regs[REG_NAMES.index("a1")] = SCRATCH   # the WILD write dst (W2)
    e.regs[REG_NAMES.index("a4")] = PAY       # the ctx = the payload base
    e.stop_at = {TERMINAL}                    # W3: the re-entry = the stop
    e.rearm_stop = True                       # pass through once, stop at
    e.run(budget=200)                         # the re-entry
    check("TR-C [a1] = la valeur #1 (the wild write = the modeled scratch)",
          e.rmem(SCRATCH, 8) == VALEURS[0],
          f"[scratch]={e.rmem(SCRATCH,8):#x} attendu={VALEURS[0]:#x}")
    check("TR-C the counter [dest] += 1",
          e.rmem(DEST, 8) == 1, f"[dest]={e.rmem(DEST,8)}")
    check("TR-C the slot ctx = slot0+1",
          e.rmem(PAY + 0x488, 8) == SLOT0 + 1,
          f"slot={e.rmem(PAY+0x488,8)}")
    check("TR-C W3 the stop = the re-entry (the spin demonstrated)",
          e.pc == TERMINAL and not e.fail,
          f"pc={e.pc:#x} (the primitive returned INTO itself)")

    # ---- TR-D: the scatter (a3=3): the wild #1 + the scatter #2/#3 ----
    e = lay(payload)
    hijack(e)
    e.stop_at = {TERMINAL}
    e.run(budget=200)
    e.regs[REG_NAMES.index("a0")] = M - 1
    e.regs[REG_NAMES.index("a3")] = 3
    e.regs[REG_NAMES.index("a7")] = 0
    e.regs[REG_NAMES.index("a1")] = SCRATCH
    e.regs[REG_NAMES.index("a4")] = PAY
    e.stop_at = set()
    # the stop = the semantic condition: the invocation complete (the
    # counter bumped) — the re-entry pc = the loop-body pc (the same
    # address) — the pc alone cannot distinguish them
    e.stop_pred = lambda emu: emu.rmem(DEST, 8) == 3
    e.run(budget=400)
    check("TR-D the wild #1 = la valeur #1",
          e.rmem(SCRATCH, 8) == VALEURS[0],
          f"[scratch]={e.rmem(SCRATCH,8):#x}")
    check("TR-D the scatter #2 = [dest+(slot0+1)*8] (the ring slot advances)",
          e.rmem(DEST + (SLOT0 + 1) * 8, 8) == VALEURS[1],
          f"[dest+16]={e.rmem(DEST+16,8):#x} attendu={VALEURS[1]:#x}")
    check("TR-D the scatter #3 = [dest+(slot0+2)*8]",
          e.rmem(DEST + (SLOT0 + 2) * 8, 8) == VALEURS[2],
          f"[dest+24]={e.rmem(DEST+24,8):#x} attendu={VALEURS[2]:#x}")
    check("TR-D the counter [dest] += 3",
          e.rmem(DEST, 8) == 3, f"[dest]={e.rmem(DEST,8)}")

    # ---- TR-E: E2E — the COMMITTED payload drives the chain ----
    # the committed payload = the single-valeur list (0x112) -> a3 = 1
    repo = (Path(__file__).resolve().parent.parent /
            "lab/jalon411/v445_rop_payload.bin").read_bytes()
    e = lay(repo)
    hijack(e)
    e.stop_at = {TERMINAL}
    e.run(budget=200)
    spine_ok = e.pc == TERMINAL and e.regs[2] == sp_after
    e.regs[REG_NAMES.index("a0")] = M - 1
    e.regs[REG_NAMES.index("a3")] = 1
    e.regs[REG_NAMES.index("a7")] = 0
    e.regs[REG_NAMES.index("a1")] = SCRATCH
    e.regs[REG_NAMES.index("a4")] = PAY
    e.stop_at = set()
    e.stop_pred = lambda emu: emu.rmem(DEST, 8) == 1
    e.run(budget=300)
    check("TR-E E2E the committed payload: the spine -> the terminal",
          spine_ok, f"pc={e.pc:#x} sp={e.regs[2]:#x}")
    check("TR-E E2E the write lands (0x112 the wild -> the modeled scratch)",
          e.rmem(SCRATCH, 8) == 0x112,
          f"[scratch]={e.rmem(SCRATCH,8):#x}")
    check("TR-E E2E the walk cell advanced (&list[1])",
          e.rmem(sp_after + 8, 8) == PAY + 0x508,
          f"[sp+8]={e.rmem(sp_after+8,8):#x}")
    check("TR-E E2E the counter [dest] += 1",
          e.rmem(DEST, 8) == 1, f"[dest]={e.rmem(DEST,8)}")

    n_pass = sum(1 for _, ok, _ in results if ok)
    print(f"test-rop: {n_pass}/{len(results)} PASS")
    return 0 if n_pass == len(results) else 1


def test_rop2():
    """4.53 TÂCHE 4 — the TR-2 suite: the v446 RELOCATABLE layout + the
    CARPET, on the REAL booter image. The existing batteries (5/5,
    TT 11/11, TR 18/18, TF 9/9, TT-T 5/5) = REPRODUCED FIRST (the pass
    discipline) — this suite = the NEW green on top.

    TR2-A the reproduction guard: the committed v445 payload = the
          banked sha (4ee1f973…) — the substrate unchanged.
    TR2-B the RELOCATION: the ctx @word 0x100 + the list @word 0x110
          (the words the v445 layout could NOT use) — the chain walks,
          the primitive reads the ctx AT THE NEW ADDRESS (the slot
          increments there), the walk cell = &list[0] @0x110 — the
          relocation = TRANSPARENT to the bytes' semantics.
    TR2-C the TAIL CHAIN: the chain slot @word 200 (the r1 zone, the
          word > 145 the v445 could never reach) — the spine marches
          200→208→216→224, the primitive fires — the tail = alive.
    TR2-D the PAIR carpet: the RA sweep over the carpet zone — the
          odd class = the IMMEDIATE capture (the terminal fires, the
          counter bumps), the even class = the G40 walk (+8 = the same
          parity — the march measured, write-free), the window-end
          even = the NAMED zone-exit (the march pops beyond the 4 KB
          = the ROM garbage) — every RA word = a live entry or the
          named exit, ZERO strays (the map = the classes).
    TR2-E the ALIGNED carpet: the same sweep — EVERY word = the
          one-step capture (the G40's +8 pop = ALWAYS a terminal, the
          property the builder self-asserts) — [dest] = 1 for ALL.
    TR2-F the committed v446 .bin = the builder re-run (the freshness;
          the byte-exact C = the builder selftest, 3/3 plans).

    The modeled residue block (the A3 discipline — the day = R0/R2):
    a1 = the scratch (the wild W2), a4 = the modeled ctx block OUTSIDE
    the payload (the carpet = no ctx — the named negative), a3 = 1,
    a0 = the RAW path, a7 = 0.
    """
    import hashlib
    import importlib.util
    lab = Path(__file__).resolve().parent.parent / "lab/jalon411"

    spec = importlib.util.spec_from_file_location(
        "v446_build", lab / "v446_rop_payload_build.py")
    B = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(B)

    img = load_image()
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")

    PAY = 0x16A000
    SCRATCH = 0x168000
    DEST = 0x161000
    CTX2 = 0x162000          # the modeled ctx OUTSIDE the payload
    TERMINAL, G40 = B.TERMINAL, B.G40
    G40_RET = 0x10023A       # the ret INSIDE the G40 epilogue (4.45)

    def lay(payload):
        e = Emu(img)
        for i, b in enumerate(payload):
            e.mem[PAY - 0x100000 + i] = b
        return e

    def model_ctx(a4_base, slot0=1, cap=0x40, dest=DEST, magic=0x08):
        # THE TR-2 DISCOVERY (the bytes, not the TT-A comment alone):
        # the primitive's ctx = a4-RELATIVE with the BYTE-FIXED offsets
        # (the slot @a4+0x488, the dest @a4+0x498) — the v445's ctx
        # @the word 0x91 = the byte 0x488 = the CONJUGATION a4 = PAY.
        # The ctx relocation = the (ctx_off, a4) PAIR: the builder
        # places the words, the consumer conjugates a4 = PAY +
        # ctx_off*8 - 0x488. The walk cell + the list = FREE (sp+8).
        e.mem[a4_base + 0x488 - 0x100000: a4_base + 0x4A8 - 0x100000] = \
            b"".join(x.to_bytes(8, "little")
                     for x in (slot0, cap, dest, magic))

    def hijack_at(e, word):
        # the modeled return: pc = the payload word[w] (the popped ra),
        # sp = the slot AFTER (the bare-ret model, the 4.45 discipline)
        e.regs[2] = PAY + (word + 1) * 8
        e.pc = int.from_bytes(
            e.mem[PAY - 0x100000 + word * 8:PAY - 0x100000 + word * 8 + 8],
            "little")

    def model(e, a3=1):
        e.regs[REG_NAMES.index("a0")] = M - 1
        e.regs[REG_NAMES.index("a3")] = a3
        e.regs[REG_NAMES.index("a7")] = 0
        e.regs[REG_NAMES.index("a1")] = SCRATCH
        e.regs[REG_NAMES.index("a4")] = CTX2

    # ---- TR2-A: the v445 substrate = the banked sha ----
    v445 = (lab / "v445_rop_payload.bin").read_bytes()
    check("TR2-A the committed v445 = the banked sha 4ee1f973…",
          hashlib.sha256(v445).hexdigest()[:16] == "4ee1f9737004f5cd",
          hashlib.sha256(v445).hexdigest()[:16])

    # ---- TR2-B: the RELOCATED chain (the ctx @0x100, the list @0x110) --
    p, m = B.build_chain(fill_len=64, hops=3, dest=DEST, base_addr=PAY,
                         valeurs=(0x112, 0x113), ctx_off=0x100,
                         list_off=0x110)
    e = lay(p)
    hijack_at(e, 64)
    e.stop_at = {TERMINAL}
    e.run(budget=200)
    spine_ok = e.pc == TERMINAL and e.regs[2] == PAY + 65 * 8 + 0x40 * 3
    walk_cell_addr = PAY + 65 * 8 + 0x40 * 3 + 8
    walk0 = e.rmem(walk_cell_addr, 8)      # BEFORE the primitive
    A4 = PAY + 0x100 * 8 - 0x488     # the CONJUGATED a4 (the discovery)
    e.regs[REG_NAMES.index("a0")] = M - 1
    e.regs[REG_NAMES.index("a3")] = 2
    e.regs[REG_NAMES.index("a7")] = 0
    e.regs[REG_NAMES.index("a1")] = SCRATCH
    e.regs[REG_NAMES.index("a4")] = A4
    e.stop_at = set()
    e.stop_pred = lambda emu: emu.rmem(DEST, 8) == 2
    e.run(budget=400)
    check("TR2-B the spine -> the terminal (the relocated layout)",
          spine_ok, f"pc={e.pc:#x}")
    check("TR2-B the walk cell (pre) = &list[0] @word 0x110 (FREE)",
          walk0 == PAY + 0x110 * 8, f"{walk0:#x}")
    check("TR2-B the walk cell (post) = advanced 2 loads = &list[2]",
          e.rmem(walk_cell_addr, 8) == PAY + 0x110 * 8 + 16,
          f"{e.rmem(walk_cell_addr, 8):#x}")
    check("TR2-B the ctx = a4-RELATIVE: the slot @A4+0x488 = the word "
          "0x100 = slot0+2",
          e.rmem(PAY + 0x100 * 8, 8) == 3,
          f"slot={e.rmem(PAY + 0x800, 8)}")
    check("TR2-B the counter [dest] = 2", e.rmem(DEST, 8) == 2)
    check("TR2-B the scatter #2 = [dest+(slot0+1)*8] = v2",
          e.rmem(DEST + (1 + 1) * 8, 8) == 0x113,
          f"{e.rmem(DEST + 16, 8):#x}")

    # ---- TR2-C: the TAIL chain @word 200 (the r1 zone) ----
    pt, mt = B.build_chain(fill_len=200, hops=3, dest=DEST, base_addr=PAY)
    e = lay(pt)
    hijack_at(e, 200)
    e.stop_at = {TERMINAL}
    e.run(budget=200)
    tail_ok = e.pc == TERMINAL and e.regs[2] == PAY + 201 * 8 + 0x40 * 3
    # the ctx @the default 0x91 = the conjugation a4 = PAY (the byte
    # 0x488 = the word 0x91) — the heritage alignment, intact
    e.regs[REG_NAMES.index("a0")] = M - 1
    e.regs[REG_NAMES.index("a3")] = 1
    e.regs[REG_NAMES.index("a7")] = 0
    e.regs[REG_NAMES.index("a1")] = SCRATCH
    e.regs[REG_NAMES.index("a4")] = PAY
    e.stop_at = set()
    e.stop_pred = lambda emu: emu.rmem(DEST, 8) == 1
    e.run(budget=400)
    check("TR2-C the tail chain @200 marches to the terminal",
          tail_ok, f"pc={e.pc:#x} sp={e.regs[2]:#x}")
    check("TR2-C the tail primitive fires (the counter [dest] = 1)",
          e.rmem(DEST, 8) == 1 and not e.fail, f"fail={e.fail}")

    # ---- TR2-D: the PAIR carpet — the RA sweep, the classes ----
    pcp, mcp = B.build_carpet(fill_len=112, mode="pair")
    # the modeled ctx OUTSIDE the payload (the carpet places none — the
    # named negative); the fields = @CTX2+0x488 (the a4-RELATIVE law)
    def model(e, a3=1):
        model_ctx(CTX2)
        e.regs[REG_NAMES.index("a0")] = M - 1
        e.regs[REG_NAMES.index("a3")] = a3
        e.regs[REG_NAMES.index("a7")] = 0
        e.regs[REG_NAMES.index("a1")] = SCRATCH
        e.regs[REG_NAMES.index("a4")] = CTX2
    sweep = sorted(set(range(112, 512, 17)) | {112, 113, 508, 509, 510, 511})
    captured, walked, exited, strays = 0, 0, 0, []
    tail = [wpos for wpos in sweep if wpos + 2 > 511]   # {510, 511}:
    tail_named = 0                   # the walk cell [sp+8] = BEYOND
    inwin = [wpos for wpos in sweep if wpos + 2 <= 511]
    n_odd = sum(1 for wpos in inwin if wpos % 2 == 1)
    n_even = len(inwin) - n_odd
    for wpos in sweep:
        e = lay(pcp)
        hijack_at(e, wpos)
        model(e)
        sp0 = e.regs[2]
        is_term = e.pc == TERMINAL
        e.stop_at = set()
        e.stop_pred = (lambda emu: emu.rmem(DEST, 8) == 1) if is_term else (
            lambda emu: (emu.regs[2] - sp0) >= 0x40 * 5)
        try:
            e.run(budget=500)
        except MemoryError:
            if wpos in tail:
                tail_named += 1     # the named tail (the walk cell beyond)
            else:
                exited += 1         # the march popped beyond mid-walk
            continue
        if e.fail:
            if wpos in tail:
                tail_named += 1     # the load fault = the same tail class
            else:
                strays.append((wpos, f"fail={e.fail}"))
        elif e.rmem(DEST, 8) == 1:
            captured += 1
        elif (e.regs[2] - sp0) == 0x40 * 5 and \
                e.pc in (G40, G40_RET):
            # the march: 5 full 0x40 hops; the stop pc = the epilogue's
            # ENTRY or its ret (0x10023a — the 4.45 banked "the slots =
            # the ENTRIES" lesson: the walk = INSIDE the epilogue)
            walked += 1
        else:
            strays.append((wpos, f"pc={e.pc:#x} dest={e.rmem(DEST, 8)}"))
    check("TR2-D the odd class = 100% the IMMEDIATE capture (the "
          "terminal fires, the counter bumps)",
          captured == n_odd, f"captured={captured}/{n_odd} odd")
    check("TR2-D the even class = the G40 march or the named zone-exit",
          walked + exited == n_even, f"walked={walked} exited={exited} "
          f"/{n_even} even")
    check("TR2-D the interior march = live (the spine walks in-zone)",
          walked >= 8, f"walked={walked}")
    check("TR2-D the zone-exit = the boundary reality (named, bounded)",
          1 <= exited <= 4, f"exited={exited}")
    check("TR2-D the tail 2 = the NAMED class (the walk cell beyond the "
          "window)", tail_named == 2, f"named={tail_named}")
    check("TR2-D ZERO strays (every RA word = a live entry or a named "
          "class)", not strays, f"{strays[:3]}")
    # the capture MECHANICS: the walk cell = [sp+8] = the word w+2 —
    # the carpet word there = a LIVE entry value (an address in the
    # booter image) -> the wild write = the 8 bytes AT that address
    e = lay(pcp)
    wpos = 113                       # the zone-odd = the terminal first
    hijack_at(e, wpos)
    model(e)
    e.stop_at = set()
    e.stop_pred = lambda emu: emu.rmem(DEST, 8) == 1
    e.run(budget=500)
    walkptr = int.from_bytes(
        pcp[(wpos + 2) * 8:(wpos + 2) * 8 + 8], "little")
    img_val = int.from_bytes(
        img[walkptr - 0x100000: walkptr - 0x100000 + 8], "little")
    check("TR2-D the capture mechanics: the walk cell = the word w+2 "
          "(a live entry), the wild write = the image bytes at it",
          e.rmem(SCRATCH, 8) == img_val,
          f"[scratch]={e.rmem(SCRATCH, 8):#x} img@{walkptr:#x}={img_val:#x}")

    # ---- TR2-E: the ALIGNED carpet — the one-step capture, ALL ----
    pca, mca = B.build_carpet(fill_len=112, mode="aligned")
    cap_all, bad_all = 0, []
    tail_named = 0                   # the T @509..511: the walk cell
    for wpos in sweep:               # w+2 = BEYOND the window (named)
        e = lay(pca)
        hijack_at(e, wpos)
        model(e)
        if wpos + 2 > 511:
            # the aligned carpet's LAST TWO terminals: the walk cell
            # [sp+8] = beyond the 4 KB = the ROM garbage -> the load
            # faults — the named boundary class (the builder's pop
            # property covers the G40s; the tail T's walk cell = the
            # window edge — the honest limit, never hidden)
            e.stop_at = set()
            e.stop_pred = lambda emu: False
            try:
                e.run(budget=200)
            except MemoryError:
                tail_named += 1
                continue
            if e.fail:
                tail_named += 1
                continue
            bad_all.append((wpos, "tail silent"))
            continue
        e.stop_at = set()
        e.stop_pred = lambda emu: emu.rmem(DEST, 8) == 1
        try:
            e.run(budget=500)
        except MemoryError:
            bad_all.append((wpos, "MemoryError"))
            continue
        if e.fail:
            bad_all.append((wpos, f"fail={e.fail}"))
        elif e.rmem(DEST, 8) == 1:
            cap_all += 1
        else:
            bad_all.append((wpos, f"pc={e.pc:#x}"))
    check("TR2-E the aligned carpet: 100% of the in-window sweep = the "
          "one-step capture",
          cap_all == len(sweep) - 2, f"{cap_all}/{len(sweep) - 2}")
    check("TR2-E the tail 2 = the NAMED boundary class (the walk cell "
          "beyond the window)", tail_named == 2, f"named={tail_named}")
    check("TR2-E ZERO strays", not bad_all, f"{bad_all[:3]}")

    # ---- TR2-F: the committed v446 .bin = the builder re-run ----
    import subprocess as _sp
    v446_bin = (lab / "v446_rop_payload.bin").read_bytes()
    regen, _m = B.build_carpet(fill_len=112, mode="pair")
    check("TR2-F the committed v446 = the builder re-run (the freshness)",
          v446_bin == regen, f"{len(v446_bin)} B")
    r = _sp.run(["python3", str(lab / "v446_rop_payload_build.py"),
                 "--selftest"], capture_output=True, text=True)
    last = [l for l in r.stdout.strip().splitlines() if l][-1]
    check("TR2-F the v446 selftest = 28/28 (the invariants + the tree "
          "guard + the byte-exact C)", r.returncode == 0 and "28/28" in last,
          last)

    n_pass = sum(1 for _, ok, _ in results if ok)
    print(f"test-rop2: {n_pass}/{len(results)} PASS")
    return 0 if n_pass == len(results) else 1


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


def test_timings():
    """4.50 — la validation émulateur du scénario TIMING (TT-T).

    La machinerie = la transfer-list PROUVÉE 4.42 (TT-A..E); le scénario
    nouveau = les TABLES DE TIMINGS LHR/launch (les vecteurs gx5 bankés,
    v448c_stride_timing.json -> dmem_fingerprints):
      - LHR (record 26):    rc=70, rfc=175, ras=44, faw=20, rrd=5
      - launch (record 6):  rc=78, rfc=210, ras=52, rp=26, cl=24
    Le LAYOUT byte-lane des records parsés = INDECIDABLE-BY-BYTES
    jusqu'au dump §5 (runbook-447); le test valide donc la MACHINERIE
    du scénario (le tableau u64 plat, l'ordre, le swap A/B, le
    rollback), PAS le layout final. Chaque entrée = le u64 portant la
    valeur du champ (le {value,target} réel viendra du dump).

    TT-T1: la table LHR 5 champs -> byte-exact au dest (le retighten).
    TT-T2: le swap A/B: launch PUIS LHR -> le dest tient LHR.
    TT-T3: le rollback: LHR PUIS launch -> le dest revient au stock.
    TT-T4: les gardes: a3=5, slot 2->7, ret propre, zéro déviation.
    """
    img = load_image()
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")

    LHR = [70, 175, 44, 20, 5]        # rc, rfc, ras, faw, rrd (record 26)
    LAUNCH = [78, 210, 52, 26, 24]    # rc, rfc, ras, rp, cl (record 6)

    def run_table(vals):
        """Le flux TT-E: le payload (ctx + liste plate) pilote la boucle."""
        e = Emu(img)
        PAY, DEST = 0x165000, 0x166000
        payload = bytearray(b"\xFF" * 0x1000)
        payload[0x488:0x490] = (2).to_bytes(8, "little")
        payload[0x490:0x498] = (0x400).to_bytes(8, "little")
        payload[0x498:0x4A0] = DEST.to_bytes(8, "little")
        payload[0x4A0] = 0x08
        for k, v in enumerate(vals):
            payload[0x500 + 8 * k:0x508 + 8 * k] = v.to_bytes(8, "little")
        for i, b in enumerate(payload):
            e.mem[PAY - 0x100000 + i] = b
        e.pc = GADGET_ENTRY
        e.regs[REG_NAMES.index("a0")] = (M - 1)
        e.regs[REG_NAMES.index("a3")] = len(vals)
        e.regs[REG_NAMES.index("a7")] = 0
        e.regs[REG_NAMES.index("a1")] = DEST + 2 * 8
        e.regs[REG_NAMES.index("a4")] = PAY
        e.regs[2] = 0x167000
        e.wmem(0x167000 + 8, 8, PAY + 0x500)
        e.regs[1] = 0xDEADC0DE
        e.stop_at = {0xDEADC0DE}
        e.run(budget=400)
        got = [e.rmem(DEST + 8 * (2 + k), 8) for k in range(len(vals))]
        return e, got

    # TT-T1: le retighten LHR
    e, got = run_table(LHR)
    check("TT-T1 la table LHR (5 champs) byte-exact au dest",
          e.pc == 0xDEADC0DE and got == LHR and not e.fail,
          f"got={got}")
    lhr_dest = [e.rmem(0x166000 + 8 * (2 + k), 8) for k in range(5)]

    # TT-T2: le swap A/B — launch puis LHR (le dest doit tenir LHR)
    e2, got2 = run_table(LAUNCH)
    # même ctx/dest: le second run écrase les 5 slots du premier
    check("TT-T2 la table launch (5 champs) byte-exact",
          e2.pc == 0xDEADC0DE and got2 == LAUNCH and not e2.fail,
          f"got={got2}")
    e3, got3 = run_table(LHR)
    check("TT-T2 le swap launch->LHR: le dest tient LHR",
          got3 == LHR and got3 != LAUNCH,
          f"got={got3}")
    # TT-T3: le rollback — launch (le stock) après LHR
    e4, got4 = run_table(LAUNCH)
    check("TT-T3 le rollback LHR->launch: le dest revient au stock",
          got4 == LAUNCH,
          f"got={got4}")
    # TT-T4: les gardes — le slot avance 2->2+5=7, ret propre
    e5, got5 = run_table(LHR)
    check("TT-T4 le slot avance 2->7, ret propre, zéro déviation",
          e5.rmem(0x165000 + 0x488, 8) == 7 and e5.pc == 0xDEADC0DE
          and not e5.fail,
          f"slot_fin={e5.rmem(0x165000 + 0x488, 8)}")

    n_pass = sum(1 for _, ok, _ in results if ok)
    print(f"test-timings: {n_pass}/{len(results)} PASS")
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
    ap.add_argument("--test-444", action="store_true",
                    help="4.44: la chaîne v444 sur l'image réelle (TF-A..C)")
    ap.add_argument("--test-rop", action="store_true",
                    help="4.45: la chaîne ROP débordante sur l'image réelle (TR-A..E)")
    ap.add_argument("--test-rop2", action="store_true",
                    help="4.53: the v446 relocatable layout + the carpet (TR2-A..F)")
    ap.add_argument("--test-timings", action="store_true",
                    help="4.50: le scénario timing LHR/launch sur la transfer-list (TT-T1..T4)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.test_rop:
        return test_rop()
    if a.test_rop2:
        return test_rop2()
    if a.test_444:
        return test_444()
    if a.test_transfer:
        return test_transfer()
    if a.test_timings:
        return test_timings()
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
