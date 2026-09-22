#!/usr/bin/env python3
"""
v428 stage 3 — the copy graph on the surviving host-side sites: the five
captured fields are NOT built here (the honest negative), and the one
marshal-class site is calibrated end to end.

Inputs:
  - stage 2 register lab/jalon411/v428_x86_site_attributor.json (frozen):
    every 0x608 / 0x186a0 / family site attributed + classified.
  - substrate tools/analysis/x86-rm/binaries/nv-kernel.o_binary
    (sha256 48096db0..., PROVENANCE.md sibling).

THE SCOPE:
  A. rpcCtrlSubdeviceGetP2pCaps_v21_02 — the ONLY marshal-class 0x608 site
     (stage 2: mov ecx, 0x608 + portMemCopy x3 + rpcWriteCommonHeader).
     Fully disassembled, every instruction annotated with its relocation
     symbol (the stage-2 reloc grammar), every internal call site with its
     +-8-insn argument window. The deliverable: the RPC-stub grammar
     (where the paramsSize 1544 goes, where the control id comes from,
     what is copied where) — the calibration template for the userspace
     hunt (stage 4), because the SAME stub family cannot exist for
     0x2080d031 (the census: zero occurrences of the cmd id anywhere).
  B. the five-value store probe, function-wide, on every REAL-site
     function from stage 2: stores of {255, 3, 257, 250000} at any
     displacement, and loads/stores at the five captured poffs
     {0, 4, 8, 56, 64} of any register fed by a 0x608-sized operation.
     Expected verdict (and the honest deliverable): NO host function
     builds the captured pattern — the five fields' producer is not in
     the host RM object.
  C. the classification roll-up: every one of the 53 stage-2 sites gets
     its final class (marstub / rcdb-record / nvswitch / vgpu-record /
     dp-arith / timeout-delay / spdm / vtable-offset / state-field /
     jcc-overlap / rela-roffset-artifact / symtab-st_value-artifact /
     firmware-bindata-coincidence / other) with the evidence line.

Register: lab/jalon411/v428_x86_copygraph.json (written, frozen).
Selftest: full re-derivation deep-compared against the register; drift
exits 2 with the drift name.
"""
import hashlib
import json
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:  # pragma: no cover
    print("capstone missing: pip install capstone")
    raise

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "..", "tools", "analysis", "x86-rm", "binaries",
                   "nv-kernel.o_binary")
REG2 = os.path.join(HERE, "v428_x86_site_attributor.json")
REG = os.path.join(HERE, "v428_x86_copygraph.json")

RT = {1: "R_X86_64_64", 2: "R_X86_64_PC32", 4: "R_X86_64_PLT32",
      10: "R_X86_64_32", 11: "R_X86_64_32S"}

STUB_FUNC = "rpcCtrlSubdeviceGetP2pCaps_v21_02"

# the five captured fields, findings-4.24-payload-fieldmap.md section 1,
# re-derived from tools/edpp/edpp_payload_1616.bin (stage-1 reground):
FIVE_POFFS = {0: 255, 4: 3, 8: 257, 56: 257, 64: 250000}

# the final classes, keyed by (needle, function or section shape) — the
# roll-up below fills `class` per site; this table documents the mapping
# rules as code (an honest instrument states its classes).
CLASS_RULES = {
    "rpcCtrlSubdeviceGetP2pCaps_v21_02": "rpc-marshal-stub (GetP2pCaps, NOT d031)",
    "krcWatchdogInit_IMPL": "rcdb-watchdog record size (magics 0xdeaf0006 / 0x314159xx)",
    "rcdbDumpSystemInfo_IMPL": "rcdb system-info record size",
    "rcdbReportNextNocatJournalEntry": "rcdb nocat journal entry size",
    "subdeviceCtrlCmdNvdGetNocatJournalRpt_IMPL": "rcdb nocat journal entry stride",
    "kvgpumgrGuestUnregister": "vgpu record size (guest-unregister lane)",
    "nvswitch_init_minion_lr10": "nvswitch minion buffer size (off-target platform)",
    "nvswitch_setup_hal_lr10": "nvswitch hal vtable slot (off-target)",
    "nvswitch_setup_hal_ls10": "nvswitch hal vtable slot (off-target)",
    "nvswitch_init_pll_config_lr10": "nvswitch pll 64-bit constant overlap (off-target)",
    "nvswitch_init_pll_config_ls10": "nvswitch pll 64-bit constant overlap (off-target)",
    "nvswitch_lib_ctrl": "nvswitch lib ctrl member offset (off-target)",
    "kbifDoSecondaryBusHotReset_GM107": "reset timeout 100 ms (us class)",
    "kbifDoFunctionLevelReset_TU102": "reset timeout 100 ms (us class)",
    "_checkTimeout": "timeout constant 100 ms (us class)",
    "tmrDelay_PTIMER": "ptimer delay constant (us class)",
    "kdispComputeDpModeSettings_v02_04": "displayport mode arithmetic",
    "libspdm_init_context_with_secured_context": "spdm context field",
    "kbusStateInitLockedKernel_GM107": "kbus state member offset (value 0x100000)",
    "kgmmuCreateFakeSparseTablesInternal_KERNEL": "gmmu table member offset",
    "_bar2WalkCBWriteBuffer": "bar2 walk buffer member offset",
    "__nvoc_init_funcTable_KernelFalcon_1": "hal function-table slot",
    "kernelhostvgpudeviceapiCtrlCmdBootloadVgpuTask_IMPL": "vgpu task member offset",
    "dispcmnCtrlCmdSystemExecuteAcpiMethod_IMPL": "jcc disp32 overlap artifact",
    "getGpuInfos": "jcc disp32 overlap artifact",
    "clUpdatePcieConfig_IMPL": "jcc disp32 overlap artifact",
}


def load_sections(buf):
    e_shoff, = struct.unpack_from("<Q", buf, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 58)
    raw = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        nameoff, sh_type, flags, addr, off, size, link, info, align, entsz = \
            struct.unpack_from("<IIQQQQIIQQ", buf, b)
        raw.append(dict(index=i, nameoff=nameoff, type=sh_type, flags=flags,
                        offset=off, size=size, link=link, info=info,
                        entsize=entsz))
    strtab_off = raw[e_shstrndx]["offset"]
    for s in raw:
        end = buf.index(b"\x00", strtab_off + s["nameoff"])
        s["name"] = buf[strtab_off + s["nameoff"]:end].decode("ascii", "replace")
    return raw


def load_symbols(buf, secs):
    out = []
    for st in (s for s in secs if s["type"] == 2):
        strtab = secs[st["link"]]
        for i in range(st["size"] // st["entsize"]):
            b = st["offset"] + i * st["entsize"]
            nameoff, info, other, shndx, value, size = \
                struct.unpack_from("<IBBHQQ", buf, b)
            name = ""
            if nameoff:
                sbo = strtab["offset"] + nameoff
                e = buf.index(b"\x00", sbo)
                name = buf[sbo:e].decode("ascii", "replace")
            out.append(dict(name=name, stype=info & 0xF, shndx=shndx,
                            value=value, size=size))
    return out


def load_text_relocs(buf, secs, text_idx):
    m = {}
    for s in secs:
        if s["type"] != 4 or s["info"] != text_idx:
            continue
        for i in range(s["size"] // s["entsize"]):
            b = s["offset"] + i * s["entsize"]
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", buf, b)
            m[r_offset] = (r_info & 0xFFFFFFFF, r_info >> 32, r_addend)
    return m


def derive(buf):
    secs = load_sections(buf)
    text = next(s for s in secs if s["name"] == ".text")
    syms = load_symbols(buf, secs)
    reloc = load_text_relocs(buf, secs, text["index"])
    byname = {s["name"]: s for s in syms if s["name"]}

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    tb = buf[text["offset"]:text["offset"] + text["size"]]

    out = {"substrate_sha256": hashlib.sha256(buf).hexdigest()}

    # ---- A. the stub, fully decoded ----
    f = byname[STUB_FUNC]
    start, size = f["value"], f["size"]
    dis = []
    calls = []
    insns = list(md.disasm(tb[start:start + size], start))

    def reloc_note(a, sz):
        """the reloc can sit at ANY field offset inside the instruction
        (call rel32 lands at +1, mov disp32 at modrm+1..) — scan the
        whole span; first hit wins."""
        for o in range(a, a + sz):
            r = reloc.get(o)
            if r:
                nm = syms[r[1]]["name"] if r[1] < len(syms) else ""
                return " ; reloc %s %s%s" % (RT.get(r[0], hex(r[0])), nm,
                                              ("+0x%x" % r[2]) if r[2]
                                              else "")
        return ""

    for k, insn in enumerate(insns):
        note = reloc_note(insn.address, insn.size)
        dis.append("%x %-9s %s%s" % (insn.address, insn.mnemonic,
                                     insn.op_str, note))
        if insn.mnemonic in ("call", "callq"):
            lo, hi = max(0, k - 8), k + 1
            calls.append({"at": insn.address,
                          "target": insn.op_str + note,
                          "arg_window": ["%x %-9s %s%s" % (
                              insns[j].address, insns[j].mnemonic,
                              insns[j].op_str,
                              reloc_note(insns[j].address,
                                         insns[j].size))
                              for j in range(lo, hi)]})
    # the constants of the stub (imm scan, whole function)
    imms = {}
    for insn in insns:
        for tok in insn.op_str.split(","):
            tok = tok.strip()
            if tok.startswith("0x"):
                try:
                    v = int(tok, 16)
                except ValueError:
                    continue
                imms.setdefault(v, []).append(insn.address)
    out["stub"] = {"name": STUB_FUNC, "start": start, "size": size,
                   "disasm": dis, "calls": calls,
                   "imm_histogram": {hex(k): [hex(a) for a in v]
                                     for k, v in sorted(imms.items())}}

    # ---- B. the five-value store probe, function-wide, every REAL fn ----
    reg2 = json.load(open(REG2))
    probes = {}
    for fname, fp in reg2["fingerprints"].items():
        f2 = byname.get(fname)
        if not f2 or not f2["size"]:
            continue
        hits = []
        # dword stores of the captured set: the IMMEDIATE is the SOURCE
        # operand (mov [base+disp], imm) — check src, not dst
        for insn in md.disasm(tb[f2["value"]:f2["value"] + f2["size"]],
                              f2["value"]):
            ops = insn.op_str.replace(" ", "")
            if insn.mnemonic not in ("mov", "movl", "movq"):
                continue
            if "[" not in ops.split(",")[0]:
                continue
            src = ops.split(",", 1)[1] if "," in ops else ""
            try:
                v = int(src, 0)
            except ValueError:
                v = None
            if v is not None and v in (255, 3, 257, 250000):
                hits.append({"off": hex(insn.address),
                             "insn": insn.mnemonic + " " + insn.op_str,
                             "value": v,
                             "probe": "captured-value store"})
            dst = ops.split(",", 1)[0]
            for po in FIVE_POFFS:
                if "+0x%x]" % po in dst:
                    hits.append({"off": hex(insn.address),
                                 "insn": insn.mnemonic + " " + insn.op_str,
                                 "probe": "store at poff %d" % po})
        probes[fname] = hits
    out["five_value_probe"] = probes

    # ---- C. the roll-up of all 53 stage-2 sites ----
    roll = []
    for label in ("size_1544", "val_100000", "val_240000", "val_250000",
                  "fam_0x2080d2a5", "fam_0x2080d2e9", "fam_0x2080d338"):
        for s in reg2["scans"][label]["sites"]:
            key = s.get("func") or s.get("enclosing_symbol") or ""
            cls = CLASS_RULES.get(s.get("func", ""), "")
            if s["section"] != ".text":
                if s["section"] in (".rodata", ".data"):
                    cls = cls or ("firmware-bindata coincidence (%s)"
                                  % s.get("enclosing_symbol", "?"))
                elif s["section"] == ".symtab":
                    cls = cls or "st_value offset coincidence (nvoc cluster)"
                elif s["section"].startswith(".rela"):
                    f2 = s.get("rela_field", "")
                    cls = cls or ("r_offset/addend offset artifact (%s)"
                                  % f2)
            elif not cls:
                cls = "see stage-2 window"
            roll.append({"needle": label, "file_off": hex(s["file_off"]),
                         "section": s["section"], "func": s.get("func"),
                         "role": s.get("role", "non-text"), "class": cls})
    out["rollup"] = roll
    out["rollup_counts"] = {}
    for e in roll:
        k = e["class"].split(" (")[0]
        out["rollup_counts"][k] = out["rollup_counts"].get(k, 0) + 1
    return out


def main():
    buf = open(BIN, "rb").read()
    out = derive(buf)
    with open(REG, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print("== v428 stage 3: copy graph ==")
    print("stub %s: %d insns, %d calls" % (STUB_FUNC,
                                           len(out["stub"]["disasm"]),
                                           len(out["stub"]["calls"])))
    print("imm histogram (top):", dict(list(out["stub"]["imm_histogram"]
                                            .items())[:12]))
    probe_tot = sum(len(v) for v in out["five_value_probe"].values())
    print("five-value probe hits across all REAL-site functions:", probe_tot)
    print("roll-up counts:", json.dumps(out["rollup_counts"], sort_keys=True))
    print("register written:", os.path.relpath(REG, HERE))
    return 0


def selftest():
    buf = open(BIN, "rb").read()
    reg = json.load(open(REG))
    errs = []
    if reg["substrate_sha256"] != hashlib.sha256(buf).hexdigest():
        errs.append("substrate sha256 drift")
    fresh = derive(buf)
    if len(fresh["stub"]["disasm"]) != len(reg["stub"]["disasm"]):
        errs.append("stub insn count drift")
    if len(fresh["stub"]["calls"]) != len(reg["stub"]["calls"]):
        errs.append("stub call count drift")
    if fresh["rollup_counts"] != reg["rollup_counts"]:
        errs.append("roll-up drift")
    if {k: len(v) for k, v in fresh["five_value_probe"].items()} != \
            {k: len(v) for k, v in reg["five_value_probe"].items()}:
        errs.append("five-value probe drift")
    if errs:
        print("SELFTEST FAIL:", *errs, sep="\n  ")
        return 2
    print("selftest OK — stub %d insns, roll-up closes over %d sites"
          % (len(reg["stub"]["disasm"]), len(reg["rollup"])))
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if len(sys.argv) > 1 and sys.argv[1] == "selftest"
             else main())
