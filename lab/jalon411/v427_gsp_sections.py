#!/usr/bin/env python3
"""v427 — sections/coverage/decoy analysis of gsp_ga10x.bin (pass 4.27).

Follows v427_gspbin_container.py. Emits v427_gsp_sections.json next to the
findings. Byte-derived only.

Checks:
  S1. Parse the ELF64 section table (19 entries @ e_shoff=0x050673d8,
      shstrndx=18) — names, types, offsets, sizes, addrs.
  S2. Coverage map: does the union of sh_offset..sh_offset+sh_size cover
      [0x40, e_shoff) exactly, with what gaps?
  S3. The gzip-magic hits at ~0xe08xxx: real gzip streams (10-byte header
      + raw DEFLATE that actually decompresses) or data coincidences?
  S4. The odd ELF magic @0x1cefb3e: real ELF or data coincidence?
  S5. Cross-map: v424_gfw_directory.json windows (fwimage coords) onto
      gsp coords (+0x40) and onto the section table.
"""
import json
import struct
import zlib
from pathlib import Path

GSP = Path("/home/z/my-project/work/downloads/extracted/firmware/gsp_ga10x.bin")
FWI = Path("/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/fwimage.bin")
GFW_JSON = Path("/home/z/my-project/work/gpu-repo/lab/jalon411/v424_gfw_directory.json")
OUT = Path("/home/z/my-project/work/gpu-repo/lab/jalon411/v427_gsp_sections.json")

EHDR_FMT = "<16sHHIQQQIHHHHHH"
SHDR_FMT = "<IIQQQQIIQQ"
SHDR_SIZE = 64

def parse():
    data = GSP.read_bytes()
    (e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from(EHDR_FMT, data, 0)
    hdr = dict(e_type=e_type, e_machine=e_machine, e_entry=e_entry,
               e_phoff=e_phoff, e_shoff=e_shoff, e_phnum=e_phnum,
               e_shnum=e_shnum, e_shstrndx=e_shstrndx)
    shdrs = []
    for i in range(e_shnum):
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
            SHDR_FMT, data, e_shoff + i * SHDR_SIZE)
        shdrs.append(dict(index=i, sh_name=sh_name, sh_type=sh_type,
                          sh_flags=sh_flags, sh_addr=sh_addr,
                          sh_offset=sh_offset, sh_size=sh_size,
                          sh_link=sh_link, sh_info=sh_info,
                          sh_addralign=sh_addralign, sh_entsize=sh_entsize))
    # names
    strtab_off = shdrs[e_shstrndx]["sh_offset"]
    strtab = data[strtab_off:strtab_off + shdrs[e_shstrndx]["sh_size"]]
    for s in shdrs:
        end = strtab.find(b"\x00", s["sh_name"])
        s["name"] = strtab[s["sh_name"]:end].decode("utf-8", "replace")
    return data, hdr, shdrs

def s1_s2(data, hdr, shdrs):
    print("== S1: section table ==")
    for s in shdrs:
        print(f"  [{s['index']:2d}] {s['name']:<26s} type={s['sh_type']:<2d} "
              f"addr=0x{s['sh_addr']:08x} off=0x{s['sh_offset']:08x} "
              f"size=0x{s['sh_size']:08x} align={s['sh_addralign']}")
    print("\n== S2: coverage of [0x40, e_shoff) ==")
    e_shoff = hdr["e_shoff"]
    lo, hi = 0x40, e_shoff
    spans = sorted((s["sh_offset"], s["sh_offset"] + s["sh_size"], s["name"])
                   for s in shdrs
                   if s["sh_type"] != 8 and s["sh_size"] > 0)  # skip NOBITS
    covered = 0
    gaps = []
    cursor = lo
    for off, end, name in spans:
        if end <= lo or off >= hi:
            continue
        off2, end2 = max(off, lo), min(end, hi)
        if off2 > cursor:
            gaps.append((cursor, off2 - cursor))
        cursor = max(cursor, end2)
        covered += end2 - off2
    if cursor < hi:
        gaps.append((cursor, hi - cursor))
    print(f"  data region [0x40, 0x{e_shoff:x}) = {e_shoff-0x40:,} B")
    print(f"  covered by sections: {covered:,} B; gaps: "
          + ", ".join(f"[0x{g:08x} +{n:,}]" for g, n in gaps) if gaps else "  no gaps")
    # the fwimage window
    fwi_len = FWI.stat().st_size
    print(f"  fwimage.bin = gsp[0x40 : 0x{0x40+fwi_len:x}) ({fwi_len:,} B); "
          f"tail gap to e_shoff = {e_shoff - 0x40 - fwi_len:,} B")
    return spans, gaps

def s3(data):
    print("\n== S3: the gzip-magic hits — real streams? ==")
    verdict = []
    pos = 0
    tested = 0
    while True:
        i = data.find(b"\x1f\x8b\x08", pos)
        if i < 0:
            break
        pos = i + 1
        tested += 1
        if tested > 12:
            break
        try:
            d = zlib.decompressobj(wbits=-15)
            out = d.decompress(data[i+10:i+10+65536])
            ok = len(out) > 16
        except Exception:
            out, ok = b"", False
        ctx = data[i+4:i+10].hex()
        verdict.append(dict(offset=i, hdr_follow=ctx, decompresses=ok,
                            out_len=len(out) if ok else 0,
                            sample=(out[:24].decode('latin1') if ok else None)))
        print(f"  @0x{i:08x} next={ctx} -> {'OK '+str(len(out))+' B: '+repr(out[:24]) if ok else 'NOT a deflate stream'}")
    return verdict

def s4(data):
    print("\n== S4: the odd ELF magic @0x1cefb3e ==")
    i = 0x1cefb3e
    chunk = data[i:i+32]
    print(f"  bytes: {chunk[:16].hex()} ...")
    real = chunk[:4] == b"\x7fELF" and chunk[4] == 2 and chunk[5] == 1
    print(f"  plausible ELF (class2/data1): {real}")
    return dict(offset=i, plausible=real, head_hex=chunk[:16].hex())

def s5(hdr, shdrs):
    print("\n== S5: cross-map with v424_gfw_directory.json (fwimage coords -> gsp = +0x40) ==")
    gfw = json.loads(GFW_JSON.read_text())
    rows = []
    for comp in gfw["regions"]:
        name, at = comp["name"], int(comp["at"], 16)
        g_at = at + 0x40
        holder = None
        for s in shdrs:
            if s["sh_offset"] <= g_at < s["sh_offset"] + max(s["sh_size"], 1) and s["sh_size"] > 0:
                holder = s["name"]
                break
        regs = [dict(vaddr=r["vaddr"], fw_at=r["window"][3], fw_size=r["window"][4])
                for r in comp.get("regions", [])]
        for r in regs:
            r["gsp_at"] = hex(int(r["fw_at"], 16) + 0x40)
        rows.append(dict(component=name, dir_at_fwi=hex(at), dir_at_gsp=hex(g_at),
                         section_holder=holder, load_regions=regs))
        print(f"  {name:9s} dir@fwi 0x{at:06x} -> gsp 0x{g_at:06x} in section: {holder}; regions: "
              + "; ".join(f"{r['vaddr']}@gsp {r['gsp_at']} +0x{int(r['fw_size'],16):x}" for r in regs))
    cont = gfw.get("containment", {})
    for k, v in cont.items():
        g_off = int(v["present_at"], 16) + 0x40
        holder = None
        for s in shdrs:
            if s["sh_offset"] <= g_off < s["sh_offset"] + max(s["sh_size"], 1) and s["sh_size"] > 0:
                holder = s["name"]
                break
        print(f"  containment {k}: fwi 0x{int(v['present_at'],16):x} -> gsp 0x{g_off:x} in section: {holder}")
    return rows

def main():
    data, hdr, shdrs = parse()
    print(f"ELF: e_type={hdr['e_type']} e_machine={hdr['e_machine']:#x} "
          f"e_shoff=0x{hdr['e_shoff']:x} e_shnum={hdr['e_shnum']} "
          f"e_shstrndx={hdr['e_shstrndx']} e_phnum={hdr['e_phnum']}")
    spans, gaps = s1_s2(data, hdr, shdrs)
    gz = s3(data)
    odd = s4(data)
    xmap = s5(hdr, shdrs)
    OUT.write_text(json.dumps(dict(
        elf=hdr,
        sections=[{k: (hex(v) if isinstance(v, int) and k != 'index' and k != 'sh_type' and k != 'sh_link' and k != 'sh_info' and k != 'sh_addralign' and k != 'sh_entsize' and k != 'sh_name' else v)
                   for k, v in s.items()} for s in shdrs],
        coverage=dict(data_region_end=hex(hdr['e_shoff']),
                      gaps=[(hex(g), n) for g, n in gaps]),
        gzip_hits=gz, odd_elf=odd, gfw_crossmap=xmap,
    ), indent=1))
    print(f"\nwritten: {OUT}")

if __name__ == "__main__":
    main()
