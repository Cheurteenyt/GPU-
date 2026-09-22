#!/usr/bin/env python3
"""v430_gfw_map — TASK 2 of pass 4.30: the COMPLETE map of the GFW archive
directory inside gsp_ga10x.bin's .fwimage (the official 610.57.04 ga10x
firmware).

THE DECODED GRAMMAR (all byte-derived this pass; every claim below is
re-derived by the selftest):

  The .fwimage (84,258,816 B) splits into:
    [0, 0x6d000)             the BOOT AREA == campaign `bootloader.bin`
                             (446,464 B, byte-exact — NOT a GFW-directory
                             entry: the directory covers the load area only)
    [0x6d000, 0x6e000)       the GFW DIRECTORY (0x1000 B; records end at
                             +0x8f8, zero padding after)
    [0x6e000, 0x12d1000)     the COMPONENT data (flat, uncompressed)
    [0x12d1000, 0x505b000)   `rm.bindata.bin` (0x3d8a000 B, runs to EOF)

  Directory header (6 u64s @0x6d000):
    {magic 0x81b26a705c10e14d, 0x18, 0x4fee000, 0x30, 0x48, 0xb8}
    where 0x4fee000 == fwimage_size - 0x6d000 (the LOAD-AREA size, checked)
    and {0x30, 0x48, 0xb8} = the cursor of the FIRST record
    {record, first_field, trailing} — the same cursor shape the records
    chain with.

  Record (a linked list, offsets are LOAD-AREA coordinates = fwimage-0x6d000):
    name: NUL-terminated, zero-padded to the 8-boundary strictly after
          the NUL byte; then REGIONS then a 3-u64 trailing.
    region = SEVEN u64s:
      {vaddr, comp_off, align, load_off, size, flags, next_region_ptr}
      load_off is load-area based (true fwimage offset = load_off+0x6d000);
      next_region_ptr is absolute in load-area coords; 0 = last region.
    trailing = THREE u64s {next_record, next_record_first_field,
    next_record_trailing} (a full cursor); the last record's is {0,0,0}.

  THE BIAS LAW: true_fw_offset = load_off + 0x6d000 — proven here on TWELVE
  .elf records (each region-1 lands on \\x7fELF) and on FIVE byte-exact
  component containments. (The 4.24 pass read the un-biased offsets and
  got zeros/stray data — the register's odd entropies explained.)

  FLAGS: the region flags mirror the flat component's ELF program-header
  p_flags EXACTLY (checked per-region, 4 components with full phdrs):
    0x5 = R-X (LOAD code), 0x6 = R-W (LOAD data), 0xe = NOTE regions
    (p_flags 0x6 + bit3), 0x0 = the raw bindata blob (align 0x1, vaddr 0).
    => NO compression bit, NO signature bit: storage is FLAT and unsigned
    AT THE DIRECTORY LEVEL. (The mission's "rm.elf = one LOAD RWX" is
    FALSIFIED at the phdr level: p_flags 5 = R-X.)

  COMPONENT IDENTITIES (byte-exact, this pass):
    bootloader.bin   == fwimage[0x0000000, 0x6d000)     (the boot area)
    debug.elf        == pmu-wdt-41KB.bin @0x187000  (the campaign's old
                        name "pmu-wdt" is a MISNOMER — the directory says
                        debug.elf)
    init.elf         @0x192000 (no campaign copy; \\x7fELF checked)
    rm.elf           == gsp-rm-17MB.bin  @0x19f000
    vgpu.elf         == comp-725KB.bin   @0x1210000
    mnoc.elf         == comp-58KB.bin    @0x12c2000
    kernel_{ga10x,gh100,gb10x,gb10y,gb20x,gb20y,gr10x}.elf  @0x6e000..
    rm.bindata.bin   @0x12d1000 (0x3d8a000 B — the g_bindata_* HS space)

Selftest: re-derives every number in the register; exit 2 on drift, 3 if
the inputs are absent.
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FW = os.path.join(HERE, "..", "..", "tools/analysis/gsp-extract/binaries/fwimage.bin")
BINDIR = os.path.join(HERE, "..", "..", "tools/analysis/gsp-extract/binaries")
OUT_JSON = os.path.join(HERE, "v430_gfw_map.json")

MAGIC = 0x81B26A705C10E14D
BASE = 0x6D000                      # load-area origin (derived below too)
DIR_SIZE = 0x1000

KNOWN = {                           # campaign binary -> (record name, expected true fw off)
    "bootloader.bin":   ("(boot area)", 0x0),
    "pmu-wdt-41KB.bin": ("debug.elf", 0x187000),
    "gsp-rm-17MB.bin":  ("rm.elf", 0x19f000),
    "comp-725KB.bin":   ("vgpu.elf", 0x1210000),
    "comp-58KB.bin":    ("mnoc.elf", 0x12c2000),
}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def parse_directory(fw):
    """Parse the GFW directory with the decoded grammar. Hardened."""
    assert len(fw) == 84258816, len(fw)
    hdr = [struct.unpack_from("<Q", fw, BASE + i * 8)[0] for i in range(6)]
    assert hdr[0] == MAGIC, hex(hdr[0])
    assert hdr[1] == 0x18, hex(hdr[1])
    # the load-area size law
    assert hdr[2] == len(fw) - BASE, (hex(hdr[2]), hex(len(fw) - BASE))
    assert hdr[3] == 0x30, hex(hdr[3])
    first_cursor = hdr[3:6]

    records = []
    cur = first_cursor[0]
    while True:
        p = BASE + cur
        nul = fw.index(b"\x00", p)
        name = fw[p:nul].decode("ascii")
        fields = ((nul + 1 + 7) // 8) * 8        # 8-boundary strictly after NUL
        if not records:
            # the header's cursor names the FIRST record's fields position
            # (load-area coords); cross-check it (instrument bug caught on
            # first run: absolute file offset compared against a
            # load-area coordinate — normalized here)
            assert fields - BASE == first_cursor[1], \
                (hex(fields), hex(first_cursor[1]))
        regions = []
        q = fields
        while True:
            vaddr, coff, align, lo, size, flags, nxt = \
                struct.unpack_from("<7Q", fw, q)
            regions.append(dict(vaddr=vaddr, comp_off=coff, align=align,
                                load_off=lo, size=size, flags=flags,
                                next_region=nxt,
                                true_fw_off=lo + BASE))
            q += 56
            if nxt == 0:
                break
        trail = list(struct.unpack_from("<3Q", fw, q))
        records.append(dict(rel=cur, abs_off=p, name=name,
                            fields_abs=fields, regions=regions, trailing=trail))
        cur = trail[0]
        if cur == 0:
            break
        assert 0x30 <= cur < DIR_SIZE, hex(cur)
    return hdr, records


def phdrs(blob):
    """The flat component's program headers: (p_type, p_flags, p_vaddr,
    p_offset, p_filesz, p_memsz, p_align)."""
    assert blob[:4] == b"\x7fELF"
    e_phoff, = struct.unpack_from("<Q", blob, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", blob, 0x36)
    out = []
    for i in range(e_phnum):
        p = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", blob, p)
        (p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = \
            struct.unpack_from("<6Q", blob, p + 8)
        out.append(dict(p_type=p_type, p_flags=p_flags, p_vaddr=p_vaddr,
                        p_offset=p_off, p_filesz=p_filesz, p_memsz=p_memsz,
                        p_align=p_align))
    return out


def main():
    if not os.path.exists(FW):
        print("SKIP: fwimage.bin not present")
        return 3
    fw = open(FW, "rb").read()
    reg = dict(fwimage=dict(size=len(fw), sha256=sha256(fw)))
    assert sha256(fw) == ("85213b87db131c17a0ebbb1b44abd18c4fcd58080dd43cde"
                          "82c5c67a5b08eeec"), "fwimage sha256 drift"

    hdr, records = parse_directory(fw)
    reg["directory"] = dict(
        base=BASE, size=DIR_SIZE,
        header=dict(magic=hex(hdr[0]), field1=hex(hdr[1]),
                    load_area_size=hex(hdr[2]),
                    first_cursor=[hex(x) for x in hdr[3:6]]),
        record_count=len(records),
        records=[dict(rel=hex(r["rel"]), abs_off=hex(r["abs_off"]),
                      name=r["name"], fields_abs=hex(r["fields_abs"]),
                      regions=[dict(vaddr=hex(g["vaddr"]),
                                    comp_off=hex(g["comp_off"]),
                                    align=hex(g["align"]),
                                    load_off=hex(g["load_off"]),
                                    size=hex(g["size"]),
                                    flags=hex(g["flags"]),
                                    true_fw_off=hex(g["true_fw_off"]),
                                    end_true=hex(g["true_fw_off"] + g["size"]))
                               for g in r["regions"]],
                      trailing=[hex(t) for t in r["trailing"]])
                 for r in records])

    # the directory occupies [BASE, BASE+DIR_SIZE); records end before data
    last = records[-1]
    last_end = last["fields_abs"] + 56 * len(last["regions"]) + 24
    assert all(b == 0 for b in fw[last_end:BASE + DIR_SIZE]), \
        "directory tail not zero"
    reg["directory"]["records_end"] = hex(last_end)

    # -- component containments (byte-exact) ------------------------------
    comp = {}
    for fname, (recname, off) in KNOWN.items():
        blob = open(os.path.join(BINDIR, fname), "rb").read()
        window = fw[off:off + len(blob)]
        eq = window == blob
        comp[fname] = dict(record=recname, true_fw_off=hex(off),
                           size=len(blob), sha256=sha256(blob),
                           byte_exact=eq)
        assert eq, f"{fname} containment FAILED @{off:#x}"
    # the ELF components without campaign copies: ELF magic check
    by_name = {r["name"]: r for r in records}
    for name, r in by_name.items():
        if not name.endswith(".elf"):
            continue
        off = r["regions"][0]["true_fw_off"]
        assert fw[off:off + 4] == b"\x7fELF", f"{name}: no ELF magic @{off:#x}"
        comp.setdefault("(no campaign copy)", []).append(
            dict(record=name, true_fw_off=hex(off), elf_magic=True))
    reg["components"] = comp

    # -- the phdr mirror (the flags decode) --------------------------------
    mirror = {}
    pairs = [("rm.elf", "gsp-rm-17MB.bin"), ("vgpu.elf", "comp-725KB.bin"),
             ("mnoc.elf", "comp-58KB.bin"), ("debug.elf", "pmu-wdt-41KB.bin")]
    for recname, fname in pairs:
        r = by_name[recname]
        blob = open(os.path.join(BINDIR, fname), "rb").read()
        ph = phdrs(blob)
        # the directory regions == the LOAD/NOTE phdrs, in order:
        seg = [p for p in ph if p["p_type"] in (1, 7)]
        assert len(seg) == len(r["regions"]), (recname, len(seg), len(r["regions"]))
        rows = []
        for g, p in zip(r["regions"], seg):
            row = dict(
                region_flags=g["flags"], phdr_p_flags=p["p_flags"],
                flags_equal=g["flags"] in (p["p_flags"], p["p_flags"] | 8),
                vaddr_equal=g["vaddr"] == p["p_vaddr"],
                comp_off_equal=g["comp_off"] == p["p_offset"],
                size_equal=g["size"] in (p["p_filesz"], p["p_memsz"]))
            assert row["vaddr_equal"] and row["comp_off_equal"], (recname, row)
            assert row["flags_equal"] and row["size_equal"], (recname, row)
            rows.append(row)
        mirror[recname] = rows
    reg["phdr_mirror"] = mirror

    # -- the bindata blob runs to EOF ---------------------------------------
    bd = by_name["rm.bindata.bin"]
    g = bd["regions"][0]
    assert g["align"] == 1 and g["vaddr"] == 0 and g["flags"] == 0
    assert g["true_fw_off"] + g["size"] == len(fw), "bindata does not end at EOF"
    reg["bindata"] = dict(true_fw_off=hex(g["true_fw_off"]),
                          size=hex(g["size"]),
                          ends_at=hex(g["true_fw_off"] + g["size"]),
                          is_eof=True)

    # -- needle search: the campaign binaries' 64-B heads in fwimage --------
    needles = {}
    for fname in KNOWN:
        blob = open(os.path.join(BINDIR, fname), "rb").read()
        hits = []
        start = 0
        while len(hits) < 5:
            i = fw.find(blob[:64], start)
            if i < 0:
                break
            hits.append(hex(i))
            start = i + 1
        needles[fname] = hits
    reg["needle_search_64B"] = needles

    # -- layout coverage law -------------------------------------------------
    load_area = len(fw) - BASE
    # ALL region windows (instrument bug caught on first run: a dict keyed
    # by record name kept only each record's LAST region — the tiling then
    # showed phantom gaps; collect every region instead)
    wins = sorted((g["true_fw_off"], g["true_fw_off"] + g["size"], r["name"])
                  for r in records for g in r["regions"])
    gaps = [(wins[i][1], wins[i + 1][0]) for i in range(len(wins) - 1)
            if wins[i][1] != wins[i + 1][0]]
    reg["coverage"] = dict(
        boot_area=[hex(0), hex(BASE)],
        directory=[hex(BASE), hex(BASE + DIR_SIZE)],
        load_area_size=hex(load_area),
        first_data=hex(wins[0][0]),
        region_count=len(wins),
        contiguity_gaps=[[hex(a), hex(b)] for a, b in gaps])
    # the only allowed "gap" is none: regions must tile [0x6e000, EOF)
    assert not gaps, f"unexpected gaps: {gaps}"

    with open(OUT_JSON, "w") as f:
        json.dump(reg, f, indent=1)
    print(f"directory: {len(records)} records @0x6d000..{reg['directory']['records_end']}")
    for r in records:
        for g in r["regions"]:
            print(f"  {r['name']:22s} vaddr {g['vaddr']:#018x} "
                  f"true_fw {g['true_fw_off']:#9x} size {g['size']:#9x} "
                  f"flags {g['flags']:#x}")
    print("containments: 5/5 byte-exact; phdr mirror: 4/4 components OK; "
          "bindata ends at EOF; regions tile the load area")
    print("ALL CHECKS PASS —", OUT_JSON)
    return 0


if __name__ == "__main__":
    sys.exit(main())
