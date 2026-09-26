#!/usr/bin/env python3
"""v463a_vbios_decode — the 4.63 ROM decoder: identity gates + the power
budget, re-derived per-ROM (no hardcoded offsets — the LHR-seam lesson).

Grammar = the ring-3 banked decode (gx3-perf, findings-gx3, 2026-09-15),
re-derived from scratch on every input:

  ROM chain     : 0x55AA images, PCIR @0x18, image_length @PCIR+0x10 (×512),
                  code_type @PCIR+0x14 (0x00 legacy x86, 0x03 EFI).
  BIT table     : the 6-byte magic ff b8 'B' 'I' 'T' 00 inside the legacy
                  image; hlen @+8, rlen @+9, count @+10; tokens at
                  BIT+hlen+i*rlen, token id = first byte, pointer u16 @+4.
  'P' table     : the token id 'P' pointer → the performance table v2;
                  58 dword pointers; pointer #11 (rel 44) = POWER BUDGET.
  Pointer rule  : raw > legacy image length → raw + UEFI image length
                  (the spec's own rule; the tail is the table farm).
  POWER BUDGET  : version 0x30, hlen @+1, rlen @+2, count @+3,
                  cap index @+0xA (which entry is THE cap);
                  entry k base = table + hlen + k*rlen;
                  min u32 mW @+2, avg u32 mW @+6, peak u32 mW @+10.

  On the verified sibling specimen (MSI.RTX3070.8192.210519_1.rom,
  sha256_16 41a0860f8abfcfa7): budget @0x8FB48, cap entry 2 =
  {100000, 240000, 250000} — min 100 W floor, avg 240 W default,
  peak 250 W maximum; 250000 mW lives at 0x8FC0C.

The 4.63 mission adds the IDENTITY GATE that the day-0 VFIO sessions
taught the hard way (35 sessions, the 0000 trap): before ANY flash the
image's PCI identity must be INTACT — vendor 10DE, device 2488, nonzero
subsystem — and named aloud, because the modded unlock.rom staged a
zeroed head and nvflash answered "GPU PCI Device ID mismatch … Nothing
changed!" every time.

Selftest: --selftest builds synthetic fixtures (the correct grammar with
planted values + the zeroed-ID trap + the wrong-grammar trap) and runs
the whole battery host-only. Zero GPU, zero boot.

── 4.63a (the founder admission day, 2026-09-26) — three corrections the
REAL target file taught ────────────────────────────────────────────────

1. THE NVGI CONTAINER: TechPowerUp now serves .rom downloads wrapped in
   NVIDIA's own NVGI flash-image container ("NVGI" magic). The active
   image = the first 55AA whose PCI chain parses — in the GA10x layout
   the PCIR sits at image_start+0x170 (verified on TWO independent
   genuine sources: our own chip's dump 94.04.46.00.EB and the TPU
   archive 94.04.46.00.E5). nvgi_extract() splits them; the ring-12/14
   hash admission = computed on the FILE AS DOWNLOADED (the container),
   the grammar decode = on the extracted raw. THE FLASH FILE = THE RAW.

2. THE SUBSYSTEM GATE, CORRECTED: the day-0 35-session trap = the
   zeroed PCI *Device ID* ("Firmware image PCI Device ID (0000) …
   mismatch. Nothing changed!"). The zeroed *subsystem* = THE MSI
   FAMILY NORM in the ROM image: our own chip's ROM reads 0000:0300
   while lspci reports the LIVE 1462:3904 — the subsystem = loaded
   from the strap region, not baked in the image. Verdict law now:
   vendor != 10de OR device zero/!=2488 → REFUSED; subsystem zero →
   OK with the named note (the nvflash SUBSYSTEM mismatch = the
   patched binary's job, unchanged).

3. THE P-TABLE v0x4D FALLBACK: the .E5 target carries a P table
   version 0x4D (the ring-3 grammar named v2 + budget v0x30). The
   budget cluster = the 4-aligned consecutive u32 triple
   {min ≤ 150000, cap, max} with all three in the mW census net —
   on the admitted target exactly ONE such triple exists:
   0x86A04 = {100000, 280000, 300000}. The other 280000 hits fail
   the shape (unaligned, or max outside the net) — the census itself
   is the grammar when the named one doesn't parse.
"""
import argparse
import hashlib
import struct
import sys

MAGICS = {
    "rom_head": b"\x55\xaa",
    "bit": b"\xff\xb8BIT\x00",
    "pcir": b"PCIR",
}

BUDGET_VERSION = 0x30
P_TABLE_VERSION = 2
POWER_BUDGET_REL = 44  # the P-table pointer index (rel 44, ring-3)

# the mW universe the campaign has ever seen in a power field (the scan net)
SCAN_MW = [100000, 150000, 175000, 220000, 226800, 240000, 250000, 252000,
           265000, 280000, 300000, 5001000]


def sha(data):
    return {
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
    }


def images(rom):
    """The PCI expansion-ROM chain, walked the chip's own way."""
    out, base = [], 0
    while base + 0x20 <= len(rom):
        if rom[base:base + 2] != MAGICS["rom_head"]:
            break
        pcir = base + struct.unpack_from("<H", rom, base + 0x18)[0]
        if rom[pcir:pcir + 4] != MAGICS["pcir"]:
            break
        length = struct.unpack_from("<H", rom, pcir + 0x10)[0] * 512
        code_type = rom[pcir + 0x14]
        indicator = rom[pcir + 0x15]
        out.append({"base": base, "pcir": pcir, "length": length,
                    "code_type": code_type, "indicator": indicator,
                    "vendor": struct.unpack_from("<H", rom, pcir + 4)[0],
                    "device": struct.unpack_from("<H", rom, pcir + 6)[0]})
        if indicator & 0x80:
            break
        base += length
        if len(out) > 8:
            break
    return out


def identity(rom):
    """The identity table the 0000 trap taught: every field named."""
    imgs = images(rom)
    if not imgs:
        return {"verdict": "REFUSED", "reason": "no 55AA image found"}
    legacy = next((i for i in imgs if i["code_type"] == 0), imgs[0])
    ident = {
        "vendor": f"{legacy['vendor']:04x}",
        "device": f"{legacy['device']:04x}",
        "code_types": [i["code_type"] for i in imgs],
        "images": len(imgs),
        "total_chain": imgs[-1]["base"] + imgs[-1]["length"],
    }
    # subsystem lives in the PCI data structure (vendor @+0xC, id @+0xE)
    if legacy["pcir"] + 0x10 <= len(rom):
        svid = struct.unpack_from("<H", rom, legacy["pcir"] + 0xC)[0]
        sid = struct.unpack_from("<H", rom, legacy["pcir"] + 0xE)[0]
        ident["subsystem_vendor"] = f"{svid:04x}"
        ident["subsystem_id"] = f"{sid:04x}"
    # the version string "94.04.46.00.EB" lives in the head (scan 0x0-0x200)
    head = rom[:0x200]
    import re
    m = re.search(rb"94\.04\.[0-9A-Fa-f]{2}\.[0-9A-Fa-f]{2}\.[0-9A-Fa-f]{2}",
                  head)
    ident["version_string"] = m.group(0).decode() if m else None
    verdict = "OK"
    reasons = []
    if legacy["vendor"] != 0x10DE:
        verdict, _ = "REFUSED", reasons.append(f"vendor {legacy['vendor']:04x} != 10de")
    if legacy["device"] != 0x2488:
        verdict, _ = "REFUSED", reasons.append(
            f"device {legacy['device']:04x} != 2488 — THE 0000 TRAP (day-0)")
    if ident.get("subsystem_vendor") in ("0000", None) or \
       ident.get("subsystem_id") in ("0000", None):
        # 4.63a: NOT a refusal — the zeroed subsystem = the MSI family norm
        # in the ROM image (our own chip .EB + the TPU archive .E5 = both
        # 0000:0300; the live 1462:3904 = the strap region, not the image).
        ident["subsystem_note"] = ("zeroed subsystem = the MSI family norm "
                                   "(chip-own .EB + TPU .E5 both 0000:0300)")
    ident["verdict"] = verdict
    ident["reasons"] = reasons
    return ident


def nvgi_extract(data):
    """The NVGI container split (4.63a): the active image = the first 55AA
    whose PCI chain parses. Returns (raw, offset) — (data, 0) unchanged."""
    if data[:4] != b"NVGI":
        return data, 0
    pos = 0
    while True:
        pos = data.find(MAGICS["rom_head"], pos)
        if pos < 0:
            raise SystemExit("error: NVGI container, no parsable 55AA image")
        if images(data[pos:]):
            return data[pos:], pos
        pos += 1


def power_budget(rom):
    """The ring-3 grammar, re-derived from scratch; nothing hardcoded."""
    imgs = images(rom)
    if not imgs:
        raise SystemExit("error: no image")
    legacy = next((i for i in imgs if i["code_type"] == 0), imgs[0])
    efi_len = next((i["length"] for i in imgs if i["code_type"] == 3), 0)

    bit = rom.find(MAGICS["bit"], legacy["base"],
                   legacy["base"] + legacy["length"])
    if bit < 0:
        raise SystemExit("error: BIT table not found")
    hlen, rlen, count = rom[bit + 8], rom[bit + 9], rom[bit + 10]
    token = None
    for i in range(count):
        off = bit + hlen + i * rlen
        if rom[off:off + 1] == b"P":
            token = legacy["base"] + struct.unpack_from("<H", rom, off + 4)[0]
            break
    if token is None:
        raise SystemExit("error: no 'P' token in BIT")

    pver = rom[token]
    if pver != P_TABLE_VERSION:
        raise SystemExit(f"error: P table version {pver:#x} != 2")

    def resolve(raw):
        return legacy["base"] + raw if raw <= legacy["length"] \
            else legacy["base"] + raw + efi_len

    praw = struct.unpack_from("<I", rom, token + 8 + POWER_BUDGET_REL)[0]
    boff = resolve(praw)
    if boff + 16 > len(rom):
        raise SystemExit(f"error: budget @{boff:#x} beyond the image "
                         "(the full-dump law: the sysfs window is not enough)")
    ver, bh, br, cnt = rom[boff], rom[boff + 1], rom[boff + 2], rom[boff + 3]
    if ver != BUDGET_VERSION:
        raise SystemExit(f"error: budget version {ver:#x} != 0x30 — refusing")
    cap = rom[boff + 0xA]
    entry = boff + bh + cap * br
    vals = {"min_mw": struct.unpack_from("<I", rom, entry + 2)[0],
            "avg_mw": struct.unpack_from("<I", rom, entry + 6)[0],
            "peak_mw": struct.unpack_from("<I", rom, entry + 10)[0]}
    all_entries = []
    for k in range(min(cnt, 24)):
        e = boff + bh + k * br
        all_entries.append(
            {"k": k, "min_mw": struct.unpack_from("<I", rom, e + 2)[0],
             "avg_mw": struct.unpack_from("<I", rom, e + 6)[0],
             "peak_mw": struct.unpack_from("<I", rom, e + 10)[0]})
    return {"bit_offset": bit, "bit_tokens": count, "p_token": token,
            "budget_offset": boff, "budget_version": ver,
            "budget_hlen": bh, "budget_rlen": br, "budget_count": cnt,
            "cap_entry": cap, "entry_offset": entry, **vals,
            "entries": all_entries,
            "entry_bytes": {"min": f"@{entry+2:#x}", "avg": f"@{entry+6:#x}",
                            "peak": f"@{entry+10:#x}"}}


def budget_cluster(rom):
    """The v0x4D fallback (4.63a): when the named ring-3 grammar doesn't
    parse (the .E5's P table = version 0x4D), the budget = the 4-aligned
    consecutive u32 triple {min ≤ 150000, cap, max} — all three in the
    mW census net, max ≥ cap. The census IS the grammar when the named
    one doesn't parse. On the admitted target: exactly one triple."""
    net = set(SCAN_MW)
    cands = []
    for val in SCAN_MW:
        if not (220000 <= val <= 300000):   # the cap-class universe
            continue
        for cap_off in scan_mw(rom).get(val, []):
            base = cap_off - 4
            if base < 0 or base % 4 or base + 12 > len(rom):
                continue
            mn = struct.unpack_from("<I", rom, base)[0]
            if mn not in net or mn > 150000:
                continue
            mx = struct.unpack_from("<I", rom, base + 8)[0]
            if mx not in net or mx < val:
                continue
            cands.append({"cluster_offset": base, "min_mw": mn,
                          "peak_mw": val, "max_mw": mx,
                          "entry_bytes": {"min": f"@{base+4:#x}",
                                          "avg": f"@{base+8:#x}",
                                          "peak": f"@{base:#x}"}})
    if not cands:
        raise SystemExit("error: no budget cluster (min/cap/max triple) found")
    if len(cands) > 1:
        raise SystemExit(f"error: {len(cands)} budget clusters — ambiguous")
    c = cands[0]
    c.update({"grammar": "cluster (P table v0x4D — the named grammar did not parse)"})
    return c


def scan_mw(rom):
    """The whole-image u32-LE mW census (the 4.38 pair-scanner law)."""
    hits = {}
    for val in SCAN_MW:
        pat = struct.pack("<I", val)
        start = 0
        while True:
            i = rom.find(pat, start)
            if i < 0:
                break
            hits.setdefault(val, []).append(i)
            start = i + 1
    return hits


def decode(rom):
    rom, _ = nvgi_extract(rom)      # idempotent: the container or the raw
    ident = identity(rom)
    out = {"identity": ident, "sha": sha(rom)}
    if ident["verdict"] == "OK":
        try:
            out["power_budget"] = power_budget(rom)
        except SystemExit as e:
            if "P table version" not in str(e):
                raise
            out["power_budget"] = budget_cluster(rom)
    out["scan"] = {str(k): v for k, v in scan_mw(rom).items()}
    return out


# ─────────────────────────── selftest fixtures ───────────────────────────

def build_fixture(peak=280000, avg=265000, mn=100000, zero_ids=False,
                  bad_grammar=False, zero_subsys=False):
    """A synthetic but grammar-correct minimal ROM.

    1536 B = legacy 512 + EFI 512 + the 512-B data tail BEYOND the PCI
    image chain — the table farm, exactly where the real ROM keeps the
    power budget (the vbios-power-mod law).

    zero_ids zeroes ALL identity fields (the day-0 modded head);
    zero_subsys zeroes ONLY the subsystem (the MSI family norm).
    """
    legacy_len = 512
    efi_len = 512
    rom = bytearray(legacy_len + efi_len + 512)
    rom[0:2] = b"\x55\xaa"
    pcir = 0x40
    struct.pack_into("<H", rom, 0x18, pcir)
    rom[pcir:pcir + 4] = b"PCIR"
    struct.pack_into("<H", rom, pcir + 0x10, legacy_len // 512)
    rom[pcir + 0x14] = 0            # legacy x86
    rom[pcir + 0x15] = 0            # not last
    struct.pack_into("<H", rom, pcir + 4, 0x0000 if zero_ids else 0x10DE)
    struct.pack_into("<H", rom, pcir + 6, 0x0000 if zero_ids else 0x2488)
    struct.pack_into("<H", rom, pcir + 0xC,
                     0x0000 if (zero_ids or zero_subsys) else 0x1462)
    struct.pack_into("<H", rom, pcir + 0xE,
                     0x0000 if (zero_ids or zero_subsys) else 0x3884)

    # EFI image second
    efi = legacy_len
    rom[efi:efi + 2] = b"\x55\xaa"
    pcir2 = efi + 0x40
    struct.pack_into("<H", rom, efi + 0x18, 0x40)
    rom[pcir2:pcir2 + 4] = b"PCIR"
    struct.pack_into("<H", rom, pcir2 + 0x10, efi_len // 512)
    rom[pcir2 + 0x14] = 3
    rom[pcir2 + 0x15] = 0x80

    # BIT table inside the legacy image
    bit = 0x100
    rom[bit:bit + 6] = b"\xff\xb8BIT\x00"
    rom[bit + 8] = 12               # hlen
    rom[bit + 9] = 8                # rlen
    rom[bit + 10] = 2               # count: 2 tokens (filler + 'P')
    struct.pack_into("<H", rom, bit + 12 + 0 * 8 + 4, 0x80)   # filler
    tok_off = bit + 12 + 1 * 8
    rom[tok_off:tok_off + 1] = b"P"
    struct.pack_into("<H", rom, tok_off + 4, 0x180)  # raw P-table ptr

    # P table (v2) at legacy 0x180
    p = 0x180
    rom[p] = 2
    # pointers start at p+8; pointer #11 (rel 44) = POWER BUDGET
    praw = legacy_len + 0x40        # raw > legacy length → lands in the tail
    struct.pack_into("<I", rom, p + 8 + POWER_BUDGET_REL, praw)

    # the budget table in the tail (after the EFI image → resolve +efi_len)
    b = praw + efi_len
    if bad_grammar:
        rom[b] = 0x31               # wrong version
    else:
        rom[b] = 0x30
    rom[b + 1] = 16                 # hlen
    rom[b + 2] = 16                 # rlen
    rom[b + 3] = 4                  # count
    rom[b + 0xA] = 2                # cap index = entry 2
    for k, (mnk, avgk, peakk) in enumerate(
            [(100000, 200000, 220000), (100000, 220000, 240000),
             (mn, avg, peak), (100000, 250000, 252000)]):
        e = b + 16 + k * 16
        struct.pack_into("<I", rom, e + 2, mnk)
        struct.pack_into("<I", rom, e + 6, avgk)
        struct.pack_into("<I", rom, e + 10, peakk)
    return bytes(rom)


def selftest():
    ok, tot = 0, 0

    def chk(name, cond):
        nonlocal ok, tot
        tot += 1
        if cond:
            ok += 1
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name}")

    # 1 — the good fixture: full grammar decode, cap entry 2, 280000 peak
    rom = build_fixture()
    d = decode(rom)
    ident = d["identity"]
    chk("identity OK on the intact fixture", ident["verdict"] == "OK")
    chk("vendor named 10de", ident["vendor"] == "10de")
    chk("device named 2488", ident["device"] == "2488")
    chk("subsystem named 1462:3884",
        ident["subsystem_vendor"] == "1462" and ident["subsystem_id"] == "3884")
    pb = d.get("power_budget", {})
    chk("budget version 0x30", pb.get("budget_version") == 0x30)
    chk("cap entry = 2", pb.get("cap_entry") == 2)
    chk("peak = 280000 mW", pb.get("peak_mw") == 280000)
    chk("avg = 265000 mW", pb.get("avg_mw") == 265000)
    chk("min = 100000 mW", pb.get("min_mw") == 100000)
    chk("pointer rule crossed into the tail",
        pb.get("budget_offset", 0) >= 1024)
    scan = d["scan"]
    chk("scan finds 280000", "280000" in scan)
    chk("scan finds 240000 and 250000 (the cap-1/entry markers)",
        "240000" in scan and "250000" in scan)

    # 2 — THE 0000 TRAP: zeroed identity → REFUSED, no budget decode
    romz = build_fixture(zero_ids=True)
    dz = decode(romz)
    chk("zeroed IDs REFUSED (the day-0 35-session trap)",
        dz["identity"]["verdict"] == "REFUSED")
    chk("trap names the zeroed DEVICE (4.63a: the device = the trap)",
        any("2488" in r for r in dz["identity"].get("reasons", [])))
    chk("no budget object on a refused image",
        "power_budget" not in dz)

    # 2b — THE 4.63a CORRECTION: zeroed SUBSYSTEM alone = OK (the MSI norm:
    # our own chip .EB + the TPU archive .E5 = both 0000:0300)
    roms = build_fixture(zero_subsys=True)
    ds = decode(roms)
    chk("zeroed subsystem alone = OK (the MSI family norm)",
        ds["identity"]["verdict"] == "OK")
    chk("the norm is NAMED, not silent",
        "family norm" in ds["identity"].get("subsystem_note", ""))

    # 2c — THE NVGI CONTAINER: wrap the good fixture, the decode survives
    nvgi = b"NVGI" + b"\x00" * 0x20 + b"\x00" * 0x100 + bytes(rom)
    dn = decode(nvgi)
    chk("NVGI-wrapped fixture decodes",
        dn["identity"]["verdict"] == "OK" and
        dn["power_budget"]["peak_mw"] == 280000)
    raw, off = nvgi_extract(nvgi)
    chk("nvgi_extract finds the image (the first parsable 55AA)",
        off > 0 and raw == bytes(rom))
    raw2, off2 = nvgi_extract(bytes(rom))
    chk("non-NVGI input passes through untouched", off2 == 0 and raw2 == bytes(rom))

    # 2d — THE v0x4D CLUSTER FALLBACK: the P token = version 0x4D and the
    # budget = the .E5-style ALIGNED triple appended in the tail
    romc = bytearray(build_fixture())
    p = 0x180                       # the fixture's P table address
    romc[p] = 0x4D                  # the .E5-era P version
    romc[0x600:0x60c] = struct.pack("<III", 100000, 280000, 300000)
    dc = decode(bytes(romc))
    pb = dc.get("power_budget", {})
    chk("v0x4D P table falls back to the cluster grammar",
        pb.get("grammar", "").startswith("cluster"))
    chk("cluster still names the peak", pb.get("peak_mw") == 280000)
    chk("cluster min/max named",
        pb.get("min_mw") == 100000 and pb.get("max_mw") == 300000)
    chk("cluster offset named and aligned",
        pb.get("cluster_offset", 1) % 4 == 0)

    # 3 — the wrong-grammar trap: budget v0x31 → the refusal raises
    romg = build_fixture(bad_grammar=True)
    try:
        decode(romg)
        chk("bad grammar refused (exception)", False)
    except SystemExit as e:
        chk("bad grammar refused (exception)", "0x31" in str(e) or "version" in str(e))

    # 4 — the ring-3 banked numbers hold on a replica of OUR family
    rom2 = build_fixture(peak=250000, avg=240000)
    d2 = decode(rom2)
    pb2 = d2["power_budget"]
    chk("our-family replica: peak 250000", pb2["peak_mw"] == 250000)
    chk("our-family replica: avg 240000", pb2["avg_mw"] == 240000)
    chk("our-family replica: the 250000 offset is named",
        pb2["entry_bytes"]["peak"].startswith("@"))

    # 5 — sha admission helpers
    chk("sha256_16 is 16 hex", len(d["sha"]["sha256_16"]) == 16)

    print(f"\nselftest: {ok}/{tot}")
    return 0 if ok == tot else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rom", nargs="?", help="the ROM image to decode")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--expect-md5", help="the TPU-published MD5 (admission gate)")
    ap.add_argument("--expect-sha1", help="the TPU-published SHA1 (admission gate)")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.rom:
        ap.error("a ROM path or --selftest is required")

    data = open(args.rom, "rb").read()
    fsha = sha(data)                 # the admission basis = the file as downloaded
    raw, nvoff = nvgi_extract(data)
    d = decode(raw)

    print(f"== {args.rom}")
    print(f"   file: size {fsha['size']}  sha256_16 {fsha['sha256_16']}  "
          f"md5 {fsha['md5']}")
    if nvoff:
        rawpath = args.rom + ".raw.rom"
        with open(rawpath, "wb") as fh:
            fh.write(raw)
        rsha = sha(raw)
        print(f"   NVGI CONTAINER: the active image @ {nvoff:#x} — the "
              f"grammar decodes the raw")
        print(f"   raw:  size {rsha['size']}  sha256_16 {rsha['sha256_16']}  "
              f"md5 {rsha['md5']}")
        print(f"   ⇒ THE FLASH FILE = THE RAW: {rawpath}")
    if args.expect_md5:
        verdict = "MATCH" if fsha["md5"] == args.expect_md5.lower() else "MISMATCH"
        print(f"   md5 admission: {verdict} (expected {args.expect_md5})")
        if verdict == "MISMATCH":
            raise SystemExit("REFUSED: md5 admission failed — the ring-12/14 law")
    if args.expect_sha1:
        verdict = "MATCH" if fsha["sha1"] == args.expect_sha1.lower() else "MISMATCH"
        print(f"   sha1 admission: {verdict} (expected {args.expect_sha1})")
        if verdict == "MISMATCH":
            raise SystemExit("REFUSED: sha1 admission failed — the ring-12/14 law")

    ident = d["identity"]
    print(f"   identity: vendor {ident.get('vendor')} device "
          f"{ident.get('device')} subsystem "
          f"{ident.get('subsystem_vendor')}:{ident.get('subsystem_id')} "
          f"version {ident.get('version_string')} → {ident['verdict']}")
    if ident.get("subsystem_note"):
        print(f"      ℹ {ident['subsystem_note']}")
    for r in ident.get("reasons", []):
        print(f"      !! {r}")
    if ident["verdict"] == "REFUSED":
        raise SystemExit("REFUSED: the identity gate (the 0000 trap law)")

    pb = d["power_budget"]
    if "grammar" in pb:
        print(f"   POWER BUDGET (the {pb['grammar']}):")
        print(f"      cluster @{pb['cluster_offset']:#x}: min {pb['min_mw']} mW | "
              f"peak {pb['peak_mw']} mW | max {pb['max_mw']} mW")
        print(f"      ⇒ the cap = {pb['peak_mw']//1000} W maximum")
    else:
        print(f"   BIT @{pb['bit_offset']:#x} ({pb['bit_tokens']} tokens), "
              f"P table @{pb['p_token']:#x}")
        print(f"   POWER BUDGET @{pb['budget_offset']:#x} v{pb['budget_version']:#x} "
              f"hlen {pb['budget_hlen']} rlen {pb['budget_rlen']} "
              f"count {pb['budget_count']} cap_entry {pb['cap_entry']}")
        e = pb["entry_offset"]
        print(f"   CAP ENTRY: min {pb['min_mw']} mW @{e+2:#x} | avg {pb['avg_mw']} "
              f"mW @{e+6:#x} | peak {pb['peak_mw']} mW @{e+10:#x}")
        print(f"   ⇒ the cap = {pb['avg_mw']//1000} W default / "
              f"{pb['peak_mw']//1000} W maximum")
    scan = d["scan"]
    interesting = {k: v for k, v in scan.items()
                   if k in ("240000", "250000", "265000", "280000", "220000")}
    if interesting:
        print("   the mW census (240/250/265/280/220 kW-class values):")
        for k in sorted(interesting, key=int):
            print(f"      {k} mW ×{len(interesting[k])} @ "
                  + ", ".join(f"0x{x:x}" for x in interesting[k][:8]))


if __name__ == "__main__":
    main()
