#!/usr/bin/env python3
"""
4.42 TASK 1c — the RING CONFIG GLOBALS of the transfer function.

The function @0x100aec composes its context base a4 = 0x124000
(auipc a4, 0x23 @0x100afc + 0x504 @0x100b00 -> 0x100afc+0x23000+0x504
= 0x124000). The fields:
  [a4+0x488] = 0x124488 : the SLOT INDEX (auto-advancing, wraps)
  [a4+0x490] = 0x124490 : the CAPACITY (the wrap bound)
  [a4+0x498] = 0x124498 : the DEST BASE pointer
  [a4+0x4a0] = 0x1244a0 : the MAGIC BYTE (<<56 in the signature word)
  0x16d000              : the t3 subtractor (the signature offset base)
  0x16C082              : the config byte read by the neighbor wrapper

This tool reads the bootloader.elf phdrs, maps VA -> file offset, and
dumps the u64s at those VAs = the STATIC INIT (PROVEN bytes of OUR
image). Also scans the 0x16d000 region identity (what section lives
there).
"""
import struct, json

ELF = "tools/analysis/gsp-extract/bootloader.elf"
data = open(ELF, "rb").read()

assert data[:4] == b"\x7fELF", "not an ELF"
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
print(f"[+] phoff=0x{e_phoff:x} phentsize={e_phentsize} phnum={e_phnum}")

segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, off + 8)
    if p_type == 1:
        segs.append((p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
        print(f"  LOAD#{i}: off=0x{p_offset:x} va=0x{p_vaddr:x} filesz=0x{p_filesz:x} "
              f"memsz=0x{p_memsz:x} flags={p_flags:x}")

def va2off(va):
    for p_offset, p_vaddr, p_filesz, p_memsz, p_flags in segs:
        if p_vaddr <= va < p_vaddr + p_memsz:
            d = va - p_vaddr
            if d < p_filesz:
                return p_offset + d, True
            return p_offset + d, False  # in memsz only (BSS/zero-init)
    return None, False

def rd(va, n):
    off, in_file = va2off(va)
    if off is None:
        return None, "UNMAPPED"
    if not in_file:
        return b"\x00" * n, "BSS(zero-init at runtime)"
    return data[off:off + n], f"file@0x{off:x}"

out = {}
print("\n[+] the ring-config globals (STATIC INIT):")
for name, va, n in [
    ("slot_index  [0x124488]", 0x124488, 8),
    ("capacity    [0x124490]", 0x124490, 8),
    ("dest_base   [0x124498]", 0x124498, 8),
    ("magic_byte  [0x1244a0]", 0x1244a0, 1),
    ("ctx_guard   [0x124487]", 0x124487, 1),
    ("post_magic  [0x1244a1..3]", 0x1244a1, 3),
]:
    raw, src = rd(va, n)
    if raw is None:
        print(f"  {name}: UNMAPPED")
        continue
    if n == 8:
        v = struct.unpack("<Q", raw)[0]
        print(f"  {name}: 0x{v:016x}   ({src})")
        out[name] = {"va": f"0x{va:x}", "u64": f"0x{v:016x}", "src": src}
    else:
        print(f"  {name}: 0x{raw.hex()}   ({src})")
        out[name] = {"va": f"0x{va:x}", "hex": raw.hex(), "src": src}

# the t3 region identity: what is at 0x16d000?
for va in (0x16d000, 0x16c080, 0x16c082):
    raw, src = rd(va, 16)
    print(f"  [0x{va:x}]: {raw.hex() if raw else 'UNMAPPED'}  ({src})")
    out[f"probe_0x{va:x}"] = {"hex": raw.hex() if raw else None, "src": src}

# PT_LOAD#0 extent + which VA range covers 0x16d000
print("\n[+] the code-vs-data layout:")
for p_offset, p_vaddr, p_filesz, p_memsz, p_flags in segs:
    print(f"  seg va=[0x{p_vaddr:x}, 0x{p_vaddr+p_memsz:x}) "
          f"file=[0x{p_offset:x}, 0x{p_offset+p_filesz:x}) flags={p_flags:x}")

json.dump(out, open("lab/jalon411/v442c_ring_globals.json", "w"), indent=2)
print("\n[+] wrote lab/jalon411/v442c_ring_globals.json")
