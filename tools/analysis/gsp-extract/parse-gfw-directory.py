#!/usr/bin/env python3
"""parse-gfw-directory — walk the .fwimage section directory properly.
Records are length-prefixed: u64 length, then payload (name + fields).
Walk from a plausible start, emit every record's name + u64 fields, and
save the images the table names.
Usage: python3 parse-gfw-directory.py  (reads fwimage.bin from this dir)
"""
import struct
from pathlib import Path

fw = Path('fwimage.bin').read_bytes()

def walk(start):
    pos = start
    records = []
    while pos < 0x6f000:
        if pos + 8 > len(fw):
            break
        (length,) = struct.unpack_from('<Q', fw, pos)
        if not (0x20 <= length <= 0x200):
            break
        payload = fw[pos + 8:pos + 8 + length]
        m = None
        for cand in (payload, payload[:64]):
            m2 = __import__('re').search(rb'[\x20-\x7e][\x20-\x7e_.]{3,19}\x00', cand)
            if m2:
                m = m2
                break
        name = m.group().decode() if m else ''
        fields = []
        # u64s after the name area: scan payload in 8-byte steps, keep plausible
        for o in range(0, len(payload) - 7, 8):
            (v,) = struct.unpack_from('<Q', payload, o)
            if v < (1 << 40) and v not in (0,):
                fields.append(v)
        records.append((pos, length, name, fields))
        pos += 8 + length
    return records

# find the walk start: first position whose length field chains cleanly
for start in range(0x6cf00, 0x6d040, 8):
    (length,) = struct.unpack_from('<Q', fw, start)
    if 0x20 <= length <= 0x200:
        recs = walk(start)
        names = [r[2] for r in recs]
        if len(recs) >= 10 and any('rm.' in n or 'kernel' in n for n in names):
            print(f'chain start {start:#x}: {len(recs)} records')
            for pos, length, name, fields in recs:
                print(f'  {pos:#x} len {length:<4} {name:<20} fields: {[hex(f) for f in fields[:8]]}')
            Path('directory.json').write_text(__import__('json').dumps(
                [{'pos': hex(p), 'len': l, 'name': n, 'fields': [hex(f) for f in fl]} for p, l, n, fl in recs], indent=1))
            print('directory.json written')
            break
