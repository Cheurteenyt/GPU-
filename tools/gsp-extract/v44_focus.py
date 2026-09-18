#!/usr/bin/env python3
"""v44-focus — ré-émet une fenêtre v44 en ne gardant que [lo,hi] (VAs hex)."""
import re
import sys
from pathlib import Path

lo = int(sys.argv[2], 0)
hi = int(sys.argv[3], 0)
path = Path(sys.argv[1])
for l in path.read_text().splitlines():
    m = re.match(r"\s*0x([0-9a-f]+):", l)
    if not m:
        print(l)
        continue
    a = int(m.group(1), 16)
    if lo <= a <= hi:
        print(l)
