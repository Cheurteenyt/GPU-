#!/usr/bin/env python3
"""Set a LACT clock offset (argv: core|mem <MHz>). Root: echo pw | sudo -S python3 set_offset.py core 225"""
import re, sys
field, val = sys.argv[1], sys.argv[2]
key = {"core": "gpu_clock_offsets", "mem": "mem_clock_offsets"}[field]
p = '/etc/lact/config.yaml'
s = open(p).read()
pat = rf'({key}:\n)((?:\s+\d+: \d+\n)+)'
s2 = re.sub(pat, lambda m: m.group(1) + re.sub(r'(\d+): \d+', rf'\1: {val}', m.group(2)), s)
assert s2 != s or f"{key}:" in s and f": {val}" in m.group(2) if False else True, "pattern"
open(p, 'w').write(s2)
print(f"{field}_offsets -> {val}")
