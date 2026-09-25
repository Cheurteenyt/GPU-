#!/usr/bin/env bash
# r1point.sh <fill_len> — UN point du balayage r1 (run as root)
# le payload régénéré au fill_len, le header C régénéré, le rebuild dkms
# (kernel_gsp.c = déjà patché include+call — le rebuild = ramasse le header)
set -euo pipefail
FL=${1:?usage: r1point.sh <fill_len>}
LOG=/home/cheurteen/dmem-451
SRC=/usr/src/nvidia-610.57.04
GSPDIR=$SRC/src/nvidia/src/kernel/gpu/gsp

python3 - "$FL" <<'EOF'
import importlib.util, sys, hashlib
spec = importlib.util.spec_from_file_location('B', '/home/cheurteen/Projects/GPU-/lab/jalon411/v445_rop_payload_build.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
fl = int(sys.argv[1])
p, meta = B.build(fill_len=fl, fill_value=0x4a7)
open('/home/cheurteen/dmem-451/v445_payload_r1.bin','wb').write(p)
lines = ['#define V445_PAYLOAD_SIZE 4096u',
         'static const unsigned char v445_payload[4096] = {']
for i in range(0, 4096, 16):
    lines.append('    ' + ', '.join(f'0x{b:02x}' for b in p[i:i+16]) + ',')
lines.append('};')
open('/home/cheurteen/Projects/GPU-/tools/booter-patch/v445_payload.h','w').write('\n'.join(lines) + '\n')
print(f'payload fill_len={fl} ok, sha16={hashlib.sha256(p).hexdigest()[:16]}')
EOF

cp /home/cheurteen/Projects/GPU-/tools/booter-patch/v445_payload.h "$GSPDIR/"
dkms build -m nvidia -v 610.57.04 --force 2>&1 | tail -1
dkms install -m nvidia -v 610.57.04 --force 2>&1 | tail -1
limine-mkinitcpio 2>&1 | tail -1
echo "R1-POINT-$FL-READY"
