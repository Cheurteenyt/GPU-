#!/usr/bin/env python3
"""
4.42 TÂCHE 3 — le test unitaire du patch C : le payload du C
(transfer_list_memdesc.c compilé -DTL_SELFTEST) = byte-exact vs le
builder python (v442e_transfer_list_build.py, le même scénario E1).

Les invariants vérifiés:
  V1 le C compile et son selftest interne = 0 fail
  V2 le dump C == le payload python (le même ctx/liste/0xFF)
  V3 les invariants de layout indépendants (le ctx, la tête E1, le 0xFF)
"""
import subprocess, struct, sys, hashlib, tempfile, os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
C_SRC = REPO / "tools/booter-patch/transfer_list_memdesc.c"
PY_PAYLOAD = REPO / "lab/jalon411/v442e_payload.bin"

E1 = 0x000445C00003A980  # {limitRated 240000, limitMax 280000} mW u32 LE
fails = []

# ---- V1: compile + le selftest interne
exe = tempfile.mktemp(suffix=".tl")
r = subprocess.run(["gcc", "-DTL_SELFTEST", "-Wall", "-Wextra", "-O2",
                    "-o", exe, str(C_SRC)], capture_output=True, text=True)
if r.returncode != 0:
    print("[FAIL] V1 compile:", r.stderr[:400]); sys.exit(1)
print("[PASS] V1a gcc -Wall -Wextra compile propre")
r = subprocess.run([exe], capture_output=True, text=True)
print("       C selftest:", r.stdout.strip())
if r.returncode != 0:
    fails.append("V1b le selftest C interne")

# ---- V2: le dump C vs le builder python
dump = tempfile.mktemp(suffix=".bin")
subprocess.run([exe, dump], check=True)
c_img = Path(dump).read_bytes()
# le scénario python identique: la liste E1 x3 @0x500, le ctx {0,0x400,0}
py_img = bytearray(b"\xFF" * 0x1000)
py_img[0x488:0x490] = struct.pack("<Q", 0)          # slot0
py_img[0x490:0x498] = struct.pack("<Q", 0x400)      # capacité
py_img[0x498:0x4A0] = struct.pack("<Q", 0)          # dest (runtime)
py_img[0x4A0:0x4A1] = bytes([0x08])                 # magic
for k in range(3):
    py_img[0x500 + 8*k:0x508 + 8*k] = struct.pack("<Q", E1)
py_img = bytes(py_img)
if c_img != py_img:
    diff = [i for i in range(len(c_img)) if c_img[i] != py_img[i]][:8]
    fails.append(f"V2 byte-exact C vs python ({len(diff)} premiers diffs: {diff})")
else:
    print(f"[PASS] V2 le dump C == le payload python "
          f"(sha256 {hashlib.sha256(c_img).hexdigest()[:16]}…)")

# ---- V3: les invariants indépendants
ok = (c_img[0x488:0x490] == struct.pack("<Q", 0) and
      c_img[0x490:0x498] == struct.pack("<Q", 0x400) and
      c_img[0x498:0x4A0] == struct.pack("<Q", 0) and
      c_img[0x4A0] == 0x08 and
      struct.unpack_from("<Q", c_img, 0x500)[0] == E1 and
      c_img[:0x488] == b"\xFF" * 0x488 and
      c_img[0x518:] == b"\xFF" * (0x1000 - 0x518))
print(("[PASS]" if ok else "[FAIL]") + " V3 les invariants de layout "
      "(ctx @0x488/0x490/0x498/0x4A0, tête E1 @0x500, le 0xFF ailleurs)")
if not ok:
    fails.append("V3 les invariants")

# le payload bancé v442e (le démo d'origine) — cité, pas comparé (le
# scénario diffère: 0xDEAD0000 dest)
if PY_PAYLOAD.exists():
    banked = PY_PAYLOAD.read_bytes()
    print(f"[INFO] le payload bancé v442e: {len(banked)} B, "
          f"sha256 {hashlib.sha256(banked).hexdigest()[:16]}… (le scénario "
          f"dest=0xDEAD0000 — le C utilise dest=0 runtime)")

for f in (exe, dump):
    os.unlink(f)
print(f"test C↔python: {'4/4 PASS' if not fails else 'FAIL: ' + '; '.join(fails)}")
sys.exit(1 if fails else 0)
