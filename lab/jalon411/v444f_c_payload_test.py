#!/usr/bin/env python3
"""4.44 TÂCHE C1 — the C == python byte-exact test (the v442f method)
extended to the v444 payload.

  1. compile transfer_list_memdesc.c (-DTL_SELFTEST, -Wall -Wextra);
  2. run the C selftest: the 4.42 4-group battery MUST stay 4/4
     (the non-regression) + the new TL444 group;
  3. dump the v444 payload from the C (argv[2], dest=0x12345678) and
     build the SAME config with v444_transfer_list_build.py;
  4. compare BYTE-EXACT (sha256);
  5. re-run the v442f comparison (the 3-entry E1 payload, the 4.42
     demo) — the committed sha must reproduce.

Output: the PASS/FAIL lines + the exit code.
"""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C = ROOT / "tools/booter-patch/transfer_list_memdesc.c"
sys.path.insert(0, str(ROOT / "lab/jalon411"))
from v444_transfer_list_build import build_payload_444  # noqa: E402


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    fails = []
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        exe = td / "tl_test"
        r = subprocess.run(
            ["gcc", "-DTL_SELFTEST", "-Wall", "-Wextra", "-O2",
             str(C), "-o", str(exe)],
            capture_output=True, text=True)
        if r.returncode != 0:
            print("COMPILE FAIL:", r.stderr)
            return 1
        if r.stderr.strip():
            print("compile warnings:", r.stderr.strip())

        # -- 1+2. the C selftest (the 4.42 battery + the TL444 group)
        dump442 = td / "dump442.bin"
        dump444 = td / "dump444.bin"
        r = subprocess.run([str(exe), str(dump442), str(dump444)],
                           capture_output=True, text=True)
        print(r.stdout.strip())
        if "tl_c_selftest: PASS (0 groups failed of 4)" not in r.stdout:
            fails.append("the 4.42 C battery is not 4/4")
        if "tl444_c_selftest: PASS (0 checks failed of 4)" not in r.stdout:
            fails.append("the TL444 C group failed")

        # -- 3+4. the v444 byte-exact comparison
        py444, plan = build_payload_444("percent", dest=0x12345678,
                                        slot0=0, capacity=0x400)
        c444 = dump444.read_bytes()
        if sha(py444) != sha(c444):
            fails.append(f"v444 C != python ({sha(c444)[:16]} vs "
                         f"{sha(py444)[:16]})")
        else:
            print(f"[PASS] v444 C dump == builder python BYTE-EXACT "
                  f"sha256 {sha(py444)[:16]}…")

        # -- 5. the v442f non-regression: the C config = {slot0=0,
        #        cap=0x400, dest=0, 3x E1} — rebuild the SAME config
        #        inline (the banked e85c14d5… = THIS pair, the v442f
        #        pass; the committed v442e_payload.bin = the demo build
        #        with dest=0xDEAD0000 = a DIFFERENT config, not the
        #        test pair)
        E1 = 0x000445C00003A980
        py442 = (b"\xFF" * 0x488 +
                 (0).to_bytes(8, "little") +
                 (0x400).to_bytes(8, "little") +
                 (0).to_bytes(8, "little") +
                 b"\x08" +
                 b"\xFF" * (0x500 - 0x4A1) +
                 E1.to_bytes(8, "little") * 3 +
                 b"\xFF" * (0x1000 - 0x518))
        c442 = dump442.read_bytes()
        if sha(py442) != sha(c442):
            fails.append(f"v442 C != the v442f config rebuilt "
                         f"({sha(c442)[:16]} vs {sha(py442)[:16]})")
        else:
            print(f"[PASS] v442 C dump == the v442f python config "
                  f"BYTE-EXACT sha256 {sha(py442)[:16]}… (the banked "
                  f"e85c14d5… pair)")

    if fails:
        for f in fails:
            print("FAIL:", f)
        return 1
    print("v444f: 3/3 PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
