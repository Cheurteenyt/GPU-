#!/usr/bin/env python3
"""gx12-callgraph — the GPU ring-12 instrument (the devinit call graph).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Reuses the ring-10 walker (imported: grammar imported there from nouveau
init.c). Adds the SUB_DIRECT (0x5b, u16 offset target) and SUB (0x6b,
u8 index target) call accounting:
  * direct calls resolve against the script-start set,
  * index calls reference the macro/script index table — whose pointer
    (NVINIT u16 @+2) is 0x0000 on this ROM (measured ring 10), so they
    are registered unresolved, never guessed.

Modes:
  callgraph <rom>...     roots, subroutines, depth, hot callees
  selftest               two-tier gates over the persisted register
"""

import argparse
import collections
import hashlib
import json
import sys
from pathlib import Path

import importlib.util
_spec = importlib.util.spec_from_file_location("gx10", Path(__file__).parent / "gx10-init.py")
gx10 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gx10)


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    legacy = gx10.find_legacy(data)
    base = legacy["base"]
    lo, hi = 0x3000, legacy["length"]
    donemap = {}
    for start in range(base + lo, base + hi):
        r = gx10.walk_to_done(data, start, base + hi)
        if r:
            key = r["done"]
            if key not in donemap or r["start"] < donemap[key]["start"]:
                donemap[key] = r
    scripts = sorted(donemap.values(), key=lambda x: x["start"])
    starts = set(s["start"] - base for s in scripts)

    direct, indexed = {}, {}
    for s in scripts:
        d = data
        off = s["start"]
        for op in s["ops"]:
            if op == 0x5B:
                t = gx10.u16(d, off + 1)
                direct[t] = direct.get(t, 0) + 1
            elif op == 0x6B:
                indexed[d[off + 1]] = indexed.get(d[off + 1], 0) + 1
            off += gx10.size_of(op, d, off)

    resolved = {c: n for c, n in direct.items() if c in starts}
    unresolved = {c: n for c, n in direct.items() if c not in starts}

    graph = collections.defaultdict(list)
    for s in scripts:
        rel = s["start"] - base
        d = data
        off = s["start"]
        for op in s["ops"]:
            if op == 0x5B and gx10.u16(d, off + 1) in starts:
                graph[rel].append(gx10.u16(d, off + 1))
            off += gx10.size_of(op, d, off)
    roots = starts - set(resolved)
    depth = {r: 0 for r in roots}
    q = collections.deque(roots)
    while q:
        u = q.popleft()
        for v in graph[u]:
            if v not in depth:
                depth[v] = depth[u] + 1
                q.append(v)

    return {
        "file": path.name,
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
        "script_count": len(scripts),
        "roots": len(roots),
        "subroutines": len(resolved),
        "direct_calls_resolved": sum(resolved.values()),
        "direct_calls_unresolved": {hex(k): v for k, v in sorted(unresolved.items())},
        "index_calls": sum(indexed.values()),
        "max_depth": max(depth.values()) if depth else 0,
        "hot_callees": [(hex(k), v) for k, v in sorted(resolved.items(), key=lambda kv: -kv[1])[:10]],
    }


def selftest(register_path: Path, corpus_dir: Path) -> int:
    reg = json.loads(register_path.read_text())
    failures = []
    for spec in reg["specimens"]:
        name = spec["file"]
        p = corpus_dir / name
        if not p.exists():
            p = corpus_dir.parent / "day0" / name
        if not p.exists():
            failures.append(f"tier-I: corpus file missing: {name}")
            continue
        live = analyze(p)
        if live["sha256_16"] != spec["sha256_16"]:
            failures.append(f"G-hash {name}: drift")
            continue
        for k in ("script_count", "roots", "subroutines", "direct_calls_resolved", "max_depth"):
            if live[k] != spec[k]:
                failures.append(f"G-{k} {name}: {live[k]} != {spec[k]}")
        if [list(x) for x in live["hot_callees"]] != spec["hot_callees"]:
            failures.append(f"G-hot-callees {name}: drifted")
    print(f"gx12-callgraph selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["callgraph", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx12-callgraph-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "callgraph":
        specs = [analyze(Path(p)) for p in args.roms]
        out = {"instrument": "gx12-callgraph", "ring": 12, "specimens": specs}
        text = json.dumps(out, indent=2)
        if args.out:
            args.out.write_text(text + "\n")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    return selftest(args.register, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
