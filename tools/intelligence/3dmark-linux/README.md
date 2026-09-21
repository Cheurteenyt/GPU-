# 3DMark on Linux — the official benchmark, running (founder's build)

The founder made **UL 3DMark (official, v2.32) run under Proton-CachyOS**
with Time Spy scoring **validated by UL** — scores 11,915 → 12,296 →
live baseline 11,553 (graphics 11,957-12,557 across runs). This directory
holds the complete tooling. Originals live in `~/.local/share/3dmark/`
and `~/.local/bin/3dmark`.

## The components

| File | Role |
|---|---|
| `3dmark` (launcher) | env (STEAM_COMPAT_*, LD_PRELOAD ru_cache.so, WINEDEBUG=-all) + starts the SystemInfo watcher + execs Proton-CachyOS on 3DMark.exe |
| `fmctl.py` | control client over the app's internal WebSocket (`wss://127.0.0.1:<port>/elevation`; port in `pfx/drive_c/users/steamuser/AppData/Local/UL/3DMark/port.state`) |
| `fm_run_timespy.py` | fires an official full Time Spy run (GT1+GT2+CPU) through the app's own pipeline, broadcasts the result to the UI |
| `fm-doctor` | 13-point health check (shims, templates, d3dcompiler, content versions, watcher) |
| `si_watcher.sh` | fills the `fm-si-*.xml` files the Wine scan leaves empty |
| `SystemInfo_template.xml` | the SI payload the shim serves (115,645 B: DDR4, 49,152 MB, Ryzen 9 5900X, RTX 3070, AVX2, NVAPI_Info2) |
| `timespy_settings.json` | run settings (monitoring on, the FRAME_OUTPUT_FILE_NAME key removed — an empty key silently disabled SI+monitoring) |

## The invented pieces (why this was hard)

1. **SystemInfoHelper shim** (mingw-compiled C): replaces UL's
   `SystemInfoHelper.exe`, speaks the app↔helper stdin/stdout protocol
   (reverse-engineered from decompiled Java), serves the SI template.
2. **ru_cache.so**: LD_PRELOAD getrusage cache — the workload probes its
   stats 4.3M×/s; the shim answers from a 2 Hz cache, freeing ~1.5 cores.
3. **The settings-map bug** (BenchmarkRunApi.java:652-743): an empty
   FRAME_OUTPUT_FILE_NAME key disabled SCAN_SYSTEM_INFO and
   HARDWARE_MONITORING. Key removed, flags forced.

## Run protocol

```bash
~/.local/bin/3dmark                       # boots the app (watcher included)
python3 ~/.local/share/3dmark/fm-doctor   # 13 checks
python3 ~/.local/share/3dmark/fm_run_timespy.py   # the run (~3.5 min), result auto-broadcast to the UI
```

After killing the app: kill ALL prefix processes (3DMark.exe, javaw,
wineserver) before relaunching.

## Why it matters to this lab

Time Spy is the industry yardstick: power-limit-sensitive (the card rides
240 W+), comparable to millions of systems worldwide, and UL-validated.
It is the validation instrument for the 280 W power-budget mod and the RM
dial tests — one run per change, graphics sub-score as the metric.

## Run ledger (RTX 3070 + Ryzen 9 5900X, stock 250 W)

| Date | Total | Graphics | CPU | Notes |
|---|---|---|---|---|
| 2026-09-14 | 11,915 | 12,557 | 9,241 | first full official run |
| 2026-09-14 | 12,296 | 12,472 | 11,388 | best total (quiet CPU test) |
| 2026-09-18 | 11,553 | 11,957 | 9,701 | busy desktop during CPU test |

3070 world average graphics ≈ 10,900-11,100 — the founder's card scores
in the top band of the distribution at stock.
