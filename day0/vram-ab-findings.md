# LACT VRAM +200: applied successfully, no demonstrated performance gain

Date: 2026-09-17. GPU: RTX 3070, driver 610.57.04, LACT 0.10.1.

## Method

Three sequential A/B pairs: A = all offsets zero; B = memory offsets +200 on all exposed P-States, core offsets unchanged at zero. LACT local API applies and confirms each change; driver-reported offsets are checked after application. Power cap stays 250 W, clock limits and fan curve unchanged. Background applications (including mpvpaper and Vesktop) remain running.

Each condition uses one glmark2-wayland process, off-screen at 1920x1080, terrain scene for 8 seconds followed by a measured 20-second scene. Table scores are FPS from the second scene, not the overall glmark2 score. NVIDIA telemetry is sampled approximately every second. Frequency summaries exclude the first 10 seconds of process runtime.

This is a different workload from the earlier three-window default suite: these FPS must not be directly compared with its summed scores.

## Observations

| Pair | A FPS | B FPS | A memory MHz | B memory MHz | A core median MHz | B core median MHz |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 1163 | 1162 | 6801 | 6901 | 1875 | 1905 |
| 2 | 1130 | 1103 | 6801 | 6901 | 1905 | 1905 |
| 3 | 1104 | 1041 | 6801 | 6901 | 1905 | 1890 |

All measured conditions report P2. Temperatures range from 47 to 56 C during the measured portions. Median GPU utilization ranges from 91 to 94 percent. No NVIDIA Xid is found in the kernel journal for the test interval.

The +200 LACT memory offset corresponds here to +100 MHz in the NVIDIA frequency readout; the two interfaces do not use an identical numerical scale for this setting. Both the offset readback and the sustained frequency change establish that the setting is applied.

## Interpretation and limits

The setting works, but these measurements demonstrate no performance gain. The zero-offset reference itself declines from 1163 to 1104 FPS (about 5.1 percent). Temperature, core boost, background activity, and fixed A-then-B ordering are confounders. Therefore these runs cannot attribute the lower B scores specifically to the overclock. They also cannot prove memory bandwidth is the bottleneck, establish long-term stability, or predict gaming performance.

No further glmark2 loop is warranted for the narrow question of whether the offset is applied: that question is answered by telemetry. No artifacts or memory correctness test was performed; absence of Xid is not a stability certification.

## Final state

Memory offsets restored to zero through LACT and confirmed. After waiting beyond the rollback timer, the full GPU configuration matches the initial configuration. Driver-reported core and memory offsets are zero for P-States 0, 2, 3, 5 and 8. A later check again reports 6801 MHz VRAM in P2. No firmware, fan curve, power cap, desktop service, or clock limit was changed.

Raw logs, applied clock tables, before/after configuration, and per-second telemetry are retained alongside this note. The prepared three-window baseline script was not executed.
