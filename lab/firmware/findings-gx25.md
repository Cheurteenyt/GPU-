# findings-gx25 — the fan-curve/boost experiment, closed honestly

Date: 2026-09-17. Subject: can a more aggressive mid-range fan curve raise
sustained boost clocks? Measured with the paired-protocol discipline.

## Method

Three-phase A/B: baseline load with the current curve, curve swap through
the LACT daemon API (set_gpu_config), repeat load, automated keep/restore
rule (keep only if steady-state median core clock improves). Load = 3
parallel glmark2-wayland offscreen run-forever instances; telemetry every
2 s; steady state = after 120 s. Two resolutions: 2560x1440 and
3840x2160.

New curve tested: 40→40 %, 45→45 %, 50→55 %, 55→65 %, 60→80 %, 65→95 %,
70→100 % (stock: 40→30, 50→35, 60→50, 70→75, 80→100).

## Results

| Load | Curve | median core | median temp | max temp | median W | fan % |
|---|---|---:|---:|---:|---:|---:|
| 1440p×3 | stock | 1875 | 47.0 | 54 | 92.1 | 33 |
| 1440p×3 | new | 1905 | 48.0 | 55 | 96.9 | 33 |
| 4K×3 | stock | 1905 | 49.0 | 56 | 105.4 | 35 |
| 4K×3 | new | 1890 | 50.0 | 57 | 109.0 | 35.5 |

1440p delta +30 MHz (one 15 MHz clock step), 4K delta −15 MHz — both
inside the run-to-run noise this workload family has shown all day. Root
cause: **glmark2 saturates at 92–109 W of the 250 W ceiling** (draw-call
submission-bound), so the GPU never enters the temperature region
(65–75 °C in real games) where fan behavior changes boost. The 4K run's
negative delta triggered the automated restore — the stock curve is back
and verified.

## Verdict

- The synthetic cannot measure this effect; only a real game (220–240 W,
  65–75 °C) can. Next measurement belongs to the founder's actual games
  with MangoHud logging clocks/temps, curve A vs B, one session each.
- The experiment infrastructure is reusable: `fan-boost-experiment.py`
  takes instances/resolution/seconds and self-restores.
- Reliability framing (the founder's goal): the new curve holds lower
  temps under real load at more noise; whether that trade is wanted is a
  preference decision, not a benchmark one.

## Also this ring: BIOS 3644 → 3645 diff (motherboard lane)

Full binary diff of both 32 MiB CAPs: one replaced module block (3.37 MB)
in the main boot FV, X.509 certificate-rollover timestamps (2026), NVRAM
default touches, no visible AGESA landing. "Improve system
compatibility" is a housekeeping release. Recommendation: **stay on
3644**; re-evaluate only for a future security update. Full note in the
BIOS- lab (`lab/diff-3644-to-3645.md`).
