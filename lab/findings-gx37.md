# findings-gx37 — the VF-curve anchor hunt: runtime-constructed, pairing anchor set

Date: 2026-09-18. Subject: where does the 127-point voltage/frequency curve
come from, and where is the voltage that holds the 1890 wall?

## Proven (negative, structuring)

1. The LACT-displayed VF curve (127 interpolated points, 450-1237 mV over
   210-1935 MHz) is **not stored in the VBIOS** — the plaintext sequence
   (450/456/462 as u16 LE, and the clock/voltage interleaved form) is
   absent from the full image. The curve is **constructed at runtime** by
   the RM from the anchor points (the vP-state profiles) plus the voltage
   controller codes.
2. The known-plaintext pairing anchor is established: the live machine
   runs **1770 MHz at 987 mV** (LACT, idle/desktop state) — this
   (clock, voltage) pair is the decoder key for the voltage-code encoding
   once the anchor table is located.

## The state of the hunt

- The vP-state profiles are a chained structure with voltage candidates
  (the 990 mV entries, ring 36) — the top-profile voltage encoding is
  still open.
- The cloud vague 4.8+ (not yet pushed) holds the next layer: the RM's
  curve construction from the vague 4.6 request enum. This lane belongs
  to the cloud session; this lab provides the live pairing anchor and the
  flash path once the encoding is known.

## Next

1. The founder pushes the cloud vague 4.8+ → this lab audits and pairs.
2. Phase V (a Genshin session with gpu_voltage logging) provides the
   second live pairing point (the load-state voltage at 1890 MHz).
3. With two live pairs + the anchor table located, the voltage encoding
   falls out — then the raise design for the wall.
