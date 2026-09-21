# 4.21 — the PFM worker decoded, the mW scan, the table consumption, and the RatedTdp pair

Substrate: `tools/analysis/gsp-extract/rm-full.elf` (v414 — fingerprint
unchanged). Instruments: inline decodes over the 4.16 verified map
(regions + `seen`), the mW-constant scan, the table-consumer scan.
Queue of 4.20: (a) the clamp walk, (b) the init-values origin, (c) the
0x2080Axxx event space.

## 1. The recomputation worker — fully decoded (0x14400b6..0x1440186)

```
s6 = *(state + 0x4E98)      # the EDPp policy object (4.20)
s5 = *(state + 0x4EA0)      # the COMPANION pointer — the 4.15/4.16
                            #   0xA78-page family, CONFIRMED live here
memset(sp_buf, 0, 0x34)     # a 52-byte result buffer
a6 = *(state2 + 0x138)      # a state vtable slot (runtime-bound)
call a6(state+0x4100, lw(+0xdc), lw(+0xe4), 0x2080A080, buf, 52)
if (ret) return ret
obj->0x660 = buf[0x10]      # ONE refreshed dword into the object
if (*(s5) & 2) skip
walk a listener list (nodes at *(state+0x2050)):
    fn = *(node+0x420); call fn(node)
    a1 = lhu(node+0x178); a4 = lhu(node+0x18)
    if (a1 < a4): obj->0x6c8 |= 2 ; *(s5) |= 2      # the change flags
return
```

Reading: the worker = the policy REFRESH/NOTIFY routine — it refreshes
one field (0x660), flags the policy (0x6c8 bit 1) and notifies listeners
on a threshold comparison of two u16s. **The limitMax clamp is NOT in
this function** — it lives in the runtime callee (the state vtable slot)
or deeper. Honest: the runtime-bind wall holds here.

## 2. The mW constant scan — no static defaults (honest negative)

The decisive question: is the 250 W ceiling hardcoded or runtime data?
Scan of the 250000/280000/240000/265000/220000/200000/170000/100000
constants (both `li`-pair code forms and raw u32 data):

- **NO data-word hits in plausible tables** — the five 100000 u32 hits
  sit inside high-entropy (compressed) streams at unrelated offsets:
  coincidences, banked as negatives.
- **6 code sites with the 250000 immediate**: 0x10190fe (a comparison
  against a table-loaded value: `bltu 250000, *(x+0x4a8)`), 0x101a062
  (250000 as a CALL ARGUMENT), 0x11f09e0 (added to a computed value then
  range-compared), 0x17c46b4 (`divuw` — a unit conversion), 0x1b99bec +
  0x1b99cc8 (range checks; 500000 (=0x7A120) also forms nearby).
- **280000: ZERO hits** in code and data.

The strategic reading: **rm-full.elf is the GENERIC firmware shared by
every consumer GA10x card** — a per-card 250 W ceiling CANNOT be
hardcoded in it. The six 250000 sites are generic constants
(conversions, reference checks). Combined with (1) and the ring-41
architecture: **the per-card limits are RUNTIME DATA** — provided by the
host (the parsed VBIOS values) and carried in the RM's state objects.
The enforcement reads state; the state is host-fed. **The 280 W lane is
host-side** (the open-source audit: where the driver passes the power
values to the GSP), not a binary hunt.

## 3. The table consumption — runtime, through a master descriptor

Scanning every auipc/lui+addi formation in the whole image for addresses
inside the dispatch table [0x1c183b8..0x1c21438]: **one static
reference only** (0x1a15494 → 0x1c21428, the table end — a bound).
The table is consumed by a RUNTIME loop (the linear id scan), and the
loop's base comes from **the master descriptor @0x1c23870** (= the table
entries' common pA field!): its u64 quad = {0x1e90c88 (code ptr),
**0x1c17e60** (= 0x558 before the table head — the wider table region
start), 0x1f0 | 0x4789f2 (sizes/flags), 0x1e90ee8 (code ptr)}. No static
formation references the descriptor either — one more indirection level
(the RM's object graph holds a pointer to it). The raw bytes are in the
JSON for the 4.22 loop-hunt.

## 4. The RatedTdp pair — the nvml-class power control resolved

- `NV2080_CTRL_CMD_PERF_RATED_TDP_SET_CONTROL` (0x2080206f) → handler
  **0x163c42c** (boundary-verified) — and the host-side KERNEL handler is
  in the OPEN source: `subdeviceCtrlCmdPerfRatedTdpSetControl_KERNEL`
  (`kern_perf_pwr.c:53`): the admin/SMC permission gating, then a
  redirect to the Physical RM (= the GSP RPC). This is the command class
  nvml's power/TDP controls flow through.
- The RM-side function (prologue 0x163c478, decoded byte-exact): builds
  the response as **5 × {u32, u32} pairs — a 5-entry vP-state limit
  table** — via a 5-iteration loop calling a helper per vP-state. The
  GET/control path; the SET path and the policy clamp remain queued.

## 5. The B-field handler anomaly — named, not yet closed

The 4.20 "handler" reading needs a caveat banked: for most entries the
+0x10 pointer sits at small adjacent functions (adjacent ids → adjacent
handlers — the table is real), but for SOME (GET_EDPP 0x1458bec,
RatedTdp 0x163c42c) the pointer lands at a non-prologue block. Both
decodes showed REAL semantic code at the pointer (the GET's reset with
its 0x6d0 memset is unambiguous), so the pointers are meaningful —
whether they are the callable ENTRY or a fixed-offset view into the
handler will be settled by the dispatch-loop decode (4.22a). Banked
honestly, not silently.

## 6. Queue for 4.22

- **The host-side lane (the strategic one)**: in the OPEN source, trace
  the parsed VBIOS power values from the perf table parser to the GSP
  init/RPC payloads (kernel_gsp.c, the perf/Pmgr construct path). The
  target: a host-built buffer carrying the limits — the 280 W write
  point WITHOUT the EEPROM and WITHOUT the booter exploit.
- The dispatch-loop hunt: decode the code reachable from the descriptor
  (the pointer chain that ends at 0x1c17e60) and close the B-field
  question.
- The RatedTdp SET path + the 5-pair table storage.
- The 0x2080Axxx space: 31 sites classified (values 0x2080a001-0xa7a0);
  no header names — the RM-internal event/task ids. Low priority.

## Discipline

Inline decodes over the verified map only; every negative banked. PR +
rebase-merge; zero force-push.
