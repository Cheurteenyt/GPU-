# 4.20 — the RPC anchor lane: the dispatch table found, the EDPp handlers resolved, the policy object mapped

Substrate: `tools/analysis/gsp-extract/rm-full.elf` (v414 — fingerprint
re-verified in-flight: ONE RWX LOAD `vaddr=0x1000000 filesz==memsz`,
`shnum=0`, RISC-V 64).
Instruments: `v420_rpcanchor.py` (the id-space scan, three dispatch
shapes), `v420_resolve.py` (the table parser + header naming + map
cross-check), `v420_edpp.py` (the policy-object consumer census).
JSONs: `v420_rpcanchor.json`, `v420_resolve.json`, `v420_edpp.json`.

Lane justification: the 4.19 wall (the dispatch graph is runtime-bound
end to end — 0 named targets in 3,542 slot fills) does NOT bind the RPC
interface, because it is a PROTOCOL: the host driver sends control
commands with PUBLIC ids and the RM must dispatch them by id — an
id-keyed structure is static and survives the runtime-bind. The ids come
from THIS driver's FINN-generated headers
(`/usr/src/nvidia-610.57.04/src/common/sdk/nvidia/inc/ctrl/ctrl2080/`).
This pass deliberately deviates from the 4.19 queue (the caller census /
sum census / pseudo-seeds) — those continue the derivation graph but do
not break the naming wall; the RPC anchors do.

## 1. THE DISPATCH TABLE (the pass headline)

**One table @0x1c183b8..0x1c21438: 1,156 entries, stride 0x20.** Entry
layout (byte-exact from the dump):

```
+0x00 u32 id      — the FINN command id (0x2080xxxx)
+0x04 u32 tag     — the RESPONSE payload size (validated: GET_EDPP_LIMIT_INFO
                    tag=0x18 = 24 B = exactly the 6×u32 limits struct;
                    UPDATE_EDPP_LIMIT tag=0x8 = the bare RPC header)
+0x08 u64 pA      — COMMON to all 1,156 entries (0x1c23870): the family
                    descriptor / shared glue
+0x10 u64 handler — VARIES per entry: the handler pointer
+0x18 u32 sz0, u32 sz1 — the request sizes (sz0=0xc0 on the INTERNAL page)
```

Quality gates: ids 100 % unique, pA 100 % common, handlers 100 % in-image;
**637/1,156 entries NAMED from our own driver headers** (exact FINN
regex); **606/1,156 handlers boundary-verified** on the 4.16 map. Three
false 0x20-stride tables (compressed-data coincidences) were filtered out
by the pA-common + handler-in-image test and are kept in the JSON as the
honest negatives.

This is the static anchor that names the RM's control plane. The
runtime-bound wall does not apply to it.

## 2. The EDPp anchors resolved

| command | id | handler | verified | reading |
|---|---|---|---|---|
| `PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO` | 0x20800afd | **0x1458bec** | YES | the handler **RESETS** the policy object: `memset(obj, 0, 0x6d0)` + `sb zero,(obj)` — a re-derivation request, not a response fill |
| `PMGR_PFM_REQ_HNDLR_UPDATE_EDPP_LIMIT` | 0x20800ad0 | **0x1862480** | no | the handler is a 2-byte **`c.jr ra` NO-OP STUB** on this firmware — the host-side caller (`platform_request_handler_ctrl.c`) sends only the POR enable bit, no limit value; the clamp lives elsewhere |
| `PERF_GPU_BOOST_SYNC_SET_LIMITS` | 0x20800a7f | 0x16e4f20 | YES | the dynamic-boost limit path (next-pass walk) |
| `PMGR_UNSET_DYNAMIC_BOOST_LIMIT` | 0x20800a7b | 0x15bf898 | no | the boost-limit unset |
| `GPU_SET_POWER` (legacy) | 0x20800112 | 0x1402f24 | YES | the legacy set-power |

Host-side cross-check (the open driver source): the UPDATE_EDPP_LIMIT
params struct = `{NvBool bEnable; NvU32 clientLimit;}` — but the only
host caller sends `bEnable` alone (the POR platform path). The nvml power
limit does NOT flow through this command.

## 3. The EDPp policy object — found and mapped

The GET handler's memset exposes the object: **size 0x6d0 (1,744 B),
pointer cached at `state + 0x4E98` (= 0x5000 − 0x168 on the page-5
idiom), allocated at init by the call window @0x1458cf8 (allocator
~0x18C373C, a descriptor @0x1c390de8 passed as arg0)**. The whole
lifecycle sits in the PMGR/PFM module `[0x1458000-0x1459100]`.

The consumer census (`v420_edpp.py` — every `-0x168` access on a page-5
base inside the verified regions, both page-merge idioms A and B; a
LOWER BOUND, the unverified islands excluded honestly):

- **17 sites / 4 functions-clusters**: 10 × `[0x1458xxx]` (the PFM
  module itself), **5 × `[0x1440xxx-0x1446xxx]`** (the recomputation
  worker — see §4), 1 × `0x143fde2`, 1 × `0x15fbad6` (`lw`, the only
  outlier).
- All reads (`ld` ×16, `lw` ×1) — no direct stores through the cached
  pointer in the verified set: the object is filled through callee
  pointers/worker writes.

## 4. The recomputation worker (the clamp candidate) — first window

The site `0x14400c6` opens the worker that holds BOTH the EDPp object
(`s6 = *(state+0x4E98)`) AND the 4.15 companion pointer (`s5 =
*(state+0x4EA0)` — the same 0xA78-page family the 4.15/4.16 passes
banked):

```
ld   s6, -0x168(a5)      # the EDPp policy object
ld   s5, -0x160(a5)      # the companion pointer (state+0x4EA0)
addi a2, zero, 0x34      # a 52-byte result buffer
lui  a3, 0x2080a ; addi a3, a3, 0x80     # the notify/event id 0x2080A080
ld   a6, 0x138(a5)       # the state vtable slot
c.jalr a6                # the recomputation call (args from +0xdc/+0xe4)
lw   a5, 0x10(s4)        # the result
sw   a5, 0x660(s6)       # STORED INTO THE OBJECT at +0x660
```

This is the EDPp recomputation path — the field writer the GET handler's
reset implies, and the natural home of the limitMax clamp. The next pass
walks it (and the `0x2080A080` notify id — the RM→host event space is
the same anchor class, nameable from the headers).

## 5. Queue for 4.21

- Walk the recomputation worker from `0x14400c6` (call-graph bounded:
  the callee of the `c.jalr a6` slot, the other 0x144xxx sites) to the
  limitMax CLAMP — the code that caps a requested limit against the
  policy.
- Find who INITIALIZES the object's 6 limit fields — the init RPC that
  carries the VBIOS power values host→GSP (the ring-41 architecture).
  If the values ride a host-built buffer, the driver-side patch is the
  280 W lane WITHOUT the EEPROM or the booter exploit.
- Name the `0x2080Axxx` event space from the headers (the RM→host
  notifications — the same table class, probably a second table near
  the dispatch table).
- The outlier `0x15fbad6` and the unverified-island consumers (the
  pseudo-seed idea remains the route in).

## Discipline

Local commit on the pass branch, PR, rebase-merge (the founder's PR-only
workflow; the merge-commit refusal verified). The 3 false tables and the
UPDATE-stub reading are banked as honest negatives. Zero findings
overstated: the tag=response-size reading is 2/2 confirmed, not proven
on all 1,156.
