# 4.24 — pass II: the EDPp limit lifecycle — the open-source model (driver 610.57.04)

Substrate: `open-gpu-kernel-modules` **tag 610.57.04** (the exact branch
of the LIVE machine — cloned for this pass, not committed: size).
Files: `src/nvidia/src/kernel/platform/platform_request_handler.c`
(1,043 lines), `src/nvidia/src/kernel/platform/platform_request_handler_ctrl.c`
(2,917 lines), plus the headers cited inline. Every claim carries
file:line. The task brief's four questions — who pushes what, platform
vs client limit, the value 0, the 250 W cap — each get a section.

## 1. The cast (who pushes what)

| actor | role | evidence |
|---|---|---|
| **SBIOS/ACPI** | the ORIGIN of platform intent: the request bits and the platform limit value arrive from the platform; the limit info is reported BACK to it | the DSM-GPS calls: PSHARESTATUS decode `platform_request_handler_ctrl.c:2369-2376`, GETEDPPLIMIT `:1001-1019`, SETEDPPLIMITINFO `:1022-1037` |
| **PRH module (the open kernel, host side)** | a RELAY + a small state machine: it caches what the SBIOS asked (`sensorData`), what was applied (`controlData`), and converts deltas into RM control calls | the two caches `g_platform_request_handler_nvoc.h:152-157, 223-234, 255`; the apply-tolerance macro `ctrl.c:146-147` |
| **GSP-RM (the closed firmware)** | the limit AUTHORITY: it holds the policy object, re-derives the limits, applies the cap | 4.20 pass (the policy object 0x6d0 @ state+0x4E98, the GET handler memset, the recomputation worker); the negative proof §5 below |

The whole EDPp RPC surface of the open kernel = **3 call sites**
(exhaustive grep): UPDATE_EDPP_LIMIT ×2 (`ctrl.c:1615, 1672`) and
GET_EDPP_LIMIT_INFO ×1 (`ctrl.c:1757`). No other module sends them.

## 2. The lifecycle

### 2.0 Init

- `pfmreqhndlrStateInit_IMPL` (`platform_request_handler.c:384`):
  `controlData.bEDPpeakUpdateEnabled = NV_FALSE` (**:425**) — the
  applied-state cache starts "reset".
- The initial PSHARESTATUS with `bInit=NV_TRUE`
  (`ctrl.c:1170`, inside `pfmreqhndlrInitSensors`).
- The PMGR/PMU post-load sync
  (`NV2080_CTRL_CMD_INTERNAL_PMGR_PFM_REQ_HNDLR_STATE_LOAD_SYNC`,
  `platform_request_handler.c:499-504`) — this is what defers the
  init-time EDPp apply until PMGR is loaded.

### 2.1 The deferred apply (the init-time work item)

`_pfmreqhndlrPmgrPmuPostLoadWorkItem`
(`platform_request_handler.c:925-1002`, queued by the prereq callback
`:1009-1042` once PMGR is loaded):

1. **The toggle**: if the SBIOS request
   (`sensorData.PFMREQHNDLRACPIData.bEDPpeakLimitUpdateRequest`) differs
   from the applied state (`controlData.bEDPpeakUpdateEnabled`) —
   **:947-948** — call `pfmreqhndlrHandleEdppeakLimitUpdate`
   (**:951-952**).
2. **The platform limit** if deferred
   (`controlData.edppLimit.bDifferPlatformEdppLimit`, **:983**): call
   `pfmreqhndlrHandlePlatformEdppLimitUpdate` with the cached
   `platformEdppLimit` (**:985-986**), then clear the defer flag
   (**:997**).

### 2.2 The runtime event flow

SBIOS event / v-Pstate change →
`pfmreqhndlrHandleStatusChangeEvent` (`ctrl.c:1488`) →
`_pfmreqhndlrCallPshareStatus(bInit=NV_FALSE)` (`ctrl.c:1501`, def
`:2337`). ONE ACPI PSHARESTATUS call returns the request bits
(`ctrl.c:2369-2376`):

```
_PLATFORM_GETEDPPEAKLIMIT_SET   -> bQueryEdppRequired      (:2369)
_PLATFORM_SETEDPPEAKLIMITINFO_SET -> bPlatformEdpUpdate    (:2370)
_EDPPEAK_LIMIT_UPDATE           -> bEDPpeakLimitUpdateRequest (:2376)
```

then three branches:

**1.A — the legacy toggle (the "client limit" path).**
`PFM_REQ_HNDLR_IS_EDPPEAK_UPDATE_REQUIRED(request, enabled)`
(`ctrl.c:146-147`) fires only on a TRANSITION (request XOR applied) and
only when `!bInit` (**:2386-2391**). →
`pfmreqhndlrHandleEdppeakLimitUpdate_IMPL` (`ctrl.c:1597-1631`): the
RPC `UPDATE_EDPP_LIMIT` with **`params.bEnable = bEnable; clientLimit
stays 0`** (**:1609-1615** — the params struct is `{0}`-initialized).
On success the applied-state cache is updated (**:1625-1628**). The
"client limit" of the header doc
(`ctrl2080internal.h:3220-3241`: "bEnable: Enable or Reset the
settings; clientLimit: Client requested limit") is therefore a
*bPotential* field this caller never sets — the POR path toggles
enable state only.

**1.B — the platform limit.** If the SBIOS raised
`_PLATFORM_GETEDPPEAKLIMIT_SET` (**:2402**):
`pfmreqhndlrHandlePlatformGetEdppLimit_IMPL` (`ctrl.c:1697-1725`) →
ACPI DSM `GETEDPPLIMIT` → `*pPlatformEdppLimit = result[0]`
(**:1722**) — the limit VALUE comes from the platform, in mW, over
ACPI. It is cached (the GET call `:2407`, the cache write `:2416`) and
then applied:

- at runtime: `pfmreqhndlrHandlePlatformEdppLimitUpdate_IMPL`
  (`ctrl.c:1647-1686`) → RPC `UPDATE_EDPP_LIMIT` with
  **`clientLimit = platformEdppLimit; bEnable = NV_TRUE`**
  (**:1659-1664**).
- at init: DEFERRED (`bDifferPlatformEdppLimit = NV_TRUE`,
  **:2419-2422**), applied later by the §2.1 work item.

**2 — the limit-info report (the round trip).** If the SBIOS raised
`_PLATFORM_SETEDPPEAKLIMITINFO_SET` (`ctrl.c:2493-2500`):
`pfmreqhndlrHandlePlatformSetEdppLimitInfo_IMPL` (`ctrl.c:1738-1800`)
→ RPC `GET_EDPP_LIMIT_INFO` (**:1757**) → the six limits are cached
host-side (**:1762-1767**) → a work item
(`_pfmreqhndlrHandlePlatformSetEdppLimitInfoWorkItem`, `ctrl.c:2814`)
calls ACPI `SETEDPPLIMITINFO` with the full struct
`NV0000_CTRL_PFM_REQ_HNDLR_EDPP_LIMIT_INFO_V1`
(`platform_request_handler_utils.h:82-92`: ulVersion, **limitLast** =
the cached platform limit, limitMin, limitRated, limitMax, limitCurr,
limitBattRated, limitBattMax) (**fill :2837-2849, the ACPI call
:2858**). The SBIOS gets told what the GPU's policy allows.

## 3. Platform limit vs client limit — when each applies

- **The platform limit** = a mW value pushed BY the SBIOS (the DSM
  GETEDPPLIMIT result). Applied whenever the SBIOS raises the
  `_PLATFORM_GETEDPPEAKLIMIT_SET` bit — i.e., on platform-triggered
  events (the SBIOS-side trigger conditions are platform policy:
  HYPOTHESIS — the open code shows the driver is passive here, it only
  polls PSHARESTATUS on events/v-Pstate changes).
- **The client limit** = the enable-toggle path (§2.2 1.A): no value,
  only the bEnable bit. The header names the field "Client requested
  limit" but the ONLY open-source caller sends it as 0 — the value
  semantics on the GSP-RM side are unobservable in the open source
  (and the receiving handler is a stub, §5).
- Both ride the SAME RPC (`UPDATE_EDPP_LIMIT`, 0x20800ad0, params
  `{NvBool bEnable; NvU32 clientLimit}` = 8 B,
  `ctrl2080internal.h:3238-3241`).

## 4. The value 0 — PROVEN, the exact lines

`platform_request_handler_ctrl.c:1661-1668`:

```c
params.clientLimit = platformEdppLimit;
params.bEnable     = NV_TRUE;

// Platform can remove its EDPp and fall back to GPU default by setting a limit of value 0
if (platformEdppLimit == 0)
{
    params.bEnable = NV_FALSE;
}
```

(Citation audit: the if-block itself sits at :1665-1668, the quoted
assignment block at :1661-1664.)

**0 = "remove the platform limit / fall back to the GPU default" — a
RESET request, never a 0 W limit.** The bEnable-only call of §2.2 1.A
sends clientLimit=0 for the same reason: an enable/reset toggle, not a
value. (The same 0-means-clear convention appears on the SMBPBI
operating-limit lane: `platform_request_handler.c:661-672`, the
`_SMBPBI_OP_CLEAR` sync calls `pfmreqhndlrOperatingLimitUpdate(..., 0,
NV_FALSE)`.)

## 5. Where the 250 W cap applies — the honest answer

- **PROVEN negative (the open source):** no `250000`, no `0x3D090`,
  no `240000`, no `100000` power constant anywhere in `src/` or
  `kernel-open/` (exhaustive grep — the only hits are a NVLink-Gbps
  comment and IP-version ranges). No host-side EDPp clamp exists in
  the open code. The open kernel relays; it never owns a limit.
- **PROVEN (the closed firmware, this campaign):** the cap = the RM's
  internal EDPp policy — the 0x6d0 policy object (4.20), RESET by the
  GET_EDPP_LIMIT_INFO handler (`memset(obj,0,0x6d0)` + `sb zero`,
  handler @0x1458bec — the object is re-derived, not refilled from the
  RPC) and recomputed by the worker @0x14400c6 (the result stored at
  obj+0x660, 4.20 §4).
- **The reconciliation:** the open-source reading now proves from the
  code side what 4.23 proved at the transport level — *no open-code
  path carries min/rated/max INTO the RM*. The three EDPp RPCs are the
  toggle (a bit), the platform limit (a value — into a handler that is
  a **2-byte `c.jr ra` no-op stub** on this firmware, 4.20 §2), and
  the info GET (an OUT-only query). **The 250 W cap is applied inside
  the GSP-RM, in the recomputation of its own policy object, whose
  source values come from the RM's VBIOS parse — unreachable from the
  open kernel.**

## 6. The flow diagram

```
SBIOS/ACPI (the platform)
   │  DSM-GPS: PSHARESTATUS / GETEDPPLIMIT / SETEDPPLIMITINFO
   ▼
PRH module (open kernel)  — sensorData (the requests) vs controlData (the applied)
   │
   ├─ 1.A toggle:   RPC UPDATE_EDPP_LIMIT {bEnable, clientLimit=0}  ──▶ GSP-RM handler = c.jr ra STUB (4.20)
   ├─ 1.B platform: RPC UPDATE_EDPP_LIMIT {bEnable=1, clientLimit=mW (0 ⇒ bEnable=0)} ──▶ same STUB
   └─ 2 info:       RPC GET_EDPP_LIMIT_INFO ──▶ GSP-RM RESETS the policy object (memset 0x6d0),
                        RE-DERIVES from its VBIOS-parsed tables ──▶ the 6 limits OUT
                        ──▶ cached ──▶ ACPI SETEDPPLIMITINFO ──▶ SBIOS

GSP-RM internal (closed): the policy object (0x6d0) ◀── the VBIOS parse
                          the recomputation worker (0x14400c6) ──▶ obj+0x660
                          THE 250 W CAP LIVES HERE — no open-code equivalent exists
```

## 7. The campaign hooks (what the model predicts)

1. **The 1616-byte payload (4.24 pass I) is NOT part of this flow.**
   The PRH module sends only 0x20800ad0 and 0x20800afd (§1, exhaustive).
   The 0x2080d031 carrier belongs to another lane.
2. **The response of GET_EDPP_LIMIT_INFO is where the triple should
   appear.** The control's response params = the 24-byte
   GET_EDPP_LIMIT_INFO_PARAMS (tag=0x18, the dispatch table). On a boot
   where the SBIOS raises `_PLATFORM_SETEDPPEAKLIMITINFO_SET`, the
   driver sends the GET and the GSP-RM answers with
   {limitMin, limitRated, limitMax, ...} — the response body = 40+24 B,
   the dumped length (with the 4.24 pass I capture law) = 96 B. The
   4.23 "max/default NEVER transmitted" verdict = the SEND path only;
   the response dump (the recv hook — the pass I queue item) is the
   concrete next experiment. **Prediction: a 96-byte dumped payload
   with 100000/240000/250000 at poff {0,4,8} of the params.**
3. The platform-limit write-path is a dead end on this firmware (the
   stub) — the 280 W lane stays host-side (the v9 scanner) or
   firmware-side (the recomputation worker walk, 4.20 queue).

## Discipline

Every line number was read from the 610.57.04 tree in this pass and
RE-AUDITED post-PR (71 citations re-checked against the raw tag
sources by the windowed audit: all 71 quoted constructs exist; 60 line
numbers exact as banked, 12 drifts of 1-11 lines corrected in place —
the audit record is `findings-4.24-citation-audit.md`). The
SBIOS-side trigger conditions and the GSP-RM stub consequences are
labeled HYPOTHESIS/PROVEN respectively and not mixed. The negative
grep (§5) is reproducible with one command.
