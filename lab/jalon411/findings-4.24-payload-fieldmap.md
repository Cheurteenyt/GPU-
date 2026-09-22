# 4.24 — pass I: the 1616-byte payload field map — the EDPp-table assumption FALSIFIED, the capture-length law PROVEN, the carrier handler identified

Substrate: `tools/edpp/edpp_payload_1616.bin` (sha256
`573a2836428bda3c…`, 1,616 B — the 4.23 transport capture), the open
kernel modules **tag 610.57.04** (the driver's exact branch, cloned for
this pass; citations carry file:line), the 4.20 dispatch table
(`rm-full.elf`). Instruments: `v424_payload_map.py` (+ `.json`),
`v424_handler_walk.py`, `v424_entry_calib.py`, `v424_pa_glue.py`.

## 1. The headline (honest): this payload is NOT the EDPp min/default/max table

The working assumption inherited from 4.23 ("250000 @104 = the EDPp
policy structure — min/default/max") is **FALSIFIED for this capture**,
on three independent byte-level facts:

1. **100000 (0x186A0): ZERO occurrences** in the whole file, at ANY
   alignment (u32 scan, step 1).
2. **240000 (0x3A980): ZERO occurrences** — same scan.
3. The
   `NV2080_CTRL_CMD_INTERNAL_PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO_PARAMS`
   field-order test (`ctrl2080internal.h:3988`, fields limitMin /
   limitRated / limitMax / limitCurr / limitBattRated / limitBattMax)
   at the ONLY base consistent with limitMax=250000 (base 96) reads
   limitMin=257, limitRated=0 — **not the struct**.

What the file actually contains: **five nonzero u32s** in the params,
everything else zero:

| poff (params) | abs | value | reading |
|---|---|---|---|
| 0 | 40 | 255 (0xFF) | IN field, unknown semantics |
| 4 | 44 | 3 | IN field, unknown semantics |
| 8 | 48 | 257 (0x101) | IN field, unknown semantics |
| 56 | 96 | 257 (0x101) | IN field, unknown semantics |
| 64 | 104 | 250000 (0x3D090) | a 250 W-class value — CARRIED, not consumed (§4) |

## 2. THE CAPTURE-LENGTH LAW (new, applies to every RPCDUMP76 capture)

The 4.23 capture is 32 bytes LONGER than the message, and this is now
PROVEN from the open source:

- `src/nvidia/src/kernel/rmapi/rpc_common.c:184`:
  `pVgpuRpcHeader->length = sizeof(rpc_message_header_v) + paramLength;`
  (citation-audit correction: the pass originally cited :182 — the drifted
  line numbers in this doc were re-audited against the 610.57.04 raw
  sources; see findings-4.24-citation-audit.md)
  — the header's `length` field INCLUDES the 32-byte RPC message header
  (`g_rpc-message-header.h:41`, `rpc_message_header_v03_00`: 8 u32s =
  32 B, `rpc_message_data[]` follows).
- The 4.23 dump patch (`tools/edpp/patch_rpc_final.py`) dumps
  `rpc_len = vgpuHeader->length` bytes starting at
  `vgpuHeader->rpc_message_data` — the BODY start.
- Therefore: dumped(1,616) = body(1,584) + residue(32). The body =
  40 (the rm-control prefix) + 1,544 (params). The last 32 bytes
  (@1584..1615, all zeros — the queue was memset) are NOT the message.

Every 4.23 offset reading survives (the residue sits at the end), but
every future analyzer must trim 32. The declared `paramsSize=1544`
matches the body exactly — internal consistency restored.

## 3. The field map (the full table)

Layout sources: `g_rpc-structures.h:1423`
(`rpc_gsp_rm_control_v03_00`), sender assignment
`src/nvidia/src/kernel/vgpu/rpc.c:10792-10800`.

| offset | field | value | status | evidence |
|---|---|---|---|---|
| 0x00 | hClient | 0xc1d0004c | **PROVEN** (layout) | g_rpc-structures.h:1423; rpc.c:10794 `rpc_params->hClient = hClient` |
| 0x04 | hObject | 0xa55a0030 | **PROVEN** (layout) | rpc.c:10795 |
| 0x08 | cmd | **0x2080d031** | **PROVEN** | exists in the firmware dispatch table (§4, raw entry); FINN interface `0x2080d0` = CLOSED-ONLY: the open SDK exposes 38 subdevice-0x2080 interfaces, max id 0x2080a7 — `0x2080d0` appears in none of the headers |
| 0x0C | status | 0 | **PROVEN** (send path: zeroed) | rpc_common.c:150-152 portMemSet before write |
| 0x10 | paramsSize | 1544 | **PROVEN + cross-validated** | == the dispatch entry tag 0x608 (§4) |
| 0x14 | rmapiRpcFlags | 0 | **PROVEN** (RMAPI_RPC_FLAGS_NONE) | rpc.c:10798 |
| 0x18 | rmctrlFlags | 0 | **PROVEN** | rpc.c:10799 |
| 0x1C | rmctrlAccessRight | 0 | **PROVEN** | rpc.c:10800 |
| 0x20 | reserved0 | 0 (u64) | **PROVEN** | g_rpc-structures.h:1432 |
| 0x28 (poff 0) | param[0] | 255 | **HYPOTHESIS** (semantics) | the struct = closed-only; only the byte values are proven |
| 0x2C (poff 4) | param[4] | 3 | **HYPOTHESIS** | " |
| 0x30 (poff 8) | param[8] | 257 | **HYPOTHESIS** | " |
| 0x58 (poff 56) | param[56] | 257 | **HYPOTHESIS** | " |
| 0x68 (poff 64) | param[64] | 250000 | **PROVEN carried / HYPOTHESIS semantics** | the handler NEVER touches the params (§5) |
| 1584..1615 | — | 0 ×32 | **PROVEN: queue residue** | the capture-length law (§2) |
| all other params | | 0 | **PROVEN zeros** | the send path marshals the full struct; OUT fields are filled in the GSP→CPU RESPONSE, which the send-side hook never sees |

## 4. The dispatch-table cross-check (byte-exact)

The 4.20 table (@0x1c183b8, 1,156 entries, stride 0x20) entry for this
cmd, raw from `rm-full.elf`:

```
id=0x2080d031 tag=0x608 pA=0x1c23870 handler=0x11267fc sz0=0x44 sz1=0x0
raw: 31d08020 08060000 7038c201 00000000 fc671201 00000000 44000000 00000000
```

- `tag = 0x608 = 1544` — **EXACTLY the declared paramsSize**. The
  cmd↔size pair is cross-validated firmware↔transport.
- `handler = 0x11267fc` — boundary-verified on the 4.16 map.
- Calibration with the KNOWN-GOOD entries (same raw dump):
  GET_EDPP_LIMIT_INFO (0x20800afd, tag=0x18, handler=0x1458bec — the
  4.20 memset-confirmed one) and UPDATE_EDPP_LIMIT (0x20800ad0,
  tag=0x8, handler=0x1862480 — the stub). The layout reading is not
  assumed; it reproduces on the two anchors.

## 5. The handler walk — the params are IGNORED on this firmware

`v424_handler_walk.py` / `v424_entry_calib.py`, capstone RISCV64+C:

```
011267fc  c.swsp   s1, 36(sp)   [manual: bytes 27 d2; capstone's 32-bit-first skips it; 4.16 map: 0x11267fe = next verified start]
011267fe  addi     a3, a4, 0x52c
01126802  c.add    a3, a5
01126804  c.lw     a1, 0(a3)
01126806  lui      a0, 0x400        ; 0x400000
0112680a  addi     a2, a4, 0x520
0112680e  c.or     a1, a0
01126810  c.sw     a1, 0(a3)        ; *(state+0x52c) |= 0x400000
01126812  addi     a4, a4, 0x3d0
01126816  add      a3, a5, a2
0112681a  lui      a2, 0x400
0112681e  c.sw     a2, 0(a3)        ; *(state+0x520) = 0x400000
01126820  c.add    a5, a4
01126822  sw       zero, 0(a5)      ; *(state+0x3d0) = 0
01126826  c.j      -0x168           ; -> 0x11266be: the shared log/assert path ending
                                     restore + return a0 = 0x40 = NV_ERR_INVALID_STATE
                                     (nvstatuscodes.h:93)
```

**Not one load/store touches the RPC params** — no reference to the
params/arg register anywhere in the block. The handler = a state-flag
setter (two `0x400000` bits + one cleared u32) — a "dirty/re-derive"
marker shape. The EDPp-critical consequence:

> **250000 @104 rides the transport but is NOT consumed by this
> handler.** The GSP-RM does not read the policy value from this
> payload on this build.

Sibling-block note (honest): the same flag-set block exists standalone
at ~0x112674e (it forms `a4=0x11100000` itself) — two entry points into
one shared "mark state" routine, consistent with the 4.19
mid-function-entry dispatch architecture (the GET_EDPP handler
0x1458bec itself starts `sd zero,0x240(s2)` — a CALLEE-SAVED reg —
i.e., entered mid-function with prepared context).

`v424_pa_glue.py`: the common `pA=0x1c23870` decodes as DATA, not code
(honest negative — it is the family descriptor, not executable glue).

## 6. What this changes for the campaign

1. **The 1616-byte payload ≠ the EDPp policy table.** The v9 host-RAM
   scanner fingerprint {100000, 240000, 250000} stays the right lane —
   and the fact that the triple NEVER rode the transport (4.23
   finding #3, re-confirmed here by the zero-hit scan) stays consistent
   with the enforcement = host-side (the x86 RM holds it from the
   VBIOS parse).
2. **The 4.23 degradation has a named mechanism candidate.** The
   rewriter (`patch_rpc_final.py:40-54`) rewrote EVERY u32==250000 in
   EVERY fn=76 payload (no cmd filter, no offset filter, limit
   min(rpc_len,1616)). This pass proves at least one control carries
   250000 as non-consumable payload data — rewriting it feeds garbage
   into unrelated controls. Any future in-flight rewrite MUST filter by
   cmd AND params offset.
3. **The send-side dump can never see the OUT values.** A GET-type
   control's limits ride the RESPONSE (GSP→CPU). The response-path hook
   (the recv side) is the missing capture — queue 4.25.
4. The capture-length law (§2) retro-validates all 4.23 offsets and
   fixes every future analyzer.

## Queue for 4.25

- The RESPONSE-path dump (the recv hook) — the GET-type responses are
  where filled limit values could appear; the send-only blind spot is
  now named.
- The 0x2080d031 params struct: mine the closed x86 RM
  (`tools/analysis/gsp-extract/win.elf`) for the interface-0x2080d0
  marshal code (the marshal embeds the field offsets).
- The v9 scanner boot verdict (unchanged by this pass; the fingerprint
  survives — it was never contradicted by the transport).

## Discipline

Every claim above carries its byte or file:line. The falsified
assumption is banked as the headline, not buried. The handler
"dirty-flag" reading is labeled HYPOTHESIS (the flag semantics are not
statically resolvable — the 4.19 wall); what is PROVEN is the absence
of params access in the handler block.
