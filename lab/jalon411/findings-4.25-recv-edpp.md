# 4.25 — the recv hook: the GSP→CPU completion point proven end to end, the response-capture instrument delivered and verified, the §7.2 prediction armed for the boot

Substrate: `open-gpu-kernel-modules` **tag 610.57.04** (cloned for this pass,
not committed: size), the 4.23/4.24 findings (`findings-4.23-transport-edpp.md`,
the three `findings-4.24-*.md`, `findings-4.24-citation-audit.md`), the 4.23
send-side instrument (`tools/edpp/patch_rpc_final.py`,
`tools/edpp/edpp_payload_1616.bin`). Instruments delivered:
`tools/edpp/patch_rpc_recv.py` (the recv hook + the opt-in force-get),
`tools/edpp/rpcdump_recv_analyze.py` (the response analyzer). Every claim
carries file:line read from the tag in this pass; the pass brief's constraint
— build the RECEVEUR (GSP→CPU of fn=76), capture at boot the
GET_EDPP_LIMIT_INFO response, test the §7.2 prediction — is delivered as an
armed instrument + protocol; the boot itself is named honestly as NOT run
(§4).

## 1. The completion point — the whole GSP→CPU chain, proven

fn=76 = `X(GSP, GSP_RM_CONTROL, 76)` (`src/nvidia/inc/kernel/vgpu/
rpc_global_enums.h:86`). The chain, every hop cited:

1. **The funnel (CPU, request side).** `rpcRmApiControl_GSP`
   (`src/nvidia/src/kernel/vgpu/rpc.c:10659`) is the ONLY marshaller of
   fn=76 in the core RM — `rpcWriteCommonHeader(pGpu, pRpc,
   NV_VGPU_MSG_FUNCTION_GSP_RM_CONTROL, rpc_params_size)` at `rpc.c:10790`,
   with `rpc_params_size = sizeof(rpc_gsp_rm_control_v03_00) + paramsSize`
   (`rpc.c:10784`) and the marshal `rpc.c:10793-10800` + params copy-in
   `:10827`. (Excluded, honestly: the DCE display client has its own small
   fn=76 lane — `src/nvidia/src/kernel/gpu/dce_client/dce_client_rpc.c:415-418`
   + `_dceRpcIssueAndWait` `:431` — display-only, not the RM-API funnel, not
   active on this GA104 config. The hook below does not cover it.)
2. **The header init.** `rpcWriteCommonHeader`
   (`src/nvidia/src/kernel/rmapi/rpc_common.c:124-187`) zeroes the message
   buffer (`:149-152`, `maxRpcSize` for this fn), sets
   `rpc_result = rpc_result_private = NV_VGPU_MSG_RESULT_RPC_PENDING`
   (`:158-159`; the constant `0xFFFFFFFF`, `rpc_headers.h:148`), and
   `length = sizeof(rpc_message_header_v) + paramLength` (`:184`) — the
   capture-length law's source (4.24 pass I §2).
3. **The send.** `_issueRpcAndWait` (`rpc.c:1836`) calls `rpcSendMessage`
   (`:1890`, the fn-ptr macro `generated/g_rpc_hal.h:45`) →
   `_kgspRpcSendMessage` (`kernel_gsp.c:387`, fn ptr assigned `:3189`),
   which stamps the sequence (`:404`) and calls `GspMsgQueueSendCommand`
   (`:410` — the 4.23 send-hook site).
4. **The wait.** `_issueRpcAndWait` calls `rpcRecvPoll` (`rpc.c:1990`,
   macro `g_rpc_hal.h:47`) → `_kgspRpcRecvPoll` (`kernel_gsp.c:2848`,
   fn ptr `:3190`): the poll loop `:2962` drains events
   (`_kgspRpcDrainEvents` `:2970`, loop `kernel_gsp.c:1869-1873`, one event
   per `_kgspRpcDrainOneEvent` `:1802`).
5. **THE recognition (the response is in the buffer).**
   `_kgspRpcDrainOneEvent`: memory fence (`kernel_gsp.c:1817`), then
   `GspMsgQueueReceiveStatus` (`:1819` =
   `src/nvidia/src/kernel/gpu/gsp/message_queue_cpu.c:640`, which copies the
   received record from the rx queue into the staging element,
   `portMemCopy(pTgt, …)` `:680-682`), then the match test —
   **`kernel_gsp.c:1825-1828`: `pMsgHdr->function == expectedFunc &&
   pMsgHdr->sequence == expectedSequence` → `NV_WARN_MORE_PROCESSING_REQUIRED`**
   ("The synchronous RPC response we were waiting for is here",
   `kernel_gsp.c:2972-2981`). That test is the exact instant the transport
   declares the GSP→CPU transfer complete.
6. **The result read.** Back in `_issueRpcAndWait`: `rpc.c:2012-2027` reads
   `pVgpuRpcHeader->rpc_result` — the field left PENDING at `rpc_common.c:158`
   has been overwritten by the GSP; `NV_VGPU_MSG_RESULT_SUCCESS = NV_OK`
   (`rpc_headers.h:68`). (The vGPU-GSP plugin lane reads
   `rpc_result_private` the same way, `rpc.c:8841-8843` — the GSP client lane
   checks `rpc_result`.)
7. **THE copyout (params OUT leave the buffer).** `rpcRmApiControl_GSP`
   `rpc.c:10868`: on `status == NV_OK` the GSP handler's status is read
   (`rpc_params->status`, `:10871/:10873`) and the params are copied to the
   caller — **`rpc.c:10891-10894`:
   `portMemCopy(pParamStructPtr, paramsSize, rpc_params->params, paramsSize)`**
   (the FINN-serialized variant at `:10880`). From here the PRH caches the
   six limits (`platform_request_handler_ctrl.c:1762-1767`).

**The message reuse (the buffer identity — proven, not assumed).** The RPC
object's buffer and the receive staging area are the SAME memory:
`pRpc->message_buffer = pRpc->pMessageQueueInfo->pRpcMsgBuf`
(`kernel_gsp.c:3185`), and `pRpcMsgBuf = gspMsgQueueGetRpcMessageHeader(pMQI,
pMQI->pCmdQueueElement)` (`message_queue_cpu.c:188`) — i.e. the RPC header
*inside* the staging work-area element (`pCmdQueueElement`,
`message_queue_cpu.c:162-163`, allocated from `pWorkArea` `:150-153`).
`GspMsgQueueReceiveStatus` copies the GSP's response record back INTO that
same element (`:680-682`). One buffer, both directions: the request the 4.23
send hook dumped from is overwritten by the response, in place — which is
why a recv hook at the completion point sees the response at the very
offsets the send-side field map already decoded (4.24 pass I §3).

## 2. The hook — read-only by construction

`tools/edpp/patch_rpc_recv.py` patches two files of the DKMS tree
(default `--src /usr/src/nvidia-610.57.04`):

- **rpc.c** — inserts, right after the issue-RPC block (`rpc.c:10853-10861`,
  anchor unique: `// Issue RPC` ×1 in the file), a dump block gated
  `status == NV_OK && large_message_copy == NULL`: exactly "au retour GSP",
  small-path only. It prints one decoded line —
  `RPCRECVINFO seq=.. fn=.. cmd=0x.. status=0x.. psz=.. rres=0x.. rpriv=0x.. len=.. dump=..`
  (the transport result `rres`, the private result `rpriv` — both
  capture-revealed: no open-source writer of `rpc_result_private` exists on
  the GSP client lane) — then the raw body in send-compatible 512-byte
  chunks (`RPCRECV76 seq=.. off=.. len=..: …`) read from
  `rpc_message_data` for `length` bytes, the same view and the same
  capture-length law as `RPCDUMP76` (trim 32, 4.24 pass I §2). The `seq`
  printed is the RPC header sequence (`kernel_gsp.c:404`) — the
  authoritative send↔recv correlation id (the 4.23 send hook's own counter
  is NOT the header sequence; a 4.26 refinement notes this).
- **platform_request_handler.c** (`--force-get`, opt-in) — §3 below.

Registry keys (read once, `osReadRegistryDword`, the file's own precedent
`rpc.c:1637`; the symbol is declared in `generated/g_os_nvoc.h`, force-included
in every RM translation unit): **RpcDump** (the 4.23 key — one boot captures
BOTH sides) enables mode 1; **RpcRecvMode** overrides (1 = every small fn=76
response — same volume as the 4.23 send dumps, 3-4 MB/boot; 2 = EDPp only,
`cmd ∈ {0x20800ad0, 0x20800afd}`).

**Scope, honestly stated:** the hook covers the RM-API funnel's small
controls — the EDPp pair (8 B / 24 B params) always qualifies
(`message_buffer_remaining = maxRpcSize − 72` ≫ 24, `rpc.c:10678-10679`).
Large controls (`message_buffer_remaining < paramsSize` → local copy,
`rpc.c:10809-10816`; response reassembled by `_issueRpcAndWaitLarge` →
`_issueRpcLarge(..., NV_TRUE, NV_TRUE)`, `rpc.c:2246-2258`) are excluded:
their response head lives in the caller's local copy, not the staging
buffer — dumping the staging tail there would mislead. The DCE lane (§1)
is likewise out of scope.

**The read-only guarantee:** the inserted block contains zero writes to the
buffer, zero control-flow changes (it sits after the `status` assignment,
before the existing `if (status == NV_OK)`), and no rewrite of any payload.
The 4.23 rewriter lesson (4.24 pass I §6.2: any future in-flight write MUST
filter by cmd AND offset) is banked in the patch's comments — this pass
writes nothing anywhere.

**Verification (run in this pass, on the pristine tag):** apply + idempotent
re-apply + `--revert` are **byte-exact** (`cmp` clean against the pristine
`rpc.c` / `platform_request_handler.c`); the anchors are unique
(`NV_STATUS rpcRmApiControl_GSP` ×1, `// Issue RPC` ×1 in rpc.c; the
force-get anchor disambiguated by its `EDPpeak event update` continuation ×1
in platform_request_handler.c); braces/parens balance identically to the
pristine files. The C comments are ASCII-only (the 4.23 patch's own
convention — no build-locale surprises).

## 3. The capture protocol (the boot) — and the SBIOS condition

1. **Patch**: `patch_rpc_recv.py` (recv hook) [+ `patch_rpc_final.py` for
   the send side, **EdppOverride ABSENT = no rewrite**]; DKMS rebuild; the
   module params ride the UKI/Limine plumbing banked in 4.23
   (`RpcDump=1` in the modprobe conf inside the initramfs, the Blake2b
   re-align after rebuild).
2. **The SBIOS condition (proven, 4.24 §2.2 « 2 », re-cited)**: the GET is
   emitted only when the PSHARESTATUS bits say so —
   `_PLATFORM_SETEDPPEAKLIMITINFO_SET` → `bPlatformEdpUpdate`
   (`platform_request_handler_ctrl.c:2369-2376`, the branch `:2493-2500`)
   → `pfmreqhndlrHandlePlatformSetEdppLimitInfo_IMPL` (`:1738-1802`, the
   RM control `:1754-1759`, params `{0}`-initialized `:1752`) → the six
   limits cached `:1762-1767` → the ACPI SETEDPPLIMITINFO work item
   (`:2814`, fill `:2837-2849`, call `:2858`). If this boot's SBIOS never
   raises the bit, NO GET rides the transport — an honest negative the
   analyzer reports by name.
3. **The fallback (§2.2 « 2 » forced — documented AND shipped, opt-in)**:
   `patch_rpc_recv.py --force-get` adds a registry-gated one-shot emission
   of the OUT-only query at the head of the post-load work item
   (`_pfmreqhndlrPmgrPmuPostLoadWorkItem`,
   `platform_request_handler.c:925-1002` — the same work item that already
   runs the boot-time EDPp syncs `:947-952, :983-997`): with
   `EdppForceGet=1` it calls `pfmreqhndlrHandlePlatformSetEdppLimitInfo`
   once. This is a REQUEST emission through the stock §2.2 « 2 » code path
   (the handler self-guards on full power, `ctrl.c:1750`); the response
   path is untouched. A natural SBIOS-triggered GET and a forced GET are
   distinguishable in the capture (the forced one is preceded by the
   `EDPP-FORCE-GET` printk).
4. **The harvest**: `journalctl -b -k | grep -E 'RPCRECV' |
   python3 tools/edpp/rpcdump_recv_analyze.py` — the analyzer reassembles by
   seq, applies the capture-length law (verifies the 32-byte residue is
   zero, trims, flags honestly if not), decodes the 40-byte
   `rpc_gsp_rm_control_v03_00` response prefix
   (`g_rpc-structures.h:1423-1435`), decodes the 24-byte
   GET_EDPP_LIMIT_INFO params (`ctrl2080internal.h:3988-3995`), prints the
   offset→field→value→PROVEN/HYPOTHÈSE table and the §7.2 verdict
   (CONFORME/NON-CONFORME per check). `--predict` prints the expected table
   pre-boot; `--selftest` validates the decode pipeline on a SYNTHETIC
   §7.2-shaped buffer (instrument check ONLY — nothing synthetic is ever
   banked as a capture).

## 4. The honest ledger — what this pass did NOT run

- **No hardware boot was executed in this pass.** The working environment
  has no GA104 machine: the capture itself is the 4.26 boot. What was run
  here: the full source proof of §1 (every citation read from the pristine
  tag, not from the 4.24 docs), the patch apply/revert byte-exact cycle,
  the anchor-uniqueness counts, the brace balance, the analyzer selftest +
  predict modes. What is missing: the patched driver build on the target,
  the boot with `RpcDump=1` (+ `EdppForceGet=1` if the SBIOS bit never
  comes), the journal harvest, the analyzer run on the real log.
- **The §7.2 test is therefore ARMED, not answered.** No value in §5 is
  banked as observed; every value row is HYPOTHESIS until the capture
  lands. (INTERDICTION respected: nothing below is a fabricated result.)
- Known unknowns the capture will settle: the response's `length` (the GSP
  rewrites the header in place — the request for this control is already
  96 B of message, 32+40+24, `rpc_common.c:184` + `rpc.c:10784`, so 96 is
  the consistent prediction either way); `rpc_result_private`'s value on
  the GSP client lane (no open-source reader exists); whether the response
  prefix echoes hClient/hObject; `limitCurr`/`limitBatt*` (the §7.2
  prediction is silent on them — desktop, no battery expected).

## 5. The predicted response, field by field (the §7.2 test table)

The expected dump: **96 bytes = 40 (response prefix) + 24 (params) + 32
(queue residue, zero)** — the §7.2 prediction of
`findings-4.24-edpp-flow.md`, now groundable line-by-line:
prefix layout `g_rpc-structures.h:1423-1435`, params layout
`ctrl2080internal.h:3988-3995` (all-OUT, doc block `:3966-3977`), residue
law 4.24 pass I §2. The triplet at params offsets {0,4,8} = dump offsets
{40,44,48} — the dump starts at `rpc_message_data` (body offset 0).

| dump off | poff | field | predicted | status |
|---|---|---|---|---|
| 0x00 | — | hClient | echo of the request (internal client) | layout PROVEN (`:1425`) — value HYPOTHESIS |
| 0x04 | — | hObject | echo (internal subdevice) | layout PROVEN (`:1426`) — value HYPOTHESIS |
| 0x08 | — | cmd | 0x20800afd | layout PROVEN (`:1427`) — value HYPOTHESIS (echo expected) |
| 0x0C | — | status (rmctrl) | 0x00000000 (NV_OK) | layout PROVEN (`:1428`) — value HYPOTHESIS |
| 0x10 | — | paramsSize | 24 | layout PROVEN (`:1429`) — value HYPOTHESIS (cross-validated: dispatch tag 0x18, 4.24 pass I §4) |
| 0x14/0x18/0x1C | — | rmapiRpcFlags / rmctrlFlags / rmctrlAccessRight | 0 / 0 / 0 | layout PROVEN (`:1430-1432`) — values HYPOTHESIS |
| 0x20 | — | reserved0 (u64) | 0 | layout PROVEN (`:1433`) — value HYPOTHESIS |
| **0x28** | **0** | **limitMin** | **100000 (100 W)** | field order PROVEN (`:3989`) — value HYPOTHESIS (§7.2) |
| **0x2C** | **4** | **limitRated** | **240000 (240 W)** | field order PROVEN (`:3990`) — value HYPOTHESIS (§7.2) |
| **0x30** | **8** | **limitMax** | **250000 (250 W, the VBIOS ceiling)** | field order PROVEN (`:3991`) — value HYPOTHESIS (§7.2) |
| 0x34 | 12 | limitCurr | unknown (the runtime resultant) | field order PROVEN (`:3992`) — value HYPOTHESIS |
| 0x38 | 16 | limitBattRated | unknown (DC — 0 expected, desktop) | field order PROVEN (`:3993`) — value HYPOTHESIS |
| 0x3C | 20 | limitBattMax | unknown (DC) | field order PROVEN (`:3994`) — value HYPOTHESIS |
| 0x40-0x5F | — | queue residue | 0 ×32 | PROVEN as law on the send side (4.24 §2) — recv-side application to VERIFY on the capture |

The §7.2 verdict checklist the analyzer runs: len(header) == 96; body+residue
== 64+32 with the residue all-zero; the triplet {100000, 240000, 250000} at
{40, 44, 48}; paramsSize == 24. If the triplet appears, **the response is
the only place the transport ever carries the EDPp min/default/max** — the
4.23 "never transmitted" verdict was send-side only, by construction.

## 6. Queue for 4.26

1. **The boot capture** (§3): `RpcDump=1` first; if zero GET responses and
   the journal shows no `_PLATFORM_SETEDPPEAKLIMITINFO_SET`-triggered flow,
   the `EdppForceGet=1` boot. Then the analyzer's verdict on §7.2, and the
   findings-4.25 tables move from HYPOTHESIS to PROVEN/REFUTED per row.
2. If the triplet lands: reconcile `limitCurr` against the applied limit
   (LACT reads) — the response becomes the transport-side witness of the
   policy state the v9 scanner hunts host-side.
3. If the SBIOS bit never comes AND the forced GET errors: the honest
   negative (the handler's status line names the refusal) — the §2.2 « 2 »
   lane's liveness on this SBIOS becomes itself a banked fact.
4. Send-hook refinement (one line): print `vgpuHeader->sequence` in
   `patch_rpc_final.py`'s RPCDUMP76 lines for exact send↔recv pairing.
5. Carried over unchanged: the 0x2080d031 params-struct mining
   (`tools/analysis/gsp-extract/win.elf`), the v9 scanner boot verdict
   (4.24 pass I queue).

## Discipline

Every file:line above was read from the pristine tag 610.57.04 in this pass
(the 4.24 audit's windowed method is the precedent; the anchors' uniqueness
was counted programmatically, not assumed). The completion-point chain is
proven from source, not inferred from the 4.23 captures. The capture itself
was NOT executed (no hardware in this environment) and no observed value is
claimed anywhere in this document — the §5 table is prediction, labeled as
such row by row.
