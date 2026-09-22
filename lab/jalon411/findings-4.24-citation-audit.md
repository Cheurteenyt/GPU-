# 4.24 — the post-PR verification & citation audit — the deliverables re-executed, the citations re-checked against the raw tag

Substrate: the PR branch `pass/4.24-payload-flow-lz` as opened, the raw
`open-gpu-kernel-modules` **tag 610.57.04** sources fetched file-by-file
(raw.githubusercontent.com, per-file sha256 pinned in the audit run),
the payload `tools/edpp/edpp_payload_1616.bin`. Instruments:
`v424_verify_payload_claims.py` (the independent byte re-check),
`v424_citation_audit.py` (the windowed citation audit).

## 1. Why this pass exists

The PR carries three falsification-bearing findings. Before it is
merged, every reproducible claim in it was re-executed independently —
not by re-reading the pass's own outputs, but by re-running the
instruments from the committed sources and re-deriving the byte facts
with fresh code that does not import the pass's tooling. The audit's
own rule: a claim survives only if a clean-room re-execution or a raw
source line reproduces it.

## 2. The re-execution verdict (all instruments, all identical)

| instrument | re-run result |
|---|---|
| `tools/gsp-lz/tests_gsplz.py` | **ALL TESTS PASSED** — the full battery (T1 round-trip, T2 reference-decodes-ours, T3 ours-decodes-reference, T4 adversarial incl. 1 MiB incompressible / RLE offsets 1-2-3 / length boundaries, T5 the real RM-image slices 1 MiB + 4 MiB), ~100 checks, 0 failures |
| `v424_payload_map.py` | JSON **byte-identical** to the committed `v424_payload_map.json` |
| `v424_handler_walk.py` | JSON **byte-identical** to the committed `v424_handler_walk.json` (401 insns) |
| `v424_gfw_directory.py` | JSON **byte-identical** to the committed `v424_gfw_directory.json` |
| `v424_entry_calib.py` | reproduced (the GET_EDPP handler tail, `sb zero` @0x1458c12 region) |
| `v424_pa_glue.py` | reproduced (the pA = DATA verdict) |

The independent byte re-check (`v424_verify_payload_claims.py`, 11
checks, **11/11 PASS**) re-derived WITHOUT importing the pass code:
sha256 prefix `573a2836428bda3c…`; cmd 0x2080d031 @0x08; paramsSize
1544 @0x10; 250000 @abs 104; **zero occurrences** of 100000/0x186A0 and
240000/0x3A980 at any offset; the exact five-nonzero-u32 census
{(40,255),(44,3),(48,257),(96,257),(104,250000)}; the 1616 = 1584 + 32
all-zero-residue length law; the base-96 field-order test reading
257/0; and one new cross-check — **250000 occurs at offset 104 ONLY**
(sharpening §6.2 of pass I: the 4.23 rewriter's blanket u32==250000
rule hit exactly this one position in this capture).

## 3. The citation audit (71 citations, the honest ledger)

Every file:line citation of the two open-source passes was re-checked
against the raw tag with a ±6-line window (`v424_citation_audit.py`,
71 checks, needles chosen independently from the claims' quoted
content).

**The headline: 71/71 quoted constructs EXIST in the 610.57.04 tree —
zero fabricated claims. 60 line numbers were exact as originally
banked; 12 correction items (itemized below, drifts of 1-11 lines)
were applied in place in the two findings docs. One item is the audit
catching its own first pass: the strict-needle check falsely flagged
`:425` (the aligned-space spacing of the source line defeated the
substring); the windowed audit re-confirmed the original :425 — it was
NEVER drifted and stays as banked.**

| doc | cited | actual | what is there |
|---|---|---|---|
| fieldmap §2 | `rpc_common.c:182` | **:184** | `pVgpuRpcHeader->length = sizeof(rpc_message_header_v) + paramLength;` |
| fieldmap §3 | `rpc_common.c:139` | **:150-152** | the message_buffer `portMemSet` before the header write |
| fieldmap §3 | `rpc.c:10793` (hClient) | **:10794** | `rpc_params->hClient = hClient;` |
| fieldmap §3 | `rpc.c:10794` (hObject) | **:10795** | `rpc_params->hObject = hObject;` |
| fieldmap §3 | `rpc.c:10801` | **:10798** | `rmapiRpcFlags = RMAPI_RPC_FLAGS_NONE` |
| fieldmap §3 | `rpc.c:10802` | **:10799** | `rmctrlFlags = 0` |
| fieldmap §3 | `rpc.c:10803` | **:10800** | `rmctrlAccessRight = 0` |
| edpp-flow §1,§2.2 | `:2375` (3rd request bit) | **:2376** | the `_EDPPEAK_LIMIT_UPDATE` FLD_TEST_DRF (the assignment spans the line pair) |
| edpp-flow §2.2 1.B | `:2402-2410 region` (cache) | **:2407 (GET call), :2416 (cache write)** | the GET + the `platformEdppLimit` cache |
| edpp-flow §2.2 1.B | `:2418-2421` (defer) | **:2419-2422** | `if (bInit) { ... bDifferPlatformEdppLimit = NV_TRUE; }` |
| edpp-flow §2.2 2 | `:2837-2857` (fill+call) | **fill :2837-2849, call :2858** | the struct fill then `pfmreqhndlrCallACPI` |
| edpp-flow §4 | `:1665-1670` (the value-0 block) | **:1661-1668** (if-block :1665-1668) | the quoted block verbatim |

Ranges that re-audited EXACT (no change): `:384`, `:425`, `:661-672`,
`:1001-1019`, `:1022-1037`, `:1170`, `:146-147`, `:1488`, `:1501`,
`:1597`, `:1609-1615` (the `{0}` init @1609), `:1615` (the 1.A RPC cmd),
`:1625-1628`, `:1647`, `:1659-1664`, `:1665` (the `if`), `:1667`,
`:1672`, `:1697-1725`, `:1722`, `:1738`, `:1757`, `:1762-1767`,
`:2337`, `:2369`, `:2370`, `:2386-2391`, `:2402`, `:2493-2500`,
`:2814`, `:925-1002`, `:947-952`, `:983-997`, `:1009`,
`g_rpc-structures.h:1423/1432`, `g_rpc-message-header.h:41`,
`nvstatuscodes.h:93`, `ctrl2080internal.h:3220-3241` (the struct at
:3238-3241 verbatim) and `:3988` (the struct typedef), `platform_request_handler_utils.h:82-92`
(ulVersion/limitLast/limitMin at :83/:84/:85, the close at :92),
`g_platform_request_handler_nvoc.h:152-157/223-234/255`.

## 4. What the audit changes — and what it does not

1. **No verdict changes.** Every PROVEN/HYPOTHESIS/FALSIFIED verdict of
   the pass stands; the corrections are line-number hygiene only. The
   two falsifications (the EDPp-table assumption; the envytools LZ
   citation) and the three proofs (the capture-length law; the
   handler-ignores-params walk; the LZ4 differential validation) all
   re-executed clean.
2. The drift pattern is consistent with hand-transcription from a
   locally patched or slightly different tree revision — the quoted
   CONTENT never differed, only the stored line numbers. The audit pins
   the canonical numbers to the unmodified tag.
3. The audit's own false positive (:425, the strict-needle pass) is
   banked here because the audit's discipline applies to the auditor:
   a strict equality check on whitespace-formatted C code yields false
   negatives, and the windowed substring check is the canonical method
   (the committed script implements it).
4. The pass I §6.2 corruption-risk statement gains one sharpening: in
   THIS capture the blanket `u32==250000` rewriter had exactly one hit
   (offset 104). The MUST filter by cmd AND offset conclusion is
   unchanged.

## Discipline

Both audit scripts are committed next to the pass instruments and run
standalone. The citation audit downloads nothing at repo-build time —
the raw-source URLs and the expected needles are in the script, and the
audit is reproducible with one command per script.
