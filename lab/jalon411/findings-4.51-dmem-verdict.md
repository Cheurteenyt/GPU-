# 4.51 — the DMEM verdict instrument, the gated timing-target table, the ways card: the 4.47-4.50 proofs become decidable experiments

Pass: 4.51 (stacked on main `a0bab00` — the 4.47-4.50 stack is MERGED).
Date: 2026-09-25.
Trigger: the founder's directive — « PASSE 4.51 — LE VERDICT DMEM ET LES
LEVIERS BANDWIDTH : transformer les preuves 4.47-4.50 en expériences
décidables » (TÂCHE A the instrument, TÂCHE B the gated table, TÂCHE C
the ways card; the machine = NOT this terrain).
Deliverables: `tools/edpp/gsp_dmem_dump.c` (the driver instrument),
`lab/jalon411/v451a_dmem_scan.py` (the searcher), `tools/edpp/runbook-451.sh`
(the four-boot day), `tools/edpp/pillarB-sysmem.py` (the ways battery),
`lab/jalon411/v451b_timing_targets.json` (the gated template), this file
+ the INDEX row.
Baseline gate: ALL banked counts reproduced first on this machine —
**auipc 416,206 ✓ (match=True), the coordinate law 512/512 ✓, the map
670 covered regions ✓, the v431 census 17/17 ✓, the fingerprint
selftest 8/8 ✓, selftest 5/5 ✓, TT 11/11 ✓, TF 9/9 ✓, TR 18/18 ✓,
TT-T 5/5 ✓.** (The environment was rebuilt mid-pass; every count
reproduced on the fresh clone.)

## §1 TÂCHE A1 — the instrument, grounded on the EXACT source (PROUVÉ grounding)

The brief asked for the kernel_gsp.c patch design. This pass did better
than a design: it grounded every anchor on the open source of the EXACT
driver tag — `open-gpu-kernel-modules @ 610.57.04` — and shipped the
drop-in C (`tools/edpp/gsp_dmem_dump.c`):

- `src/nvidia/generated/g_kernel_gsp_nvoc.h` @610.57.04: the FULL
  KernelGsp member list read directly — `pSysmemHeapDescriptor`,
  `pGspArgumentsCached` + `pGspArgumentsDescriptor`,
  `pLibosInitArgumentsCached` + descriptor, `pRmStateMonitorBuffer(MD)`,
  `rmLibosLogMem[8]` ({pTaskLogDescriptor, pTaskLogBuffer, priv, id8}),
  `pWprMeta` + `pWprMetaDescriptor`, `pGspFw->{pImageData, imageSize,
  pUcodesBin, ucodesBinSize, pBuf, size, pSignatureData, signatureSize,
  pLogElf, logElfSize}` — every member the brief called "connus du
  loader" is now named with its EXACT type and mapped status.
- `kernel_gsp.c` @610.57.04: the call-site citations per anchor
  (kgspCreateRadix3 ~5930-6045 = the memdescMap pattern;
  `_kgspPrepareGspRmBinaryImage` @5828 with the pImageData/radix3
  wiring @5871-5899; the monitor read `osReadRegistryDword(pGpu,
  NV_REG_STR_RM_ENABLE_STATE_MONITOR, ...)` @4322; the 4-arg
  `memdescUnmap` pattern @4033; the `kgspInitRm_IMPL` hook anchor =
  the `kgspStartLogPolling` line, success path).
- **The regkey discovery**: the state-monitor gate = `RMGspStateMonitor`
  — the string is IN OUR BANKED `rm-strings.txt` (the 4.35b census
  banked it without naming its role). NVIDIA SHIPS a host-readable RM
  state export, one regkey away. The runbook gives it its own boot.

### The reachability matrix (the honest physics)

| Surface | Content | Host reachability | Verdict |
|---|---|---|---|
| S1 image.bin | the packed WPR2 image (host copy) | CERTAIN (a live host buffer) | the STATIC reference |
| S2 ucodes.bin | the ucodes bin (host copy) | CERTAIN | static |
| S3 args.bin | GSP_ARGUMENTS_CACHED | CERTAIN (mapped by the driver) | the boot config |
| S4 libosinit.bin | LibosMemoryRegionInitArgument[] | CERTAIN (mapped) | **THE REGION INVENTORY** — the memory map GSP-RM booted with |
| S5 sysmemheap.bin | the Libos sysmem heap (RPC/console/host-shared state) | CERTAIN (memdescMap by the instrument) | the LIVE state surface #1 |
| S6 statemonitor.bin | the RM state monitor export | GATED (`RMGspStateMonitor`) | the LIVE state surface #2 |
| S7 logs0-7.bin | the 8 Libos task-log rings | CERTAIN (pointers mapped) | logs |
| S8 wpr2meta.bin | GspFwWprMeta (gspFwWprStart, gspFwHeapOffset/Size, gspFwOffset, gspFwWprEnd) | CERTAIN (mapped) | **the WPR2 map** — the v2 probe's input |
| — the WPR2 FB heap proper | the RM FW heap (the Libos core heap) | UNDECIDABLE (the seal's CPU-read behavior) | the v2 probe, designed, gated on S8's layout |
| — the falcon-internal DMEM | the GSP RISC-V core's local memory | NOT host-reachable while running | **the NAMED NEGATIVE** — the miss-classification is honest by construction |

The instrument: read-only everywhere, OPT-IN via the registry key
`RmGspDmemDump=1` (ONE key ONE boot), the dump = zero-copy debugfs
blobs into the live mappings + the dmesg ledger (the nv_printf lesson),
the delay 8 s (RM finishes init in the window). Rollback = the driver
revert ONLY (the proven ~10 min ritual + the UKI lesson banked).

## §2 TÂCHE A2 — the searcher (selftested, floor-disciplined)

`v451a_dmem_scan.py` — the pattern set is 100% banked-sourced:

- the **raw76 verbatim records** (id 6 launch, id 26 LHR) from
  `mem-timings-65records.json` — the strongest possible pattern (76
  specified bytes; this pass verified the raw records BEGIN with the
  fingerprint pairs: raw[6] = `4e d2 ...` (rc,rfc launch), raw[26] =
  `46 af ...` (rc,rfc LHR) — the (rc,rfc) pair is byte-true in the
  VBIOS record itself);
- the **whole-table shadow detector** (raw_any65: how many of the 65
  records appear verbatim anywhere — 1 hit = the table is shadowed);
- the **4.48 fingerprints** (u8/u16le/u32le × both records) — the
  UNPACKED-parse hypothesis, with the standing caveat (the VBIOS
  fields are PACKED sub-fields — the note in the raw table JSON);
- the **(rc,rfc) pairs** at the 1/2/4-byte lanes;
- the **fieldwise u32 co-location walk** (±32 B, ≥2 siblings) — the
  detector that survives unknown packing.

The floor discipline (the 4.49 lesson, applied per pattern): the
expected random-hit count = size/256^k; verdicts HIT/FLOOR/SUSPECT/MISS.
The selftest is MANDATORY before every scan and it caught a real bug in
the first classification draft (the arbitrary min-10 bar classified a
unique 76-byte hit as SUSPECT — the floor-relative bar replaced it).
**Selftest 4/4 embed + 4/4 control ✓; the rehearsal (a synthetic 4 MiB
"heap" with the raw LHR record + the launch u32 vector embedded) hits
every family and assembles the correct HIT verdict ✓.**

## §3 TÂCHE A3 — the four-boot day

`runbook-451.sh` — one instrument, four boots, ONE regkey delta per
transition: **A** (`RmGspDmemDump=1`, the dump) → **B** (+
`RMgspStateMonitor=1`, the state-monitor surface) → **C** (+
`RML2MaxWaysSysmem=0`, the ways A/B) → **D** (the ways reverted, the
proof re-run). §0 = the sha guard + SEVEN anchor greps against the
founder's tree (the build judge pre-check) + the instrument coherence
batteries; §1 = the drop-in + the ONE hook line (the exact anchor
text) + dkms + **limine-mkinitcpio** (the banked UKI lesson); the
search step runs v451a with the decision tree printed; §7 = the
rollback checklist (driver ONLY — the firmware sha guard holds).

## §4 TÂCHE B — the gated {value,target} table + THE route named

`v451b_timing_targets.json` is the template with EVERY target
placeholder (null) until the dump fills it — and the ROUTE DECISION
TABLE naming the coherent machinery per hit location:

- **Route H (PREFERRED)** — hit in S5/S6 (host-mapped RM state): the
  same kernel_gsp.c hook generalized to a write regkey; the surface is
  host-writable RAM by construction, post-verify by construction (the
  4.44-machine lesson: post-verify surfaces = alive). The named risk:
  the recompute question (the 4.44 analog — does the clk recompute
  rewrite the parsed timings? the f18 lesson says the analogous path
  never rewrites the field class).
- **Route W (SECOND)** — hit only in the WPR2 FB heap (the v2 probe
  read succeeds): extend read→write, the seal's CPU-write behavior
  INDECIDABLE until the read probe passes (ReBAR 8192 MiB standing).
- **Route ROP (LAST RESORT)** — falcon-internal DMEM only: the 4.45
  chain (18/18, the spin 0x4a7, the write primitive 0x100b3e/0x100b48).
  The boot-vehicle risk class of the 0x1d day applies.
- **Route IMG: REFUSED-BY-CARD** — a hit in S1/S2 alone proves nothing
  about runtime (the static reference matched); patching the image =
  the booter VERIFIES it (the 0x1d family, the 4.44-machine
  falsification).

The values: the LHR retightening (rc 76→70, rfc 210→175, ras 49→44,
faw 28→20, rrd 7→5) = THE VENDOR'S OWN headroom proof; the protocol =
ONE field per boot, the quad gate from the first write; the honesty
note: the mechanism-proof lane is the point — the M2 OC lane likely
banks more GB/s than the timing retight; the id-19 all-zero landmine
stands (never retarget a record resolving to it).

## §5 TÂCHE C — the RML2MaxWaysSysmem card (complete, machine-ready)

- **The value domain** (4.49 PROVEN): {0} ∪ {7}; 1-6 clamped to 7; 0 =
  honored (the ways released, config untouched); the consumer programs
  reg 0x2AC ways<<8.
- **The experiment**: boot C (`RML2MaxWaysSysmem=0`) vs boot D (the
  revert) — the judge = `pillarB-sysmem.py` ×2 per boot + the 4.47 §1
  battery; the observables = `nvidia-smi -q -d CLOCK`, dmesg (zero
  Xid), the battery JSONs.
- **The physics named before the first run**: sysmem reads are
  PCIe-bound (~25-32 GB/s raw) — EXCEPT the warm L2-resident case;
  the battery measures device_warm (the L2 reference), sysmem_warm
  (the ways question), sysmem_cold (the PCIe floor), and the
  **warm:cold ratio = the ways verdict** (ratio ~1 on the =0 boot vs
  ratio >> 1 on the default boot = the caching surface proven live).
- **The RISK card, with the tension named**: the historical -13% (the
  pre-repo `RML2MaxWaysSysmem=1` test) CONTRADICTS the 4.49 clamp
  reading — =1 is clamped to 7, so a real -13% under =1 means the
  clamp decode is wrong (or the test was confounded). The =0 experiment
  decides cleanly because 0 is IN-DOMAIN and honored. The revert is
  MANDATORY in the runbook (§6 boot D = the proof re-run, not just a
  cleanup).
- **The fallback honesty**: without nvcc the battery emits the copy
  paths + `kernel_read: INDECIDABLE` — the A/B survives on the DMA
  surface, the CACHE verdict needs the kernel (the pillarB.cu toolchain
  precedent says nvcc is on the machine).

## §6 The honesty ledger

- PROUVÉ: the grounding (every struct member + call site cited from the
  exact 610.57.04 tree); the raw-record byte-truth of the (rc,rfc)
  pairs; the searcher selftests (4/4+4/4 + the rehearsal); the route
  decision table (post-verify logic per the 4.44-machine falsification);
  the reachability matrix (host-mapped surfaces enumerated from the
  driver's own struct); the state-monitor regkey's presence in our own
  banked strings.
- HYPOTHÈSE: that the parsed timing records live in ANY of the
  host-mapped surfaces (the S4/S5/S6 hypothesis — the dump decides);
  the sysmem warm-cache behavior (the ways A/B decides); the -13%
  contradiction reading (the =0 boot decides).
- INDECIDABLE-BY-BYTES: the WPR2 seal's CPU read/write behavior (the
  v2 probe); the falcon-internal DMEM (the named negative — unreachable
  while running); the byte-lane layout of the parsed records (the hit
  context decodes it); whether the clk recompute rewrites the parsed
  timings (the route-H experiment).
- REFUSED-BY-CARD: Route IMG (the image patch — the booter verifies);
  RMClkVfOverride (the 4.23 precedent); RMUseTc0NonCoherent
  (correctness); the machine EXECUTION (this pass designed and armed —
  nothing ran on the GPU).

## §7 The queue (what the day decides)

1. **The J-451 day** (runbook-451 §0-§7, four boots): the dump verdict
   = TÂCHE B opens (route H/W) or the honest close (falcon-internal);
   the ways card = the first L2 knob delta of the campaign.
2. The v2 probe design is IN the instrument's comments (the WPR2 read
   via the S8 layout) — its build-time anchors get their own grep in
   §0 (the memdesc-over-phys API of this tree).
3. Between-days: the 0x85C4/0x85E4 reader hunt (the 4.50 parked lane,
   the corrected c.add filter) — unchanged, still queued.
