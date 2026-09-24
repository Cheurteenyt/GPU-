# 4.47 — the bandwidth hunt: the 0xSero metric decoded, the two-pillar map, the MCLK/L2 knob cards

Pass: 4.47 (stacked on 4.46 `bed9a1a`). Date: 2026-09-24.
Trigger: the founder's X reference — « quelqu'un a optimisé le GPU à
600 GB/s de bande passante sur un autre GPU… on doit trouver des moyens
et une grosse tâche nous attend ».
Instruments: `v447a_clkknobs` (+JSON), `v447b_knob_contexts` (+JSON),
`tools/edpp/runbook-447.sh`.
Baseline gate: ALL banked counts reproduced on this machine before
production — auipc 416,206 (byte-level census) ✓, the coordinate law
512/512 ✓, selftest 5/5 ✓, TT 11/11 ✓, TF 9/9 ✓, TR 18/18 ✓, map 670
covered regions ✓.

## §1 The reference, decoded honestly (PROUVÉ — the post text)

The oembed payload of `x.com/0xSero/status/2103072230162981072`
(2026-09-24):

> "Claude took an Intel GPU, and built kernels that got within 8% of
> the memory bandwidth ceiling — 555 / 608 GB/s."

What it is: **555 of 608 GB/s = 91.3 % of the theoretical ceiling**,
delivered by **software kernels** (STREAM-class load/store kernels) on
an Intel AI GPU. What it is NOT: no firmware hack, no ceiling raised —
the achievement is *saturating* the hardware's own number.

What transfers to us and what does not:

| The reference | Our card (RTX 3070, GA104, GDDR6 256-bit, 14 Gbps) |
|---|---|
| The METRIC: % of the ceiling | **448 GB/s theoretical → what real %?** Never measured in this campaign (PROUVÉ absence — no bandwidth battery exists anywhere in the repo) |
| The METHOD: kernel optimization | Pillar B — buildable on the machine (the runbook §1) |
| The HARDWARE: HBM, AI GPU | GDDR6 — the OC headroom question differs; the ceiling itself is our Pillar A |
| 555/608 | the 91 % target: ~408 GB/s effective at stock ceiling |

The honest split the reference forces: **Pillar A = raise the ceiling**
(firmware/VBIOS/host levers — our campaign's home turf), **Pillar B =
saturate the ceiling** (kernels — the machine day). The campaign has
never run Pillar B and has Pillar A half-mapped.

## §2 Pillar A — the lever map (what can raise 448)

### A1. The LACT mclk lane — applied-proven, gain UNPROVEN (PROUVÉ from vram-ab)

`day0/vram-ab-findings.md` (2026-09-17): the +200 LACT offset (=
+100 MHz NVIDIA readout, 6801→6901 MHz) **applies and persists**, but
the three A/B pairs with glmark2 showed **no demonstrable gain**
(confounded, non-bandwidth-bound workload). STATE.md's standing row:
"Memory OC — not applied, GDDR6 typically +1000-1500 MHz = +5-10 %
bandwidth — pending". **The lesson banked: the judge must be a
bandwidth-bound workload** — runbook-447 §2 re-runs the sweep with the
§1 battery as judge.

### A2. The VBIOS timing layer — decoded, headroom PROVEN by the vendor itself (gx4/gx5, banked)

- The ladder (gx4): 10 bins × 14 straps; the top bin (6301–16383 MHz)
  serves the live 6801 MHz; bins 2–6 share one config.
- The table (gx5): 65 records × 76 B, 18 named fields (rc, rfc, ras,
  rp, cl, wl, rd_rcd, wr_rcd, rpre, wpre, cdlr, wr, w2r_bus, r2w_bus,
  faw, refresh, rrd, wrcrc — controller cycle counts). The top-bin
  record: rc=78, rfc=210, ras=52, rp=26, cl=24.
- **The vendor's own headroom proof**: the LHR-era build TIGHTENED the
  Hynix records within the same bins — rc 76→70, rfc 210→175,
  ras 49→44, faw 28→20, rrd 7→5. Same silicon, tighter timings
  shipped by MSI/NVIDIA. **Headroom exists by construction.**
- The walls: EEPROM flash = CERT20 RSA-3072 (any modified byte =
  SIG_INVALID) — the VBIOS lane is UNFLASHABLE on Ampere (the wall
  table). **The open road = the runtime retarget**: if the GSP-RM
  parses those records into RM state, the proven write machinery
  (the 4.42 transfer-list, the 4.45 ROP chain, the 4.46 DMEM-tail
  lane) can retighten the parsed copies at runtime — the exact
  f18-analog that turned 250→280 W. That hunt is the grosse tâche's
  TÂCHE B.
- The landmine registered by gx5 stands: record id 19 = ALL-ZERO,
  referenced by bin 6 × strap 7.

### A3. The RM knob cards — NEW this pass (v447a/v447b)

Method: the proven 4.35b machinery (string census → runtime VA →
exact-composition PIC xrefs → first-consumer classification), pointed
at the bandwidth family. **The instrument lesson banked first**: the
regkey names are SUBSTRINGS of concatenated printable runs — the
first run returned occ=0 for every name under exact-run equality;
the fixed instrument matches containment and cites the name's first
byte. ("DRAMCLK", 7 chars, sits below the census's ≥8 threshold —
1 hit at threshold 4, probe banked in v447b.)

The cards (full detail in the JSONs):

| Knob | xrefs | Verdict | Note |
|---|---|---|---|
| RmDisableDecompOnlyLce | 9 | REGKEY-CANDIDATE | the LCE decomp-only disable |
| RMUseTc0NonCoherent | 7 | REGKEY-CANDIDATE | TC0 coherency mode — REFUSED-BY-CARD for the day (correctness risk) |
| RML2MaxWaysSysmem | 4 | **CITED (pointer-range switch)** | 4 compares @0x130697e-0x1306aec against consecutive interned name VAs — a string-switch dispatcher, i.e. REAL consumption, mechanism ≠ the strcmp call |
| RmIsoHubMCLKSwitch | 2 | REGKEY-CANDIDATE | the MCLK switch isolation hub |
| RMClkSlowDown | 2 | REGKEY-CANDIDATE | |
| RMReportMclkSwitchFbStopTime | 1 | REGKEY-CANDIDATE | |
| RMClkSwitchWithinMargin | 1 | REGKEY-CANDIDATE | |
| RmMClkP5LinkTrainingWckStopClks | 1 | REGKEY-CANDIDATE | WCK-stop clock count for P5 link training |
| RMClkVfOverride | 1 | REGKEY-CANDIDATE | **REFUSED-BY-CARD for the day** — the 4.23 precedent (a clock-table rewrite degraded the RM's power state to 240/245) |
| **RmClkMclkProg** | 1 | REGKEY-CANDIDATE | the classic lookup-by-name window banked: name→a1, type-tag a0=3, call ~0x1A9E65C, result store `sb zero,0x38(s8)` @0x10e8f7e |
| RmOptp2LowerMclk | 1 | REGKEY-CANDIDATE | OPT P2 lower-mclk |
| RmLpwrSysClkSd | 1 | REGKEY-CANDIDATE | sys-clk shutdown in LPWR |
| RmPerfCfPmSensorOverrides | 1 | REGKEY-CANDIDATE | the perf-Cf controller sensor overrides |
| **MCLK_LIMIT** | 0 PIC, **4 ptr-table** | DATA-CITED | u64 records @0xe15c78 / 0xe17918 / 0xe22e88 / 0xe24e08 — the same {name-ptr,…} shape ×4; the perf/clock limit tables carry the interned name |
| (the soft-floor assert strings ×3) | 0 | PRESENCE | the NV2080_CTRL_CLK_CLK_DOMAIN_INDEX / softFloor machinery compiles into OUR image even though no adjacent-PIC xref resolves |

Day-1 SAFE pack (the runbook §3): **one cleared key** (`RmClk2Enable=1`
— the 4.35 card, 8 xrefs banked, re-cited by v447a); everything else
is named-refused or pending semantics. The house rule holds: one key,
one boot, one counter delta, a named mechanism, zero Xid — otherwise
NO-EFFECT or UNPROVEN.

### A4. The booter surface — 0 knobs (4.46, re-cited)

The booter carries no bandwidth-relevant knob; the boot lane stays
out of Pillar A.

## §3 Pillar B — the % ceiling battery (the runbook §1)

The metric of the reference, ported: D2D copy (R+W), read-only (sum),
write-only (fill) on a 2 GiB working set, 3 reps, medians, GB/s, **%
of 448**. Harness probe order: nvbandwidth → torch → nvcc-built.
No harness = INDECIDABLE, honestly logged. The first stock numbers
from this battery are the campaign's first bandwidth baseline — the
0xSero row of our own.

## §4 The GROSSE TÂCHE — MISSION 4.47 continuation (designed, armed)

- **TÂCHE A (machine, the runbook day)**: run runbook-447.sh — the
  stock % baseline (§1), the mclk sweep judged by the battery (§2),
  the cleared regkey (§3), the rollback checklist (§4). Deliverable:
  ~/bandwidth-447/verdict-*.json + the A/B table.
- **TÂCHE B (static+capture, the f18-analog hunt)**: find where the
  parsed timing records live at runtime. The deciding experiment =
  the post-boot GSP DMEM dump searched for the decoded record bytes
  (the top-bin record's field pattern — the 4.44-machine memdesc
  dump method). If the records sit in DMEM state: the {value,target}
  table becomes a timing-patch payload (TÂCHE D). If NOT (the values
  live in the FB Falcon / MC registers directly): the lane honestly
  dies and A2 closes as runtime-unreachable.
- **TÂCHE C (static, mine)**: name the store target of
  RML2MaxWaysSysmem (the pointer-switch dispatcher's destination
  object) and the RmClkMclkProg call (@~0x1A9E65C) semantics —
  until named, the L2 knob stays observe-only.
- **TÂCHE D (payload, gated on TÂCHE B)**: the timing-record patch
  payload on the proven machinery (transfer-list / ROP / DMEM-tail),
  the emulator battery extension (--test-timings), the runbook day.
- **The queue note**: 4.45 (ROP runtime) and 4.46 (PR #35) are open;
  4.47 Pillar A/B do not touch them. The push of this branch needs a
  fresh PAT (none in this session — hygiene rule held).

## §5 Honesty ledger

- PROUVÉ: the reference text + its 91.3 % reading; the baseline
  reproduction (all six batteries); the v447a/v447b cards (exact
  composition by construction); MCLK_LIMIT's 4 pointer-table records;
  the RML2MaxWaysSysmem pointer-switch; the RmClkMclkProg
  lookup-by-name window; the vram-ab applied-not-proven state.
- HYPOTHÈSE: the +5-10 % OC gain (STATE.md's folklore — untested with
  a bandwidth judge); any timing-retightening runtime gain; the
  interned-name-switch reading of the 0x130697e chain.
- INDECIDABLE-BY-BYTES: where the parsed timing records live at
  runtime (TÂCHE B's dump decides); the stock % of ceiling (the
  battery decides); whether the 10 UNREFERENCED-in-image names are
  consumed by non-adjacent-PIC mechanisms (the soft-floor strings'
  own xref mechanism unresolved).
- REFUSED-BY-CARD: RMClkVfOverride (the 4.23 corruption precedent);
  RMUseTc0NonCoherent (correctness); blind turns of the time-math
  families (4.32/4.35 stand).
