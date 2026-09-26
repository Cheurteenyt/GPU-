# gpu-lab — state of the campaign (2026-09-22)

One page to answer: where the campaign stands, what is proven, what is
open, what is next. The historical snapshots (2026-09-17, 2026-09-20)
are at the bottom.

## The 4.38-4.42 arc: the dual-core provenance, the transfer-list, the booter bypass validated

The five passes (4.38→4.42) completed the dual-core power provenance
and built the offensive tooling:

- **4.38**: the applied 250 W lives in **NO binary as a constant** —
  the VBIOS parse is the source; the patch design = Lane V (the
  VBIOS-in-RAM), Lane R (the corrected {240000, 250000} pair scanner),
  Lane T (the RatedTdp hook). The v9 triple fingerprint = PROVEN
  INVALID.
- **4.40**: the ROP gadget hunt in OUR plaintext booter — **the
  self-advancing transfer-list write-primitive** found @0x100b3e/
  0x100b48 (ld stack → [a1], the bounds built-in).
- **4.41**: the transfer loop decoded instruction by instruction — the
  memdesc stack = the SOURCE, the RM state register = the DESTINATION.
- **4.42**: **the transfer-list BUILT and PROVEN end-to-end**: the C
  patch (`transfer_list_memdesc.c`), the {value, target} table for
  limitMax=280000, the emulator validation 11/11 (the TT battery), the
  C dump == the Python builder BYTE-EXACT.
- **The boot test**: the patched gsp_ga10x.bin (sha 6a3c1a06…)
  **booted WITHOUT signature rejection** — the rm.elf modification =
  accepted by the silicon. The power limit = 250 (the constants = the
  time hysteresis, 4.32 confirmed live). The machine = stable.
- **The booter bypass validated**: the plaintext booter (gsp_ga10x.bin
  = a RISC-V ELF, the booter = the first section @0x40) = emulated
  (RV64IMC, the 4.31 tool), the locate-gsp = byte-exact on the real
  firmware.

The current state: the machine = restored to STOCK (250 W, zero Xid).
The patched firmware artifact = preserved (~/gsp_ga10x_patched.bin).
The static hunt = exhausted (4.36 the floor). The remaining roads =
the 4.26 recv capture (the large-path hook = built) and the runtime
ROP (the transfer-list = ready, the chain = the remaining work).

## The 4.37 addition: the break-day package (the data twins are descriptor-linked; the two boot days armed)

The pass 4.37 (`lab/jalon411/findings-4.37-breakday-package.md`) ran
the one reachability probe the campaign never ran — **who references
the banked data tables** — and armed the founder's two boot days.
**(A) Code side all zero:** absolute lui+addi pairs into any table
window = 0; lui+direct-access (the %lo-on-the-load idiom) = 0 with 0
page-bases even in reach; PIC auipc refs = 0; resolved indexed access
= 0. The widened diagnostic banks the boundary: 24 lui values land in
the data LOAD (232 sites, `0x4000000` ×180 = the segment base,
`0x4040000` ×2 = the defaults-table page) and auipc+addi into data = 0
over all 416,206 auipc — **the data LOAD is never PIC-addressed at
all.** **(B) The data-side probe = the result:** 25 u64 pointers from
the data LOAD land one-per-record in the 22×1000000 defaults window
(three structural families by stride) — **the compiled defaults are
descriptor-linked instance state, not a loader-copied array**; the
fill path = the RPC object-create path, exactly what the 4.26 capture
watches. The knob card is unchanged (1000000 stays the DO-NOT-TOUCH-
BLIND time family). **(C) The regkey experiment cards:** 17 cards from
the banked evidence (xrefs ≥ 3 minus the REFUSED gate —
RmClockUprocSecurityCheck / RmAllowChannelCreationOnPendingReset /
RmDisableFbflcnDevinitBoot, reasons named), each with the nvlddmkm
DWORD path, the test value, the concrete observable, the HYPOTHESIS
prediction and the risk class. **(D) runbook-426.sh** scripts the
capture day end to end (the STOCK sha check, the 4.25 recv hook
byte-exact apply/restore, the initramfs plumbing, the §7.2 verdict
checklist with the honest negative, the day-2 regkey pack). **The
road is unchanged and now fully armed: day 1 = the 4.26 capture, day
2 = the regkey experiments — the 280 W rm.elf lane stays CLOSED (the
4.34 REVERT).**

## The 4.36 addition: the static hunt reaches its floor (the regkey canal is runtime)

The pass 4.36 (`lab/jalon411/findings-4.36-regkey-flow.md`) paid the
4.35 queue and closes the static program. **(A) The regkey-to-knob
canal is NOT in-situ:** 0/12 shortlist knobs carry a regkey xref in
their ret-bounded function, 0/12 at covered-region level (331
distinct xrefs windowed, 366 verified xrefs over 148,249 canonical
PIC pairs — the banked callee 0x188EF44 fan-in 50 reproduces
exactly); the field flow cartographed the STATE-DEFAULT store targets
instead (400000 into the -0xa0(s0) record with 5 same-field stores,
1250000 into the adjacent 0x274/0x27c pair; zero a0 ret-stores). The
C.LUI layout is byte-settled (quadrant 1, funct3 011, full 5-bit rd
at [11:7]). **(B) The function-level owners:** 18/300 sites window
ret-bounded, all with PIC fan-in 0 (leaf fragments / value-blocks);
zero RPC-anchor and zero name-pointer ties at region level — the
4.35a region cards remain the finest static attribution. **(C) The
interrupted slices:** 5 of the 11 interrupted c.lui-100000 sites now
BOTH-ARMS-AGREE:ARITH-CHAIN at CFG level (the 4.34 value-blocks
confirmed + 0x1280da4 promoted); the 7 loop-shaped sites stay honest
HYPOTHESIS (backward polling-loop edges). **The road forward: the
SAFE host-regkey experiments on STOCK firmware (the 4.35 tunables),
the knob cards as the gate, and the 4.26 recv-hook capture for the
real values — the 280 W rm.elf lane stays CLOSED (the 4.34 REVERT).**

## The 4.35 addition: the SAFE optimization lane proven (the host regkeys), the knobs carded

The pass 4.35 (`lab/jalon411/findings-4.35-optimization-hunt2.md`) is
the optimization hunt, round 2. **(A) The knob cards:** the 60 knobs of
4.33 each carry a unit hypothesis, a risk class and an owner fan-in
(the banked 4.32 counts reproduce exactly). The time-math knobs are
refused BY CARD (1000000 = the 1e9/1e6 conversion chain,
DO-NOT-TOUCH-BLIND; 10000000 = a 10-ms quanta with rdtime in-body); a
coherent CLK-270k-FAMILY of 14 knobs (270000 × {1,2,3,6,8,9,10,12,16,
20,25,30,50,100}) is catalogued; the GATED-TUNABLE shortlist is ranked
by leverage (500000 / 100000000 / 4000000 in the fan-in-794 region
0x10844a4); 1435840000 = a 1.43584-GHz clock threshold materialized on
BOTH sides (3 COMPARE sites + a 16-entry data table @0x1c0d38c).
**(B) The regkey lane = the no-patch lever, PROVEN:** 864 `Rm*`/`RM*`
names in the firmware, 251 with direct PIC code xrefs (366 xrefs, 291
PASS-TO-CALL — the lookup-by-name pattern: string → a1 → call → status
gate), the name-pointer tables in the wild (RmVgpcSkyline ×27 + masks
@0x1d858b8; RmCePceMap @0x1c492e0), the FNV-1a-32 hash machinery
(basis 0x811C9DC5 at 3 sites, the hash-context init window cited), and
the top tunables named (RML2MaxWaysSysmem = the L2-ways partitioning
knob, RmClk2Enable, RMUseTc0NonCoherent, RmDisableDecompOnlyLce…).
**(C) The data twins:** the 22×1000000 compiled-default table
@0x404b4b0 (the top knob's data twin), the 2^n size-class ladders
(@0x1c4ad68, 0x1c4ab68), the duplicated config blocks (the clone
mass's data twin), and the d4d856ff ×666 DECODED — a live fill-value
table (u32 0xff56d8d4 among distinct descending 0xff57xx records, step
≈ −0x24), correcting the lane-D "waste" reading for that family (the
banked 666 = the a_img-aligned 16-B unit, reproduced exactly). The two
VA universes are formalized: runtime = campaign + 0x38 (the container
phdrs = the loader truth). **The 280 W lane state is unchanged: the
rm.elf patch lane stays CLOSED (the 4.34 REVERT verdict); round 2 adds
the SAFE host-regkey road — the regkey experiments run on the STOCK
firmware, one key, one boot, one counter delta.**
## The 4.34 addition: the rm.elf lane CLOSED (REVERT), the TIME domain resolved

The pass 4.34 (`lab/jalon411/findings-4.34-time-queue-and-430-closure.md`)
did three things. **(A) The 4.30 closure:** the split-form finder
(capstone clobber check) entered gspbuild and found exactly the 7th
250000 site (lui a4 @rm+0xb99c4a, addi @+0xb99c52, gap 8 — the
`sub s2,s10,s2` between); the 7/7-complete patch is PRODUCED (21 B
differ, all pairs re-decode 280000, artifact outside the repo) with the
verdict **REVERT for any boot** — the seven sites are TIME logic, not
power (4.32), so the runbook-280.sh now refuses the half-turned 6/7
container and gates the 7/7 behind RUNBOOK_77_ACK=1; the 280 W road is
the host feed, on the STOCK firmware. **(B) The 34 c.lui-100000 bodies**
(the 4.33 queue) classified by first consumer: 6 CALL-ARG, 4 MUL
(×1e5/div converters), 5 STORE-DATA, 3 COMPARE (one against a rdtime
delta), 8 ARITH, 11 slice-interrupted, 0 dead — the family is the RM's
fine time quantum, never a power knob. **(C) The tick rate PROVEN:**
451 rdtime reads; the literal conversion chain (s2 = 1e9 → divu =
seconds → ×0xF4240 = µs) pins the RISC-V time CSR at **1 tick = 1 ns
(1 GHz)** — 31.25 MHz appears zero times in code and data; the µs
ladder of 4.32 is the policy layer on the nanosecond counter, and the
100000-vs-rdtime threshold = 100 µs. Tests: 27 PASS / 0 FAIL
(gspbuild R18-R20 + the always-on fwimage lane S1-S8).

## The 4.30 addition: the gsp.bin pipeline is packaged end to end

The pass 4.30 (`lab/jalon411/findings-4.30-gspbin-pipeline.md`) closed
the packaging lane of the fallback path: the GFW directory grammar
decoded (13 records, the true = field + 0x6d000 bias law, five
byte-exact component containments — `bootloader.bin` = the boot area,
debug.elf = the old "pmu-wdt-41KB.bin", mnoc.elf = comp-58KB), the
container's signature inventory (twelve per-family blobs, 4 × RSA-3K
blocks each; no digest stored anywhere — the coverage stays
UNDECIDABLE-BY-BYTES with the one-boot experiment armed), and the
250000→280000 patch landed byte-precisely (`gspbuild.py patchrm`):
the mission's six-u32 premise falsified — the six sites are lui+addi
pairs (the mission's VAs = rm-full.elf coordinates) — 48 B rewritten,
18 B differ, tests 42 PASS / 0 FAIL including the 84 MB byte-exact
rebuild. The driver-side file selection is source-proven: the GA104
loads `/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin`. The patch's
SEMANTIC (power policy vs clock) stays HYPOTHÈSE until the one-boot
experiment or the 4.26 capture observes it.

## The current phase: the transport instrumented → the recv capture (pass 4.26)

**The falsification of record (the passes 4.23-4.28, the night of
2026-09-21/22):** the "250000 mW" values captured in the RPC transport
were **the LACT clock-VF offsets, not power** — the issuer = NVML
userspace (proven: no code immediate in either x86 core; the 53 kernel
sites attributed). The power limit value **never travels** the fn=76
(`GSP_RM_CONTROL`) transport. The 4.23 rewrites corrupted the clock
table (the RM's power state degraded to 240/245; the restoration = the
power cycle + the LACT re-apply).

**The enforcement map now stands:** the GSP-RM's EDPp policy object
(the 0x6d0 object, pass 4.20) = fed by mechanisms still unobserved.
**The only road to the real data = pass 4.26: the recv-hook capture**
(the response-path instrument = merged and armed; the 96-byte
prediction). The tools for the fallback path (the gsp.bin rebuild =
the LZ4 codec + the byte-exact container, 13/13 tested) = ready in
tools/gsp-lz/ + tools/gsp-container/.

The wave's master index: **lab/jalon411/INDEX.md** (the passes
4.14→4.28, the verdicts, the instruments). The power-limit instruments:
tools/edpp/.

## The current phase: the GSP-RM cartography → the EDPp handlers

### 4.31 (2026-09-23) — the booter verify hunt: the bypass target is NOT in the plaintext booter

- The LS-signature verification is NOT in bootloader.bin (the gsp.bin boot-area libos ELF):
  proven by the exhaustive negative census (no crypto CSRs 0x7d5-0x7d9, no SBI crypto
  ecall — our SBI = a7 0x900001EB a6 {0,7,8,9,0xa}, no SHA/RSA constants, no 0xc0deca7e).
  The paper's verify/dma/auth/fail addresses are all < 0x8000 = BROM-resident for THEIR
  build; for OUR stack the crypto lives in the BROM and/or the ENCRYPTED BooterLoad
  (nvidia.ko BINDATA IMAGE_PROD 0x87d7 B, NUM_SIGS=2) that the BROM RSA-3K covers —
  patching it requires a re-sign we cannot make. The driver-patch bypass (proven, 7+ runs)
  remains the production path.
- New facts banked: gsp_ga10x.bin = a RISC-V ELF and our booter = its first section at
  container offset 0x40 (boot area sha ab90560b, 0x6d000); the booter's secure plumbing =
  SBI stubs (fail=ecall a7=8 @0x103a7e), region CSRs 0x5ca-0x5d1/0x8d0, the MEMMAP
  builders (0x100258 defaults, 0x101798 family), the handler table @0x1244A0-E8, the
  boot-params handoff @0x168000, and the kernel_<chip>.elf name table matching the 4.30
  GFW record names.
- Delivered: tools/booter-patch/patch_booter.py (locate-ko/locate-gsp/patch-gsp, 5/5 —
  the encrypted-IMAGE patch is REFUSED by construction) and tools/booter_emu.py (RV64
  emulator on OUR image, 5/5 — directed patch demo: 0x1014DC bounds check original→FAIL
  oracle vs NOP'd→clean ret, exactly 4 bytes differ).


**Phase III is proven in silicon.** The hardware campaign (7+ runs,
`day0/cert20-plm-feat-test.log`) fired the published ROP chain on our
GA104 with the driver patch (kernel_gsp.c `_kgspCreateSignatureMemdesc`,
the 0xF800 signature memdesc → the unbounded DMA). The verdict is the
paper's own test/stall payload observed live: **the SEC2 Falcon spins at
V=0x4a7 — the IMEM self-loop gadget** — the canary defeat and the PC
hijack confirmed on real consumer-Ampere silicon. The V=0x7dd9 probe
produced the same `0xbadf5620` abort signature (V-independent — the
failure sits upstream of the epilogues, in the HMAC validation of our
payload; the GA100 gadget addresses do not transfer to our build).

**The two campaign facts learned in hardware:**

1. **The anti-tamper lock.** After a fire, the secure domain reads
   DENIED across the registers and the entire FEAT region
   (6144/6144), surviving warm reboots — the always-on island.
   Recovery = a full power cycle. One fire per power cycle.
2. **The honest 280 W map.** The exploit opens fuse shadows
   (FEAT_OVR). The 250 W ceiling is the **EDPp table applied by the
   GSP-RM at runtime** — a policy, not a fuse. The FEAT_OVR lane does
   not reach it.

**The cartography (phase IV, merged via PR #1):** the rm-full.elf
reverse engineering passes 4.14→4.19 (`lab/jalon411/`) boundary-verified
66 % of the image (recursive descent, 3.4M insns, 81,871 validated call
edges), counted 221,201 verified indirect transfers (47,961
object-vtable, 1,201 state-frame), resolved the state-pointer economy
into a **derivation graph** (base = argument + 0x1000; 0.4 % static
formation; one state shape through dozens of carried bases) — and hit
the wall honestly: **the dispatch is runtime-bound end to end** (0
named targets in 3,542 slot fills). Static analysis alone will not name
the dispatch targets.

**The next lane (designed):** the RPC dispatch tables — static ID→
handler anchors inside the closed firmware. The `NV2080_CTRL_CMD_PWR_*`
command IDs are public (the open kernel modules headers); locating
their handler tables in rm-full.elf and walking from a known ctrl (the
power-limit GET/SET) into the EDPp enforcement code turns the
runtime-bound graph into a bounded hunt. That is the path to 280 W.

## The standing results (real, on the machine now)

| Item | State | Source |
|---|---|---|
| Resizable BAR | 8192 MiB BAR1 | ring 18 |
| Core offset | +225 MHz — **max graphics 2325 MHz, above the 2200 target** | the VF campaign (vague 2) |
| Undervolt | 1995 MHz @ 987 mV (vs 1890 @ 1075 stock) — the effective 280 W perf/watt | the VF campaign |
| Power limit | 250 W (the VBIOS ceiling; 280 W = the EDPp target) | LACT |
| Memory OC | **not applied** — GDDR6 typically +1000-1500 MHz = +5-10 % bandwidth | pending (LACT) |
| The unlock ROM | built, verified, ready (2200 MHz + 265/280 W) — unf lashable on Ampere (CERT20) | ring 42 / unlock-v2-REALCHIP |

## The wall (proven, documented)

| Layer | Mechanism | Verdict |
|---|---|---|
| EEPROM image write | Falcon VV (CERT20/VDPA RSA-3072 manifest) | SIG_INVALID on any modified byte |
| EEPROM programming | PMU EWR OK-to-flash check | refuses, then stops answering |
| GSP-RM firmware | SEC2 Boot ROM, fused keys | patch = rejected at load |
| Host-side table patch | the parse lives in the GSP-RM (closed) | not reachable |
| InfoROM policies | PPO object absent on GeForce | not applicable |
| HULK license | needs NVIDIA's signature | partner process only |
| Secure domain (post-fire) | the anti-tamper lock, always-on island | DENIED until a full power cycle |
| The 280 W ceiling | the EDPp runtime policy of the GSP-RM | not a fuse shadow — the FEAT_OVR lane misses it; the RPC-table lane is open |

The full map: the CHANGELOG, the memory of record, and the cmp170hx wiki
(278k words, cloned at `../cmp170hx-wiki/`).

## The tools (all in tools/, committed)

- `cert20-plm-feat-test.py` — the staged GA104 ROP test (7+ hardware
  runs; the fill-V parameter, the ROP chain, the ELF growth, the log
  tee, the driver-unload/reload flow, the full restore).
- `cert20/` — `cert20-verify.py` (the post-boot register verdicts,
  the DENIED = the signal), `cert20-scan.py` (the FEAT region sweep),
  `cert20-brom-dump.py` (the BROM read attempt via the Falcon XFER
  ports).
- `scan-kcore-power.py` — the host-RAM power-value scan (run once,
  died silently with its session — no result; rerun when the
  EDPp-in-host-RAM question reopens).
- `vfio-flash-session.sh` v14 — the VM flash pipeline (the signed images).
- `nvflash-5.792-k4/nvflash-k4-vv` + `nvflash-5.867/x64/nvflash-patched` —
  the verification/protectoff tools.
- `vbios-unlock-mod.py --source` — the unlock builder (the real chip dump).
- `analysis/gsp-extract/` — the GSP-RM extracted (rm-full.asm = 5M lines
  of RISC-V disassembly; the minimal rm-full.elf), the booter
  disassembled (bootloader.asm), the cartography instruments v414-v419
  (with `lab/jalon411/`), rm-strings.txt.
- `../cmp170hx-wiki/` + the cmpunlocker clone (at `../cmpunlocker/`) —
  the published research.

## Open questions

1. Where are the RPC dispatch tables in rm-full.elf, and which handlers
   serve `NV2080_CTRL_CMD_PWR_*`? (The designed next pass — the lane to
   the EDPp code and 280 W.)
2. Does a host-RAM copy of the power policy exist (the kcore scan died
   without output — rerun), or does the GSP-RM read the tables alone?
3. The exact GA104 booter gadget set for a productive chain (the GA100
   addresses abort upstream — the V sweep with the mailbox oracle
   remains the mapping method, one fire per power cycle).
4. The Xid 109 CTX SWITCH TIMEOUT on memtest_vulkan: patched-driver
   caused (suspect n°1) or independent? — pending the stock-driver
   memtest baseline.

## The historical snapshot (2026-09-20, evening — kept for the record)

Phase III as designed, before the hardware runs: the emulator
validation (16 BAR0 writes, 0 deviations), the discovery campaign
planned (the baseline fire, the V sweep, the chain), the wall table at
six layers. Superseded by the phase III→IV state above.

## The historical snapshot (2026-09-17 — kept for the record)

The performance campaign as it stood before the unlock ROM existed:
ReBAR was the one real gain; the power budget read 100/240/250 W; the
vP-states matched LACT's ceilings; the verdict then was "the performance
campaign is closed honestly" — **the unlock ROM (ring 42) and the CERT20
research superseded that verdict**. The method library (the sysfs reads,
the kcore scan, the LACT socket API, the decoder suite gx1-gx15) remains
the foundation everything above was built on.

## Incidents ledger (transparency)

- The faillock incidents: all from the assistant's heredoc + `sudo -S`
  mistake (the garbage-as-password), never the founder's actions.
- 3 black screens during the PLM tests: the GSP re-init after FLR + the
  ROP attempts — all recovered without damage (the stock firmware
  restored in-flow each time).
- **The anti-tamper lock** (the first ROP fire with the patched driver):
  the secure domain DENIED and persistent across warm reboots; a full
  power cycle is the documented recovery — not yet exercised at the
  time of writing.
- **The Xid 109** (memtest_vulkan, patched driver): the first NVRM Xid
  of the campaign — the TDR recovered, the system unharmed; the
  stock-driver baseline is pending to attribute it. Every read was
  passive; the EEPROM write attempts never reached a partial state.

## The machine days 4.51 + 4.45 (2026-09-25) — the phase change

The DMEM verdict day (4 boots) + the ROP overflow day (6 boots), all
zero-Xid, the rollbacks clean, the firmware untouched (c0156954):

1. **The sysmem heap does not exist on this config** (sysmemHeapArgs =
   {0,0} decoded in args.bin) — ROUTE H closed; the timing records =
   the FB/WPR2 heap → ROUTE W (the read probe) = the next instrument.
2. **The ways knob = NO-EFFECT** (the warm:cold ratio = 0.95-0.97 both
   states, x2 each — closed honestly).
3. **THE HIJACK CONFIRMED IN SILICON**: the v445 overflow payload in the
   signature memdesc → the booter copied BEFORE the verify (no 0x1d) and
   spun (GFW_BOOT progress 0xff = the paper's predicted state). The r1
   map = the uniform spin → the return address = beyond the ctx block →
   the pass 4.53 = the ctx relocation + the carpet probe + the MMIO
   scatter chain.

**The current phase: the hijack is confirmed — the control lane
(builder v446, the carpet, the MMIO scatter) is the deliverable.**

## The machine day 4.58 (2026-09-26) — the frame math closes the tail-chain guesswork

The synthesis (the stock signature INTACT + the enlarged memdesc + the
cmpunlocker chain in the tail + the flush x2 + the WPR_META re-point):
**the write did not fire — and the MATH explains it: the copy's stack
frame = <= 0x620 (the word 196) while our chain was at the word 790.**
The return = lands on the fill = the trap = the spin. The
cmpunlocker's 0xf754 = THEIR frame. **The gift: the PLM post-mortem
probe = the CLEAN BINARY OBSERVABLE for the sweep** (the falcon =
PLM-sealed, unobservable; the PLM registers = post-boot readable). The
next wave = the chain position sweep {0x300-0x580}, one boot per
position, the binary verdict per boot. The rollback = clean (0 v448
strings, the firmware c0156954).

## The machine test 4.60 (2026-09-26) — the NVML bypass executed live, the wall advanced and named

The zero-boot zero-patch hot test, executed the same session as the
merge:

1. **The capture shim worked live**: the LD_PRELOAD capture of the
   real `-pl 250` = 47 ioctls, the payloads dumped (the ledger = 64
   lines, saved outside /tmp per the law).
2. **THE DISCOVERY: the -pl value travels in the 0xFE01 payload**
   (cmd 0x2080e61e, the mW @offset 4 = 250000 = the 4.23
   differential confirmed by our own capture; the 0xFE01 = the
   mapper/clock channel = the 4.22 lesson re-confirmed — the mW
   = the numeric coincidence).
3. **THE GET = READ THE POWER LIVE WITHOUT NVML**: the ctypes bypass
   (the full alloc chain via /dev/nvidiactl) returned
   [65025, 250000] — the first direct power read of the campaign.
4. **THE SET 280000 = REJECTED with the progression named**:
   the stale handle = 0x57 (the invalid object), the fresh subdevice =
   **0x1F INVALID_ARGUMENT = the value validation kernel-side** — the
   wall = advanced from "unknown" to "named: the kernel validates the
   value BEFORE the GSP".
5. The cmd 0xe61e = FINN closed-only (absent from the entire public
   source) — the semantics = INDECIDABLE-BY-BYTES.

**The 4.60-era phase pointer (the kernel-side 0x1F study) = SUPERSEDED
the same day by the arc below — the closure verdict moved the campaign
to the hardware route.**

## The 2026-09-26 arc: 4.61→4.62, the boot-lane closure, the 4.63a admission, and the flash day

1. **4.61 (the DMEM tail-write)**: the two-sided writer ported to the
   real target — the base uW at obj+0x618+k*0x10, the 0x0EE6B280 marker
   read BEFORE any write, the plan gate = REFUSED without the dump scan,
   the 11 verdict codes. The f18 lane proven persistent = the route 4.62.
2. **4.62 (ROUTE W)**: the FB/WPR2 read lane executed as designed — the
   BAR1/ReBAR probe PROT_READ zero-patch, the memdesc-over-phys
   two-sided, the window math double-emitted honest, the seal guards
   verbatim in C, the decision table coded. The write-free law in code.
3. **THE BOOT-LANE CLOSURE (the 4.59 machine day)**: the audit's plan
   executed — the v448b flush + the geometric sweep, the first
   discriminant 0x578 (the chain fits the frame exactly, the ra @0x618
   receives OUR gadget 0x0ccb, byte-verified). **THE WRITE DID NOT FIRE**
   (the post-mortem WPR = 0x4cb8f = the stock). The direct model
   falsified by its own discriminant. **THE STRUCTURAL VERDICT: the RSA
   wall (any modified memdesc = the cryptographic failure) + the falcon
   wall (the GA104 error handler = the secure no-return loop; the
   exploitable handler = the GA100/CMP 170HX difference). The boot lane
   280 W = CLOSED BY DESIGN on this card — 8 variants, 15+ boots.** The
   rollbacks definitive (0 strings, the firmware c0156954, zero Xid).
4. **4.63/4.63a — the pivot to the only remaining route (the vBIOS
   cross-flash)**: the TPU census (the Suprim X .E5 = the only MSI 3070
   at 280 W), the in-repo patched nvflash named to the byte (2 bytes
   @0x18460B, JNE→NOP×2), the day-0 autopsy (the 35 VFIO sessions died
   on the zeroed Device ID — the transport fail-safe, the image the
   cause), the decoder v463a (selftest 29/29), the real-ROM admission
   (the NVGI container law — the flash file = the raw @0x9200; the
   zeroed subsystem = the MSI family norm; the budget cluster
   {100000, 280000, 300000} @0x86A04 = THE 280 W GATE PASSED on the real
   file), the DEV_ID fix landed in the runbooks 462 AND 463 (#66).
5. **THE FLASH DAY (the evening — the runbook-463 §2 transport)**: the
   guest built (vmlinuz extracted from the UKI, the initramfs
   busybox+nvflash 5.867+the raw ROM, the no-GPU rehearsal = the clean
   ABORT), six attempts v1→v6 = **ZERO EEPROM writes, the card intact
   after every one** (.EB re-verified each time; v4 = the rmmod fbcon
   hang, v5 = the vtcon freeze, v6 = nvidia loaded from the initramfs →
   ten clean abort loops 19h02–19h13 → the snapshot restored). THE
   STRUCTURAL LESSON: the GPU isolation must live at the kernel cmdline
   (module_blacklist) — the file-level blacklists arrive too late. The
   ROM artifacts classified honestly (the flash file = the raw
   ccabe841 55AA; the TPU container = the NVGI 54968a59; the 118041-B
   file = the bot-check HTML; the existing vbios-stock.rom = the
   complete legacy chain 135b2153 — the full SPI read stays the first
   gesture of the §2, in the guest).
   **v7 = the founder architecture (the single-use Limine entry
   "Flash463" + module_blacklist, the service, the arming flag, the 3
   anti-loop locks) — WRITTEN, NOT INSTALLED.**

**The current phase: the flash transport = the only road, proven
fail-safe in real conditions; the next gesture = the v7 install (the
syntax check, the one-sudo install, the boot on Flash463, the ~3-min
write, the verdict .E5/280 W or .EB/rollback) — with the full chip read
×2 BEFORE any write (the runbook-463 rollback law).**

## The pass 4.65 (2026-09-27) — the EB↔E5 comparison executed offline, the gate filled

The external audit's Phase 2 executed with ZERO boots: the sibling-_1
raw (the same MSINV390MH board as our chip) ↔ the .E5 raw = **455 bytes
of diff over 962,048 = 0.047 %** — the same size, the same tables at the
same offsets, the board marker IDENTICAL, the memory SAMSUNG both sides,
the power deltas IN-PLACE ({100000,240000,250000} → {100000,280000,300000}
at the same 0x86a04), the clock bins = the Suprim class (WARN), **one
UNKNOWN (the 326-B region @0xe8e12)**. The gate: ZERO INCOMPATIBLE
known; the cross-flash admissible pending (a) the full chip read ×2 in
the guest (the true ~1-MB SPI chip-before — the in-session read was
closed by measurement) and (b) the 0xe8e12 classification. The
provenance corrections banked: vbios-stock.rom = the complete
self-consistent legacy chain (135b2153, the Sep-17 double read), not
"partial", but not the full SPI either; the day-0 "BAR window" dumps =
failed reads (v1 = another device's RAM). findings-4.65-eb-e5-comparison.md
