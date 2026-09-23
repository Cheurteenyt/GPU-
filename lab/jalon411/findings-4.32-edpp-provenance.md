# 4.32 — the provenance of the EDPp policy constant in GSP-RM: the six
# 250000 sites are TIME logic, not power — the firmware patch does NOT
# modify the power policy

Substrate: `tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin` (the
mission's) and `tools/analysis/gsp-extract/rm-full.elf` (the map
coordinates). The decisive prerequisite, PROVEN first:
`v432_coord_check.py` — the two substrates are byte-identical code
images under **`B_file = A_img − 0x38`** (3,739/3,739 sampled 0x100-B
windows equal at stride 0x1000 across the whole 0xE9B000 code image;
the six 4.30 patch sites and the 17 v420 census sites all re-verified
byte-exact under the law). The v416 map and every campaign coordinate
transfer to the mission's substrate without loss. Instruments:
`lab/jalon411/v432_coord_check.py`, `v432_sites.py`, `v432_sisters.py`,
`v432_allpairs.py`, `v432_edpp_fill.py` (+ their JSONs). All five
self-checks pass (the census re-derivation reproduces v420 17/17 with
zero mismatches).

## Verdict first

1. **The six 250000 sites are NOT the EDPp/power policy.** Each site's
   mechanical role is now PROVEN by cited disassembly (§2): a
   threshold compare against a table field (s0), a call argument
   consumed as a TIMEOUT (s1), a deadline/deadband pair (s2), a
   dividend of a packed rate pair (s3), a clamp-and-threshold
   (s4+s5). The shared callee of s1/s2 reads **`rdtime`** (the RISC-V
   time counter) and adds the 250000 argument to the tick to form a
   deadline — the constant is a DURATION in timer ticks.
2. **The power-trio premise is falsified in the firmware.** 100000 and
   240000 materialize at **ZERO** lui+addi sites in the whole code
   image (7,434 pairs enumerated, every legal decomposition — §3).
   No rm.elf function manipulates {100000, 240000, 250000} together.
3. **The co-occurring family is a time ladder, not a power table.**
   Within the six sites' own functions/neighborhoods: 500000, 1000000,
   4000000, 100000000, −250000, −1000000 — scale-coherent as µs
   (250 ms / 500 ms / 1 s / 4 s / 100 s), absurd as mW on a GA104
   (500 W / 1000 W / 4000 W / 100 kW), partially absurd as kHz.
4. **The EDPp policy object (0x6d0) is filled from RM-internal runtime
   state** — vtable-call results (the 0x2080A080/0x2080A618 internal
   event space), field copies from other runtime objects, and
   zero/flag immediates. NO write in the verified set takes a value
   from a static firmware table, and none traces to the RPC request
   buffer (§4).
5. **The global conclusion (the mission's OUI/NON/INCERTAIN):**
   patching the six rm.elf sites 250000→280000 is **NOT** a power
   policy modification — **NON** at the proven level. It would alter
   timer/threshold logic (250000→280000 ticks) while the EDPp policy
   object is fed by runtime state upstream of any static constant.
   The 280 W lane stays where 4.21/4.24/4.30 left it: the host/VBIOS
   feed of the policy (transport or the HS-execution rewrite of the
   policy object), not this constant.

## 1. The coordinates (the law everything rides on)

| coordinate | meaning |
|---|---|
| `A_img` | the v416-map / campaign image offset (rm-full.elf image, p_offset 0x40) |
| `VA_A` | `A_img + 0x1000000` (the mission's historical VA list) |
| `B_file` | gsp-rm-17MB.bin file offset = `A_img − 0x38` (PROVEN, image-wide) |

The mission's VA list {0x10190fe, 0x101a062, 0x11f09e0, 0x17c46b4,
0x1b99bec, 0x1b99cc8} = `VA_A`. The 4.30 patch offsets {0x190c6, …}
= `B_file`. Both substrates carry the SAME bytes (law proven); the
disassembly below is cited in `VA_A` coordinates.

## 2. T1 — the six sites: the cited disassembly, per-site verdicts

### s0 — VA_A 0x10190fe (B 0x190c6) — THRESHOLD against a table field

```
0x10190f4: mul      a5, s6, a5          # record index × stride
0x10190f8: c.add    a5, s1              # + table base
0x10190fa: ld       a6, 0x4a8(a5)       # a6 = *(rec + 0x4a8)   ← the TABLE-LOADED value
0x10190fe: lui      a5, 0x3d            # ┐
0x1019102: addi     a5, a5, 0x90        # ┘ 250000
0x1019106: bltu     a5, a6, +0x1fa      # if (250000 <u rec->0x4a8) → other path
...
0x101913e: sb       zero, 0x48f(s2)     # the taken path CLEARS the record flag
0x1019142: sd       zero, 0x4a8(s2)     #           and the 0x4a8 field itself
```
Record stride **0x4f0** (`addi a5, zero, 0x4f0 ; mul ; c.add`), flag
byte at +0x48f, value at +0x4a8. **PROUVÉ**: the constant is a compare
operand against a per-record runtime field; the exceed-path zeroes the
field. (Map note, honest: s0 sits in an UNCOVERED island of the 4.16
map — the window is anchor-synced from the site itself, whose bytes
are proven by v432_coord_check on both substrates.)

### s1 — VA_A 0x101a062 (B 0x1a02a) — CALL ARGUMENT = a TIMEOUT

```
0x101a060: c.li     gp, 2
0x101a062: lui      a2, 0x3d            # ┐
0x101a066: addi     a2, a2, 0x90        # ┘ a2 = 250000 (3rd argument)
0x101a06a: c.mv     a0, s5              # a0 = the object
0x101a06c: auipc    ra, 0x875
0x101a070: jalr     ra, ra, -0x128      # call 0x188EF44(a0=obj, a1=entry, a2=250000)
```
The callee **0x188EF44** (shared with s2's second call — PROVEN same
target by auipc/jalr arithmetic) is timestamp-based:
```
0x188ef6c: c.mv     s4, a2              # s4 = the 250000 argument
...
0x188efae: rdtime   a0                  # ← THE RISC-V TIME COUNTER
0x188efb2: c.sd     a0, 0x40(s1)        #    stored into the entry
...
0x188effe: ld       a5, -0x50(s0)       # a5 = the tick returned by the obj+0x1a0 vmethod
0x188f002: add      a2, a5, s4          # a2 = now + 250000     ← THE DEADLINE
0x188f006: bltu     a2, a5, +0x42       # overflow → error path
0x188f00e: auipc    ra, 0
0x188f012: jalr     ra, ra, -0x1f2      # worker(obj, entry, deadline)
...
0x188f038: c.mv     a2, s4              # other path: a2 = 250000 itself
0x188f03e: auipc    ra, 0
0x188f042: jalr     ra, ra, -0x3d2      # worker2(obj, entry, 250000)
```
**PROUVÉ**: the constant is a call argument consumed as a
DURATION added to the current tick — a timeout/period, downstream of
`rdtime`. No power semantics anywhere in the callee.

### s2 — VA_A 0x11f09e0 (B 0x1f09a8) — DEADLINE / DEADBAND pair

```
0x11f09d0: ld       a5, 0x1a0(s7)       # obj+0x1a0 = the get-current-tick vmethod
0x11f09d4: addi     a1, s0, -0x60
0x11f09d8: c.mv     a0, s7
0x11f09da: c.jalr   a5                  # tick = vmethod(obj, buf)
0x11f09dc: ld       a5, -0x60(s0)       # a5 = buf[0] = the tick
0x11f09e0: lui      a2, 0x3d            # ┐
0x11f09e4: addi     a2, a2, 0x90        # ┘ 250000
0x11f09e8: add      a4, a5, a2          # a4 = now + 250000
0x11f09ec: bgeu     a4, s4, +0x80       # if (now+250000 >= s4) skip
0x11f09f0: sub      s3, s4, a5          # s3 = s4 − now  (the remaining time)
0x11f0a04: sd       a4, 0x470(a5)       # *(rec+0x470) = the deadline (stride 0x4f0)
0x11f0a26: c.mv     a2, s3              # arg = the remaining time
0x11f0a2a: auipc    ra, 0x69e
0x11f0a2e: jalr     ra, ra, 0x51a       # call 0x188EF44(obj, entry, remaining)
```
And the counterpart 96 B earlier — the SAME record field:
```
0x11f097c: ld       a5, 0x470(a5)       # a5 = *(rec+0x470)  (the stored deadline)
0x11f0980: lui      a3, 0xfffc3         # ┐
0x11f0984: addi     a3, a3, -0x90       # ┘ −250000
0x11f0988: c.add    a5, a3              # a5 = deadline − 250000
0x11f098a: bltu     s4, a5, -0x2e       # if (s4 < deadline − 250000) → re-arm path
```
**PROUVÉ**: a deadline stored into rec+0x470 with a ±250000 deadband —
the classic schedule/debounce pattern; the record field and the
0x4f0 stride match s0's table.

### s3 — VA_A 0x17c46b4 (B 0x7c467c) — DIVIDEND of a packed rate pair

```
0x17c46b4: lui      a5, 0x3d            # ┐
0x17c46b8: addiw    a5, a5, 0x90        # ┘ 250000
0x17c46bc: divuw    a5, a5, a2          # a5 = 250000 /u a2   (a2 = the divisor argument)
0x17c46c0: slli     a4, a2, 0x20        # a4 = a2 << 32
0x17c46c4: c.or     a5, a4              # a5 = {hi: divisor, lo: 250000/divisor}
0x17c46c6: addi     a4, zero, 0xc0      # stride 0xc0
0x17c46ca: mul      a4, s4, a4
0x17c46ce: add      a3, s1, a4
0x17c46d2: sd       a5, 0x380(a3)       # stored into (0xc0-stride records)+0x380
```
**PROUVÉ**: the constant is a DIVIDEND packed with its divisor into a
u64 {divisor, quotient} pair — a period/interval configuration (the
4.21 "unit conversion" reading sharpened: it is the numerator of a
tick-count computation, not a power conversion). A percentage-flavored
`sltu a2, a3(=0x63=99), a2` sits later in the same flow.

### s4 — VA_A 0x1b99bec (B 0xb99bb4) — CLAMP to 500000 then THRESHOLD

```
0x1b99bde: lui      a5, 0x7a            # ┐
0x1b99be2: addi     a5, a5, 0x120       # ┘ 500000
0x1b99be6: bgeu     a5, s2, +6          # if (500000 >= s2) skip
0x1b99bea: c.mv     s2, a5              # s2 = min(s2, 500000)   ← THE CLAMP
0x1b99bec: lui      a5, 0x3d            # ┐
0x1b99bf0: addi     a5, a5, 0x90        # ┘ 250000
0x1b99bf4: c.add    a5, s2              # a5 = s2 + 250000
0x1b99bf6: bgeu     s10, a5, +0xca      # if (s10 >= s2+250000) → other branch
```
**PROUVÉ**: operand of a clamp-and-threshold on a runtime value
(s2 loaded from *(state −0x88) via the page-5 idiom; s10 compared).
0x1b99bec's earlier v421 label ("divuw") belonged to the s3 site's
function — this site is the clamp/threshold.

### s5 — VA_A 0x1b99cc8 (B 0xb99c90) — the same flow, the other arm

```
0x1b99cc6: c.bnez   a5, -0xae           # (back into s4's flow)
0x1b99cc8: lui      s2, 0x3d            # ┐
0x1b99ccc: addi     s2, s2, 0x90        # ┘ s2 = 250000
0x1b99cd0: c.j      -0x3c               # → the same threshold block
```
**PROUVÉ**: s5 assigns 250000 to the SAME register (s2) in the
alternate arm of s4's function — the default when the loaded value is
not clamped. One function, one threshold structure.

### Cross-cutting: the six sites never touch the EDPp object

The six sites live in covered regions `[0x1019c28,0x10217da]`,
`[0x11ea28c,0x11f145c]`, `[0x17c09b8,0x17c65b8]`, `[0x1b991a0,0x1b9b968]`
(s0: uncovered island). The EDPp object's census regions are
`[0x143f4f8,0x1446e60]`, `[0x145419c,0x145ec6a]`, `[0x15fab38,0x15fc42e]`
— **disjoint** (region-granular PROVEN). No 250000-site function
appears in the object's consumer census (17 sites, §4).

## 3. T2 — the sisters 100000/240000: zero sites; the family is a time ladder

### 3.1 The exact encodings (computed, the mission's arithmetic checked)

| value | hex | canonical lui | addi (signed) | note |
|---|---|---|---|---|
| 100000 | 0x186A0 | 0x18 | +0x6A0 | the mission's "lui 0x187" was off — computed here |
| 240000 | 0x3A980 | 0x3B | −0x680 | canonical NEGATIVE addi split |
| 250000 | 0x3D090 | 0x3D | +0x90 | the six sites' encoding |
| 2500 (0.1 W units) | 0x9C4 | 0x1 | −0x63C | ≠ the bytes |
| 25000 (%) | 0x61A8 | 0x6 | +0x1A8 | ≠ the bytes |
| 280000 | 0x445C0 | 0x44 | +0x5C0 | the 4.30 patch value |
| 500000 | 0x7A120 | 0x7A | +0x120 | s4's clamp |
| 1000000 | 0xF4240 | 0xF4 | +0x240 | |
| 4000000 | 0x3D0900 | 0x3D1 | −0x700 | |

So IF the sites were power, the bytes would force **mW** (2500 and
25000 do not match 0x3D090). They are not power — §2 — so the mW
question is moot for rm.elf and stays with the VBIOS/host lane.

### 3.2 The scan (exhaustive, all decompositions)

`v432_allpairs.py` enumerates EVERY lui+addi/addiw pair in the code
image (rd==rs1, rd≠0, both add opcodes, 2-byte steps, gaps 2 and 4,
canonical AND alternative splits, 20-bit lui sign-extended):
**7,434 pairs, 1,695 distinct values.**

| value | pair sites | verdict |
|---|---|---|
| 100000 | **0** | ABSENT from the firmware code |
| 240000 | **0** | ABSENT from the firmware code |
| 250000 | 6 | exactly the mission's six sites |
| 280000 | 0 | absent (the patch value) |
| 500000 | 25 | present; one 14 B from s4 (the clamp) |
| 1000000 | 123 | common |
| 4000000 | 15 | present |
| 100000000 | 17 | present |
| −250000 | 1 | 96 B before s2 (the deadband arm) |
| −1000000 | 3 | 694 B from s0 (divu-conversion math) |
| −500000 | 5 | nearest 8,114 B away (unrelated) |

Data words: 100000 = 5 raw u32 hits in the code image (all inside the
high-entropy stretches already banked as coincidences by 4.21:
0x4a7be0, 0x7bcbe0, 0xb1abe0, 0xb33be0, 0xb73be0), 0 in the data
LOAD; 240000/250000/500000/280000 = **0 u32 hits anywhere**.

**The power-table signature is ABSENT**: no rm.elf function
manipulates {100000, 240000, 250000} together — the trio the ring-3
side decoded (100/240/250 W) does not exist in the RM code.

### 3.3 The co-occurrence ladder around the six sites

Constants materialized within ±0x300 of each 250000 site
(`v432_sisters.constants_within_0x300`):

| site | family in ±0x300 |
|---|---|
| s0 | 250000, 4000000, 100000000, −1000000 |
| s1 | 250000 |
| s2 | 250000, 1000000, −250000 |
| s3 | 250000, 1000000, 0xdf38e6 (stray) |
| s4/s5 | 250000, 500000, 0x441F0*, 0x272cdd (stray) |

\* the 0x441F0 (279,024) nearest occurrence @0x1b99b80 is **address
arithmetic, not a value** — `lui a4, 0x44 ; addi a4, a4, 0x1f0 ;
c.add a5, a4` feeding an id-scan loop (`c.lw a3, 8(a5) ; bne a3, a2`)
— an offset into a table, EXCLUDED from the value family. Banked as a
census caveat: lui+addi materializes large offsets too; each family
member's role was read before counting it.

The value family {±250000, ±500000, 1000000, 4000000, 100000000} is
scale-coherent ONLY as µs (250 ms / 500 ms / 1 s / 4 s / 100 s and
their negative delta forms). The `rdtime` callee (§2, s1) anchors the
semantic: DURATIONS in ticks. The exact tick rate (µs?) = HYPOTHÈSE;
the TIME semantic = PROVEN at the code level.

## 4. T3 — what fills the 0x6d0 EDPp policy object

`v432_edpp_fill.py` re-derives the v420 census **17/17 identically**
(zero missing/extra/mismatch), then traces every use of the object
pointer within its region (≤120 insns, vs v420's ±8 — this is what
exposes the writers the first census missed).

### 4.1 The writer map (all WRITE-FIELD uses in the verified set)

| field | writer | value source (classified) |
|---|---|---|
| 0x0 | `sb zero, (obj)` @0x14584a4, @0x1458c12 | the RESET byte |
| 0x8 | `c.sw a3, 8(s1)` @0x143ff1a | DEF(andi) — a flag |
| 0x65c | `sw a5, 0x65c(s1)` @0x143fe3e | FIELD-COPY(mem) |
| 0x660 | `sw a5, 0x660(s6)` @0x144011c | the WORKER: buf[0x10] of the 0x2080A080 vtable call |
| 0x664 | `sb a5, 0x664(s2)` @0x1458502 (0xFF), `sh a5, 0x664(s2)` @0x14585b0 | immediate −1; a flags halfword from the runtime object's +0x98 byte |
| 0x668–0x684 | 8×`sw` @0x145857a–0x1458596 | an 8-dword block COPY from a runtime object (fields +0x4DA0..) |
| 0x6b0/0x6b4/0x6b8 | @0x1440a76-a7e | c.li ZERO (init), + one runtime halfword |
| 0x6bc | @0x1440de6/e26 | zero / FIELD-COPY |
| 0x6c0 | @0x1440616/0x144067e | zero / a runtime byte |
| 0x6c4 | @0x145887e | DEF(ori) — a flag OR |
| 0x6c8 | @0x1440150, 0x144068a, 0x1440e3c, 0x14585d6 | DEF(ori) — the change-FLAG field (4.21's bit 1) |

**No write takes a CONSTANT-FORM value; no write traces to an RPC
request buffer.** The only immediate-valued writes are ZERO/0xFF flag
initializations.

### 4.2 The three anchors (re-decoded, cited)

**GET_EDPP_LIMIT_INFO handler (0x1458bec)** — a pure RESET, nothing
else:
```
0x1458bfc: ld       a0, -0x168(s1)      # the object
0x1458c00: addi     a2, zero, 0x6d0
0x1458c04: c.li     a1, 0
0x1458c06: auipc    ra, 0x78b
0x1458c0a: jalr     ra, ra, 0x61e       # memset(obj, 0, 0x6d0)
0x1458c0e: ld       a5, -0x168(s1)
0x1458c12: sb       zero, 0(a5)         # the byte flag
0x1458c16: (epilogue — returns)
```

**The recomputation worker (0x14400c6)** — the one refreshed field:
```
0x14400e8: c.lui    a0, 4 ; add a5, s1, a0     # state2 = s1 + 0x4100
0x14400ee: ld       a6, 0x138(a5)              # the RUNTIME vtable slot
0x14400f2: lw       a2, 0xe4(a5)
0x14400f6: lw       a1, 0xdc(a5)
0x14400fe: lui      a3, 0x2080a ; addi a3, a3, 0x80    # 0x2080A080
0x144010c: c.jalr   a6                         # the internal-event call
0x1440118: lw       a5, 0x10(s4)               # buf[0x10]
0x144011c: sw       a5, 0x660(s6)              # obj->0x660
```
(The 4.21 register's `c.li a1, 0`-led memset of the 52-B buffer at
0x14400e0 is re-verified: `auipc ra, 0x7a4 ; jalr +0x144` with
(a0=s4, a1=0, a2=0x34).)

**UPDATE_EDPP_LIMIT handler (0x1862480)** — re-confirmed: `c.jr ra`
(2 bytes), the no-op stub of 4.20.

### 4.3 The init path (the 8-dword block copy, decoded from the anchor)

```
0x14584d8: ld       s2, -0x168(a5)      # the object (census site)
0x14584ec: zero obj+0x668..0x688 (8 dwords, sw zero loop)
0x1458502: sb       a5(-1), 0x664(s2)
0x145850a: auipc    a0, 0x2d39 ; addi a0, a0, -0x722   # a STATIC DESCRIPTOR address
0x1458512: auipc    ra, 0x46b ; jalr +0x22a            # lookup/allocate by descriptor
0x145852e: c.lui    a5, 4 ; c.add a5, s1 ; ld a6, 0x138(a5)   # the state2 vtable slot
0x145853e: lui      a3, 0x2080a ; addi a3, a3, 0x618   # 0x2080A618
0x145854e: c.jalr   a6                                 # the internal-event call
0x1458556: add      a5, s5, s4                          # + the 8-dword load block
0x145857a: sw a3, 0x67c(s2) ... sw a5, 0x684(s2)        # COPY into the object
```
The copied values come from the looked-up RUNTIME object — not from a
static table, not from the request buffer. The request-consuming code
does exist in the module (the function at 0x14581f0 reads fields
0x0/0x4/0x104/0x108/0x10c of its second argument and marshals via
vtable calls) — but its writes target OTHER objects, not the policy.

### 4.4 The T3 answer

The policy object is **re-derived from RM-internal runtime state**
(the 0x2080Axxx internal-event mechanism + field copies from other
runtime objects + flag immediates). Within the verified 66 % of the
image: no static-constant fill, no request-buffer fill. The values'
ultimate origin lies UPSTREAM of these sites (the state fields
+0xdc/+0xe4, the descriptor-looked-up object, the listener chain) —
the 4.24 model's "VBIOS-parsed runtime data" remains the HYPOTHÈSE for
that upstream origin, now with the added PROVEN fact that the fill
sites themselves consume call results, never literal constants.
Consequence for the mission's fork: neither arm of the mission's
dilemma resolves to "patch the six sites" — the object is not fed by
the 250000 sites (disjoint, §2), nor by static constants (§4.1).

## 5. The global conclusion (the mission's deliverable)

**Does the rm.elf patch (250000→280000 at the six sites) modify the
power policy? — NON** at the proven level:

1. the six sites are timer/threshold logic (deadlines, deadbands,
   rate pairs, clamps) — every mechanical role PROVEN with cited
   disassembly (§2);
2. the constant never co-materializes with the power trio's other
   members — 100000/240000 have ZERO sites in the whole image (§3);
3. the co-occurring value family is only scale-coherent as time
   (§3.3), anchored by the `rdtime`-consuming shared callee (§2);
4. the EDPp policy object (0x6d0) is disjoint from all six sites and
   is filled exclusively from runtime call results (§4).

**INCERTAIN remains** (honest residual): the exact tick rate (so
whether 250000 = 250 ms), and the upstream origin of the policy
object's values (the VBIOS-parse chain). Neither can turn the patch
into a power modification — the patch would change timer durations,
not power fields.

**The resolution path for 280 W** (unchanged by this pass, now
sharpened):
- the policy values arrive at the object via the internal-event
  vtable calls from RM state — the state's origin = the upstream
  parse chain (the 4.21 host-lane queue item: kernel_gsp.c / the perf
  construct path — the open-source side),
- or the HS-execution route rewrites the policy object itself at
  runtime (the campaign's proven driver-patch bypass; the object's
  fields +0x65c/+0x660/+0x668-0x688 are the writable targets),
- the rm.elf six-site patch stays byte-VALID (4.30's tests) but
  semantically pointless for 280 W — do NOT boot it expecting watts.

## 6. The honest ledger

1. The coordinate law (−0x38) is PROVEN image-wide; every prior
   pass's coordinates remain valid, and the two rm.elf substrates are
   one code image.
2. The per-site roles are PROVEN from linear anchor-synced
   disassembly; the SEMANTIC label "time" rests on the rdtime callee
   (PROVEN) + the scale ladder (PROVEN co-occurrence) — the exact
   unit (µs vs other tick scales) is HYPOTHÈSE.
3. s0's window sits in an uncovered map island; its window is
   anchor-synced and its bytes proven equal on both substrates, but
   the 4.16 verification does not cover it — flagged.
4. The 0x441F0 "family member" near s4/s5 is an ADDRESS offset — the
   correction is banked (a lesson: lui+addi also builds large
   offsets; read the use before counting the value).
5. The census re-derivation is exactly 17/17 — the map-transfer law
   and the v420 instrument both verified on this machine.
6. The v420 census remains a lower bound (verified regions only);
   writers outside the 66 % would be NEW evidence, not a
   contradiction.
7. The 4.21 label "0x17c46b4 = divuw (unit conversion)" is sharpened:
   the divuw belongs to the s3 site (same VA) — the dividend of a
   packed {divisor, quotient} pair; no power conversion is involved.

## 7. The queue

1. The upstream origin of the policy values: walk the 0x2080A080 /
   0x2080A618 internal-event mechanism and the state fields
   (+0x4100, +0xdc/+0xe4) to their writers — the last RM-side hop
   before the host/VBIOS lane.
2. The 0x4f0-stride table's identity (the records at +0x460/0x470/
   0x48f/0x4a8 that s0/s2 schedule) — name it from the descriptors.
3. The tick rate: the RM's timebase programming (the rdtime scale) —
   one boot-params/CSR pass would convert 250000 into a wall-clock
   duration and close the last INCERTAIN.
4. The 4.26 recv capture stays the only road for the live policy
   values (the 96-B prediction remains armed).
5. Function-level attribution of the three c.lui-100000 sites that sit
   inside s2's and s3's covered regions (§8.1) — the region-granular
   co-occurrence is proven; the same-FUNCTION question needs the
   function-boundary walk.

## 8. Addendum — the reconciliation pass (v432e): the local draft
## arbitrated, two corrections, one confirmation

A second, independent execution of this pass ran under the token
session (the draft commit 0b6981e, pre-push). It disagreed with this
document on three points. `v432e_reconcile.py` (+ `.json`) arbitrates
all three on the bytes, on this machine, under the proven law; its
coordinate-law re-check is 518/518 windows equal and the v416 map
semantics are proven in passing (seen = instruction starts, covered =
byte coverage: s1's start=1 / mid=0 / next=1).

### 8.1 The c.lui loophole: 100000 is NOT absent from the firmware

`v432_allpairs` promised c.lui/c.addi coverage in its docstring and did
not implement it (full lui opcode 0x37 only). The compressed census,
every hit validated against the map's seen bitmap, finds **36 real
c.lui+addi materializations of 100000** (32 adjacent + 4 with one
compressed instruction between; rd-matched; every one an instruction
start). The §3.2 sentence "ABSENT from the firmware code" is CORRECTED:
100000 is present in compressed form. The power-TRIO premise stays
falsified exactly as stated, because 240000/250000/280000/500000/
1000000/4000000 are NOT c.lui-encodable (|hi| > 0x1F — the theorem is
asserted in the instrument): 240000 has ZERO sites under EVERY form.
And what co-occurs with the 250000 sites is the time ladder itself:
3 of the 36 c.lui-100000 sites fall INSIDE the covered regions of s2
(two sites: A 0x1eb6f0, 0x1f04c6) and s3 (one site: A 0x7c1212) —
100000 = 0.1 s next to the 0.25 s/0.5 s band, coherent only as µs.

### 8.2 The seventh 250000 site: REAL (the gap-{2,4} scan hole)

The allpairs scan enumerated gaps {2,4} only. Extended to {6,8} with an
intermediate-instruction CLOBBER check, it finds ONE gap-8 split —
exactly the draft's claim, here in law-correct coordinates:

```
0x1b99c82: lui      a4, 0x3d
0x1b99c86: sub      s2, s10, s2      # does NOT write a4 — no clobber
0x1b99c8a: addi     a4, a4, 0x90     # a4 = 250000
0x1b99c8e: bgeu     s2, a4, 6        # threshold the difference
0x1b99c92: c.mv     s2, a4           # s2 = min(s2, 250000)
```

seen=1, covered=1 (a verified instruction start, inside s4/s5's region
[0x1b991a0,0x1b9b968]). The role: the SECOND clamp of the same
threshold flow — s4/s5 clamp the value to 500000, this arm clamps the
DIFFERENCE (s10 − s2) to 250000: the band [250000, 500000] is a
hysteresis pair. The TIME verdict is REINFORCED (a 0.25–0.5 s deadband
under the rdtime anchor). Two corrections follow: the six-site
enumeration → **SEVEN** sites (§2's framing updated), and **the 4.30
patched container still carries this live 250000 — that patch is 6/7
regardless of semantics**; its boot stays barred as a 280 W experiment
(keep it for the signature-coverage question only).

### 8.3 The UPDATE_EDPP_LIMIT handler: both passes read the same bytes

The handler @A 0x862480 ends `c.jr ra` (bytes 8082) after the s0/s1
epilogue — the stub, exactly as §4.2 states. The draft's "real
function" sat at A 0x8624B8 = B_file 0x862480: the draft read
gsp-rm-17MB.bin WITHOUT the coordinate law (VA = B_file + 0x1000000),
i.e. 0x38 bytes past the true handler, landing on the NEXT function's
prologue (`c.addi16sp sp, -0xc0 ; c.sdsp s0/s3/s5 ...` — a real
function, a real prologue, the wrong label). The draft's disassembly
was accurate; only its addressing was off. Every coordinate the draft
quoted carries the same −0x38 (its callee "0x188ef0c" = this
document's 0x188EF44). Lesson banked beside §6: a coordinate law is a
PREREQUISITE, not a finding — verify it before the first disassembly,
not after the contradictions.

### 8.4 The draft's "57 materializations of 100000": a worklog misreading

The draft's own JSON says: full-form 100000 = 0, c.lui 100000 = 32,
full-form 500000 = 25. Its worklog added the last two numbers into the
wrong row. The v432e re-scan reproduces every full-form count of §3.2
exactly at gaps {2,4} (100000=0, 240000=0, 250000=6, 280000=0) and
asserts the five u32 hits equal under the law (the draft's B 0x4a7ba8,
0x7bcba8, 0xb1aba8, 0xb33ba8, 0xb73ba8 = §3.2's A 0x4a7be0, 0x7bcbe0,
0xb1abe0, 0xb33be0, 0xb73be0 — the same five words, two coordinate
systems).

### 8.5 The net effect on the global conclusion

UNCHANGED and now stress-tested by an independent execution: the sites
are time logic; the rm.elf patch is not a power-policy change; the
280 W lane stays with the host feed (kernel_gsp.c / the perf construct
path) or the HS-execution rewrite of the policy object. Corrected in
this document by the reconciliation: §2's six-site framing (a seventh
split site exists — the hysteresis clamp), §3.2's "absent" sentence
(100000 is present, compressed form, 36 sites), §3.2's table row
250000 (6 → 7 pair-equivalent sites), and the §5 patch-completeness
implication (6/7). The v432e instrument closes the allpairs
docstring's promise (c.lui) and the gap-{6,8} hole; its scan pattern
is the reference for any future constant census in this repo.
