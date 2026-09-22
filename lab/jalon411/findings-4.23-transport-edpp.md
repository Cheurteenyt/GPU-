# 4.23 — the transport night: GSP_RM_CONTROL captured, the limit carrier proven, the enforcement located, the host-RAM scanner designed

Substrate: the LIVE driver 610.57.04 (the DKMS-patched transport), the
boot logs (the journal), the open source. This = the experimental
session (~10 reboots, the iterative instrumentation) — the honest
ledger includes what did NOT work and why.

## The infrastructure built

- **The RPC-dump patch** (kernel_gsp.c, the open transport): every GSP
  RPC hexdumped at the send time, the registry-gated (`RpcDump` via
  NVreg_RegistryDwords), the sequence-tagged (the printk interleaving
  across CPUs = the reassembly breaker — the seq = the fix).
- **The analyzers**: rpcdump76_analyze.py (the reassembly + the
  signature hunt), extract_edpp.py, set_mem_offset.py/set_offset.py
  (the LACT config editors), undo-edpp.sh (the one-command rollback).
- **The boot plumbing mastered**: the module params ride the UKI (the
  modprobe conf inside the initramfs — /etc/kernel/cmdline = OVERRIDDEN
  by Limine for UKIs), the Limine hash = Blake2b-512 pinned in
  limine.conf (the re-align after every UKI rebuild).

## The discoveries

1. **fn=76 = `X(GSP, GSP_RM_CONTROL, 76)`** — the RM-API control
   passthrough: the closed x86 RM sends EVERY ctrl command to the
   GSP-RM through it. ~3000 payloads, 3-4 MB per boot (the sizes
   84 B..65 KB). Absent from the RM section of the enum (my first grep
   = `X(RM,` only) — it = under the GSP unit.
2. **The runtime limit carrier = PROVEN by the differential test**:
   `nvidia-smi -pl 210` → an 84-byte payload, the attribute type
   0xFE01 @40, the value 210000 @44 — the EXACT same structure the
   rewrite touched. The `-pl` path = the same carrier.
3. **The max (250) and the default (240) = NEVER transmitted** —
   zero occurrences in any boot. **The enforcement = host-side** in
   the closed x86 RM, which holds them from its VBIOS parse.
4. **The 1616-byte payloads (250000 @104)** = pushed only at SOME
   boots (the first two dump boots — the condition = still
   unidentified); the RM's fallback default without them = 240 W.

## What did NOT work (the honest ledger)

- The in-flight rewrites (260000, 280000) = delivered into the 0xFE01
  attribute and IGNORED by the applied limit — and progressively
  degraded the RM's power state (the default 250 → 240, the `-pl 250`
  = refused): **the 0xFE01 attribute = informational or clamped
  elsewhere**; the rewrites = the corruption source (the attribute
  turned out to = the NV00FE Memory-Mapper operation queue — the
  FINN name decoded it).
- The `EdppOverride` second registry pair = never reached the driver
  (the param parsing) — the single-key v5 = the fix.
- `module_param` in kernel_gsp.c = macro collision (the build fail);
  `linux/mm.h` = not in the RM-source include path (the scanner =
  relocated); `max_pfn` = not exported (→ `get_num_physpages()`).

## The v9 design: the host-RAM EDPp policy scanner

The enforcement = host-side ⇒ the patch = host-side, in OUR compiled
code — no gsp.bin, no signatures, no recompression:

- The scanner = in `nv.c` (the UNIX layer, the full kernel context —
  kernel_gsp.c = the portable RM source, no mm access), a delayed
  workqueue 30 s after the module load.
- **The EDPp fingerprint**: {100000, 240000, 250000} within ±32 bytes
  = the min/default/max triple of the ring-3-decoded power budget —
  unique by construction, scanned across the kernel physmap
  (`get_num_physpages()` pages).
- Every 250000 in a fingerprint → rewritten to `edpp_fix` (the module
  param, 280000) — the x86 RM's policy patched in RAM → the nvml max
  follows → `-pl 280` = the settable.
- kernel_gsp.c = restored to STOCK (the transport = clean, no message
  rewrites — the lesson learned).

## The state of the machine (honest)

The RM power state = degraded by the night's experiments (the 245/240
ceiling). The full power cycle + the v9 boot = the restoration AND the
experiment: the scanner logs the fingerprint locations, the patch
applies if armed.

## Queue for 4.24

- The v9 boot verdict: the EDPPSCAN matches (the count + the physical
  addresses = the policy's provenance).
- If 0 matches: the policy = not in the scanned form — the 64 KB
  payload (210000 @60) = the policy table candidate to mine.
- If the matches + the patch: `-pl 280` = the verdict, then the
  sustained-load validation (the Solar Bay / the gaming).
- The gsp.bin path = the fallback (the rm.elf compressed 725 KB→17.7
  MB inside the GFW archive + the LS-signed = the recompressor + the
  booter bypass = the session-scale work).
