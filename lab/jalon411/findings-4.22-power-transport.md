# 4.22 — the power-transport pass: the open kernel sends NO power tables, the closed x86 blob parses the VBIOS, the lane = the open RPC transport

The question: WHERE do the EDPp limit values (250 000 mW) enter the
GSP-RM? The pass traced the whole transport with the open source and
the installed binary.

## The findings, in causal order

1. **The open kernel sends NO VBIOS/power data.** The complete init
   RPC inventory of kernel_gsp.c: GET_GSP_STATIC_INFO,
   GSP_SET_SYSTEM_INFO (bus/PCI addresses ONLY — read in full),
   SET_GUEST_SYSTEM_INFO, SET_REGISTRY, the trace-crash-buffer RPCs.
   No perf, no pmgr, no VBIOS tables. The RPC enum (rpc_global_enums.h)
   contains no VBIOS-carrying entry either.

2. **The GSP-RM has NO BIT parser** — ring 41 verified against the
   STRING; this pass verified against the CODE: no `BIT\0` bytes in the
   image, no `lui 0x545+addi 0x942` immediate (0x00544942), no byte
   compare sequence (0x42/0x49/0x54). The conclusion HOLDS.

3. **The VBIOS BIT parser lives in the CLOSED x86 blob of nvidia.ko**:
   `BIT\0` appears 39 times in the unpacked module (27.7 MB). The blob
   is stripped and string-less for this function — the static analysis
   of the parse itself = a full x86 RE effort (parked).

4. **The causal chain is therefore**: the closed x86 host RM parses the
   VBIOS (BIT + the 'P' table, the power budget inside) → it hands the
   values to the GSP-RM through RPCs marshaled by the kernel transport
   → the GSP-RM's PFM module fills the EDPp policy object (the 0x6d0
   object of pass 4.20). Every functional link = closed-source EXCEPT
   THE TRANSPORT.

## The lane: the open transport is the observation point — and the write point

Every RPC to the GSP passes through the open kernel transport
(kernel_gsp.c / objrpc / the message queues). Therefore:

- **Observation**: a DKMS-patched transport that dumps every init-phase
  RPC payload would reveal the power-table carrier (the values
  240 000/250 000 = 0x3A980/0x3D090 in a payload = the signature).
- **Rewrite**: the same interception point could modify the values
  in flight — the 280 W write point WITHOUT the EEPROM, WITHOUT the
  booter exploit, in code we compile with the proven DKMS cycle.

This corrects the 4.19-4.21 lane naming: "the host-side lane in the
open source" = imprecise — the parse = closed x86; the transport =
open; the patch point = the transport.

## Queue for 4.23

- The boot-time RPC dump experiment (the DKMS patch of the transport,
  one boot, the grep for 0x3A980/0x3D090 in the payloads).
- The result names the carrier RPC → the rewrite design.
- The license note: the user's 3DMark Port Royal = license-locked
  (Solar Bay ran, the RT verdicts banked in compute-lab).
