# findings-gx18 — the eighteenth ring: the founding complaint, solved

## The story closes

The founder's founding question — *"le Resizable BAR détecte mal alors
que c'est en auto"* — is now answered with cause, fix, and measurement.

**The chain of the bug**: the board's Above 4G Decoding and Resize BAR
Support settings read Enabled/Auto in the BIOS UI (photographed), but
**CSM (Compatibility Support Module) was enabled — and CSM silently
disables Above-4G at boot**. The boot firmware therefore placed the
GPU's BAR1 at 256 MiB below the 4 GB line, no ReBAR engagement anywhere,
and the driver never saw a resizable window. The settings displayed one
truth; the boot executed another. The ASUS BIOS's own help note names
the gate ("please navigate to Boot section and disable CSM") — and the
sibling lab's rings 49–50 had predicted exactly this gray-out condition
(SystemAccess/CSM) from the IFR grammar months earlier.

**The fix** was one user gesture: Boot → CSM → Disabled. No hardware,
no purchase, no firmware modification.

**The measured before/after:**

| Observable | Before | After |
|---|---|---|
| BAR1 Total (nvidia-smi) | 256 MiB | **8192 MiB** |
| PCIe Region 1 | 0xd0000000, 256 MB, below 4 GB | **0x7c00000000, 8 GB, above 4 GB** |
| ReBAR engagement | none (no dmesg, no driver field) | **active** (full-VRAM window live) |

**Corollary**: the GPU's VBIOS (94.04.46.00.EB, the May-2021 LHR wave)
supports ReBAR natively — the anticipated VBIOS update path is moot.
The board's BIOS 3644 handles the chain correctly once CSM is out of
the way. The last suspect standing after eight measured software walls
was not a security bypass at all: it was a compatibility toggle the
board itself documents.

## Honesty ledger

- Proven: the before/after PCIe BAR placement and size, the fix gesture,
  the UEFI boot state, the settings state (photographed).
- Inferred: the CSM mechanism as the disabling agent (the ASUS note plus
  the perfect before/after correlation).
- The B550 chip dump remains open (the SMU wall stands; CH341A is the
  documented path) — but the founder's actual daily-driver problem is
  closed tonight.
