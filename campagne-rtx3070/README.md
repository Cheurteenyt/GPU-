# The cloud RM campaign (2026-09-18) — five vagues, from the strings to the VF-point bit

The cloud-side half of the campaign: **no GPU access, pure firmware mining**.
Matter: the full `rm.elf` (16,912,384 B plaintext RISC-V, extracted from the
official NVIDIA package — the successor of the `tools/gsp-extract/` rings 28-31
work) plus the 881-dial census of ring 30 and the omarchy integration files.

Deliverables are French (the founder's language); each doc is one vague, one
session, Tasks 61-67 of the shared worklog. Instruments live in
`tools/gsp-extract/` (`wave2_*`, `xref_dials.py`, `v42_*`, `v43_*`, `v44_*`);
their JSON caches are reproducible from the instruments + `win.elf` and are
deliberately not committed.

| File | Vague | What it settles |
|---|---|---|
| `campagne-rtx3070-carte-optimisation-2026-09-18.md` | 1 (Task 61) | Genshin (3 193 samples) is VOLTAGE-limited: 1890 MHz pinned, ~15 W margin under the cap, 19 °C at throttle onset — the 280 W flash buys Genshin nothing, the core offset is lever #1; the full lever map re-qualified from the 31 rings. |
| `campagne-rtx3070-vague2-linux-punitions-firmware-2026-09-18.md` | 2 (Task 62) | The punitions mapped (V4-V8) + the omarchy bridge: 881 dials settable via `NVreg_RegistryDwords` under nvidia-open-dkms (GSP mandatory, mkinitcpio early-load trap); LHR = host-driver territory (zero ethash strings in the whole RM). |
| `campagne-rtx3070-vague3-doctrine-surete-2026-09-18.md` | 3 (Task 63) | The safety doctrine: a broken dial is volatile host RAM (zero NVRAM/flash/SPI), classes A/B/C/D, rescue ladder verified against omarchy's files, kill-switch, Xid radar. |
| `campagne-dial-gate.sh` | 3 (Task 63) | The gate: `--status` / `--rollback`, validates dials against `modinfo -p nvidia`, writes the `/root/DIAL-ROLLBACK.txt` ledger before any write. |
| `campagne-rtx3070-vague4-analyse-code-rmelf-2026-09-18.md` | 4 (Task 64) | The wall crossed: rm.elf extracted, indexed, disassembled cloud-side; first calculations decoded; the encrypted-rodata boundary mapped. |
| `campagne-rtx3070-vague42-calculs-rm-2026-09-18.md` | 4.2 (Task 65) | The RM's arithmetic: internal limit tables, encoding formats, the power tree — read directly in the RISC-V bytes. |
| `campagne-rtx3070-vague43-branches-decoulees-2026-09-18.md` | 4.3 (Task 66) | The branches unrolled: every mode of the limit dispatcher followed instruction-exact to its machine effect (P-state flags, voltage rails, conversion tables). |
| `campagne-rtx3070-vague44-capacite-vfpoint-2026-09-18.md` | 4.4 (Task 67) | The RmVFPointCheckIgnore milestone, sold: dial → parser 0x1631010 → instanciation → 5 text vtables → setter 0x1630c48 (`requestCapabilityChange`) → commit bit 0 → engine 0x1634a38 → request type 0xc. |
| `campagne-rtx3070-vague45-carte-bits-capacite-2026-09-18.md` | 4.5 (Task 69) | The capability-bit map: full-linear disassembly (5 342 005 instructions), 42 direct setter callers, bits 0-11 by module; bit 8 = `RmPerfChangeSeqOverride`; the six other CheckIgnore dials consume by NAME, not by bit. |

Read order for the machine chat: vague 1 (what to test first) → vague 3
(how to stay safe) → vague 2 (how to inject) → vague 4.x (why it works,
instruction by instruction).
