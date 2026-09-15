# GPU day-0 acquisition kit — the ring-0 gestures (read-only)

Object of study: the live MSI RTX 3070 LHR (GA104). The card is read on a
declared gesture only, and the running machine's card is never written —
the lab's +0-octet rule, GPU edition.

## Identity (measured 2026-09-15, no root)

| Field | Value | Source |
|---|---|---|
| Chip | GA104 [GeForce RTX 3070 Lite Hash Rate], rev a1 | lspci |
| PCI ID | `10de:2488` | lspci |
| Subsystem | MSI `1462:3904` — a shared MSI subsystem ID; it does not name the retail board model | lspci + TechPowerUp DB |
| VBIOS | `94.04.46.00.EB` | nvidia-smi |
| Driver | KMD 610.57.04 | nvidia-smi |
| PCIe link | 16x current / 16x max (nvidia-smi); full caps need root | lspci "access denied" |
| Power limits | current **250 W** / default **240 W** / max 250 W — a written state | nvidia-smi |
| Runtime snapshot | `day0/runtime-snapshot.txt` | nvidia-smi -q + lspci |

## Gesture 1 — the VBIOS dump (read-only, root)

```bash
cd "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab"
sudo sh -c 'echo 1 > /sys/bus/pci/devices/0000:07:00.0/rom'
sudo cat /sys/bus/pci/devices/0000:07:00.0/rom > day0/vbios-94.04.46.00.EB.rom
sudo sh -c 'echo 0 > /sys/bus/pci/devices/0000:07:00.0/rom'
sha256sum day0/vbios-94.04.46.00.EB.rom
```

Admission gates (the dump only enters the register if):

1. `strings day0/vbios-*.rom | grep -m1 "94.04.46"` finds the version;
2. the sha256 is stable across a second read (re-run, compare);
3. size is a sane Option-ROM size (multiple of 512 B, 64 KiB–1 MiB).

Alternative capture: `nvflash --save` — read-only. **Never** `nvflash` in
write mode, never `flashrom` write against the live card.

## Gesture 2 — the root x-ray (same sudo session, still read-only)

```bash
sudo lspci -vv -s 07:00.0            # LnkSta (Gen), Resizable BAR, full BAR sizes
sudo dmesg | grep -iE "rebar|resize" # kernel-side ReBAR engagement (the ring-49 chain, GPU edition)
```

## Register (the vendor-acquisition equivalent, to fill after the dump)

`sha256` full + `sha256_16`, size, version-string offset, capture date,
capture method, admission-gate transcript.

## The three reference repos (cloned beside this lab)

| Repo | What it gives the GPU lane |
|---|---|
| `nvidia-bios-reader` | prior art read-only parser; GA104 in its regression set (memory entries, timing maps, RAMCFG straps) |
| `open-gpu-doc` | spec-fresh grammar anchors: BIOS-Information-Table, MemoryClockTable, virtual-p-state-table, Devinit |
| `cmp170hx` | the synthesis model (methodology, register reference, honesty markers); GSP-RM = the GA10x deep layer, the PSP of this story |

## Never (the +0-octet rule, GPU edition)

No nvflash/flashrom writes, no GPU resets, no driver reloads — those are
human gestures, typed by the human, on the human's word.
