# AGENTS.md — how AI agents operate in this repository

This repo is agent-first, in the spirit of its sibling
[BIOS-](https://github.com/Cheurteenyt/BIOS-). If you are an AI agent
working **in this codebase** or **through its instruments**, this file is
your contract.

## 0. The three laws

1. **Work from evidence.** Never reason from a guessed platform: the ROM
   comes from a register (sha256, provenance URL), the card identity from
   lspci/DMI/sysfs, every grammar from an imported source file cited in
   the instrument's docstring. A grammar written from memory is a defect
   — this lab has paid for that lesson twice and banked it in comments.
2. **The card is never written.** No `nvflash`/`flashrom` write, no GPU
   reset, no driver reload, no config-register change without an explicit
   restore path — and even then only with the human typing the sudo.
   Reads (sysfs rom, page-context fetches, passive BAR windows) are the
   only gestures. Flashing is not a call path; it does not exist here.
3. **Leave no trace.** Every mutating gesture (a BAR assignment, a kernel
   param) has its documented restore; the running machine keeps working
   while the lab runs.

## 1. Repo layout

```
lab/          the instruments (gx1..gx8) + their JSON registers + findings-gxN.md
acquisitions/ REGISTER.json (provenance, published-hash verification) — no ROMs
day0/         the live-card protocol, register and findings
imports/      vendored grammar sources (kernel .c files, the ImHex pattern)
tools/        read-rom-bar.py (+ gitignored binaries, hash-documented)
```

## 2. Instrument discipline

- One ring = one instrument = one register = one findings file, in the
  `gxN-*.py` / `gxN-*-register.json` / `findings-gxN.md` naming.
- Every grammar import cites its source **file and lines** in the
  docstring; decoders are verbatim transcriptions, and a wrong
  transcription is corrected by the source with a comment naming the
  lesson (see `gx2-bit.py`'s memory tables).
- Every register is frozen once scored: the selftest re-derives the
  anchors live and exits 2 on drift. Frozen registers are never rewritten;
  corrections land as new rings that *name* the old verdict's correction
  (the sibling lab's taxonomy: refused > beyond-register > swap-event >
  clean).
- New measurements go through the pointer rule and the admission gates;
  unresolved offsets are reported as unresolved, never guessed.

## 3. Before any push

```bash
python3 lab/gx1-anatomy.py selftest && python3 lab/gx2-bit.py selftest && \
python3 lab/gx3-perf.py selftest && python3 lab/gx4-clocks.py selftest && \
python3 lab/gx5-timings.py selftest && python3 lab/gx6-fan.py selftest && \
python3 lab/gx7-identity.py selftest && python3 lab/gx8-named.py selftest
```

All eight must print `0 failure(s)`. Without the ROM corpus the tier-I
gates degrade loudly — that is acceptable in CI, never in a finding.

## 4. Reports

- **Proven** (offsets, hashes, gate transcripts) / **inferred** (labelled
  as such, with the correlation stated) / **unknown** (registered as an
  open question). Never assemble confidence out of assumptions.
- New claims land with the measurement that falsifies them. A prediction
  made after a measurement is labelled as such.
