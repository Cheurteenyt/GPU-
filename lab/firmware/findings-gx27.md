# findings-gx27 — the GSP bootloader is now readable (RE tooling established)

Date: 2026-09-17. Subject: the "extremely complicated" track — making the
GSP bootloader disassemblable and locating its structure.

## The tooling breakthrough (reusable pipeline)

Disassembling the bootloader required defeating three layers of tooling
resistance; the working recipe is saved in
`tools/gsp-extract/` (`bootloader.elf`, `bootloader.asm`):

1. Wrap the raw RISC-V blob (fwimage 0x0-0x6d000, 446,464 B) into a
   minimal ELF64: e_machine=243 (RISC-V), e_type=EXEC, one PT_LOAD
   (RX) mapping file offset 0x78 → VA 0x100000 (the code sits after the
   64-byte EHDR + 56-byte PHDR in the wrapper).
2. **e_flags MUST carry the RVC bit (0x1)** — without it llvm-objdump
   renders every compressed instruction as `<unknown>`; the triple is
   `riscv64-unknown-elf` (`riscv64gc` does not resolve in this build).
3. Result: 5,370 instructions, 120 `<unknown>` (data words/custom ops).

## Structure found

- `0x10001c: auipc a4, 0x6d` → **a4 = 0x16d000, the section directory**
  (fw offset 0x6d000) — the parser entry is confirmed, then `j 0x101e0a`.
- `0x100be2-0x100c44`: a **width-dispatch table** (lh/lhu/lb/lbu/sd store
  cascades) — the section loader's access-width handling, not yet the LZ
  inner loop.
- The bindata stream itself has **no plaintext framing** (the 0x12d0270
  region is pure zero padding); the framing is coded, so the bootloader
  disassembly is the only road — confirmed ring 27 work.

## Next (ring 28, fresh session)

- Walk the directory parser from 0x101e0a: the record walk will reveal
  which descriptor field selects the LZ (type tags 5/6 seen; bindata
  entries likely carry their own tag).
- Map the copy loop beyond the width dispatcher; extract the LZ alphabet
  and window semantics; write the Python decompressor; verify against
  `rm.elf`'s known ELF header as the first decoded output.
- Payoff unchanged: the SES/SPI engine code and the RM's power heuristics
  — the last black box on the card.

## Sober note

This is a multi-session RE task by design (a proprietary LZ inside a
signed bootloader). The mod pipeline (ring 26) does not depend on it —
the power/vP-state tables live in the clear region of the ROM. The LZ is
the deep-knowledge track: worth it, scheduled, not blocking.
