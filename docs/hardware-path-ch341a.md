# The hardware path: CH341A + SOIC clip (documented, not chosen)

The user's decision (2026-09-21): **PC-only methods** — no hardware
purchase. The CH341A path is documented for completeness and for whoever
revisits this campaign with different constraints.

## The definitive 280 W path (per the cmp170hx wiki, hardware/vbios.md)

- The SPI flash = **hardware write-protected** on stock cards
- **"There is no OS-level flash path for this board"** — no software route
- **CH341A + SOIC-8 clip = the only path that can write an edited image**
- One tester defeated the write protection and flashed within 10 minutes:
  "an obstacle rather than a wall"
- The chip: **MX25U8033E** (identified in our logs: EEPROM ID (C2,2534))

## The procedure sketch

1. The CH341A programmer (~30 €) + the SOIC-8 clip on the MX25U8033E
2. The read → verify against the stock dump (chip-before.rom)
3. The erase + program: **unlock-v2-REALCHIP** (2200 MHz + 265/280 W,
   sha256 60db5fd2…)
4. ⚠️ **The write-protect re-enabled BEFORE power-on** — the flashing
   failure `0xBADF3000` = the missing write-protect; the recovery = the
   SOIC reflash
5. The dual-BIOS switch (pos 2) = the safety net throughout
