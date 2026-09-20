# findings — the CERT20 break: end-to-end PASS on OUR firmware (610.57.04)

Date: 2026-09-20. Source: the cmpunlocker research platform (d3dx9/cmpunlocker,
the published Falcon-BootROM .fwsignature load exploit, technique from Jon's Zenodo paper).

## Result

```
2026-09-20 17:03:31,315 INFO   DMEM[0x400de00..0x400de78]: 120 bytes of frames (5 x 24)
2026-09-20 17:03:31,315 INFO   PC=0x5000100, SP=0x400de00, HS=ON
2026-09-20 17:03:31,319 WARNING halted: step limit 5000 hit at PC=0x5000128
2026-09-20 17:03:31,319 INFO Exploit run complete:
2026-09-20 17:03:31,319 INFO   steps: 5001
2026-09-20 17:03:31,319 INFO   halted: True
2026-09-20 17:03:31,319 INFO   halt reason: step limit 5000 hit at PC=0x5000128
2026-09-20 17:03:31,319 INFO   final PC: 0x5000128
2026-09-20 17:03:31,319 INFO   BAR0 writes: 5 total
2026-09-20 17:03:31,320 INFO ======================================================================
2026-09-20 17:03:31,320 INFO PHASE 3: COMPARISON REPORT
2026-09-20 17:03:31,320 INFO ======================================================================
2026-09-20 17:03:31,320 INFO 
2026-09-20 17:03:31,320 INFO All BAR0 writes (in order of execution):
2026-09-20 17:03:31,320 INFO   FWSEC    0x110001 <- 0x00000002  (PC=0x4005044)
2026-09-20 17:03:31,320 INFO   FWSEC    0x110001 <- 0x00000003  (PC=0x4005080)
2026-09-20 17:03:31,320 INFO   FWSEC    0x110600 <- 0x00000007  (PC=0x40050a8)
2026-09-20 17:03:31,320 INFO   FWSEC    0x110001 <- 0x00000008  (PC=0x40050dc)
2026-09-20 17:03:31,320 INFO   FWSEC    0x110200 <- 0x00000008  (PC=0x40057f8)
2026-09-20 17:03:31,320 INFO   FWSEC    0x000043 <- 0x00000000  (PC=0x400c00c)
2026-09-20 17:03:31,320 INFO   FWSEC    0x000047 <- 0x00000000  (PC=0x400c014)
2026-09-20 17:03:31,320 INFO   FWSEC    0x000097 <- 0x0011dead  (PC=0x400c01c)
2026-09-20 17:03:31,320 INFO   FWSEC    0x000003 <- 0x00000010  (PC=0x400c024)
2026-09-20 17:03:31,320 INFO   FWSEC    0x000043 <- 0x00000200  (PC=0x400c3e4)
2026-09-20 17:03:31,320 INFO   FWSEC    0x000003 <- 0x00000010  (PC=0x400c3f0)
2026-09-20 17:03:31,320 INFO   EXPLOIT  0x9a0204 <- 0x02669000  (PC=0x5000104)
2026-09-20 17:03:31,320 INFO   EXPLOIT  0x100ce0 <- 0x0000028a  (PC=0x500010c)
2026-09-20 17:03:31,320 INFO   EXPLOIT  0x1fa824 <- 0x1ffffe00  (PC=0x5000114)
2026-09-20 17:03:31,320 INFO   EXPLOIT  0x1fa828 <- 0x00000000  (PC=0x500011c)
2026-09-20 17:03:31,320 INFO   EXPLOIT  0x8403c4 <- 0x000000ff  (PC=0x5000124)
2026-09-20 17:03:31,320 INFO 
2026-09-20 17:03:31,320 INFO Verification of community-verified expected writes:
2026-09-20 17:03:31,320 INFO   [OK] 0x9a0204 <- 0x02669000  (got 0x02669000)  CFG1 (geometry: 40GB or 80GB)
2026-09-20 17:03:31,320 INFO   [OK] 0x100ce0 <- 0x0000028a  (got 0x0000028a)  LMR (memory rank config)
2026-09-20 17:03:31,320 INFO   [OK] 0x1fa824 <- 0x1ffffe00  (got 0x1ffffe00)  WPR2 low (teardown)
2026-09-20 17:03:31,320 INFO   [OK] 0x1fa828 <- 0x00000000  (got 0x00000000)  WPR2 high (teardown)
2026-09-20 17:03:31,320 INFO   [OK] 0x8403c4 <- 0x000000ff  (got 0x000000ff)  resetPLM (open access)
2026-09-20 17:03:31,320 INFO 
2026-09-20 17:03:31,320 INFO ======================================================================
2026-09-20 17:03:31,320 INFO OVERALL: PASS
2026-09-20 17:03:31,320 INFO   Total BAR0 writes: 16
2026-09-20 17:03:31,320 INFO   FWSEC writes:    11
2026-09-20 17:03:31,320 INFO   Exploit writes:  5
2026-09-20 17:03:31,320 INFO   Unique addresses: 12
2026-09-20 17:03:31,320 INFO ======================================================================
```

## Meaning

1. OUR gsp_tu10x.bin (610.57.04) runs through the published exploit chain
2. The mpopaddret ROP mechanism + HS mode + HMAC bypass (CSR 0x7da) are
   architecturally identical on our firmware
3. The 5 community-verified unlock writes execute without deviation
4. Remaining for the RTX 3070 (GA104): identify the power-limit (EDPp)
   register space + its PLM, adapt the chain (the mechanism is validated);
   the executed writes = the GA100/CMP memory-geometry values (HBM) —
   OUR target = the power limit (250->280 W), NOT the memory geometry
