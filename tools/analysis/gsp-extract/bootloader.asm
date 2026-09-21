
bootloader.elf:	file format elf64-littleriscv

Disassembly of section PT_LOAD#0:

0000000000100000 <PT_LOAD#0>:
  100000: 0006c297     	auipc	t0, 0x6c
  100004: 08028293     	addi	t0, t0, 0x80
  100008: 00028283     	lb	t0, 0x0(t0)
  10000c: 00028463     	beqz	t0, 0x100014 <PT_LOAD#0+0x14>
  100010: 4c60006f     	j	0x1004d6 <PT_LOAD#0+0x4d6>
  100014: 00020117     	auipc	sp, 0x20
  100018: fec10113     	addi	sp, sp, -0x14
  10001c: 0006d717     	auipc	a4, 0x6d
  100020: fe470713     	addi	a4, a4, -0x1c
  100024: 5e70106f     	j	0x101e0a <PT_LOAD#0+0x1e0a>
  100028: 87aa         	mv	a5, a0
  10002a: 4501         	li	a0, 0x0
  10002c: c19d         	beqz	a1, 0x100052 <PT_LOAD#0+0x52>
  10002e: c295         	beqz	a3, 0x100052 <PT_LOAD#0+0x52>
  100030: 00f58833     	add	a6, a1, a5
  100034: 4505         	li	a0, 0x1
  100036: 00b86e63     	bltu	a6, a1, 0x100052 <PT_LOAD#0+0x52>
  10003a: 00c68733     	add	a4, a3, a2
  10003e: 00d76a63     	bltu	a4, a3, 0x100052 <PT_LOAD#0+0x52>
  100042: 00c7f563     	bgeu	a5, a2, 0x10004c <PT_LOAD#0+0x4c>
  100046: 4501         	li	a0, 0x0
  100048: 01067563     	bgeu	a2, a6, 0x100052 <PT_LOAD#0+0x52>
  10004c: 00e7b533     	sltu	a0, a5, a4
  100050: 8082         	ret
  100052: 8082         	ret
  100054: 4785         	li	a5, 0x1
  100056: 00f51a63     	bne	a0, a5, 0x10006a <PT_LOAD#0+0x6a>
  10005a: 0035d51b     	srliw	a0, a1, 0x3
  10005e: 8905         	andi	a0, a0, 0x1
  100060: 00154513     	xori	a0, a0, 0x1
  100064: 0ff57513     	zext.b	a0, a0
  100068: 8082         	ret
  10006a: 4501         	li	a0, 0x0
  10006c: bfe5         	j	0x100064 <PT_LOAD#0+0x64>
  10006e: 00053803     	ld	a6, 0x0(a0)
  100072: 00004797     	auipc	a5, 0x4
  100076: ec67b783     	ld	a5, -0x13a(a5)
  10007a: 00f81663     	bne	a6, a5, 0x100086 <PT_LOAD#0+0x86>
  10007e: 651c         	ld	a5, 0x8(a0)
  100080: 4301         	li	t1, 0x0
  100082: 97aa         	add	a5, a5, a0
  100084: e399         	bnez	a5, 0x10008a <PT_LOAD#0+0x8a>
  100086: 4501         	li	a0, 0x0
  100088: 8082         	ret
  10008a: 0007b803     	ld	a6, 0x0(a5)
  10008e: 88ae         	mv	a7, a1
  100090: 982a         	add	a6, a6, a0
  100092: 40b80833     	sub	a6, a6, a1
  100096: 0008ce83     	lbu	t4, 0x0(a7)
  10009a: 01088e33     	add	t3, a7, a6
  10009e: 000e4e03     	lbu	t3, 0x0(t3)
  1000a2: 000e8b63     	beqz	t4, 0x1000b8 <PT_LOAD#0+0xb8>
  1000a6: 01de0763     	beq	t3, t4, 0x1000b4 <PT_LOAD#0+0xb4>
  1000aa: 6b9c         	ld	a5, 0x10(a5)
  1000ac: 0305         	addi	t1, t1, 0x1
  1000ae: dfe1         	beqz	a5, 0x100086 <PT_LOAD#0+0x86>
  1000b0: 97aa         	add	a5, a5, a0
  1000b2: bfc9         	j	0x100084 <PT_LOAD#0+0x84>
  1000b4: 0885         	addi	a7, a7, 0x1
  1000b6: b7c5         	j	0x100096 <PT_LOAD#0+0x96>
  1000b8: fe0e19e3     	bnez	t3, 0x1000aa <PT_LOAD#0+0xaa>
  1000bc: c219         	beqz	a2, 0x1000c2 <PT_LOAD#0+0xc2>
  1000be: 00663023     	sd	t1, 0x0(a2)
  1000c2: c311         	beqz	a4, 0x1000c6 <PT_LOAD#0+0xc6>
  1000c4: e31c         	sd	a5, 0x0(a4)
  1000c6: ca89         	beqz	a3, 0x1000d8 <PT_LOAD#0+0xd8>
  1000c8: 679c         	ld	a5, 0x8(a5)
  1000ca: cb89         	beqz	a5, 0x1000dc <PT_LOAD#0+0xdc>
  1000cc: 97aa         	add	a5, a5, a0
  1000ce: 6f98         	ld	a4, 0x18(a5)
  1000d0: 739c         	ld	a5, 0x20(a5)
  1000d2: 972a         	add	a4, a4, a0
  1000d4: e298         	sd	a4, 0x0(a3)
  1000d6: e69c         	sd	a5, 0x8(a3)
  1000d8: 4505         	li	a0, 0x1
  1000da: 8082         	ret
  1000dc: 01803783     	ld	a5, 0x18(zero)
  1000e0: 9002         	ebreak
  1000e2: 00004517     	auipc	a0, 0x4
  1000e6: a5650513     	addi	a0, a0, -0x5aa
  1000ea: 8082         	ret
  1000ec: 28053683     	ld	a3, 0x280(a0)
  1000f0: c6c9         	beqz	a3, 0x10017a <PT_LOAD#0+0x17a>
  1000f2: 4701         	li	a4, 0x0
  1000f4: 4601         	li	a2, 0x0
  1000f6: 5d071073     	csrw	0x5d0, a4
  1000fa: 5d161073     	csrw	0x5d1, a2
  1000fe: 0017079b     	addiw	a5, a4, 0x1
  100102: 0007871b     	sext.w	a4, a5
  100106: 1782         	slli	a5, a5, 0x20
  100108: 9381         	srli	a5, a5, 0x20
  10010a: fed7e6e3     	bltu	a5, a3, 0x1000f6 <PT_LOAD#0+0xf6>
  10010e: 00080637     	lui	a2, 0x80
  100112: 000c05b7     	lui	a1, 0xc0
  100116: 4701         	li	a4, 0x0
  100118: 03f60613     	addi	a2, a2, 0x3f
  10011c: 03f58593     	addi	a1, a1, 0x3f
  100120: 1f000337     	lui	t1, 0x1f000
  100124: 4885         	li	a7, 0x1
  100126: 5ca71073     	csrw	0x5ca, a4
  10012a: 611c         	ld	a5, 0x0(a0)
  10012c: 5cc79073     	csrw	0x5cc, a5
  100130: 651c         	ld	a5, 0x8(a0)
  100132: 5cb79073     	csrw	0x5cb, a5
  100136: 691c         	ld	a5, 0x10(a0)
  100138: 5ce79073     	csrw	0x5ce, a5
  10013c: 02054783     	lbu	a5, 0x20(a0)
  100140: 8832         	mv	a6, a2
  100142: c391         	beqz	a5, 0x100146 <PT_LOAD#0+0x146>
  100144: 882e         	mv	a6, a1
  100146: 6d1c         	ld	a5, 0x18(a0)
  100148: 07e2         	slli	a5, a5, 0x18
  10014a: 0067f7b3     	and	a5, a5, t1
  10014e: 0107e7b3     	or	a5, a5, a6
  100152: 5cf79073     	csrw	0x5cf, a5
  100156: 5cb8a073     	csrs	0x5cb, a7
  10015a: 0705         	addi	a4, a4, 0x1
  10015c: 02850513     	addi	a0, a0, 0x28
  100160: fce693e3     	bne	a3, a4, 0x100126 <PT_LOAD#0+0x126>
  100164: 57fd         	li	a5, -0x1
  100166: 17f2         	slli	a5, a5, 0x3c
  100168: 18079073     	csrw	satp, a5
  10016c: 12000073     	sfence.vma
  100170: 0000100f     	fence.i
  100174: 4781         	li	a5, 0x0
  100176: 8d079073     	csrw	0x8d0, a5
  10017a: 8082         	ret
  10017c: 00004517     	auipc	a0, 0x4
  100180: 9d450513     	addi	a0, a0, -0x62c
  100184: 8082         	ret
  100186: 00004517     	auipc	a0, 0x4
  10018a: 9e250513     	addi	a0, a0, -0x61e
  10018e: 8082         	ret
  100190: 00004517     	auipc	a0, 0x4
  100194: 9f050513     	addi	a0, a0, -0x610
  100198: 8082         	ret
  10019a: 00004517     	auipc	a0, 0x4
  10019e: 9fe50513     	addi	a0, a0, -0x602
  1001a2: 8082         	ret
  1001a4: 7108         	ld	a0, 0x20(a0)
  1001a6: fff54513     	not	a0, a0
  1001aa: 8905         	andi	a0, a0, 0x1
  1001ac: 0536         	slli	a0, a0, 0xd
  1001ae: 8082         	ret
  1001b0: 00000317     	auipc	t1, 0x0
  1001b4: ff430067     	jr	-0xc(t1) <PT_LOAD#0+0x1a4>
  1001b8: 00000317     	auipc	t1, 0x0
  1001bc: fec30067     	jr	-0x14(t1) <PT_LOAD#0+0x1a4>
  1001c0: 00004517     	auipc	a0, 0x4
  1001c4: 9f050513     	addi	a0, a0, -0x610
  1001c8: 8082         	ret
  1001ca: 8082         	ret
  1001cc: 8082         	ret
  1001ce: 1569         	addi	a0, a0, -0x6
  1001d0: 00153513     	seqz	a0, a0
  1001d4: 8082         	ret
  1001d6: 4785         	li	a5, 0x1
  1001d8: 00f51663     	bne	a0, a5, 0x1001e4 <PT_LOAD#0+0x1e4>
  1001dc: 0035d51b     	srliw	a0, a1, 0x3
  1001e0: 8905         	andi	a0, a0, 0x1
  1001e2: 8082         	ret
  1001e4: 4501         	li	a0, 0x0
  1001e6: 8082         	ret
  1001e8: 7139         	addi	sp, sp, -0x40
  1001ea: f822         	sd	s0, 0x30(sp)
  1001ec: f426         	sd	s1, 0x28(sp)
  1001ee: f04a         	sd	s2, 0x20(sp)
  1001f0: ec4e         	sd	s3, 0x18(sp)
  1001f2: e852         	sd	s4, 0x10(sp)
  1001f4: e456         	sd	s5, 0x8(sp)
  1001f6: fc06         	sd	ra, 0x38(sp)
  1001f8: 84aa         	mv	s1, a0
  1001fa: 8a2e         	mv	s4, a1
  1001fc: 89b2         	mv	s3, a2
  1001fe: 00063023     	sd	zero, 0x0(a2)
  100202: 13050913     	addi	s2, a0, 0x130
  100206: 4401         	li	s0, 0x0
  100208: 4ac1         	li	s5, 0x10
  10020a: 00194583     	lbu	a1, 0x1(s2)
  10020e: 00094503     	lbu	a0, 0x0(s2)
  100212: 9a02         	jalr	s4
  100214: c505         	beqz	a0, 0x10023c <PT_LOAD#0+0x23c>
  100216: 1402         	slli	s0, s0, 0x20
  100218: 9001         	srli	s0, s0, 0x20
  10021a: 47e1         	li	a5, 0x18
  10021c: 02f40433     	<unknown>
  100220: 12040413     	addi	s0, s0, 0x120
  100224: 94a2         	add	s1, s1, s0
  100226: 0099b023     	sd	s1, 0x0(s3)
  10022a: 70e2         	ld	ra, 0x38(sp)
  10022c: 7442         	ld	s0, 0x30(sp)
  10022e: 74a2         	ld	s1, 0x28(sp)
  100230: 7902         	ld	s2, 0x20(sp)
  100232: 69e2         	ld	s3, 0x18(sp)
  100234: 6a42         	ld	s4, 0x10(sp)
  100236: 6aa2         	ld	s5, 0x8(sp)
  100238: 6121         	addi	sp, sp, 0x40
  10023a: 8082         	ret
  10023c: 2405         	addiw	s0, s0, 0x1
  10023e: 0961         	addi	s2, s2, 0x18
  100240: fd5415e3     	bne	s0, s5, 0x10020a <PT_LOAD#0+0x20a>
  100244: b7dd         	j	0x10022a <PT_LOAD#0+0x22a>
  100246: 00004797     	auipc	a5, 0x4
  10024a: cfa7b783     	ld	a5, -0x306(a5)
  10024e: 4388         	lw	a0, 0x0(a5)
  100250: 0045551b     	srliw	a0, a0, 0x4
  100254: 0532         	slli	a0, a0, 0xc
  100256: 8082         	ret
  100258: 1141         	addi	sp, sp, -0x10
  10025a: e022         	sd	s0, 0x0(sp)
  10025c: e406         	sd	ra, 0x8(sp)
  10025e: 09400793     	li	a5, 0x94
  100262: e11c         	sd	a5, 0x0(a0)
  100264: 04000793     	li	a5, 0x40
  100268: e51c         	sd	a5, 0x8(a0)
  10026a: 04400793     	li	a5, 0x44
  10026e: e91c         	sd	a5, 0x10(a0)
  100270: 47c1         	li	a5, 0x10
  100272: f91c         	sd	a5, 0x30(a0)
  100274: 000807b7     	lui	a5, 0x80
  100278: e13c         	sd	a5, 0x40(a0)
  10027a: 30300793     	li	a5, 0x303
  10027e: 17d6         	slli	a5, a5, 0x35
  100280: e53c         	sd	a5, 0x48(a0)
  100282: c0300693     	li	a3, -0x3fd
  100286: 4785         	li	a5, 0x1
  100288: 01280737     	lui	a4, 0x1280
  10028c: 17d6         	slli	a5, a5, 0x35
  10028e: 16d6         	slli	a3, a3, 0x35
  100290: fd18         	sd	a4, 0x38(a0)
  100292: e93c         	sd	a5, 0x50(a0)
  100294: ed34         	sd	a3, 0x58(a0)
  100296: f13c         	sd	a5, 0x60(a0)
  100298: 00053c23     	sd	zero, 0x18(a0)
  10029c: f530         	sd	a2, 0x68(a0)
  10029e: 04072023     	sw	zero, 0x40(a4)
  1002a2: 04072223     	sw	zero, 0x44(a4)
  1002a6: 842a         	mv	s0, a0
  1002a8: 07050793     	addi	a5, a0, 0x70
  1002ac: 08050713     	addi	a4, a0, 0x80
  1002b0: 56fd         	li	a3, -0x1
  1002b2: 00d78023     	sb	a3, 0x0(a5)
  1002b6: 0785         	addi	a5, a5, 0x1
  1002b8: fee79de3     	bne	a5, a4, 0x1002b2 <PT_LOAD#0+0x2b2>
  1002bc: 10000793     	li	a5, 0x100
  1002c0: 06f41823     	sh	a5, 0x70(s0)
  1002c4: 4789         	li	a5, 0x2
  1002c6: 06f40923     	sb	a5, 0x72(s0)
  1002ca: 4785         	li	a5, 0x1
  1002cc: 17f6         	slli	a5, a5, 0x3d
  1002ce: f05c         	sd	a5, 0xa0(s0)
  1002d0: 040007b7     	lui	a5, 0x4000
  1002d4: f45c         	sd	a5, 0xa8(s0)
  1002d6: 001807b7     	lui	a5, 0x180
  1002da: f85c         	sd	a5, 0xb0(s0)
  1002dc: 000807b7     	lui	a5, 0x80
  1002e0: fc5c         	sd	a5, 0xb8(s0)
  1002e2: e47c         	sd	a5, 0xc8(s0)
  1002e4: 001047b7     	lui	a5, 0x104
  1002e8: 01200737     	lui	a4, 0x1200
  1002ec: 10f43023     	sd	a5, 0x100(s0)
  1002f0: 67c9         	lui	a5, 0x12
  1002f2: e078         	sd	a4, 0xc0(s0)
  1002f4: 10f43423     	sd	a5, 0x108(s0)
  1002f8: 08043423     	sd	zero, 0x88(s0)
  1002fc: 08043823     	sd	zero, 0x90(s0)
  100300: 08043c23     	sd	zero, 0x98(s0)
  100304: 0c043823     	sd	zero, 0xd0(s0)
  100308: 0c043c23     	sd	zero, 0xd8(s0)
  10030c: 10043c23     	sd	zero, 0x118(s0)
  100310: 0006c717     	auipc	a4, 0x6c
  100314: d7174703     	lbu	a4, -0x28f(a4)
  100318: 001827b7     	lui	a5, 0x182
  10031c: c319         	beqz	a4, 0x100322 <PT_LOAD#0+0x322>
  10031e: 001847b7     	lui	a5, 0x184
  100322: 6705         	lui	a4, 0x1
  100324: 14f43023     	sd	a5, 0x140(s0)
  100328: 14e43423     	sd	a4, 0x148(s0)
  10032c: 97ba         	add	a5, a5, a4
  10032e: 00190737     	lui	a4, 0x190
  100332: 12f43023     	sd	a5, 0x120(s0)
  100336: 40f707b3     	sub	a5, a4, a5
  10033a: 12f43423     	sd	a5, 0x128(s0)
  10033e: 00000097     	auipc	ra, 0x0
  100342: f08080e7     	jalr	-0xf8(ra) <PT_LOAD#0+0x246>
  100346: 14a43c23     	sd	a0, 0x158(s0)
  10034a: 00a03533     	snez	a0, a0
  10034e: 60a2         	ld	ra, 0x8(sp)
  100350: 16a42023     	sw	a0, 0x160(s0)
  100354: 6402         	ld	s0, 0x0(sp)
  100356: 0141         	addi	sp, sp, 0x10
  100358: 8082         	ret
  10035a: 8082         	ret
  10035c: 00004797     	auipc	a5, 0x4
  100360: bec7b783     	ld	a5, -0x414(a5)
  100364: 439c         	lw	a5, 0x0(a5)
  100366: 00020537     	lui	a0, 0x20
  10036a: 157d         	addi	a0, a0, -0x1
  10036c: 0047d79b     	srliw	a5, a5, 0x4
  100370: 07b2         	slli	a5, a5, 0xc
  100372: 953e         	add	a0, a0, a5
  100374: 8082         	ret
  100376: 1101         	addi	sp, sp, -0x20
  100378: ec06         	sd	ra, 0x18(sp)
  10037a: e822         	sd	s0, 0x10(sp)
  10037c: e426         	sd	s1, 0x8(sp)
  10037e: 842a         	mv	s0, a0
  100380: 00000097     	auipc	ra, 0x0
  100384: ec6080e7     	jalr	-0x13a(ra) <PT_LOAD#0+0x246>
  100388: 84aa         	mv	s1, a0
  10038a: 00000097     	auipc	ra, 0x0
  10038e: fd2080e7     	jalr	-0x2e(ra) <PT_LOAD#0+0x35c>
  100392: 47f5         	li	a5, 0x1d
  100394: 17ea         	slli	a5, a5, 0x3a
  100396: 97a6         	add	a5, a5, s1
  100398: e01c         	sd	a5, 0x0(s0)
  10039a: e41c         	sd	a5, 0x8(s0)
  10039c: 6785         	lui	a5, 0x1
  10039e: 17fd         	addi	a5, a5, -0x1
  1003a0: 953e         	add	a0, a0, a5
  1003a2: 8d05         	sub	a0, a0, s1
  1003a4: 77fd         	lui	a5, 0xfffff
  1003a6: 8d7d         	and	a0, a0, a5
  1003a8: 4785         	li	a5, 0x1
  1003aa: 02f40023     	sb	a5, 0x20(s0)
  1003ae: 04040423     	sb	zero, 0x48(s0)
  1003b2: 4709         	li	a4, 0x2
  1003b4: c0000793     	li	a5, -0x400
  1003b8: 60e2         	ld	ra, 0x18(sp)
  1003ba: 28e43023     	sd	a4, 0x280(s0)
  1003be: e808         	sd	a0, 0x10(s0)
  1003c0: ec18         	sd	a4, 0x18(s0)
  1003c2: 02043423     	sd	zero, 0x28(s0)
  1003c6: 02043823     	sd	zero, 0x30(s0)
  1003ca: fc1c         	sd	a5, 0x38(s0)
  1003cc: 04043023     	sd	zero, 0x40(s0)
  1003d0: 6442         	ld	s0, 0x10(sp)
  1003d2: 64a2         	ld	s1, 0x8(sp)
  1003d4: 6105         	addi	sp, sp, 0x20
  1003d6: 8082         	ret
  1003d8: 00003517     	auipc	a0, 0x3
  1003dc: 7f050513     	addi	a0, a0, 0x7f0
  1003e0: 8082         	ret
  1003e2: 6509         	lui	a0, 0x2
  1003e4: 8082         	ret
  1003e6: 61dc         	ld	a5, 0x80(a1)
  1003e8: 8b85         	andi	a5, a5, 0x1
  1003ea: e7ad         	bnez	a5, 0x100454 <PT_LOAD#0+0x454>
  1003ec: 1101         	addi	sp, sp, -0x20
  1003ee: ec06         	sd	ra, 0x18(sp)
  1003f0: e822         	sd	s0, 0x10(sp)
  1003f2: e426         	sd	s1, 0x8(sp)
  1003f4: e04a         	sd	s2, 0x0(sp)
  1003f6: 4909         	li	s2, 0x2
  1003f8: 29253023     	sd	s2, 0x280(a0)
  1003fc: 842a         	mv	s0, a0
  1003fe: 00000097     	auipc	ra, 0x0
  100402: e48080e7     	jalr	-0x1b8(ra) <PT_LOAD#0+0x246>
  100406: 5795         	li	a5, -0x1b
  100408: 17ea         	slli	a5, a5, 0x3a
  10040a: 953e         	add	a0, a0, a5
  10040c: e008         	sd	a0, 0x0(s0)
  10040e: e408         	sd	a0, 0x8(s0)
  100410: 00000097     	auipc	ra, 0x0
  100414: f4c080e7     	jalr	-0xb4(ra) <PT_LOAD#0+0x35c>
  100418: 84aa         	mv	s1, a0
  10041a: 00000097     	auipc	ra, 0x0
  10041e: e2c080e7     	jalr	-0x1d4(ra) <PT_LOAD#0+0x246>
  100422: 4785         	li	a5, 0x1
  100424: 0485         	addi	s1, s1, 0x1
  100426: 02f40023     	sb	a5, 0x20(s0)
  10042a: 04040423     	sb	zero, 0x48(s0)
  10042e: 8c89         	sub	s1, s1, a0
  100430: c0000793     	li	a5, -0x400
  100434: e804         	sd	s1, 0x10(s0)
  100436: 01243c23     	sd	s2, 0x18(s0)
  10043a: 60e2         	ld	ra, 0x18(sp)
  10043c: 02043423     	sd	zero, 0x28(s0)
  100440: 02043823     	sd	zero, 0x30(s0)
  100444: fc1c         	sd	a5, 0x38(s0)
  100446: 04043023     	sd	zero, 0x40(s0)
  10044a: 6442         	ld	s0, 0x10(sp)
  10044c: 64a2         	ld	s1, 0x8(sp)
  10044e: 6902         	ld	s2, 0x0(sp)
  100450: 6105         	addi	sp, sp, 0x20
  100452: 8082         	ret
  100454: 8082         	ret
  100456: 6509         	lui	a0, 0x2
  100458: 8082         	ret
  10045a: 6509         	lui	a0, 0x2
  10045c: 8082         	ret
  10045e: 1101         	addi	sp, sp, -0x20
  100460: e822         	sd	s0, 0x10(sp)
  100462: e426         	sd	s1, 0x8(sp)
  100464: 842e         	mv	s0, a1
  100466: 84aa         	mv	s1, a0
  100468: 4305         	li	t1, 0x1
  10046a: 090008b7     	lui	a7, 0x9000
  10046e: 6188         	ld	a0, 0x0(a1)
  100470: 6810         	ld	a2, 0x10(s0)
  100472: 658c         	ld	a1, 0x8(a1)
  100474: 6c14         	ld	a3, 0x18(s0)
  100476: 7018         	ld	a4, 0x20(s0)
  100478: ec06         	sd	ra, 0x18(sp)
  10047a: 87a6         	mv	a5, s1
  10047c: 4801         	li	a6, 0x0
  10047e: 1eb88893     	addi	a7, a7, 0x1eb
  100482: 0006ce17     	auipc	t3, 0x6c
  100486: be6e0f23     	sb	t1, -0x402(t3)
  10048a: 00024197     	auipc	gp, 0x24
  10048e: 22618193     	addi	gp, gp, 0x226
  100492: 0481b023     	sd	s0, 0x40(gp)
  100496: 0491b423     	sd	s1, 0x48(gp)
  10049a: 0921b823     	sd	s2, 0x90(gp)
  10049e: 0931bc23     	sd	s3, 0x98(gp)
  1004a2: 0b41b023     	sd	s4, 0xa0(gp)
  1004a6: 0b51b423     	sd	s5, 0xa8(gp)
  1004aa: 0b61b823     	sd	s6, 0xb0(gp)
  1004ae: 0b71bc23     	sd	s7, 0xb8(gp)
  1004b2: 0d81b023     	sd	s8, 0xc0(gp)
  1004b6: 0d91b423     	sd	s9, 0xc8(gp)
  1004ba: 0da1b823     	sd	s10, 0xd0(gp)
  1004be: 0db1bc23     	sd	s11, 0xd8(gp)
  1004c2: 0011b423     	sd	ra, 0x8(gp)
  1004c6: 0021b823     	sd	sp, 0x10(gp)
  1004ca: 14002273     	csrr	tp, sscratch
  1004ce: 0e41b023     	sd	tp, 0xe0(gp)
  1004d2: 00000073     	ecall
  1004d6: 00024197     	auipc	gp, 0x24
  1004da: 1da18193     	addi	gp, gp, 0x1da
  1004de: 0401b403     	ld	s0, 0x40(gp)
  1004e2: 0481b483     	ld	s1, 0x48(gp)
  1004e6: 0901b903     	ld	s2, 0x90(gp)
  1004ea: 0981b983     	ld	s3, 0x98(gp)
  1004ee: 0a01ba03     	ld	s4, 0xa0(gp)
  1004f2: 0a81ba83     	ld	s5, 0xa8(gp)
  1004f6: 0b01bb03     	ld	s6, 0xb0(gp)
  1004fa: 0b81bb83     	ld	s7, 0xb8(gp)
  1004fe: 0c01bc03     	ld	s8, 0xc0(gp)
  100502: 0c81bc83     	ld	s9, 0xc8(gp)
  100506: 0d01bd03     	ld	s10, 0xd0(gp)
  10050a: 0d81bd83     	ld	s11, 0xd8(gp)
  10050e: 0081b083     	ld	ra, 0x8(gp)
  100512: 0101b103     	ld	sp, 0x10(gp)
  100516: 0e01b203     	ld	tp, 0xe0(gp)
  10051a: 14021073     	csrw	sscratch, tp
  10051e: 0006c817     	auipc	a6, 0x6c
  100522: b6080123     	sb	zero, -0x49e(a6)
  100526: 00979d63     	bne	a5, s1, 0x100540 <PT_LOAD#0+0x540>
  10052a: e008         	sd	a0, 0x0(s0)
  10052c: e40c         	sd	a1, 0x8(s0)
  10052e: e810         	sd	a2, 0x10(s0)
  100530: ec14         	sd	a3, 0x18(s0)
  100532: f018         	sd	a4, 0x20(s0)
  100534: 4501         	li	a0, 0x0
  100536: 60e2         	ld	ra, 0x18(sp)
  100538: 6442         	ld	s0, 0x10(sp)
  10053a: 64a2         	ld	s1, 0x8(sp)
  10053c: 6105         	addi	sp, sp, 0x20
  10053e: 8082         	ret
  100540: 451d         	li	a0, 0x7
  100542: bfd5         	j	0x100536 <PT_LOAD#0+0x536>
  100544: 7139         	addi	sp, sp, -0x40
  100546: 1682         	slli	a3, a3, 0x20
  100548: 02100793     	li	a5, 0x21
  10054c: e82a         	sd	a0, 0x10(sp)
  10054e: ec2e         	sd	a1, 0x18(sp)
  100550: 9281         	srli	a3, a3, 0x20
  100552: 002c         	addi	a1, sp, 0x8
  100554: 0006c517     	auipc	a0, 0x6c
  100558: b2e54503     	lbu	a0, -0x4d2(a0)
  10055c: fc06         	sd	ra, 0x38(sp)
  10055e: e43e         	sd	a5, 0x8(sp)
  100560: f032         	sd	a2, 0x20(sp)
  100562: f436         	sd	a3, 0x28(sp)
  100564: 00000097     	auipc	ra, 0x0
  100568: efa080e7     	jalr	-0x106(ra) <PT_LOAD#0+0x45e>
  10056c: e119         	bnez	a0, 0x100572 <PT_LOAD#0+0x572>
  10056e: 01014503     	lbu	a0, 0x10(sp)
  100572: 70e2         	ld	ra, 0x38(sp)
  100574: 6121         	addi	sp, sp, 0x40
  100576: 8082         	ret
  100578: 7139         	addi	sp, sp, -0x40
  10057a: 1682         	slli	a3, a3, 0x20
  10057c: 02400793     	li	a5, 0x24
  100580: e82a         	sd	a0, 0x10(sp)
  100582: ec2e         	sd	a1, 0x18(sp)
  100584: 9281         	srli	a3, a3, 0x20
  100586: 002c         	addi	a1, sp, 0x8
  100588: 0006c517     	auipc	a0, 0x6c
  10058c: afa54503     	lbu	a0, -0x506(a0)
  100590: fc06         	sd	ra, 0x38(sp)
  100592: e43e         	sd	a5, 0x8(sp)
  100594: f032         	sd	a2, 0x20(sp)
  100596: f436         	sd	a3, 0x28(sp)
  100598: 00000097     	auipc	ra, 0x0
  10059c: ec6080e7     	jalr	-0x13a(ra) <PT_LOAD#0+0x45e>
  1005a0: e119         	bnez	a0, 0x1005a6 <PT_LOAD#0+0x5a6>
  1005a2: 01014503     	lbu	a0, 0x10(sp)
  1005a6: 70e2         	ld	ra, 0x38(sp)
  1005a8: 6121         	addi	sp, sp, 0x40
  1005aa: 8082         	ret
  1005ac: 01455793     	srli	a5, a0, 0x14
  1005b0: 8b8d         	andi	a5, a5, 0x3
  1005b2: 37fd         	addiw	a5, a5, -0x1
  1005b4: 0007869b     	sext.w	a3, a5
  1005b8: 4709         	li	a4, 0x2
  1005ba: 02d76163     	bltu	a4, a3, 0x1005dc <PT_LOAD#0+0x5dc>
  1005be: 1782         	slli	a5, a5, 0x20
  1005c0: 9381         	srli	a5, a5, 0x20
  1005c2: 00004717     	auipc	a4, 0x4
  1005c6: 9ce70713     	addi	a4, a4, -0x632
  1005ca: 97ba         	add	a5, a5, a4
  1005cc: 0007c783     	lbu	a5, 0x0(a5)
  1005d0: 0165551b     	srliw	a0, a0, 0x16
  1005d4: 0505         	addi	a0, a0, 0x1
  1005d6: 00f51533     	sll	a0, a0, a5
  1005da: 8082         	ret
  1005dc: 478d         	li	a5, 0x3
  1005de: bfcd         	j	0x1005d0 <PT_LOAD#0+0x5d0>
  1005e0: 00024797     	auipc	a5, 0x24
  1005e4: a2078793     	addi	a5, a5, -0x5e0
  1005e8: 4701         	li	a4, 0x0
  1005ea: 95aa         	add	a1, a1, a0
  1005ec: 48c1         	li	a7, 0x10
  1005ee: 02a5e463     	bltu	a1, a0, 0x100616 <PT_LOAD#0+0x616>
  1005f2: 0007b803     	ld	a6, 0x0(a5)
  1005f6: 03056063     	bltu	a0, a6, 0x100616 <PT_LOAD#0+0x616>
  1005fa: 0087b303     	ld	t1, 0x8(a5)
  1005fe: 981a         	add	a6, a6, t1
  100600: 00b86b63     	bltu	a6, a1, 0x100616 <PT_LOAD#0+0x616>
  100604: 0107a803     	lw	a6, 0x10(a5)
  100608: 00d87833     	and	a6, a6, a3
  10060c: 00d81563     	bne	a6, a3, 0x100616 <PT_LOAD#0+0x616>
  100610: e218         	sd	a4, 0x0(a2)
  100612: 4505         	li	a0, 0x1
  100614: 8082         	ret
  100616: 0705         	addi	a4, a4, 0x1
  100618: 02078793     	addi	a5, a5, 0x20
  10061c: fd1719e3     	bne	a4, a7, 0x1005ee <PT_LOAD#0+0x5ee>
  100620: 4501         	li	a0, 0x0
  100622: 8082         	ret
  100624: 0006c797     	auipc	a5, 0x6c
  100628: a547b783     	ld	a5, -0x5ac(a5)
  10062c: 02a78e63     	beq	a5, a0, 0x100668 <PT_LOAD#0+0x668>
  100630: 052e         	slli	a0, a0, 0xb
  100632: 00044797     	auipc	a5, 0x44
  100636: 5ce78793     	addi	a5, a5, 0x5ce
  10063a: 953e         	add	a0, a0, a5
  10063c: 4741         	li	a4, 0x10
  10063e: 962e         	add	a2, a2, a1
  100640: 00b66e63     	bltu	a2, a1, 0x10065c <PT_LOAD#0+0x65c>
  100644: 6d1c         	ld	a5, 0x18(a0)
  100646: 00f5eb63     	bltu	a1, a5, 0x10065c <PT_LOAD#0+0x65c>
  10064a: 02053803     	ld	a6, 0x20(a0)
  10064e: 97c2         	add	a5, a5, a6
  100650: 00c7e663     	bltu	a5, a2, 0x10065c <PT_LOAD#0+0x65c>
  100654: 551c         	lw	a5, 0x28(a0)
  100656: 8ff5         	and	a5, a5, a3
  100658: 00d78863     	beq	a5, a3, 0x100668 <PT_LOAD#0+0x668>
  10065c: 177d         	addi	a4, a4, -0x1
  10065e: 02050513     	addi	a0, a0, 0x20
  100662: ff79         	bnez	a4, 0x100640 <PT_LOAD#0+0x640>
  100664: 4501         	li	a0, 0x0
  100666: 8082         	ret
  100668: 4505         	li	a0, 0x1
  10066a: 8082         	ret
  10066c: 8d4d         	or	a0, a0, a1
  10066e: fff58793     	addi	a5, a1, -0x1
  100672: 8d7d         	and	a0, a0, a5
  100674: e901         	bnez	a0, 0x100684 <PT_LOAD#0+0x684>
  100676: 0085b513     	sltiu	a0, a1, 0x8
  10067a: 00154513     	xori	a0, a0, 0x1
  10067e: 0ff57513     	zext.b	a0, a0
  100682: 8082         	ret
  100684: 4501         	li	a0, 0x0
  100686: 8082         	ret
  100688: 00000297     	auipc	t0, 0x0
  10068c: 02028293     	addi	t0, t0, 0x20
  100690: 0002b103     	ld	sp, 0x0(t0)
  100694: 0182b803     	ld	a6, 0x18(t0)
  100698: 0082b883     	ld	a7, 0x8(t0)
  10069c: 0102b283     	ld	t0, 0x10(t0)
  1006a0: 8282         	jr	t0
  1006a2: 0001         	nop
  1006a4: 00000013     	nop
  1006a8: 157d         	addi	a0, a0, -0x1
  1006aa: 02055793     	srli	a5, a0, 0x20
  1006ae: 8fc9         	or	a5, a5, a0
  1006b0: 0107d713     	srli	a4, a5, 0x10
  1006b4: 8f5d         	or	a4, a4, a5
  1006b6: 00875793     	srli	a5, a4, 0x8
  1006ba: 8fd9         	or	a5, a5, a4
  1006bc: 0047d713     	srli	a4, a5, 0x4
  1006c0: 8f5d         	or	a4, a4, a5
  1006c2: 00275793     	srli	a5, a4, 0x2
  1006c6: 8fd9         	or	a5, a5, a4
  1006c8: 0017d513     	srli	a0, a5, 0x1
  1006cc: 8d5d         	or	a0, a0, a5
  1006ce: 0505         	addi	a0, a0, 0x1
  1006d0: 8082         	ret
  1006d2: 0065d713     	srli	a4, a1, 0x6
  1006d6: 4785         	li	a5, 0x1
  1006d8: 00371693     	slli	a3, a4, 0x3
  1006dc: 00665813     	srli	a6, a2, 0x6
  1006e0: 00b795b3     	sll	a1, a5, a1
  1006e4: 96aa         	add	a3, a3, a0
  1006e6: 4789         	li	a5, 0x2
  1006e8: 0006b883     	ld	a7, 0x0(a3)
  1006ec: 00c79633     	sll	a2, a5, a2
  1006f0: 01071c63     	bne	a4, a6, 0x100708 <PT_LOAD#0+0x708>
  1006f4: 167d         	addi	a2, a2, -0x1
  1006f6: 40b005b3     	neg	a1, a1
  1006fa: 8e6d         	and	a2, a2, a1
  1006fc: fff64613     	not	a2, a2
  100700: 01167633     	and	a2, a2, a7
  100704: e290         	sd	a2, 0x0(a3)
  100706: 8082         	ret
  100708: 15fd         	addi	a1, a1, -0x1
  10070a: 0115f5b3     	and	a1, a1, a7
  10070e: 00381793     	slli	a5, a6, 0x3
  100712: e28c         	sd	a1, 0x0(a3)
  100714: 97aa         	add	a5, a5, a0
  100716: 6394         	ld	a3, 0x0(a5)
  100718: 40c00633     	neg	a2, a2
  10071c: 8ef1         	and	a3, a3, a2
  10071e: e394         	sd	a3, 0x0(a5)
  100720: 0705         	addi	a4, a4, 0x1
  100722: 00e81363     	bne	a6, a4, 0x100728 <PT_LOAD#0+0x728>
  100726: 8082         	ret
  100728: 00371793     	slli	a5, a4, 0x3
  10072c: 97aa         	add	a5, a5, a0
  10072e: 0007b023     	sd	zero, 0x0(a5)
  100732: b7fd         	j	0x100720 <PT_LOAD#0+0x720>
  100734: 0065d713     	srli	a4, a1, 0x6
  100738: 4789         	li	a5, 0x2
  10073a: 00665813     	srli	a6, a2, 0x6
  10073e: 00371693     	slli	a3, a4, 0x3
  100742: 00c79633     	sll	a2, a5, a2
  100746: 4785         	li	a5, 0x1
  100748: 96aa         	add	a3, a3, a0
  10074a: 00b795b3     	sll	a1, a5, a1
  10074e: 0006b883     	ld	a7, 0x0(a3)
  100752: 167d         	addi	a2, a2, -0x1
  100754: 40b005b3     	neg	a1, a1
  100758: 01071763     	bne	a4, a6, 0x100766 <PT_LOAD#0+0x766>
  10075c: 8df1         	and	a1, a1, a2
  10075e: 0115e5b3     	or	a1, a1, a7
  100762: e28c         	sd	a1, 0x0(a3)
  100764: 8082         	ret
  100766: 0115e5b3     	or	a1, a1, a7
  10076a: 00381793     	slli	a5, a6, 0x3
  10076e: e28c         	sd	a1, 0x0(a3)
  100770: 97aa         	add	a5, a5, a0
  100772: 6394         	ld	a3, 0x0(a5)
  100774: 8ed1         	or	a3, a3, a2
  100776: e394         	sd	a3, 0x0(a5)
  100778: 56fd         	li	a3, -0x1
  10077a: 0705         	addi	a4, a4, 0x1
  10077c: 00e81363     	bne	a6, a4, 0x100782 <PT_LOAD#0+0x782>
  100780: 8082         	ret
  100782: 00371793     	slli	a5, a4, 0x3
  100786: 97aa         	add	a5, a5, a0
  100788: e394         	sd	a3, 0x0(a5)
  10078a: bfc5         	j	0x10077a <PT_LOAD#0+0x77a>
  10078c: fff54793     	not	a5, a0
  100790: 0505         	addi	a0, a0, 0x1
  100792: 00003717     	auipc	a4, 0x3
  100796: 7be73703     	ld	a4, 0x7be(a4)
  10079a: 8fe9         	and	a5, a5, a0
  10079c: 02e787b3     	<unknown>
  1007a0: 00003717     	auipc	a4, 0x3
  1007a4: 5e870713     	addi	a4, a4, 0x5e8
  1007a8: 93e9         	srli	a5, a5, 0x3a
  1007aa: 97ba         	add	a5, a5, a4
  1007ac: 0007c503     	lbu	a0, 0x0(a5)
  1007b0: 8082         	ret
  1007b2: 1101         	addi	sp, sp, -0x20
  1007b4: e822         	sd	s0, 0x10(sp)
  1007b6: e426         	sd	s1, 0x8(sp)
  1007b8: e04a         	sd	s2, 0x0(sp)
  1007ba: ec06         	sd	ra, 0x18(sp)
  1007bc: 84aa         	mv	s1, a0
  1007be: 842e         	mv	s0, a1
  1007c0: 00c58933     	add	s2, a1, a2
  1007c4: 01241863     	bne	s0, s2, 0x1007d4 <PT_LOAD#0+0x7d4>
  1007c8: 60e2         	ld	ra, 0x18(sp)
  1007ca: 6442         	ld	s0, 0x10(sp)
  1007cc: 64a2         	ld	s1, 0x8(sp)
  1007ce: 6902         	ld	s2, 0x0(sp)
  1007d0: 6105         	addi	sp, sp, 0x20
  1007d2: 8082         	ret
  1007d4: 609c         	ld	a5, 0x0(s1)
  1007d6: 00044583     	lbu	a1, 0x0(s0)
  1007da: 8526         	mv	a0, s1
  1007dc: 0405         	addi	s0, s0, 0x1
  1007de: 9782         	jalr	a5
  1007e0: b7d5         	j	0x1007c4 <PT_LOAD#0+0x7c4>
  1007e2: 4501         	li	a0, 0x0
  1007e4: 8082         	ret
  1007e6: 7179         	addi	sp, sp, -0x30
  1007e8: f022         	sd	s0, 0x20(sp)
  1007ea: ec26         	sd	s1, 0x18(sp)
  1007ec: e84a         	sd	s2, 0x10(sp)
  1007ee: e44e         	sd	s3, 0x8(sp)
  1007f0: f406         	sd	ra, 0x28(sp)
  1007f2: 84aa         	mv	s1, a0
  1007f4: 89ae         	mv	s3, a1
  1007f6: 8932         	mv	s2, a2
  1007f8: 8436         	mv	s0, a3
  1007fa: 01244963     	blt	s0, s2, 0x10080c <PT_LOAD#0+0x80c>
  1007fe: 70a2         	ld	ra, 0x28(sp)
  100800: 7402         	ld	s0, 0x20(sp)
  100802: 64e2         	ld	s1, 0x18(sp)
  100804: 6942         	ld	s2, 0x10(sp)
  100806: 69a2         	ld	s3, 0x8(sp)
  100808: 6145         	addi	sp, sp, 0x30
  10080a: 8082         	ret
  10080c: 609c         	ld	a5, 0x0(s1)
  10080e: 85ce         	mv	a1, s3
  100810: 8526         	mv	a0, s1
  100812: 9782         	jalr	a5
  100814: 2405         	addiw	s0, s0, 0x1
  100816: b7d5         	j	0x1007fa <PT_LOAD#0+0x7fa>
  100818: 7119         	addi	sp, sp, -0x80
  10081a: f862         	sd	s8, 0x30(sp)
  10081c: f466         	sd	s9, 0x28(sp)
  10081e: fff58c13     	addi	s8, a1, -0x1
  100822: 40b007b3     	neg	a5, a1
  100826: 00160c93     	addi	s9, a2, 0x1
  10082a: f8a2         	sd	s0, 0x70(sp)
  10082c: f4a6         	sd	s1, 0x68(sp)
  10082e: ecce         	sd	s3, 0x58(sp)
  100830: e8d2         	sd	s4, 0x50(sp)
  100832: e4d6         	sd	s5, 0x48(sp)
  100834: e0da         	sd	s6, 0x40(sp)
  100836: fc5e         	sd	s7, 0x38(sp)
  100838: f06a         	sd	s10, 0x20(sp)
  10083a: ec6e         	sd	s11, 0x18(sp)
  10083c: fc86         	sd	ra, 0x78(sp)
  10083e: f0ca         	sd	s2, 0x60(sp)
  100840: 842a         	mv	s0, a0
  100842: 89b2         	mv	s3, a2
  100844: 8ab6         	mv	s5, a3
  100846: 84ba         	mv	s1, a4
  100848: 00675b93     	srli	s7, a4, 0x6
  10084c: 4a01         	li	s4, 0x0
  10084e: 03f77d13     	andi	s10, a4, 0x3f
  100852: 5b7d         	li	s6, -0x1
  100854: 9c32         	add	s8, s8, a2
  100856: e03e         	sd	a5, 0x0(sp)
  100858: 9cba         	add	s9, s9, a4
  10085a: fff68d93     	addi	s11, a3, -0x1
  10085e: 006a5913     	srli	s2, s4, 0x6
  100862: 00391713     	slli	a4, s2, 0x3
  100866: 9722         	add	a4, a4, s0
  100868: 6308         	ld	a0, 0x0(a4)
  10086a: 03fa7793     	andi	a5, s4, 0x3f
  10086e: 09791c63     	bne	s2, s7, 0x100906 <PT_LOAD#0+0x906>
  100872: 4589         	li	a1, 0x2
  100874: 01a595b3     	sll	a1, a1, s10
  100878: 577d         	li	a4, -0x1
  10087a: 00f717b3     	sll	a5, a4, a5
  10087e: 15fd         	addi	a1, a1, -0x1
  100880: 8dfd         	and	a1, a1, a5
  100882: fff5c593     	not	a1, a1
  100886: 00a5e933     	or	s2, a1, a0
  10088a: 57fd         	li	a5, -0x1
  10088c: 16f90463     	beq	s2, a5, 0x1009f4 <PT_LOAD#0+0x9f4>
  100890: 854a         	mv	a0, s2
  100892: 00000097     	auipc	ra, 0x0
  100896: efa080e7     	jalr	-0x106(ra) <PT_LOAD#0+0x78c>
  10089a: fc0a7a13     	andi	s4, s4, -0x40
  10089e: 00aa0933     	add	s2, s4, a0
  1008a2: 15690963     	beq	s2, s6, 0x1009f4 <PT_LOAD#0+0x9f4>
  1008a6: 6702         	ld	a4, 0x0(sp)
  1008a8: 012c07b3     	add	a5, s8, s2
  1008ac: 8ff9         	and	a5, a5, a4
  1008ae: 41378933     	sub	s2, a5, s3
  1008b2: 0f24e163     	bltu	s1, s2, 0x100994 <PT_LOAD#0+0x994>
  1008b6: 40fc87b3     	sub	a5, s9, a5
  1008ba: 0d57ed63     	bltu	a5, s5, 0x100994 <PT_LOAD#0+0x994>
  1008be: 00695793     	srli	a5, s2, 0x6
  1008c2: 012d8a33     	add	s4, s11, s2
  1008c6: 00379693     	slli	a3, a5, 0x3
  1008ca: 96a2         	add	a3, a3, s0
  1008cc: 006a5713     	srli	a4, s4, 0x6
  1008d0: 6294         	ld	a3, 0x0(a3)
  1008d2: 03f97613     	andi	a2, s2, 0x3f
  1008d6: 03fa7813     	andi	a6, s4, 0x3f
  1008da: 08e79a63     	bne	a5, a4, 0x10096e <PT_LOAD#0+0x96e>
  1008de: 557d         	li	a0, -0x1
  1008e0: 4789         	li	a5, 0x2
  1008e2: 00c51533     	sll	a0, a0, a2
  1008e6: 010797b3     	sll	a5, a5, a6
  1008ea: 8d75         	and	a0, a0, a3
  1008ec: 17fd         	addi	a5, a5, -0x1
  1008ee: 8d7d         	and	a0, a0, a5
  1008f0: c97d         	beqz	a0, 0x1009e6 <PT_LOAD#0+0x9e6>
  1008f2: fff54513     	not	a0, a0
  1008f6: 00000097     	auipc	ra, 0x0
  1008fa: e96080e7     	jalr	-0x16a(ra) <PT_LOAD#0+0x78c>
  1008fe: fc097793     	andi	a5, s2, -0x40
  100902: 953e         	add	a0, a0, a5
  100904: a051         	j	0x100988 <PT_LOAD#0+0x988>
  100906: 00f55533     	srl	a0, a0, a5
  10090a: 00fb57b3     	srl	a5, s6, a5
  10090e: 577d         	li	a4, -0x1
  100910: 02a78663     	beq	a5, a0, 0x10093c <PT_LOAD#0+0x93c>
  100914: 00000097     	auipc	ra, 0x0
  100918: e78080e7     	jalr	-0x188(ra) <PT_LOAD#0+0x78c>
  10091c: b749         	j	0x10089e <PT_LOAD#0+0x89e>
  10091e: 00391793     	slli	a5, s2, 0x3
  100922: 97a2         	add	a5, a5, s0
  100924: 6388         	ld	a0, 0x0(a5)
  100926: 00e50b63     	beq	a0, a4, 0x10093c <PT_LOAD#0+0x93c>
  10092a: 00000097     	auipc	ra, 0x0
  10092e: e62080e7     	jalr	-0x19e(ra) <PT_LOAD#0+0x78c>
  100932: 00691593     	slli	a1, s2, 0x6
  100936: 00a58933     	add	s2, a1, a0
  10093a: b7a5         	j	0x1008a2 <PT_LOAD#0+0x8a2>
  10093c: 0905         	addi	s2, s2, 0x1
  10093e: ff2b90e3     	bne	s7, s2, 0x10091e <PT_LOAD#0+0x91e>
  100942: 03f00713     	li	a4, 0x3f
  100946: 41a7073b     	subw	a4, a4, s10
  10094a: 57fd         	li	a5, -0x1
  10094c: 00e7d7b3     	srl	a5, a5, a4
  100950: 003b9713     	slli	a4, s7, 0x3
  100954: 9722         	add	a4, a4, s0
  100956: 6308         	ld	a0, 0x0(a4)
  100958: 00a7f733     	and	a4, a5, a0
  10095c: 02e78c63     	beq	a5, a4, 0x100994 <PT_LOAD#0+0x994>
  100960: 00000097     	auipc	ra, 0x0
  100964: e2c080e7     	jalr	-0x1d4(ra) <PT_LOAD#0+0x78c>
  100968: fc04f593     	andi	a1, s1, -0x40
  10096c: b7e9         	j	0x100936 <PT_LOAD#0+0x936>
  10096e: fff6c513     	not	a0, a3
  100972: 00c55533     	srl	a0, a0, a2
  100976: 00cb5633     	srl	a2, s6, a2
  10097a: 02a60e63     	beq	a2, a0, 0x1009b6 <PT_LOAD#0+0x9b6>
  10097e: 00000097     	auipc	ra, 0x0
  100982: e0e080e7     	jalr	-0x1f2(ra) <PT_LOAD#0+0x78c>
  100986: 954a         	add	a0, a0, s2
  100988: 05650f63     	beq	a0, s6, 0x1009e6 <PT_LOAD#0+0x9e6>
  10098c: 00150a13     	addi	s4, a0, 0x1
  100990: ed44f7e3     	bgeu	s1, s4, 0x10085e <PT_LOAD#0+0x85e>
  100994: 597d         	li	s2, -0x1
  100996: a8b9         	j	0x1009f4 <PT_LOAD#0+0x9f4>
  100998: 00379693     	slli	a3, a5, 0x3
  10099c: 96a2         	add	a3, a3, s0
  10099e: 6288         	ld	a0, 0x0(a3)
  1009a0: c919         	beqz	a0, 0x1009b6 <PT_LOAD#0+0x9b6>
  1009a2: fff54513     	not	a0, a0
  1009a6: e43e         	sd	a5, 0x8(sp)
  1009a8: 00000097     	auipc	ra, 0x0
  1009ac: de4080e7     	jalr	-0x21c(ra) <PT_LOAD#0+0x78c>
  1009b0: 67a2         	ld	a5, 0x8(sp)
  1009b2: 079a         	slli	a5, a5, 0x6
  1009b4: b7b9         	j	0x100902 <PT_LOAD#0+0x902>
  1009b6: 0785         	addi	a5, a5, 0x1
  1009b8: fef710e3     	bne	a4, a5, 0x100998 <PT_LOAD#0+0x998>
  1009bc: 070e         	slli	a4, a4, 0x3
  1009be: 9722         	add	a4, a4, s0
  1009c0: 6308         	ld	a0, 0x0(a4)
  1009c2: 03f00713     	li	a4, 0x3f
  1009c6: 4107073b     	subw	a4, a4, a6
  1009ca: 57fd         	li	a5, -0x1
  1009cc: 00e7d7b3     	srl	a5, a5, a4
  1009d0: 8fe9         	and	a5, a5, a0
  1009d2: cb91         	beqz	a5, 0x1009e6 <PT_LOAD#0+0x9e6>
  1009d4: fff54513     	not	a0, a0
  1009d8: 00000097     	auipc	ra, 0x0
  1009dc: db4080e7     	jalr	-0x24c(ra) <PT_LOAD#0+0x78c>
  1009e0: fc0a7793     	andi	a5, s4, -0x40
  1009e4: bf39         	j	0x100902 <PT_LOAD#0+0x902>
  1009e6: 8652         	mv	a2, s4
  1009e8: 85ca         	mv	a1, s2
  1009ea: 8522         	mv	a0, s0
  1009ec: 00000097     	auipc	ra, 0x0
  1009f0: d48080e7     	jalr	-0x2b8(ra) <PT_LOAD#0+0x734>
  1009f4: 70e6         	ld	ra, 0x78(sp)
  1009f6: 7446         	ld	s0, 0x70(sp)
  1009f8: 74a6         	ld	s1, 0x68(sp)
  1009fa: 69e6         	ld	s3, 0x58(sp)
  1009fc: 6a46         	ld	s4, 0x50(sp)
  1009fe: 6aa6         	ld	s5, 0x48(sp)
  100a00: 6b06         	ld	s6, 0x40(sp)
  100a02: 7be2         	ld	s7, 0x38(sp)
  100a04: 7c42         	ld	s8, 0x30(sp)
  100a06: 7ca2         	ld	s9, 0x28(sp)
  100a08: 7d02         	ld	s10, 0x20(sp)
  100a0a: 6de2         	ld	s11, 0x18(sp)
  100a0c: 854a         	mv	a0, s2
  100a0e: 7906         	ld	s2, 0x60(sp)
  100a10: 6109         	addi	sp, sp, 0x80
  100a12: 8082         	ret
  100a14: 00024517     	auipc	a0, 0x24
  100a18: a6c53503     	ld	a0, -0x594(a0)
  100a1c: c549         	beqz	a0, 0x100aa6 <PT_LOAD#0+0xaa6>
  100a1e: 4781         	li	a5, 0x0
  100a20: 5d079073     	csrw	0x5d0, a5
  100a24: 5d179073     	csrw	0x5d1, a5
  100a28: 4705         	li	a4, 0x1
  100a2a: 5d071073     	csrw	0x5d0, a4
  100a2e: 5d179073     	csrw	0x5d1, a5
  100a32: 00080637     	lui	a2, 0x80
  100a36: 000c05b7     	lui	a1, 0xc0
  100a3a: 00023797     	auipc	a5, 0x23
  100a3e: 7c678793     	addi	a5, a5, 0x7c6
  100a42: 4681         	li	a3, 0x0
  100a44: 03f60613     	addi	a2, a2, 0x3f
  100a48: 03f58593     	addi	a1, a1, 0x3f
  100a4c: 1f000337     	lui	t1, 0x1f000
  100a50: 4885         	li	a7, 0x1
  100a52: 5ca69073     	csrw	0x5ca, a3
  100a56: 6398         	ld	a4, 0x0(a5)
  100a58: 5cc71073     	csrw	0x5cc, a4
  100a5c: 6798         	ld	a4, 0x8(a5)
  100a5e: 5cb71073     	csrw	0x5cb, a4
  100a62: 6b98         	ld	a4, 0x10(a5)
  100a64: 5ce71073     	csrw	0x5ce, a4
  100a68: 0207c703     	lbu	a4, 0x20(a5)
  100a6c: 8832         	mv	a6, a2
  100a6e: c311         	beqz	a4, 0x100a72 <PT_LOAD#0+0xa72>
  100a70: 882e         	mv	a6, a1
  100a72: 6f98         	ld	a4, 0x18(a5)
  100a74: 0762         	slli	a4, a4, 0x18
  100a76: 00677733     	and	a4, a4, t1
  100a7a: 01076733     	or	a4, a4, a6
  100a7e: 5cf71073     	csrw	0x5cf, a4
  100a82: 5cb8a073     	csrs	0x5cb, a7
  100a86: 0685         	addi	a3, a3, 0x1
  100a88: 02878793     	addi	a5, a5, 0x28
  100a8c: fcd513e3     	bne	a0, a3, 0x100a52 <PT_LOAD#0+0xa52>
  100a90: 57fd         	li	a5, -0x1
  100a92: 17f2         	slli	a5, a5, 0x3c
  100a94: 18079073     	csrw	satp, a5
  100a98: 12000073     	sfence.vma
  100a9c: 0000100f     	fence.i
  100aa0: 4781         	li	a5, 0x0
  100aa2: 8d079073     	csrw	0x8d0, a5
  100aa6: 8082         	ret
  100aa8: 87aa         	mv	a5, a0
  100aaa: c991         	beqz	a1, 0x100abe <PT_LOAD#0+0xabe>
  100aac: 00b78533     	add	a0, a5, a1
  100ab0: e111         	bnez	a0, 0x100ab4 <PT_LOAD#0+0xab4>
  100ab2: 8082         	ret
  100ab4: 7518         	ld	a4, 0x28(a0)
  100ab6: 00c70563     	beq	a4, a2, 0x100ac0 <PT_LOAD#0+0xac0>
  100aba: 790c         	ld	a1, 0x30(a0)
  100abc: b7fd         	j	0x100aaa <PT_LOAD#0+0xaaa>
  100abe: 4501         	li	a0, 0x0
  100ac0: 8082         	ret
  100ac2: 7139         	addi	sp, sp, -0x40
  100ac4: e82a         	sd	a0, 0x10(sp)
  100ac6: ec2e         	sd	a1, 0x18(sp)
  100ac8: 02d00793     	li	a5, 0x2d
  100acc: 002c         	addi	a1, sp, 0x8
  100ace: 0006b517     	auipc	a0, 0x6b
  100ad2: 5b454503     	lbu	a0, 0x5b4(a0)
  100ad6: fc06         	sd	ra, 0x38(sp)
  100ad8: e43e         	sd	a5, 0x8(sp)
  100ada: f032         	sd	a2, 0x20(sp)
  100adc: f402         	sd	zero, 0x28(sp)
  100ade: 00000097     	auipc	ra, 0x0
  100ae2: 980080e7     	jalr	-0x680(ra) <PT_LOAD#0+0x45e>
  100ae6: 70e2         	ld	ra, 0x38(sp)
  100ae8: 6121         	addi	sp, sp, 0x40
  100aea: 8082         	ret
  100aec: 715d         	addi	sp, sp, -0x50
  100aee: f83a         	sd	a4, 0x30(sp)
  100af0: ec2e         	sd	a1, 0x18(sp)
  100af2: f032         	sd	a2, 0x20(sp)
  100af4: f436         	sd	a3, 0x28(sp)
  100af6: fc3e         	sd	a5, 0x38(sp)
  100af8: e0c2         	sd	a6, 0x40(sp)
  100afa: e4c6         	sd	a7, 0x48(sp)
  100afc: 00023717     	auipc	a4, 0x23
  100b00: 50470713     	addi	a4, a4, 0x504
  100b04: 49073783     	ld	a5, 0x490(a4)
  100b08: cba5         	beqz	a5, 0x100b78 <PT_LOAD#0+0xb78>
  100b0a: 49873783     	ld	a5, 0x498(a4)
  100b0e: c7ad         	beqz	a5, 0x100b78 <PT_LOAD#0+0xb78>
  100b10: 00150693     	addi	a3, a0, 0x1
  100b14: 083c         	addi	a5, sp, 0x18
  100b16: 567d         	li	a2, -0x1
  100b18: e43e         	sd	a5, 0x8(sp)
  100b1a: 03069313     	slli	t1, a3, 0x30
  100b1e: 4881         	li	a7, 0x0
  100b20: 4781         	li	a5, 0x0
  100b22: 157d         	addi	a0, a0, -0x1
  100b24: 0006ce17     	auipc	t3, 0x6c
  100b28: 4dce0e13     	addi	t3, t3, 0x4dc
  100b2c: 8241         	srli	a2, a2, 0x10
  100b2e: 48873803     	ld	a6, 0x488(a4)
  100b32: 49873583     	ld	a1, 0x498(a4)
  100b36: 080e         	slli	a6, a6, 0x3
  100b38: 95c2         	add	a1, a1, a6
  100b3a: 04a7f163     	bgeu	a5, a0, 0x100b7c <PT_LOAD#0+0xb7c>
  100b3e: 67a2         	ld	a5, 0x8(sp)
  100b40: 00878813     	addi	a6, a5, 0x8
  100b44: 639c         	ld	a5, 0x0(a5)
  100b46: e442         	sd	a6, 0x8(sp)
  100b48: e19c         	sd	a5, 0x0(a1)
  100b4a: 48873783     	ld	a5, 0x488(a4)
  100b4e: 49073583     	ld	a1, 0x490(a4)
  100b52: 0785         	addi	a5, a5, 0x1
  100b54: 00b7e363     	bltu	a5, a1, 0x100b5a <PT_LOAD#0+0xb5a>
  100b58: 4785         	li	a5, 0x1
  100b5a: 48f73423     	sd	a5, 0x488(a4)
  100b5e: 0018879b     	addiw	a5, a7, 0x1
  100b62: 0007889b     	sext.w	a7, a5
  100b66: 1782         	slli	a5, a5, 0x20
  100b68: 9381         	srli	a5, a5, 0x20
  100b6a: fcd7e2e3     	bltu	a5, a3, 0x100b2e <PT_LOAD#0+0xb2e>
  100b6e: 49873703     	ld	a4, 0x498(a4)
  100b72: 631c         	ld	a5, 0x0(a4)
  100b74: 97b6         	add	a5, a5, a3
  100b76: e31c         	sd	a5, 0x0(a4)
  100b78: 6161         	addi	sp, sp, 0x50
  100b7a: 8082         	ret
  100b7c: 02f51263     	bne	a0, a5, 0x100ba0 <PT_LOAD#0+0xba0>
  100b80: 67a2         	ld	a5, 0x8(sp)
  100b82: 00878813     	addi	a6, a5, 0x8
  100b86: 639c         	ld	a5, 0x0(a5)
  100b88: e442         	sd	a6, 0x8(sp)
  100b8a: 4a074803     	lbu	a6, 0x4a0(a4)
  100b8e: 41c787b3     	sub	a5, a5, t3
  100b92: 8ff1         	and	a5, a5, a2
  100b94: 1862         	slli	a6, a6, 0x38
  100b96: 0107e7b3     	or	a5, a5, a6
  100b9a: 0067e7b3     	or	a5, a5, t1
  100b9e: b76d         	j	0x100b48 <PT_LOAD#0+0xb48>
  100ba0: c01027f3     	rdtime	a5
  100ba4: b755         	j	0x100b48 <PT_LOAD#0+0xb48>
  100ba6: 35e5         	addiw	a1, a1, -0x7
  100ba8: 02059793     	slli	a5, a1, 0x20
  100bac: 01e7d593     	srli	a1, a5, 0x1e
  100bb0: 00003797     	auipc	a5, 0x3
  100bb4: 0e078793     	addi	a5, a5, 0xe0
  100bb8: 95be         	add	a1, a1, a5
  100bba: 4198         	lw	a4, 0x0(a1)
  100bbc: 973e         	add	a4, a4, a5
  100bbe: 621c         	ld	a5, 0x0(a2)
  100bc0: 8702         	jr	a4
  100bc2: 00878713     	addi	a4, a5, 0x8
  100bc6: 639c         	ld	a5, 0x0(a5)
  100bc8: e218         	sd	a4, 0x0(a2)
  100bca: e11c         	sd	a5, 0x0(a0)
  100bcc: 8082         	ret
  100bce: 00878713     	addi	a4, a5, 0x8
  100bd2: e218         	sd	a4, 0x0(a2)
  100bd4: 439c         	lw	a5, 0x0(a5)
  100bd6: bfd5         	j	0x100bca <PT_LOAD#0+0xbca>
  100bd8: 00878713     	addi	a4, a5, 0x8
  100bdc: e218         	sd	a4, 0x0(a2)
  100bde: 0007e783     	lwu	a5, 0x0(a5)
  100be2: b7e5         	j	0x100bca <PT_LOAD#0+0xbca>
  100be4: 00878713     	addi	a4, a5, 0x8
  100be8: e218         	sd	a4, 0x0(a2)
  100bea: 00079783     	lh	a5, 0x0(a5)
  100bee: bff1         	j	0x100bca <PT_LOAD#0+0xbca>
  100bf0: 00878713     	addi	a4, a5, 0x8
  100bf4: e218         	sd	a4, 0x0(a2)
  100bf6: 0007d783     	lhu	a5, 0x0(a5)
  100bfa: bfc1         	j	0x100bca <PT_LOAD#0+0xbca>
  100bfc: 00878713     	addi	a4, a5, 0x8
  100c00: e218         	sd	a4, 0x0(a2)
  100c02: 0007c783     	lbu	a5, 0x0(a5)
  100c06: b7d1         	j	0x100bca <PT_LOAD#0+0xbca>
  100c08: 00878713     	addi	a4, a5, 0x8
  100c0c: e218         	sd	a4, 0x0(a2)
  100c0e: 00078783     	lb	a5, 0x0(a5)
  100c12: bf65         	j	0x100bca <PT_LOAD#0+0xbca>
  100c14: 7131         	addi	sp, sp, -0xc0
  100c16: e556         	sd	s5, 0x88(sp)
  100c18: 8aba         	mv	s5, a4
  100c1a: 80000737     	lui	a4, 0x80000
  100c1e: fff74793     	not	a5, a4
  100c22: 674d         	lui	a4, 0x13
  100c24: d03e         	sw	a5, 0x20(sp)
  100c26: 8897079b     	addiw	a5, a4, -0x777
  100c2a: ed4e         	sd	s3, 0x98(sp)
  100c2c: e952         	sd	s4, 0x90(sp)
  100c2e: e15a         	sd	s6, 0x80(sp)
  100c30: fcde         	sd	s7, 0x78(sp)
  100c32: f8e2         	sd	s8, 0x70(sp)
  100c34: ecee         	sd	s11, 0x58(sp)
  100c36: fd06         	sd	ra, 0xb8(sp)
  100c38: f922         	sd	s0, 0xb0(sp)
  100c3a: f526         	sd	s1, 0xa8(sp)
  100c3c: f14a         	sd	s2, 0xa0(sp)
  100c3e: f4e6         	sd	s9, 0x68(sp)
  100c40: f0ea         	sd	s10, 0x60(sp)
  100c42: e42a         	sd	a0, 0x8(sp)
  100c44: 8a2e         	mv	s4, a1
  100c46: e832         	sd	a2, 0x10(sp)
  100c48: 8b36         	mv	s6, a3
  100c4a: 4b81         	li	s7, 0x0
  100c4c: 4c01         	li	s8, 0x0
  100c4e: 4d81         	li	s11, 0x0
  100c50: 4981         	li	s3, 0x0
  100c52: d23e         	sw	a5, 0x24(sp)
  100c54: 000a4703     	lbu	a4, 0x0(s4)
  100c58: 01b989bb     	addw	s3, s3, s11
  100c5c: 844e         	mv	s0, s3
  100c5e: 4e070d63     	beqz	a4, 0x101158 <PT_LOAD#0+0x1158>
  100c62: 88d2         	mv	a7, s4
  100c64: 0008c703     	lbu	a4, 0x0(a7)
  100c68: 1a070a63     	beqz	a4, 0x100e1c <PT_LOAD#0+0xe1c>
  100c6c: 02500793     	li	a5, 0x25
  100c70: 1af71163     	bne	a4, a5, 0x100e12 <PT_LOAD#0+0xe12>
  100c74: 8d46         	mv	s10, a7
  100c76: 000d4703     	lbu	a4, 0x0(s10)
  100c7a: 02500793     	li	a5, 0x25
  100c7e: 00f71663     	bne	a4, a5, 0x100c8a <PT_LOAD#0+0xc8a>
  100c82: 001d4703     	lbu	a4, 0x1(s10)
  100c86: 18f70863     	beq	a4, a5, 0x100e16 <PT_LOAD#0+0xe16>
  100c8a: 5782         	lw	a5, 0x20(sp)
  100c8c: 414888b3     	sub	a7, a7, s4
  100c90: 40878ebb     	subw	t4, a5, s0
  100c94: 151ece63     	blt	t4, a7, 0x100df0 <PT_LOAD#0+0xdf0>
  100c98: 67a2         	ld	a5, 0x8(sp)
  100c9a: 00088d9b     	sext.w	s11, a7
  100c9e: cb91         	beqz	a5, 0x100cb2 <PT_LOAD#0+0xcb2>
  100ca0: 866e         	mv	a2, s11
  100ca2: 85d2         	mv	a1, s4
  100ca4: 853e         	mv	a0, a5
  100ca6: ec76         	sd	t4, 0x18(sp)
  100ca8: 00000097     	auipc	ra, 0x0
  100cac: b0a080e7     	jalr	-0x4f6(ra) <PT_LOAD#0+0x7b2>
  100cb0: 6ee2         	ld	t4, 0x18(sp)
  100cb2: 120d9d63     	bnez	s11, 0x100dec <PT_LOAD#0+0xdec>
  100cb6: 001d4703     	lbu	a4, 0x1(s10)
  100cba: 46a5         	li	a3, 0x9
  100cbc: fd07071b     	addiw	a4, a4, -0x30
  100cc0: 16e6e063     	bltu	a3, a4, 0x100e20 <PT_LOAD#0+0xe20>
  100cc4: 002d4603     	lbu	a2, 0x2(s10)
  100cc8: 02400693     	li	a3, 0x24
  100ccc: 14d61a63     	bne	a2, a3, 0x100e20 <PT_LOAD#0+0xe20>
  100cd0: 0d0d         	addi	s10, s10, 0x3
  100cd2: 4b85         	li	s7, 0x1
  100cd4: 4481         	li	s1, 0x0
  100cd6: 457d         	li	a0, 0x1f
  100cd8: 4305         	li	t1, 0x1
  100cda: 000d4583     	lbu	a1, 0x0(s10)
  100cde: fe05869b     	addiw	a3, a1, -0x20
  100ce2: 1ad56163     	bltu	a0, a3, 0x100e84 <PT_LOAD#0+0xe84>
  100ce6: 5792         	lw	a5, 0x24(sp)
  100ce8: 00d7d63b     	srlw	a2, a5, a3
  100cec: 8a05         	andi	a2, a2, 0x1
  100cee: 12061c63     	bnez	a2, 0x100e26 <PT_LOAD#0+0xe26>
  100cf2: 02a00693     	li	a3, 0x2a
  100cf6: 18d59763     	bne	a1, a3, 0x100e84 <PT_LOAD#0+0xe84>
  100cfa: 001d4683     	lbu	a3, 0x1(s10)
  100cfe: 4625         	li	a2, 0x9
  100d00: fd06859b     	addiw	a1, a3, -0x30
  100d04: 12b66863     	bltu	a2, a1, 0x100e34 <PT_LOAD#0+0xe34>
  100d08: 002d4583     	lbu	a1, 0x2(s10)
  100d0c: 02400613     	li	a2, 0x24
  100d10: 12c59263     	bne	a1, a2, 0x100e34 <PT_LOAD#0+0xe34>
  100d14: 068a         	slli	a3, a3, 0x2
  100d16: 96d6         	add	a3, a3, s5
  100d18: 462d         	li	a2, 0xb
  100d1a: f4c6a023     	sw	a2, -0xc0(a3)
  100d1e: 001d4683     	lbu	a3, 0x1(s10)
  100d22: 4b85         	li	s7, 0x1
  100d24: 0d0d         	addi	s10, s10, 0x3
  100d26: 068e         	slli	a3, a3, 0x3
  100d28: 96da         	add	a3, a3, s6
  100d2a: e806a903     	lw	s2, -0x180(a3)
  100d2e: 00095663     	bgez	s2, 0x100d3a <PT_LOAD#0+0xd3a>
  100d32: 6689         	lui	a3, 0x2
  100d34: 8cd5         	or	s1, s1, a3
  100d36: 4120093b     	negw	s2, s2
  100d3a: 4c81         	li	s9, 0x0
  100d3c: 03900313     	li	t1, 0x39
  100d40: 03a00513     	li	a0, 0x3a
  100d44: 4615         	li	a2, 0x5
  100d46: 000d4583     	lbu	a1, 0x0(s10)
  100d4a: fbf5859b     	addiw	a1, a1, -0x41
  100d4e: 0ab36163     	bltu	t1, a1, 0x100df0 <PT_LOAD#0+0xdf0>
  100d52: 020c9693     	slli	a3, s9, 0x20
  100d56: 9281         	srli	a3, a3, 0x20
  100d58: 02a686b3     	<unknown>
  100d5c: 00003797     	auipc	a5, 0x3
  100d60: 02c78793     	addi	a5, a5, 0x2c
  100d64: 0d05         	addi	s10, s10, 0x1
  100d66: 96be         	add	a3, a3, a5
  100d68: 96ae         	add	a3, a3, a1
  100d6a: 0406cf03     	lbu	t5, 0x40(a3)
  100d6e: ffff069b     	addiw	a3, t5, -0x1
  100d72: 000f059b     	sext.w	a1, t5
  100d76: 12d67363     	bgeu	a2, a3, 0x100e9c <PT_LOAD#0+0xe9c>
  100d7a: c9bd         	beqz	a1, 0x100df0 <PT_LOAD#0+0xdf0>
  100d7c: 56fd         	li	a3, -0x1
  100d7e: 12d70163     	beq	a4, a3, 0x100ea0 <PT_LOAD#0+0xea0>
  100d82: 00271693     	slli	a3, a4, 0x2
  100d86: 070e         	slli	a4, a4, 0x3
  100d88: 96d6         	add	a3, a3, s5
  100d8a: 975a         	add	a4, a4, s6
  100d8c: 01e6a023     	sw	t5, 0x0(a3)
  100d90: 6314         	ld	a3, 0x0(a4)
  100d92: 67a2         	ld	a5, 0x8(sp)
  100d94: 14078b63     	beqz	a5, 0x100eea <PT_LOAD#0+0xeea>
  100d98: fffd4703     	lbu	a4, -0x1(s10)
  100d9c: 0007061b     	sext.w	a2, a4
  100da0: 000c8863     	beqz	s9, 0x100db0 <PT_LOAD#0+0xdb0>
  100da4: 8b3d         	andi	a4, a4, 0xf
  100da6: 458d         	li	a1, 0x3
  100da8: 00b71463     	bne	a4, a1, 0x100db0 <PT_LOAD#0+0xdb0>
  100dac: 0df67613     	andi	a2, a2, 0xdf
  100db0: 00d4d713     	srli	a4, s1, 0xd
  100db4: 8b05         	andi	a4, a4, 0x1
  100db6: c701         	beqz	a4, 0x100dbe <PT_LOAD#0+0xdbe>
  100db8: 7741         	lui	a4, 0xffff0
  100dba: 177d         	addi	a4, a4, -0x1
  100dbc: 8cf9         	and	s1, s1, a4
  100dbe: 05800713     	li	a4, 0x58
  100dc2: 24e60263     	beq	a2, a4, 0x101006 <PT_LOAD#0+0x1006>
  100dc6: f9d6071b     	addiw	a4, a2, -0x63
  100dca: 0007051b     	sext.w	a0, a4
  100dce: 45d5         	li	a1, 0x15
  100dd0: 36a5ec63     	bltu	a1, a0, 0x101148 <PT_LOAD#0+0x1148>
  100dd4: 02071593     	slli	a1, a4, 0x20
  100dd8: 01e5d713     	srli	a4, a1, 0x1e
  100ddc: 00003597     	auipc	a1, 0x3
  100de0: ed458593     	addi	a1, a1, -0x12c
  100de4: 972e         	add	a4, a4, a1
  100de6: 4318         	lw	a4, 0x0(a4)
  100de8: 972e         	add	a4, a4, a1
  100dea: 8702         	jr	a4
  100dec: 0fbedf63     	bge	t4, s11, 0x100eea <PT_LOAD#0+0xeea>
  100df0: 59fd         	li	s3, -0x1
  100df2: 70ea         	ld	ra, 0xb8(sp)
  100df4: 744a         	ld	s0, 0xb0(sp)
  100df6: 74aa         	ld	s1, 0xa8(sp)
  100df8: 790a         	ld	s2, 0xa0(sp)
  100dfa: 6a4a         	ld	s4, 0x90(sp)
  100dfc: 6aaa         	ld	s5, 0x88(sp)
  100dfe: 6b0a         	ld	s6, 0x80(sp)
  100e00: 7be6         	ld	s7, 0x78(sp)
  100e02: 7c46         	ld	s8, 0x70(sp)
  100e04: 7ca6         	ld	s9, 0x68(sp)
  100e06: 7d06         	ld	s10, 0x60(sp)
  100e08: 6de6         	ld	s11, 0x58(sp)
  100e0a: 854e         	mv	a0, s3
  100e0c: 69ea         	ld	s3, 0x98(sp)
  100e0e: 6129         	addi	sp, sp, 0xc0
  100e10: 8082         	ret
  100e12: 0885         	addi	a7, a7, 0x1
  100e14: bd81         	j	0x100c64 <PT_LOAD#0+0xc64>
  100e16: 0885         	addi	a7, a7, 0x1
  100e18: 0d09         	addi	s10, s10, 0x2
  100e1a: bdb1         	j	0x100c76 <PT_LOAD#0+0xc76>
  100e1c: 8d46         	mv	s10, a7
  100e1e: b5b5         	j	0x100c8a <PT_LOAD#0+0xc8a>
  100e20: 0d05         	addi	s10, s10, 0x1
  100e22: 577d         	li	a4, -0x1
  100e24: bd45         	j	0x100cd4 <PT_LOAD#0+0xcd4>
  100e26: 00d316bb     	sllw	a3, t1, a3
  100e2a: 8ec5         	or	a3, a3, s1
  100e2c: 0006849b     	sext.w	s1, a3
  100e30: 0d05         	addi	s10, s10, 0x1
  100e32: b565         	j	0x100cda <PT_LOAD#0+0xcda>
  100e34: fa0b9ee3     	bnez	s7, 0x100df0 <PT_LOAD#0+0xdf0>
  100e38: 67a2         	ld	a5, 0x8(sp)
  100e3a: 0d05         	addi	s10, s10, 0x1
  100e3c: 4901         	li	s2, 0x0
  100e3e: ee078ee3     	beqz	a5, 0x100d3a <PT_LOAD#0+0xd3a>
  100e42: 67c2         	ld	a5, 0x10(sp)
  100e44: 6394         	ld	a3, 0x0(a5)
  100e46: 00868613     	addi	a2, a3, 0x8
  100e4a: 0006a903     	lw	s2, 0x0(a3)
  100e4e: e390         	sd	a2, 0x0(a5)
  100e50: bdf9         	j	0x100d2e <PT_LOAD#0+0xd2e>
  100e52: 03266763     	bltu	a2, s2, 0x100e80 <PT_LOAD#0+0xe80>
  100e56: 032f833b     	<unknown>
  100e5a: 597d         	li	s2, -0x1
  100e5c: 00b302bb     	addw	t0, t1, a1
  100e60: 00a2c463     	blt	t0, a0, 0x100e68 <PT_LOAD#0+0xe68>
  100e64: 4066893b     	subw	s2, a3, t1
  100e68: 0d05         	addi	s10, s10, 0x1
  100e6a: 000d4683     	lbu	a3, 0x0(s10)
  100e6e: fd06851b     	addiw	a0, a3, -0x30
  100e72: 86aa         	mv	a3, a0
  100e74: fcaf7fe3     	bgeu	t5, a0, 0x100e52 <PT_LOAD#0+0xe52>
  100e78: 56fd         	li	a3, -0x1
  100e7a: ecd910e3     	bne	s2, a3, 0x100d3a <PT_LOAD#0+0xd3a>
  100e7e: bf8d         	j	0x100df0 <PT_LOAD#0+0xdf0>
  100e80: 597d         	li	s2, -0x1
  100e82: b7dd         	j	0x100e68 <PT_LOAD#0+0xe68>
  100e84: 0cccd637     	lui	a2, 0xcccd
  100e88: 800005b7     	lui	a1, 0x80000
  100e8c: 4901         	li	s2, 0x0
  100e8e: 4f25         	li	t5, 0x9
  100e90: ccc60613     	addi	a2, a2, -0x334
  100e94: 5fd9         	li	t6, -0xa
  100e96: fff5c593     	not	a1, a1
  100e9a: bfc1         	j	0x100e6a <PT_LOAD#0+0xe6a>
  100e9c: 8cae         	mv	s9, a1
  100e9e: b565         	j	0x100d46 <PT_LOAD#0+0xd46>
  100ea0: 02000713     	li	a4, 0x20
  100ea4: f4ec06e3     	beq	s8, a4, 0x100df0 <PT_LOAD#0+0xdf0>
  100ea8: 67c2         	ld	a5, 0x10(sp)
  100eaa: 020c1713     	slli	a4, s8, 0x20
  100eae: 01d75513     	srli	a0, a4, 0x1d
  100eb2: 955a         	add	a0, a0, s6
  100eb4: cb91         	beqz	a5, 0x100ec8 <PT_LOAD#0+0xec8>
  100eb6: 863e         	mv	a2, a5
  100eb8: f476         	sd	t4, 0x28(sp)
  100eba: ec2a         	sd	a0, 0x18(sp)
  100ebc: 00000097     	auipc	ra, 0x0
  100ec0: cea080e7     	jalr	-0x316(ra) <PT_LOAD#0+0xba6>
  100ec4: 7ea2         	ld	t4, 0x28(sp)
  100ec6: 6562         	ld	a0, 0x18(sp)
  100ec8: 6114         	ld	a3, 0x0(a0)
  100eca: 2c05         	addiw	s8, s8, 0x1
  100ecc: b5d9         	j	0x100d92 <PT_LOAD#0+0xd92>
  100ece: 4795         	li	a5, 0x5
  100ed0: 0197ed63     	bltu	a5, s9, 0x100eea <PT_LOAD#0+0xeea>
  100ed4: 00003717     	auipc	a4, 0x3
  100ed8: e3470713     	addi	a4, a4, -0x1cc
  100edc: 002c9793     	slli	a5, s9, 0x2
  100ee0: 97ba         	add	a5, a5, a4
  100ee2: 439c         	lw	a5, 0x0(a5)
  100ee4: 97ba         	add	a5, a5, a4
  100ee6: 8782         	jr	a5
  100ee8: c280         	sw	s0, 0x0(a3)
  100eea: 8a6a         	mv	s4, s10
  100eec: b3a5         	j	0x100c54 <PT_LOAD#0+0xc54>
  100eee: 0136b023     	sd	s3, 0x0(a3)
  100ef2: bfe5         	j	0x100eea <PT_LOAD#0+0xeea>
  100ef4: 01369023     	sh	s3, 0x0(a3)
  100ef8: bfcd         	j	0x100eea <PT_LOAD#0+0xeea>
  100efa: 01368023     	sb	s3, 0x0(a3)
  100efe: b7f5         	j	0x100eea <PT_LOAD#0+0xeea>
  100f00: 0084e493     	ori	s1, s1, 0x8
  100f04: 07800613     	li	a2, 0x78
  100f08: 4cc1         	li	s9, 0x10
  100f0a: 02067313     	andi	t1, a2, 0x20
  100f0e: 85b6         	mv	a1, a3
  100f10: 04b10a13     	addi	s4, sp, 0x4b
  100f14: 00003f17     	auipc	t5, 0x3
  100f18: 014f0f13     	addi	t5, t5, 0x14
  100f1c: e5fd         	bnez	a1, 0x10100a <PT_LOAD#0+0x100a>
  100f1e: 00003317     	auipc	t1, 0x3
  100f22: cc230313     	addi	t1, t1, -0x33e
  100f26: c699         	beqz	a3, 0x100f34 <PT_LOAD#0+0xf34>
  100f28: 0084f593     	andi	a1, s1, 0x8
  100f2c: c581         	beqz	a1, 0x100f34 <PT_LOAD#0+0xf34>
  100f2e: 8211         	srli	a2, a2, 0x4
  100f30: 9332         	add	t1, t1, a2
  100f32: 4d89         	li	s11, 0x2
  100f34: 04b10413     	addi	s0, sp, 0x4b
  100f38: 41440633     	sub	a2, s0, s4
  100f3c: 0016b693     	seqz	a3, a3
  100f40: 96b2         	add	a3, a3, a2
  100f42: 0196d363     	bge	a3, s9, 0x100f48 <PT_LOAD#0+0xf48>
  100f46: 86e6         	mv	a3, s9
  100f48: 00068c9b     	sext.w	s9, a3
  100f4c: 41440433     	sub	s0, s0, s4
  100f50: 008cd463     	bge	s9, s0, 0x100f58 <PT_LOAD#0+0xf58>
  100f54: 00040c9b     	sext.w	s9, s0
  100f58: 800006b7     	lui	a3, 0x80000
  100f5c: fff6c693     	not	a3, a3
  100f60: 41b686bb     	subw	a3, a3, s11
  100f64: e996c6e3     	blt	a3, s9, 0x100df0 <PT_LOAD#0+0xdf0>
  100f68: 019d87bb     	addw	a5, s11, s9
  100f6c: ec3e         	sd	a5, 0x18(sp)
  100f6e: 86be         	mv	a3, a5
  100f70: 0127d363     	bge	a5, s2, 0x100f76 <PT_LOAD#0+0xf76>
  100f74: 86ca         	mv	a3, s2
  100f76: 0006891b     	sext.w	s2, a3
  100f7a: e72ecbe3     	blt	t4, s2, 0x100df0 <PT_LOAD#0+0xdf0>
  100f7e: 66c9         	lui	a3, 0x12
  100f80: 8ee5         	and	a3, a3, s1
  100f82: ee81         	bnez	a3, 0x100f9a <PT_LOAD#0+0xf9a>
  100f84: 66e2         	ld	a3, 0x18(sp)
  100f86: 6522         	ld	a0, 0x8(sp)
  100f88: 864a         	mv	a2, s2
  100f8a: 02000593     	li	a1, 0x20
  100f8e: f41a         	sd	t1, 0x28(sp)
  100f90: 00000097     	auipc	ra, 0x0
  100f94: 856080e7     	jalr	-0x7aa(ra) <PT_LOAD#0+0x7e6>
  100f98: 7322         	ld	t1, 0x28(sp)
  100f9a: 6522         	ld	a0, 0x8(sp)
  100f9c: 866e         	mv	a2, s11
  100f9e: 859a         	mv	a1, t1
  100fa0: 00000097     	auipc	ra, 0x0
  100fa4: 812080e7     	jalr	-0x7ee(ra) <PT_LOAD#0+0x7b2>
  100fa8: 66c1         	lui	a3, 0x10
  100faa: 8ea5         	xor	a3, a3, s1
  100fac: 6649         	lui	a2, 0x12
  100fae: 8ef1         	and	a3, a3, a2
  100fb0: ea91         	bnez	a3, 0x100fc4 <PT_LOAD#0+0xfc4>
  100fb2: 66e2         	ld	a3, 0x18(sp)
  100fb4: 6522         	ld	a0, 0x8(sp)
  100fb6: 864a         	mv	a2, s2
  100fb8: 03000593     	li	a1, 0x30
  100fbc: 00000097     	auipc	ra, 0x0
  100fc0: 82a080e7     	jalr	-0x7d6(ra) <PT_LOAD#0+0x7e6>
  100fc4: 6522         	ld	a0, 0x8(sp)
  100fc6: 0004069b     	sext.w	a3, s0
  100fca: 8666         	mv	a2, s9
  100fcc: 03000593     	li	a1, 0x30
  100fd0: 00000097     	auipc	ra, 0x0
  100fd4: 816080e7     	jalr	-0x7ea(ra) <PT_LOAD#0+0x7e6>
  100fd8: 6522         	ld	a0, 0x8(sp)
  100fda: 8622         	mv	a2, s0
  100fdc: 85d2         	mv	a1, s4
  100fde: fffff097     	auipc	ra, 0xfffff
  100fe2: 7d4080e7     	jalr	0x7d4(ra) <PT_LOAD#0+0x7b2>
  100fe6: 6789         	lui	a5, 0x2
  100fe8: 8fa5         	xor	a5, a5, s1
  100fea: 6749         	lui	a4, 0x12
  100fec: 8ff9         	and	a5, a5, a4
  100fee: eb91         	bnez	a5, 0x101002 <PT_LOAD#0+0x1002>
  100ff0: 66e2         	ld	a3, 0x18(sp)
  100ff2: 6522         	ld	a0, 0x8(sp)
  100ff4: 864a         	mv	a2, s2
  100ff6: 02000593     	li	a1, 0x20
  100ffa: fffff097     	auipc	ra, 0xfffff
  100ffe: 7ec080e7     	jalr	0x7ec(ra) <PT_LOAD#0+0x7e6>
  101002: 8dca         	mv	s11, s2
  101004: b5dd         	j	0x100eea <PT_LOAD#0+0xeea>
  101006: 5cfd         	li	s9, -0x1
  101008: b709         	j	0x100f0a <PT_LOAD#0+0xf0a>
  10100a: 00f5f513     	andi	a0, a1, 0xf
  10100e: 957a         	add	a0, a0, t5
  101010: 00054503     	lbu	a0, 0x0(a0)
  101014: 1a7d         	addi	s4, s4, -0x1
  101016: 8191         	srli	a1, a1, 0x4
  101018: 00a36533     	or	a0, t1, a0
  10101c: 00aa0023     	sb	a0, 0x0(s4)
  101020: bdf5         	j	0x100f1c <PT_LOAD#0+0xf1c>
  101022: 00767593     	andi	a1, a2, 0x7
  101026: 95aa         	add	a1, a1, a0
  101028: 0005c583     	lbu	a1, 0x0(a1)
  10102c: 1a7d         	addi	s4, s4, -0x1
  10102e: 820d         	srli	a2, a2, 0x3
  101030: 00ba0023     	sb	a1, 0x0(s4)
  101034: f67d         	bnez	a2, 0x101022 <PT_LOAD#0+0x1022>
  101036: 0084f613     	andi	a2, s1, 0x8
  10103a: ce59         	beqz	a2, 0x1010d8 <PT_LOAD#0+0x10d8>
  10103c: 41470733     	sub	a4, a4, s4
  101040: 567d         	li	a2, -0x1
  101042: 08c74b63     	blt	a4, a2, 0x1010d8 <PT_LOAD#0+0x10d8>
  101046: 00170c9b     	addiw	s9, a4, 0x1
  10104a: 00003317     	auipc	t1, 0x3
  10104e: b9630313     	addi	t1, t1, -0x46a
  101052: ee0691e3     	bnez	a3, 0x100f34 <PT_LOAD#0+0xf34>
  101056: ec0c9fe3     	bnez	s9, 0x100f34 <PT_LOAD#0+0xf34>
  10105a: 04b10a13     	addi	s4, sp, 0x4b
  10105e: 8452         	mv	s0, s4
  101060: b5f5         	j	0x100f4c <PT_LOAD#0+0xf4c>
  101062: 04b10a13     	addi	s4, sp, 0x4b
  101066: 8636         	mv	a2, a3
  101068: 8752         	mv	a4, s4
  10106a: 00003517     	auipc	a0, 0x3
  10106e: ebe50513     	addi	a0, a0, -0x142
  101072: b7c9         	j	0x101034 <PT_LOAD#0+0x1034>
  101074: 0206d463     	bgez	a3, 0x10109c <PT_LOAD#0+0x109c>
  101078: 40d006b3     	neg	a3, a3
  10107c: 4d85         	li	s11, 0x1
  10107e: 00003317     	auipc	t1, 0x3
  101082: b6230313     	addi	t1, t1, -0x49e
  101086: 8736         	mv	a4, a3
  101088: 04b10a13     	addi	s4, sp, 0x4b
  10108c: 00003517     	auipc	a0, 0x3
  101090: e9c50513     	addi	a0, a0, -0x164
  101094: 45a9         	li	a1, 0xa
  101096: e715         	bnez	a4, 0x1010c2 <PT_LOAD#0+0x10c2>
  101098: 5cfd         	li	s9, -0x1
  10109a: bf65         	j	0x101052 <PT_LOAD#0+0x1052>
  10109c: 00b4d793     	srli	a5, s1, 0xb
  1010a0: 8b85         	andi	a5, a5, 0x1
  1010a2: eb91         	bnez	a5, 0x1010b6 <PT_LOAD#0+0x10b6>
  1010a4: 0014f793     	andi	a5, s1, 0x1
  1010a8: dbf9         	beqz	a5, 0x10107e <PT_LOAD#0+0x107e>
  1010aa: 4d85         	li	s11, 0x1
  1010ac: 00003317     	auipc	t1, 0x3
  1010b0: b3630313     	addi	t1, t1, -0x4ca
  1010b4: bfc9         	j	0x101086 <PT_LOAD#0+0x1086>
  1010b6: 4d85         	li	s11, 0x1
  1010b8: 00003317     	auipc	t1, 0x3
  1010bc: b2930313     	addi	t1, t1, -0x4d7
  1010c0: b7d9         	j	0x101086 <PT_LOAD#0+0x1086>
  1010c2: 02b77633     	<unknown>
  1010c6: 1a7d         	addi	s4, s4, -0x1
  1010c8: 962a         	add	a2, a2, a0
  1010ca: 00064603     	lbu	a2, 0x0(a2)
  1010ce: 02b75733     	<unknown>
  1010d2: 00ca0023     	sb	a2, 0x0(s4)
  1010d6: b7c1         	j	0x101096 <PT_LOAD#0+0x1096>
  1010d8: 00003317     	auipc	t1, 0x3
  1010dc: b0830313     	addi	t1, t1, -0x4f8
  1010e0: 5cfd         	li	s9, -0x1
  1010e2: bd89         	j	0x100f34 <PT_LOAD#0+0xf34>
  1010e4: 77c1         	lui	a5, 0xffff0
  1010e6: 17fd         	addi	a5, a5, -0x1
  1010e8: 04d10523     	sb	a3, 0x4a(sp)
  1010ec: 8cfd         	and	s1, s1, a5
  1010ee: 00003317     	auipc	t1, 0x3
  1010f2: af230313     	addi	t1, t1, -0x50e
  1010f6: 4c85         	li	s9, 0x1
  1010f8: 04b10413     	addi	s0, sp, 0x4b
  1010fc: 04a10a13     	addi	s4, sp, 0x4a
  101100: b5b1         	j	0x100f4c <PT_LOAD#0+0xf4c>
  101102: 00003a17     	auipc	s4, 0x3
  101106: aeea0a13     	addi	s4, s4, -0x512
  10110a: c291         	beqz	a3, 0x10110e <PT_LOAD#0+0x110e>
  10110c: 8a36         	mv	s4, a3
  10110e: 800006b7     	lui	a3, 0x80000
  101112: 4701         	li	a4, 0x0
  101114: fff6c693     	not	a3, a3
  101118: 00ea0633     	add	a2, s4, a4
  10111c: 00064603     	lbu	a2, 0x0(a2)
  101120: c601         	beqz	a2, 0x101128 <PT_LOAD#0+0x1128>
  101122: 0705         	addi	a4, a4, 0x1
  101124: fed71ae3     	bne	a4, a3, 0x101118 <PT_LOAD#0+0x1118>
  101128: 00ea0433     	add	s0, s4, a4
  10112c: 00044683     	lbu	a3, 0x0(s0)
  101130: cc0690e3     	bnez	a3, 0x100df0 <PT_LOAD#0+0xdf0>
  101134: 76c1         	lui	a3, 0xffff0
  101136: 16fd         	addi	a3, a3, -0x1
  101138: 8cf5         	and	s1, s1, a3
  10113a: 00070c9b     	sext.w	s9, a4
  10113e: 00003317     	auipc	t1, 0x3
  101142: aa230313     	addi	t1, t1, -0x55e
  101146: b519         	j	0x100f4c <PT_LOAD#0+0xf4c>
  101148: 00003317     	auipc	t1, 0x3
  10114c: a9830313     	addi	t1, t1, -0x568
  101150: 5cfd         	li	s9, -0x1
  101152: 04b10413     	addi	s0, sp, 0x4b
  101156: bbdd         	j	0x100f4c <PT_LOAD#0+0xf4c>
  101158: 67a2         	ld	a5, 0x8(sp)
  10115a: c8079ce3     	bnez	a5, 0x100df2 <PT_LOAD#0+0xdf2>
  10115e: 4981         	li	s3, 0x0
  101160: c80b89e3     	beqz	s7, 0x100df2 <PT_LOAD#0+0xdf2>
  101164: 67c2         	ld	a5, 0x10(sp)
  101166: cba1         	beqz	a5, 0x1011b6 <PT_LOAD#0+0x11b6>
  101168: 4405         	li	s0, 0x1
  10116a: 02100493     	li	s1, 0x21
  10116e: 00241793     	slli	a5, s0, 0x2
  101172: 97d6         	add	a5, a5, s5
  101174: 438c         	lw	a1, 0x0(a5)
  101176: e199         	bnez	a1, 0x10117c <PT_LOAD#0+0x117c>
  101178: 2401         	sext.w	s0, s0
  10117a: a831         	j	0x101196 <PT_LOAD#0+0x1196>
  10117c: 6642         	ld	a2, 0x10(sp)
  10117e: 00341513     	slli	a0, s0, 0x3
  101182: 955a         	add	a0, a0, s6
  101184: 0405         	addi	s0, s0, 0x1
  101186: 00000097     	auipc	ra, 0x0
  10118a: a20080e7     	jalr	-0x5e0(ra) <PT_LOAD#0+0xba6>
  10118e: fe9410e3     	bne	s0, s1, 0x10116e <PT_LOAD#0+0x116e>
  101192: 02100413     	li	s0, 0x21
  101196: 1402         	slli	s0, s0, 0x20
  101198: 9001         	srli	s0, s0, 0x20
  10119a: 02100713     	li	a4, 0x21
  10119e: 0004079b     	sext.w	a5, s0
  1011a2: 00e78a63     	beq	a5, a4, 0x1011b6 <PT_LOAD#0+0x11b6>
  1011a6: 0405         	addi	s0, s0, 0x1
  1011a8: 00241793     	slli	a5, s0, 0x2
  1011ac: 97d6         	add	a5, a5, s5
  1011ae: ffc7a783     	lw	a5, -0x4(a5)
  1011b2: d7f5         	beqz	a5, 0x10119e <PT_LOAD#0+0x119e>
  1011b4: b935         	j	0x100df0 <PT_LOAD#0+0xdf0>
  1011b6: 4985         	li	s3, 0x1
  1011b8: b92d         	j	0x100df2 <PT_LOAD#0+0xdf2>
  1011ba: 7141         	addi	sp, sp, -0x1f0
  1011bc: efbe         	sd	a5, 0x1d8(sp)
  1011be: 1b3c         	addi	a5, sp, 0x1b8
  1011c0: e7b6         	sd	a3, 0x1c8(sp)
  1011c2: ec3e         	sd	a5, 0x18(sp)
  1011c4: 1014         	addi	a3, sp, 0x20
  1011c6: fffff797     	auipc	a5, 0xfffff
  1011ca: 61c78793     	addi	a5, a5, 0x61c
  1011ce: f322         	sd	s0, 0x1a0(sp)
  1011d0: ebba         	sd	a4, 0x1d0(sp)
  1011d2: e83e         	sd	a5, 0x10(sp)
  1011d4: f706         	sd	ra, 0x1a8(sp)
  1011d6: 842a         	mv	s0, a0
  1011d8: ff2e         	sd	a1, 0x1b8(sp)
  1011da: e3b2         	sd	a2, 0x1c0(sp)
  1011dc: f3c2         	sd	a6, 0x1e0(sp)
  1011de: f7c6         	sd	a7, 0x1e8(sp)
  1011e0: 111c         	addi	a5, sp, 0xa0
  1011e2: 8736         	mv	a4, a3
  1011e4: 0006a023     	sw	zero, 0x0(a3)
  1011e8: 0691         	addi	a3, a3, 0x4
  1011ea: fef69de3     	bne	a3, a5, 0x1011e4 <PT_LOAD#0+0x11e4>
  1011ee: 0830         	addi	a2, sp, 0x18
  1011f0: 85a2         	mv	a1, s0
  1011f2: 4501         	li	a0, 0x0
  1011f4: e436         	sd	a3, 0x8(sp)
  1011f6: 00000097     	auipc	ra, 0x0
  1011fa: a1e080e7     	jalr	-0x5e2(ra) <PT_LOAD#0+0xc14>
  1011fe: 66a2         	ld	a3, 0x8(sp)
  101200: 1018         	addi	a4, sp, 0x20
  101202: 85a2         	mv	a1, s0
  101204: 0808         	addi	a0, sp, 0x10
  101206: 4601         	li	a2, 0x0
  101208: 00000097     	auipc	ra, 0x0
  10120c: a0c080e7     	jalr	-0x5f4(ra) <PT_LOAD#0+0xc14>
  101210: 70ba         	ld	ra, 0x1a8(sp)
  101212: 741a         	ld	s0, 0x1a0(sp)
  101214: 617d         	addi	sp, sp, 0x1f0
  101216: 8082         	ret
  101218: 7139         	addi	sp, sp, -0x40
  10121a: f822         	sd	s0, 0x30(sp)
  10121c: f426         	sd	s1, 0x28(sp)
  10121e: 842a         	mv	s0, a0
  101220: 84b2         	mv	s1, a2
  101222: 852e         	mv	a0, a1
  101224: 0830         	addi	a2, sp, 0x18
  101226: fffff597     	auipc	a1, 0xfffff
  10122a: e2e58593     	addi	a1, a1, -0x1d2
  10122e: e42a         	sd	a0, 0x8(sp)
  101230: fc06         	sd	ra, 0x38(sp)
  101232: fffff097     	auipc	ra, 0xfffff
  101236: fb6080e7     	jalr	-0x4a(ra) <PT_LOAD#0+0x1e8>
  10123a: 67e2         	ld	a5, 0x18(sp)
  10123c: 6522         	ld	a0, 0x8(sp)
  10123e: e789         	bnez	a5, 0x101248 <PT_LOAD#0+0x1248>
  101240: 00003097     	auipc	ra, 0x3
  101244: 83e080e7     	jalr	-0x7c2(ra) <PT_LOAD#0+0x3a7e>
  101248: c481         	beqz	s1, 0x101250 <PT_LOAD#0+0x1250>
  10124a: 4705         	li	a4, 0x1
  10124c: 0ee40423     	sb	a4, 0xe8(s0)
  101250: 6398         	ld	a4, 0x0(a5)
  101252: fc58         	sd	a4, 0xb8(s0)
  101254: 679c         	ld	a5, 0x8(a5)
  101256: e07c         	sd	a5, 0xc0(s0)
  101258: 00023797     	auipc	a5, 0x23
  10125c: 2887b783     	ld	a5, 0x288(a5)
  101260: cb99         	beqz	a5, 0x101276 <PT_LOAD#0+0x1276>
  101262: 9782         	jalr	a5
  101264: c909         	beqz	a0, 0x101276 <PT_LOAD#0+0x1276>
  101266: 7c5c         	ld	a5, 0xb8(s0)
  101268: f068         	sd	a0, 0xe0(s0)
  10126a: ec7c         	sd	a5, 0xd8(s0)
  10126c: 97aa         	add	a5, a5, a0
  10126e: fc5c         	sd	a5, 0xb8(s0)
  101270: 607c         	ld	a5, 0xc0(s0)
  101272: 8f89         	sub	a5, a5, a0
  101274: e07c         	sd	a5, 0xc0(s0)
  101276: 70e2         	ld	ra, 0x38(sp)
  101278: 7442         	ld	s0, 0x30(sp)
  10127a: 74a2         	ld	s1, 0x28(sp)
  10127c: 6121         	addi	sp, sp, 0x40
  10127e: 8082         	ret
  101280: 7179         	addi	sp, sp, -0x30
  101282: e42e         	sd	a1, 0x8(sp)
  101284: f406         	sd	ra, 0x28(sp)
  101286: f022         	sd	s0, 0x20(sp)
  101288: ec26         	sd	s1, 0x18(sp)
  10128a: 84aa         	mv	s1, a0
  10128c: fffff097     	auipc	ra, 0xfffff
  101290: fba080e7     	jalr	-0x46(ra) <PT_LOAD#0+0x246>
  101294: e02a         	sd	a0, 0x0(sp)
  101296: fffff097     	auipc	ra, 0xfffff
  10129a: 0c6080e7     	jalr	0xc6(ra) <PT_LOAD#0+0x35c>
  10129e: 57fd         	li	a5, -0x1
  1012a0: 5415         	li	s0, -0x1b
  1012a2: 17ea         	slli	a5, a5, 0x3a
  1012a4: 146a         	slli	s0, s0, 0x3a
  1012a6: 00f48733     	add	a4, s1, a5
  1012aa: 6602         	ld	a2, 0x0(sp)
  1012ac: 65a2         	ld	a1, 0x8(sp)
  1012ae: 9426         	add	s0, s0, s1
  1012b0: 00f77663     	bgeu	a4, a5, 0x1012bc <PT_LOAD#0+0x12bc>
  1012b4: 00002097     	auipc	ra, 0x2
  1012b8: 7ca080e7     	jalr	0x7ca(ra) <PT_LOAD#0+0x3a7e>
  1012bc: 00150693     	addi	a3, a0, 0x1
  1012c0: 8e91         	sub	a3, a3, a2
  1012c2: 8526         	mv	a0, s1
  1012c4: fffff097     	auipc	ra, 0xfffff
  1012c8: d64080e7     	jalr	-0x29c(ra) <PT_LOAD#0+0x28>
  1012cc: f565         	bnez	a0, 0x1012b4 <PT_LOAD#0+0x12b4>
  1012ce: 70a2         	ld	ra, 0x28(sp)
  1012d0: 8522         	mv	a0, s0
  1012d2: 7402         	ld	s0, 0x20(sp)
  1012d4: 64e2         	ld	s1, 0x18(sp)
  1012d6: 6145         	addi	sp, sp, 0x30
  1012d8: 8082         	ret
  1012da: 1101         	addi	sp, sp, -0x20
  1012dc: e426         	sd	s1, 0x8(sp)
  1012de: 61c4         	ld	s1, 0x80(a1)
  1012e0: ec06         	sd	ra, 0x18(sp)
  1012e2: e822         	sd	s0, 0x10(sp)
  1012e4: 8885         	andi	s1, s1, 0x1
  1012e6: e8a9         	bnez	s1, 0x101338 <PT_LOAD#0+0x1338>
  1012e8: 6dbc         	ld	a5, 0x58(a1)
  1012ea: 862e         	mv	a2, a1
  1012ec: 842e         	mv	s0, a1
  1012ee: 8d1d         	sub	a0, a0, a5
  1012f0: 6585         	lui	a1, 0x1
  1012f2: 00000097     	auipc	ra, 0x0
  1012f6: f8e080e7     	jalr	-0x72(ra) <PT_LOAD#0+0x1280>
  1012fa: 6705         	lui	a4, 0x1
  1012fc: 87aa         	mv	a5, a0
  1012fe: 972a         	add	a4, a4, a0
  101300: c915         	beqz	a0, 0x101334 <PT_LOAD#0+0x1334>
  101302: 00003697     	auipc	a3, 0x3
  101306: c566b683     	ld	a3, -0x3aa(a3)
  10130a: 02e7ff63     	bgeu	a5, a4, 0x101348 <PT_LOAD#0+0x1348>
  10130e: 6388         	ld	a0, 0x0(a5)
  101310: e119         	bnez	a0, 0x101316 <PT_LOAD#0+0x1316>
  101312: 4481         	li	s1, 0x0
  101314: a005         	j	0x101334 <PT_LOAD#0+0x1334>
  101316: 02d51663     	bne	a0, a3, 0x101342 <PT_LOAD#0+0x1342>
  10131a: 0197c683     	lbu	a3, 0x19(a5)
  10131e: 4705         	li	a4, 0x1
  101320: 6788         	ld	a0, 0x8(a5)
  101322: 00e69b63     	bne	a3, a4, 0x101338 <PT_LOAD#0+0x1338>
  101326: 6b84         	ld	s1, 0x10(a5)
  101328: 8622         	mv	a2, s0
  10132a: 85a6         	mv	a1, s1
  10132c: 00000097     	auipc	ra, 0x0
  101330: f54080e7     	jalr	-0xac(ra) <PT_LOAD#0+0x1280>
  101334: f408         	sd	a0, 0x28(s0)
  101336: f004         	sd	s1, 0x20(s0)
  101338: 60e2         	ld	ra, 0x18(sp)
  10133a: 6442         	ld	s0, 0x10(sp)
  10133c: 64a2         	ld	s1, 0x8(sp)
  10133e: 6105         	addi	sp, sp, 0x20
  101340: 8082         	ret
  101342: 02078793     	addi	a5, a5, 0x20
  101346: b7d1         	j	0x10130a <PT_LOAD#0+0x130a>
  101348: 4501         	li	a0, 0x0
  10134a: b7ed         	j	0x101334 <PT_LOAD#0+0x1334>
  10134c: 0145c737     	lui	a4, 0x145c
  101350: 40070693     	addi	a3, a4, 0x400
  101354: 429c         	lw	a5, 0x0(a3)
  101356: 60070713     	addi	a4, a4, 0x600
  10135a: 9bf1         	andi	a5, a5, -0x4
  10135c: 0017e793     	ori	a5, a5, 0x1
  101360: c29c         	sw	a5, 0x0(a3)
  101362: 431c         	lw	a5, 0x0(a4)
  101364: 400006b7     	lui	a3, 0x40000
  101368: 178a         	slli	a5, a5, 0x22
  10136a: 9389         	srli	a5, a5, 0x22
  10136c: 8fd5         	or	a5, a5, a3
  10136e: c31c         	sw	a5, 0x0(a4)
  101370: 00023797     	auipc	a5, 0x23
  101374: c9078793     	addi	a5, a5, -0x370
  101378: 00000717     	auipc	a4, 0x0
  10137c: 18270713     	addi	a4, a4, 0x182
  101380: 4ce7b023     	sd	a4, 0x4c0(a5)
  101384: fffff717     	auipc	a4, 0xfffff
  101388: ff270713     	addi	a4, a4, -0xe
  10138c: 4ce7b423     	sd	a4, 0x4c8(a5)
  101390: fffff717     	auipc	a4, 0xfffff
  101394: d5c70713     	addi	a4, a4, -0x2a4
  101398: 4ce7b823     	sd	a4, 0x4d0(a5)
  10139c: 00000717     	auipc	a4, 0x0
  1013a0: 14070713     	addi	a4, a4, 0x140
  1013a4: 4ce7bc23     	sd	a4, 0x4d8(a5)
  1013a8: e519         	bnez	a0, 0x1013b6 <PT_LOAD#0+0x13b6>
  1013aa: 1141         	addi	sp, sp, -0x10
  1013ac: e406         	sd	ra, 0x8(sp)
  1013ae: 00002097     	auipc	ra, 0x2
  1013b2: 6d0080e7     	jalr	0x6d0(ra) <PT_LOAD#0+0x3a7e>
  1013b6: 6178         	ld	a4, 0xc0(a0)
  1013b8: feb779e3     	bgeu	a4, a1, 0x1013aa <PT_LOAD#0+0x13aa>
  1013bc: 6574         	ld	a3, 0xc8(a0)
  1013be: 9736         	add	a4, a4, a3
  1013c0: fee5f5e3     	bgeu	a1, a4, 0x1013aa <PT_LOAD#0+0x13aa>
  1013c4: 00000717     	auipc	a4, 0x0
  1013c8: 3d470713     	addi	a4, a4, 0x3d4
  1013cc: 4ae7b423     	sd	a4, 0x4a8(a5)
  1013d0: 00000717     	auipc	a4, 0x0
  1013d4: 4f270713     	addi	a4, a4, 0x4f2
  1013d8: 4ae7b823     	sd	a4, 0x4b0(a5)
  1013dc: fffff717     	auipc	a4, 0xfffff
  1013e0: ffc70713     	addi	a4, a4, -0x4
  1013e4: 4ae7bc23     	sd	a4, 0x4b8(a5)
  1013e8: fffff717     	auipc	a4, 0xfffff
  1013ec: ffa70713     	addi	a4, a4, -0x6
  1013f0: 4ee7b023     	sd	a4, 0x4e0(a5)
  1013f4: 8082         	ret
  1013f6: 7139         	addi	sp, sp, -0x40
  1013f8: fc06         	sd	ra, 0x38(sp)
  1013fa: f822         	sd	s0, 0x30(sp)
  1013fc: f426         	sd	s1, 0x28(sp)
  1013fe: f04a         	sd	s2, 0x20(sp)
  101400: ec4e         	sd	s3, 0x18(sp)
  101402: e852         	sd	s4, 0x10(sp)
  101404: e509         	bnez	a0, 0x10140e <PT_LOAD#0+0x140e>
  101406: 00002097     	auipc	ra, 0x2
  10140a: 678080e7     	jalr	0x678(ra) <PT_LOAD#0+0x3a7e>
  10140e: 00003797     	auipc	a5, 0x3
  101412: b527b783     	ld	a5, -0x4ae(a5)
  101416: 0007a983     	lw	s3, 0x0(a5)
  10141a: 0019f993     	andi	s3, s3, 0x1
  10141e: 00099363     	bnez	s3, 0x101424 <PT_LOAD#0+0x1424>
  101422: c191         	beqz	a1, 0x101426 <PT_LOAD#0+0x1426>
  101424: 498d         	li	s3, 0x3
  101426: 12050413     	addi	s0, a0, 0x120
  10142a: 2a050913     	addi	s2, a0, 0x2a0
  10142e: 4481         	li	s1, 0x0
  101430: 01144783     	lbu	a5, 0x11(s0)
  101434: cf9d         	beqz	a5, 0x101472 <PT_LOAD#0+0x1472>
  101436: 02049a13     	slli	s4, s1, 0x20
  10143a: 0077f693     	andi	a3, a5, 0x7
  10143e: 8bc1         	andi	a5, a5, 0x10
  101440: 600c         	ld	a1, 0x0(s0)
  101442: 6410         	ld	a2, 0x8(s0)
  101444: 020a5a13     	srli	s4, s4, 0x20
  101448: e3d1         	bnez	a5, 0x1014cc <PT_LOAD#0+0x14cc>
  10144a: 8532         	mv	a0, a2
  10144c: e42e         	sd	a1, 0x8(sp)
  10144e: e036         	sd	a3, 0x0(sp)
  101450: fffff097     	auipc	ra, 0xfffff
  101454: 258080e7     	jalr	0x258(ra) <PT_LOAD#0+0x6a8>
  101458: 6682         	ld	a3, 0x0(sp)
  10145a: 65a2         	ld	a1, 0x8(sp)
  10145c: 862a         	mv	a2, a0
  10145e: 8552         	mv	a0, s4
  101460: fffff097     	auipc	ra, 0xfffff
  101464: 0e4080e7     	jalr	0xe4(ra) <PT_LOAD#0+0x544>
  101468: fd59         	bnez	a0, 0x101406 <PT_LOAD#0+0x1406>
  10146a: 2485         	addiw	s1, s1, 0x1
  10146c: 0461         	addi	s0, s0, 0x18
  10146e: fd2411e3     	bne	s0, s2, 0x101430 <PT_LOAD#0+0x1430>
  101472: fffff097     	auipc	ra, 0xfffff
  101476: eea080e7     	jalr	-0x116(ra) <PT_LOAD#0+0x35c>
  10147a: 842a         	mv	s0, a0
  10147c: fffff097     	auipc	ra, 0xfffff
  101480: dca080e7     	jalr	-0x236(ra) <PT_LOAD#0+0x246>
  101484: 00140613     	addi	a2, s0, 0x1
  101488: 8e09         	sub	a2, a2, a0
  10148a: e032         	sd	a2, 0x0(sp)
  10148c: fffff097     	auipc	ra, 0xfffff
  101490: dba080e7     	jalr	-0x246(ra) <PT_LOAD#0+0x246>
  101494: 6602         	ld	a2, 0x0(sp)
  101496: 4475         	li	s0, 0x1d
  101498: 146a         	slli	s0, s0, 0x3a
  10149a: 008505b3     	add	a1, a0, s0
  10149e: 4509         	li	a0, 0x2
  1014a0: fffff097     	auipc	ra, 0xfffff
  1014a4: 622080e7     	jalr	0x622(ra) <PT_LOAD#0+0xac2>
  1014a8: fffff097     	auipc	ra, 0xfffff
  1014ac: d9e080e7     	jalr	-0x262(ra) <PT_LOAD#0+0x246>
  1014b0: 85a2         	mv	a1, s0
  1014b2: 7442         	ld	s0, 0x30(sp)
  1014b4: 70e2         	ld	ra, 0x38(sp)
  1014b6: 74a2         	ld	s1, 0x28(sp)
  1014b8: 7902         	ld	s2, 0x20(sp)
  1014ba: 6a42         	ld	s4, 0x10(sp)
  1014bc: 862a         	mv	a2, a0
  1014be: 854e         	mv	a0, s3
  1014c0: 69e2         	ld	s3, 0x18(sp)
  1014c2: 6121         	addi	sp, sp, 0x40
  1014c4: fffff317     	auipc	t1, 0xfffff
  1014c8: 5fe30067     	jr	0x5fe(t1) <PT_LOAD#0+0xac2>
  1014cc: 8552         	mv	a0, s4
  1014ce: fffff097     	auipc	ra, 0xfffff
  1014d2: 076080e7     	jalr	0x76(ra) <PT_LOAD#0+0x544>
  1014d6: f905         	bnez	a0, 0x101406 <PT_LOAD#0+0x1406>
  1014d8: 2489         	addiw	s1, s1, 0x2
  1014da: bf49         	j	0x10146c <PT_LOAD#0+0x146c>
  1014dc: 6e38         	ld	a4, 0x58(a2)
  1014de: 723c         	ld	a5, 0x60(a2)
  1014e0: 953a         	add	a0, a0, a4
  1014e2: 97ba         	add	a5, a5, a4
  1014e4: 00e57863     	bgeu	a0, a4, 0x1014f4 <PT_LOAD#0+0x14f4>
  1014e8: 1141         	addi	sp, sp, -0x10
  1014ea: e406         	sd	ra, 0x8(sp)
  1014ec: 00002097     	auipc	ra, 0x2
  1014f0: 592080e7     	jalr	0x592(ra) <PT_LOAD#0+0x3a7e>
  1014f4: fef57ae3     	bgeu	a0, a5, 0x1014e8 <PT_LOAD#0+0x14e8>
  1014f8: 8082         	ret
  1014fa: 6dbc         	ld	a5, 0x58(a1)
  1014fc: 1101         	addi	sp, sp, -0x20
  1014fe: e426         	sd	s1, 0x8(sp)
  101500: 862e         	mv	a2, a1
  101502: 8d1d         	sub	a0, a0, a5
  101504: 84ae         	mv	s1, a1
  101506: 6585         	lui	a1, 0x1
  101508: ec06         	sd	ra, 0x18(sp)
  10150a: e822         	sd	s0, 0x10(sp)
  10150c: e04a         	sd	s2, 0x0(sp)
  10150e: 00000097     	auipc	ra, 0x0
  101512: fce080e7     	jalr	-0x32(ra) <PT_LOAD#0+0x14dc>
  101516: 6785         	lui	a5, 0x1
  101518: 97aa         	add	a5, a5, a0
  10151a: c919         	beqz	a0, 0x101530 <PT_LOAD#0+0x1530>
  10151c: 892a         	mv	s2, a0
  10151e: 00003717     	auipc	a4, 0x3
  101522: a3a73703     	ld	a4, -0x5c6(a4)
  101526: 06f97e63     	bgeu	s2, a5, 0x1015a2 <PT_LOAD#0+0x15a2>
  10152a: 00093503     	ld	a0, 0x0(s2)
  10152e: e119         	bnez	a0, 0x101534 <PT_LOAD#0+0x1534>
  101530: 4901         	li	s2, 0x0
  101532: a83d         	j	0x101570 <PT_LOAD#0+0x1570>
  101534: 06e51463     	bne	a0, a4, 0x10159c <PT_LOAD#0+0x159c>
  101538: 01994783     	lbu	a5, 0x19(s2)
  10153c: 4709         	li	a4, 0x2
  10153e: 00893403     	ld	s0, 0x8(s2)
  101542: 04e79063     	bne	a5, a4, 0x101582 <PT_LOAD#0+0x1582>
  101546: fffff097     	auipc	ra, 0xfffff
  10154a: d00080e7     	jalr	-0x300(ra) <PT_LOAD#0+0x246>
  10154e: 00a46c63     	bltu	s0, a0, 0x101566 <PT_LOAD#0+0x1566>
  101552: fffff097     	auipc	ra, 0xfffff
  101556: e0a080e7     	jalr	-0x1f6(ra) <PT_LOAD#0+0x35c>
  10155a: 00856663     	bltu	a0, s0, 0x101566 <PT_LOAD#0+0x1566>
  10155e: 00002097     	auipc	ra, 0x2
  101562: 520080e7     	jalr	0x520(ra) <PT_LOAD#0+0x3a7e>
  101566: 64bc         	ld	a5, 0x48(s1)
  101568: 01093903     	ld	s2, 0x10(s2)
  10156c: 00f40533     	add	a0, s0, a5
  101570: f488         	sd	a0, 0x28(s1)
  101572: 0324b023     	sd	s2, 0x20(s1)
  101576: 60e2         	ld	ra, 0x18(sp)
  101578: 6442         	ld	s0, 0x10(sp)
  10157a: 64a2         	ld	s1, 0x8(sp)
  10157c: 6902         	ld	s2, 0x0(sp)
  10157e: 6105         	addi	sp, sp, 0x20
  101580: 8082         	ret
  101582: 4705         	li	a4, 0x1
  101584: fee799e3     	bne	a5, a4, 0x101576 <PT_LOAD#0+0x1576>
  101588: 01093903     	ld	s2, 0x10(s2)
  10158c: 8626         	mv	a2, s1
  10158e: 8522         	mv	a0, s0
  101590: 85ca         	mv	a1, s2
  101592: 00000097     	auipc	ra, 0x0
  101596: f4a080e7     	jalr	-0xb6(ra) <PT_LOAD#0+0x14dc>
  10159a: bfd9         	j	0x101570 <PT_LOAD#0+0x1570>
  10159c: 02090913     	addi	s2, s2, 0x20
  1015a0: b759         	j	0x101526 <PT_LOAD#0+0x1526>
  1015a2: 4901         	li	s2, 0x0
  1015a4: 4501         	li	a0, 0x0
  1015a6: b7e9         	j	0x101570 <PT_LOAD#0+0x1570>
  1015a8: 1141         	addi	sp, sp, -0x10
  1015aa: 469d         	li	a3, 0x7
  1015ac: 00080637     	lui	a2, 0x80
  1015b0: 001005b7     	lui	a1, 0x100
  1015b4: 4501         	li	a0, 0x0
  1015b6: e406         	sd	ra, 0x8(sp)
  1015b8: e022         	sd	s0, 0x0(sp)
  1015ba: fffff097     	auipc	ra, 0xfffff
  1015be: f8a080e7     	jalr	-0x76(ra) <PT_LOAD#0+0x544>
  1015c2: c509         	beqz	a0, 0x1015cc <PT_LOAD#0+0x15cc>
  1015c4: 00002097     	auipc	ra, 0x2
  1015c8: 4ba080e7     	jalr	0x4ba(ra) <PT_LOAD#0+0x3a7e>
  1015cc: 468d         	li	a3, 0x3
  1015ce: 00080637     	lui	a2, 0x80
  1015d2: 001805b7     	lui	a1, 0x180
  1015d6: 4505         	li	a0, 0x1
  1015d8: fffff097     	auipc	ra, 0xfffff
  1015dc: f6c080e7     	jalr	-0x94(ra) <PT_LOAD#0+0x544>
  1015e0: f175         	bnez	a0, 0x1015c4 <PT_LOAD#0+0x15c4>
  1015e2: 4405         	li	s0, 0x1
  1015e4: c0300593     	li	a1, -0x3fd
  1015e8: 468d         	li	a3, 0x3
  1015ea: 03541613     	slli	a2, s0, 0x35
  1015ee: 15d6         	slli	a1, a1, 0x35
  1015f0: 4509         	li	a0, 0x2
  1015f2: fffff097     	auipc	ra, 0xfffff
  1015f6: f52080e7     	jalr	-0xae(ra) <PT_LOAD#0+0x544>
  1015fa: f569         	bnez	a0, 0x1015c4 <PT_LOAD#0+0x15c4>
  1015fc: 30300593     	li	a1, 0x303
  101600: 469d         	li	a3, 0x7
  101602: 03541613     	slli	a2, s0, 0x35
  101606: 15d6         	slli	a1, a1, 0x35
  101608: 450d         	li	a0, 0x3
  10160a: fffff097     	auipc	ra, 0xfffff
  10160e: f3a080e7     	jalr	-0xc6(ra) <PT_LOAD#0+0x544>
  101612: f94d         	bnez	a0, 0x1015c4 <PT_LOAD#0+0x15c4>
  101614: 468d         	li	a3, 0x3
  101616: 04000637     	lui	a2, 0x4000
  10161a: 03d41593     	slli	a1, s0, 0x3d
  10161e: 4511         	li	a0, 0x4
  101620: fffff097     	auipc	ra, 0xfffff
  101624: f24080e7     	jalr	-0xdc(ra) <PT_LOAD#0+0x544>
  101628: fd51         	bnez	a0, 0x1015c4 <PT_LOAD#0+0x15c4>
  10162a: 60a2         	ld	ra, 0x8(sp)
  10162c: 6402         	ld	s0, 0x0(sp)
  10162e: 0141         	addi	sp, sp, 0x10
  101630: 8082         	ret
  101632: 7179         	addi	sp, sp, -0x30
  101634: f022         	sd	s0, 0x20(sp)
  101636: f406         	sd	ra, 0x28(sp)
  101638: 842a         	mv	s0, a0
  10163a: e509         	bnez	a0, 0x101644 <PT_LOAD#0+0x1644>
  10163c: 00002097     	auipc	ra, 0x2
  101640: 442080e7     	jalr	0x442(ra) <PT_LOAD#0+0x3a7e>
  101644: 852e         	mv	a0, a1
  101646: d9fd         	beqz	a1, 0x10163c <PT_LOAD#0+0x163c>
  101648: 71fc         	ld	a5, 0xe0(a1)
  10164a: 07040713     	addi	a4, s0, 0x70
  10164e: 2b058693     	addi	a3, a1, 0x2b0
  101652: fc1c         	sd	a5, 0x38(s0)
  101654: 75fc         	ld	a5, 0xe8(a1)
  101656: e03c         	sd	a5, 0x40(s0)
  101658: 79dc         	ld	a5, 0xb0(a1)
  10165a: e43c         	sd	a5, 0x48(s0)
  10165c: 7ddc         	ld	a5, 0xb8(a1)
  10165e: e83c         	sd	a5, 0x50(s0)
  101660: 61fc         	ld	a5, 0xc0(a1)
  101662: ec3c         	sd	a5, 0x58(s0)
  101664: 65fc         	ld	a5, 0xc8(a1)
  101666: f430         	sd	a2, 0x68(s0)
  101668: f03c         	sd	a5, 0x60(s0)
  10166a: 719c         	ld	a5, 0x20(a1)
  10166c: e05c         	sd	a5, 0x80(s0)
  10166e: 2a058793     	addi	a5, a1, 0x2a0
  101672: 0007c603     	lbu	a2, 0x0(a5)
  101676: 0785         	addi	a5, a5, 0x1
  101678: 0705         	addi	a4, a4, 0x1
  10167a: fec70fa3     	sb	a2, -0x1(a4)
  10167e: fed79ae3     	bne	a5, a3, 0x101672 <PT_LOAD#0+0x1672>
  101682: 2b053783     	ld	a5, 0x2b0(a0)
  101686: 0830         	addi	a2, sp, 0x18
  101688: fffff597     	auipc	a1, 0xfffff
  10168c: b4658593     	addi	a1, a1, -0x4ba
  101690: e45c         	sd	a5, 0x88(s0)
  101692: 2b853783     	ld	a5, 0x2b8(a0)
  101696: e42a         	sd	a0, 0x8(sp)
  101698: e85c         	sd	a5, 0x90(s0)
  10169a: 2c052783     	lw	a5, 0x2c0(a0)
  10169e: 08f42c23     	sw	a5, 0x98(s0)
  1016a2: 2c452783     	lw	a5, 0x2c4(a0)
  1016a6: 08f42e23     	sw	a5, 0x9c(s0)
  1016aa: 697c         	ld	a5, 0xd0(a0)
  1016ac: f05c         	sd	a5, 0xa0(s0)
  1016ae: 6d7c         	ld	a5, 0xd8(a0)
  1016b0: f45c         	sd	a5, 0xa8(s0)
  1016b2: 695c         	ld	a5, 0x90(a0)
  1016b4: f85c         	sd	a5, 0xb0(s0)
  1016b6: 6d5c         	ld	a5, 0x98(a0)
  1016b8: fc5c         	sd	a5, 0xb8(s0)
  1016ba: 715c         	ld	a5, 0xa0(a0)
  1016bc: e07c         	sd	a5, 0xc0(s0)
  1016be: 755c         	ld	a5, 0xa8(a0)
  1016c0: e47c         	sd	a5, 0xc8(s0)
  1016c2: fffff097     	auipc	ra, 0xfffff
  1016c6: b26080e7     	jalr	-0x4da(ra) <PT_LOAD#0+0x1e8>
  1016ca: 67e2         	ld	a5, 0x18(sp)
  1016cc: 6522         	ld	a0, 0x8(sp)
  1016ce: cb95         	beqz	a5, 0x101702 <PT_LOAD#0+0x1702>
  1016d0: 6398         	ld	a4, 0x0(a5)
  1016d2: e878         	sd	a4, 0xd0(s0)
  1016d4: 679c         	ld	a5, 0x8(a5)
  1016d6: ec7c         	sd	a5, 0xd8(s0)
  1016d8: 0830         	addi	a2, sp, 0x18
  1016da: fffff597     	auipc	a1, 0xfffff
  1016de: afc58593     	addi	a1, a1, -0x504
  1016e2: fffff097     	auipc	ra, 0xfffff
  1016e6: b06080e7     	jalr	-0x4fa(ra) <PT_LOAD#0+0x1e8>
  1016ea: 67e2         	ld	a5, 0x18(sp)
  1016ec: dba1         	beqz	a5, 0x10163c <PT_LOAD#0+0x163c>
  1016ee: 6398         	ld	a4, 0x0(a5)
  1016f0: 70a2         	ld	ra, 0x28(sp)
  1016f2: 10e43823     	sd	a4, 0x110(s0)
  1016f6: 679c         	ld	a5, 0x8(a5)
  1016f8: 10f43c23     	sd	a5, 0x118(s0)
  1016fc: 7402         	ld	s0, 0x20(sp)
  1016fe: 6145         	addi	sp, sp, 0x30
  101700: 8082         	ret
  101702: 0c043823     	sd	zero, 0xd0(s0)
  101706: 0c043c23     	sd	zero, 0xd8(s0)
  10170a: b7f9         	j	0x1016d8 <PT_LOAD#0+0x16d8>
  10170c: 1101         	addi	sp, sp, -0x20
  10170e: 6789         	lui	a5, 0x2
  101710: ec06         	sd	ra, 0x18(sp)
  101712: e822         	sd	s0, 0x10(sp)
  101714: e426         	sd	s1, 0x8(sp)
  101716: 50078793     	addi	a5, a5, 0x500
  10171a: e11c         	sd	a5, 0x0(a0)
  10171c: 6785         	lui	a5, 0x1
  10171e: e51c         	sd	a5, 0x8(a0)
  101720: 10078793     	addi	a5, a5, 0x100
  101724: e91c         	sd	a5, 0x10(a0)
  101726: 47c1         	li	a5, 0x10
  101728: f91c         	sd	a5, 0x30(a0)
  10172a: 00053c23     	sd	zero, 0x18(a0)
  10172e: 842a         	mv	s0, a0
  101730: 84ae         	mv	s1, a1
  101732: 00000097     	auipc	ra, 0x0
  101736: f00080e7     	jalr	-0x100(ra) <PT_LOAD#0+0x1632>
  10173a: 2c84d783     	lhu	a5, 0x2c8(s1)
  10173e: 00180737     	lui	a4, 0x180
  101742: 85a6         	mv	a1, s1
  101744: 0047979b     	slliw	a5, a5, 0x4
  101748: 9fb9         	addw	a5, a5, a4
  10174a: 12f43823     	sd	a5, 0x130(s0)
  10174e: 2ca4d783     	lhu	a5, 0x2ca(s1)
  101752: 06840513     	addi	a0, s0, 0x68
  101756: 4601         	li	a2, 0x0
  101758: 12f43c23     	sd	a5, 0x138(s0)
  10175c: 00000097     	auipc	ra, 0x0
  101760: abc080e7     	jalr	-0x544(ra) <PT_LOAD#0+0x1218>
  101764: 00003797     	auipc	a5, 0x3
  101768: 8047b783     	ld	a5, -0x7fc(a5)
  10176c: 439c         	lw	a5, 0x0(a5)
  10176e: 60e2         	ld	ra, 0x18(sp)
  101770: 64a2         	ld	s1, 0x8(sp)
  101772: 0047d79b     	srliw	a5, a5, 0x4
  101776: 07b2         	slli	a5, a5, 0xc
  101778: 14f43c23     	sd	a5, 0x158(s0)
  10177c: 00f037b3     	snez	a5, a5
  101780: 0017979b     	slliw	a5, a5, 0x1
  101784: 16f42023     	sw	a5, 0x160(s0)
  101788: 015007b7     	lui	a5, 0x1500
  10178c: f07c         	sd	a5, 0xe0(s0)
  10178e: 6791         	lui	a5, 0x4
  101790: f47c         	sd	a5, 0xe8(s0)
  101792: 6442         	ld	s0, 0x10(sp)
  101794: 6105         	addi	sp, sp, 0x20
  101796: 8082         	ret
  101798: 1101         	addi	sp, sp, -0x20
  10179a: 6789         	lui	a5, 0x2
  10179c: ec06         	sd	ra, 0x18(sp)
  10179e: e822         	sd	s0, 0x10(sp)
  1017a0: e426         	sd	s1, 0x8(sp)
  1017a2: 50078793     	addi	a5, a5, 0x500
  1017a6: e11c         	sd	a5, 0x0(a0)
  1017a8: 6785         	lui	a5, 0x1
  1017aa: e51c         	sd	a5, 0x8(a0)
  1017ac: 10078793     	addi	a5, a5, 0x100
  1017b0: e91c         	sd	a5, 0x10(a0)
  1017b2: 47c1         	li	a5, 0x10
  1017b4: f91c         	sd	a5, 0x30(a0)
  1017b6: 00053c23     	sd	zero, 0x18(a0)
  1017ba: 842a         	mv	s0, a0
  1017bc: 84ae         	mv	s1, a1
  1017be: 00000097     	auipc	ra, 0x0
  1017c2: e74080e7     	jalr	-0x18c(ra) <PT_LOAD#0+0x1632>
  1017c6: 2c84d783     	lhu	a5, 0x2c8(s1)
  1017ca: 00180737     	lui	a4, 0x180
  1017ce: 85a6         	mv	a1, s1
  1017d0: 0047979b     	slliw	a5, a5, 0x4
  1017d4: 9fb9         	addw	a5, a5, a4
  1017d6: 12f43823     	sd	a5, 0x130(s0)
  1017da: 2ca4d783     	lhu	a5, 0x2ca(s1)
  1017de: 06840513     	addi	a0, s0, 0x68
  1017e2: 4605         	li	a2, 0x1
  1017e4: 12f43c23     	sd	a5, 0x138(s0)
  1017e8: 00000097     	auipc	ra, 0x0
  1017ec: a30080e7     	jalr	-0x5d0(ra) <PT_LOAD#0+0x1218>
  1017f0: 00002797     	auipc	a5, 0x2
  1017f4: 7787b783     	ld	a5, 0x778(a5)
  1017f8: 439c         	lw	a5, 0x0(a5)
  1017fa: 01580737     	lui	a4, 0x1580
  1017fe: 60e2         	ld	ra, 0x18(sp)
  101800: 0047d79b     	srliw	a5, a5, 0x4
  101804: 07b2         	slli	a5, a5, 0xc
  101806: 14f43c23     	sd	a5, 0x158(s0)
  10180a: 00f037b3     	snez	a5, a5
  10180e: 0017979b     	slliw	a5, a5, 0x1
  101812: 16f42023     	sw	a5, 0x160(s0)
  101816: 015007b7     	lui	a5, 0x1500
  10181a: f07c         	sd	a5, 0xe0(s0)
  10181c: 000407b7     	lui	a5, 0x40
  101820: f47c         	sd	a5, 0xe8(s0)
  101822: f878         	sd	a4, 0xf0(s0)
  101824: fc7c         	sd	a5, 0xf8(s0)
  101826: 6442         	ld	s0, 0x10(sp)
  101828: 64a2         	ld	s1, 0x8(sp)
  10182a: 6105         	addi	sp, sp, 0x20
  10182c: 8082         	ret
  10182e: 1141         	addi	sp, sp, -0x10
  101830: e022         	sd	s0, 0x0(sp)
  101832: e406         	sd	ra, 0x8(sp)
  101834: 842a         	mv	s0, a0
  101836: 00000097     	auipc	ra, 0x0
  10183a: f62080e7     	jalr	-0x9e(ra) <PT_LOAD#0+0x1798>
  10183e: 100007b7     	lui	a5, 0x10000
  101842: 60a2         	ld	ra, 0x8(sp)
  101844: f45c         	sd	a5, 0xa8(s0)
  101846: 6402         	ld	s0, 0x0(sp)
  101848: 0141         	addi	sp, sp, 0x10
  10184a: 8082         	ret
  10184c: 1141         	addi	sp, sp, -0x10
  10184e: e022         	sd	s0, 0x0(sp)
  101850: e406         	sd	ra, 0x8(sp)
  101852: 842a         	mv	s0, a0
  101854: 00000097     	auipc	ra, 0x0
  101858: f44080e7     	jalr	-0xbc(ra) <PT_LOAD#0+0x1798>
  10185c: 4785         	li	a5, 0x1
  10185e: 18f40c23     	sb	a5, 0x198(s0)
  101862: 60a2         	ld	ra, 0x8(sp)
  101864: 04043423     	sd	zero, 0x48(s0)
  101868: 04043823     	sd	zero, 0x50(s0)
  10186c: 6402         	ld	s0, 0x0(sp)
  10186e: 0141         	addi	sp, sp, 0x10
  101870: 8082         	ret
  101872: 1141         	addi	sp, sp, -0x10
  101874: e406         	sd	ra, 0x8(sp)
  101876: e022         	sd	s0, 0x0(sp)
  101878: 842a         	mv	s0, a0
  10187a: 00000097     	auipc	ra, 0x0
  10187e: fd2080e7     	jalr	-0x2e(ra) <PT_LOAD#0+0x184c>
  101882: 040007b7     	lui	a5, 0x4000
  101886: f45c         	sd	a5, 0xa8(s0)
  101888: 4785         	li	a5, 0x1
  10188a: 18f40423     	sb	a5, 0x188(s0)
  10188e: fffff097     	auipc	ra, 0xfffff
  101892: ace080e7     	jalr	-0x532(ra) <PT_LOAD#0+0x35c>
  101896: 0505         	addi	a0, a0, 0x1
  101898: 60a2         	ld	ra, 0x8(sp)
  10189a: 18a43823     	sd	a0, 0x190(s0)
  10189e: 6402         	ld	s0, 0x0(sp)
  1018a0: 0141         	addi	sp, sp, 0x10
  1018a2: 8082         	ret
  1018a4: 1141         	addi	sp, sp, -0x10
  1018a6: e022         	sd	s0, 0x0(sp)
  1018a8: e406         	sd	ra, 0x8(sp)
  1018aa: 842a         	mv	s0, a0
  1018ac: 00000097     	auipc	ra, 0x0
  1018b0: eec080e7     	jalr	-0x114(ra) <PT_LOAD#0+0x1798>
  1018b4: 040007b7     	lui	a5, 0x4000
  1018b8: 60a2         	ld	ra, 0x8(sp)
  1018ba: f45c         	sd	a5, 0xa8(s0)
  1018bc: 6402         	ld	s0, 0x0(sp)
  1018be: 0141         	addi	sp, sp, 0x10
  1018c0: 8082         	ret
  1018c2: 7139         	addi	sp, sp, -0x40
  1018c4: fc06         	sd	ra, 0x38(sp)
  1018c6: f822         	sd	s0, 0x30(sp)
  1018c8: f426         	sd	s1, 0x28(sp)
  1018ca: f04a         	sd	s2, 0x20(sp)
  1018cc: ec4e         	sd	s3, 0x18(sp)
  1018ce: e852         	sd	s4, 0x10(sp)
  1018d0: e509         	bnez	a0, 0x1018da <PT_LOAD#0+0x18da>
  1018d2: 00002097     	auipc	ra, 0x2
  1018d6: 1ac080e7     	jalr	0x1ac(ra) <PT_LOAD#0+0x3a7e>
  1018da: 4785         	li	a5, 0x1
  1018dc: 17f6         	slli	a5, a5, 0x3d
  1018de: 5907a403     	lw	s0, 0x590(a5)
  1018e2: 8805         	andi	s0, s0, 0x1
  1018e4: c011         	beqz	s0, 0x1018e8 <PT_LOAD#0+0x18e8>
  1018e6: 440d         	li	s0, 0x3
  1018e8: 12050493     	addi	s1, a0, 0x120
  1018ec: 2a050993     	addi	s3, a0, 0x2a0
  1018f0: 4901         	li	s2, 0x0
  1018f2: 0114c783     	lbu	a5, 0x11(s1)
  1018f6: cf9d         	beqz	a5, 0x101934 <PT_LOAD#0+0x1934>
  1018f8: 02091a13     	slli	s4, s2, 0x20
  1018fc: 0077f693     	andi	a3, a5, 0x7
  101900: 8bc1         	andi	a5, a5, 0x10
  101902: 608c         	ld	a1, 0x0(s1)
  101904: 6490         	ld	a2, 0x8(s1)
  101906: 020a5a13     	srli	s4, s4, 0x20
  10190a: e3d5         	bnez	a5, 0x1019ae <PT_LOAD#0+0x19ae>
  10190c: 8532         	mv	a0, a2
  10190e: e42e         	sd	a1, 0x8(sp)
  101910: e036         	sd	a3, 0x0(sp)
  101912: fffff097     	auipc	ra, 0xfffff
  101916: d96080e7     	jalr	-0x26a(ra) <PT_LOAD#0+0x6a8>
  10191a: 6682         	ld	a3, 0x0(sp)
  10191c: 65a2         	ld	a1, 0x8(sp)
  10191e: 862a         	mv	a2, a0
  101920: 8552         	mv	a0, s4
  101922: fffff097     	auipc	ra, 0xfffff
  101926: c22080e7     	jalr	-0x3de(ra) <PT_LOAD#0+0x544>
  10192a: f545         	bnez	a0, 0x1018d2 <PT_LOAD#0+0x18d2>
  10192c: 2905         	addiw	s2, s2, 0x1
  10192e: 04e1         	addi	s1, s1, 0x18
  101930: fd3491e3     	bne	s1, s3, 0x1018f2 <PT_LOAD#0+0x18f2>
  101934: fffff097     	auipc	ra, 0xfffff
  101938: a28080e7     	jalr	-0x5d8(ra) <PT_LOAD#0+0x35c>
  10193c: 84aa         	mv	s1, a0
  10193e: fffff097     	auipc	ra, 0xfffff
  101942: 908080e7     	jalr	-0x6f8(ra) <PT_LOAD#0+0x246>
  101946: 00148613     	addi	a2, s1, 0x1
  10194a: 8e09         	sub	a2, a2, a0
  10194c: e032         	sd	a2, 0x0(sp)
  10194e: fffff097     	auipc	ra, 0xfffff
  101952: 8f8080e7     	jalr	-0x708(ra) <PT_LOAD#0+0x246>
  101956: 6602         	ld	a2, 0x0(sp)
  101958: 44f5         	li	s1, 0x1d
  10195a: 14ea         	slli	s1, s1, 0x3a
  10195c: 009505b3     	add	a1, a0, s1
  101960: 4509         	li	a0, 0x2
  101962: fffff097     	auipc	ra, 0xfffff
  101966: 160080e7     	jalr	0x160(ra) <PT_LOAD#0+0xac2>
  10196a: 1402         	slli	s0, s0, 0x20
  10196c: fffff097     	auipc	ra, 0xfffff
  101970: 8da080e7     	jalr	-0x726(ra) <PT_LOAD#0+0x246>
  101974: 9001         	srli	s0, s0, 0x20
  101976: 862a         	mv	a2, a0
  101978: 85a6         	mv	a1, s1
  10197a: 8522         	mv	a0, s0
  10197c: fffff097     	auipc	ra, 0xfffff
  101980: 146080e7     	jalr	0x146(ra) <PT_LOAD#0+0xac2>
  101984: fffff097     	auipc	ra, 0xfffff
  101988: 9d8080e7     	jalr	-0x628(ra) <PT_LOAD#0+0x35c>
  10198c: 009505b3     	add	a1, a0, s1
  101990: 8522         	mv	a0, s0
  101992: 7442         	ld	s0, 0x30(sp)
  101994: 70e2         	ld	ra, 0x38(sp)
  101996: 74a2         	ld	s1, 0x28(sp)
  101998: 7902         	ld	s2, 0x20(sp)
  10199a: 69e2         	ld	s3, 0x18(sp)
  10199c: 6a42         	ld	s4, 0x10(sp)
  10199e: 463d         	li	a2, 0xf
  1019a0: 166e         	slli	a2, a2, 0x3b
  1019a2: 8e0d         	sub	a2, a2, a1
  1019a4: 6121         	addi	sp, sp, 0x40
  1019a6: fffff317     	auipc	t1, 0xfffff
  1019aa: 11c30067     	jr	0x11c(t1) <PT_LOAD#0+0xac2>
  1019ae: 8552         	mv	a0, s4
  1019b0: fffff097     	auipc	ra, 0xfffff
  1019b4: b94080e7     	jalr	-0x46c(ra) <PT_LOAD#0+0x544>
  1019b8: fd09         	bnez	a0, 0x1018d2 <PT_LOAD#0+0x18d2>
  1019ba: 2909         	addiw	s2, s2, 0x2
  1019bc: bf8d         	j	0x10192e <PT_LOAD#0+0x192e>
  1019be: 7139         	addi	sp, sp, -0x40
  1019c0: fc06         	sd	ra, 0x38(sp)
  1019c2: f822         	sd	s0, 0x30(sp)
  1019c4: f426         	sd	s1, 0x28(sp)
  1019c6: f04a         	sd	s2, 0x20(sp)
  1019c8: ec4e         	sd	s3, 0x18(sp)
  1019ca: ed09         	bnez	a0, 0x1019e4 <PT_LOAD#0+0x19e4>
  1019cc: 00002097     	auipc	ra, 0x2
  1019d0: 0b2080e7     	jalr	0xb2(ra) <PT_LOAD#0+0x3a7e>
  1019d4: 854e         	mv	a0, s3
  1019d6: fffff097     	auipc	ra, 0xfffff
  1019da: b6e080e7     	jalr	-0x492(ra) <PT_LOAD#0+0x544>
  1019de: f57d         	bnez	a0, 0x1019cc <PT_LOAD#0+0x19cc>
  1019e0: 2909         	addiw	s2, s2, 0x2
  1019e2: a0a1         	j	0x101a2a <PT_LOAD#0+0x1a2a>
  1019e4: 12050493     	addi	s1, a0, 0x120
  1019e8: 2a050413     	addi	s0, a0, 0x2a0
  1019ec: 4901         	li	s2, 0x0
  1019ee: 0114c783     	lbu	a5, 0x11(s1)
  1019f2: cf9d         	beqz	a5, 0x101a30 <PT_LOAD#0+0x1a30>
  1019f4: 02091993     	slli	s3, s2, 0x20
  1019f8: 0077f693     	andi	a3, a5, 0x7
  1019fc: 8bc1         	andi	a5, a5, 0x10
  1019fe: 608c         	ld	a1, 0x0(s1)
  101a00: 6490         	ld	a2, 0x8(s1)
  101a02: 0209d993     	srli	s3, s3, 0x20
  101a06: f7f9         	bnez	a5, 0x1019d4 <PT_LOAD#0+0x19d4>
  101a08: 8532         	mv	a0, a2
  101a0a: e436         	sd	a3, 0x8(sp)
  101a0c: e02e         	sd	a1, 0x0(sp)
  101a0e: fffff097     	auipc	ra, 0xfffff
  101a12: c9a080e7     	jalr	-0x366(ra) <PT_LOAD#0+0x6a8>
  101a16: 66a2         	ld	a3, 0x8(sp)
  101a18: 6582         	ld	a1, 0x0(sp)
  101a1a: 862a         	mv	a2, a0
  101a1c: 854e         	mv	a0, s3
  101a1e: fffff097     	auipc	ra, 0xfffff
  101a22: b26080e7     	jalr	-0x4da(ra) <PT_LOAD#0+0x544>
  101a26: f15d         	bnez	a0, 0x1019cc <PT_LOAD#0+0x19cc>
  101a28: 2905         	addiw	s2, s2, 0x1
  101a2a: 04e1         	addi	s1, s1, 0x18
  101a2c: fc8491e3     	bne	s1, s0, 0x1019ee <PT_LOAD#0+0x19ee>
  101a30: fffff097     	auipc	ra, 0xfffff
  101a34: 92c080e7     	jalr	-0x6d4(ra) <PT_LOAD#0+0x35c>
  101a38: 842a         	mv	s0, a0
  101a3a: fffff097     	auipc	ra, 0xfffff
  101a3e: 80c080e7     	jalr	-0x7f4(ra) <PT_LOAD#0+0x246>
  101a42: 00140613     	addi	a2, s0, 0x1
  101a46: 8e09         	sub	a2, a2, a0
  101a48: e032         	sd	a2, 0x0(sp)
  101a4a: ffffe097     	auipc	ra, 0xffffe
  101a4e: 7fc080e7     	jalr	0x7fc(ra) <PT_LOAD#0+0x246>
  101a52: 6602         	ld	a2, 0x0(sp)
  101a54: 5415         	li	s0, -0x1b
  101a56: 146a         	slli	s0, s0, 0x3a
  101a58: 008505b3     	add	a1, a0, s0
  101a5c: 4509         	li	a0, 0x2
  101a5e: fffff097     	auipc	ra, 0xfffff
  101a62: 064080e7     	jalr	0x64(ra) <PT_LOAD#0+0xac2>
  101a66: ffffe097     	auipc	ra, 0xffffe
  101a6a: 7e0080e7     	jalr	0x7e0(ra) <PT_LOAD#0+0x246>
  101a6e: 862a         	mv	a2, a0
  101a70: 85a2         	mv	a1, s0
  101a72: 4501         	li	a0, 0x0
  101a74: fffff097     	auipc	ra, 0xfffff
  101a78: 04e080e7     	jalr	0x4e(ra) <PT_LOAD#0+0xac2>
  101a7c: fffff097     	auipc	ra, 0xfffff
  101a80: 8e0080e7     	jalr	-0x720(ra) <PT_LOAD#0+0x35c>
  101a84: 008505b3     	add	a1, a0, s0
  101a88: 7442         	ld	s0, 0x30(sp)
  101a8a: 70e2         	ld	ra, 0x38(sp)
  101a8c: 74a2         	ld	s1, 0x28(sp)
  101a8e: 7902         	ld	s2, 0x20(sp)
  101a90: 69e2         	ld	s3, 0x18(sp)
  101a92: 564d         	li	a2, -0xd
  101a94: 166e         	slli	a2, a2, 0x3b
  101a96: 8e0d         	sub	a2, a2, a1
  101a98: 4501         	li	a0, 0x0
  101a9a: 6121         	addi	sp, sp, 0x40
  101a9c: fffff317     	auipc	t1, 0xfffff
  101aa0: 02630067     	jr	0x26(t1) <PT_LOAD#0+0xac2>
  101aa4: 0001f617     	auipc	a2, 0x1f
  101aa8: 56460613     	addi	a2, a2, 0x564
  101aac: 421c         	lw	a5, 0x0(a2)
  101aae: 1101         	addi	sp, sp, -0x20
  101ab0: e822         	sd	s0, 0x10(sp)
  101ab2: 02079713     	slli	a4, a5, 0x20
  101ab6: 4240         	lw	s0, 0x4(a2)
  101ab8: 01575693     	srli	a3, a4, 0x15
  101abc: 6585         	lui	a1, 0x1
  101abe: 00043717     	auipc	a4, 0x43
  101ac2: 14270713     	addi	a4, a4, 0x142
  101ac6: 96ba         	add	a3, a3, a4
  101ac8: ec06         	sd	ra, 0x18(sp)
  101aca: 4701         	li	a4, 0x0
  101acc: 03f00513     	li	a0, 0x3f
  101ad0: 4805         	li	a6, 0x1
  101ad2: 80058593     	addi	a1, a1, -0x800
  101ad6: 04f57c63     	bgeu	a0, a5, 0x101b2e <PT_LOAD#0+0x1b2e>
  101ada: c311         	beqz	a4, 0x101ade <PT_LOAD#0+0x1ade>
  101adc: c21c         	sw	a5, 0x0(a2)
  101ade: 4785         	li	a5, 0x1
  101ae0: 0006a717     	auipc	a4, 0x6a
  101ae4: 58f72823     	sw	a5, 0x590(a4)
  101ae8: 80000737     	lui	a4, 0x80000
  101aec: 00023797     	auipc	a5, 0x23
  101af0: a047b783     	ld	a5, -0x5fc(a5)
  101af4: 56fd         	li	a3, -0x1
  101af6: c398         	sw	a4, 0x0(a5)
  101af8: 9281         	srli	a3, a3, 0x20
  101afa: 0001f797     	auipc	a5, 0x1f
  101afe: 5067b783     	ld	a5, 0x506(a5)
  101b02: 06d78563     	beq	a5, a3, 0x101b6c <PT_LOAD#0+0x1b6c>
  101b06: 85be         	mv	a1, a5
  101b08: 0006c617     	auipc	a2, 0x6c
  101b0c: 41860613     	addi	a2, a2, 0x418
  101b10: 4509         	li	a0, 0x2
  101b12: e43e         	sd	a5, 0x8(sp)
  101b14: fffff097     	auipc	ra, 0xfffff
  101b18: fd8080e7     	jalr	-0x28(ra) <PT_LOAD#0+0xaec>
  101b1c: 02041713     	slli	a4, s0, 0x20
  101b20: 67a2         	ld	a5, 0x8(sp)
  101b22: 9301         	srli	a4, a4, 0x20
  101b24: 4681         	li	a3, 0x0
  101b26: 4601         	li	a2, 0x0
  101b28: 4581         	li	a1, 0x0
  101b2a: 4541         	li	a0, 0x10
  101b2c: a825         	j	0x101b64 <PT_LOAD#0+0x1b64>
  101b2e: 0146a883     	lw	a7, 0x14(a3)
  101b32: 0017871b     	addiw	a4, a5, 0x1
  101b36: 01089463     	bne	a7, a6, 0x101b3e <PT_LOAD#0+0x1b3e>
  101b3a: 00f41763     	bne	s0, a5, 0x101b48 <PT_LOAD#0+0x1b48>
  101b3e: 0007079b     	sext.w	a5, a4
  101b42: 96ae         	add	a3, a3, a1
  101b44: 4705         	li	a4, 0x1
  101b46: bf41         	j	0x101ad6 <PT_LOAD#0+0x1ad6>
  101b48: c218         	sw	a4, 0x0(a2)
  101b4a: 470d         	li	a4, 0x3
  101b4c: 0006a697     	auipc	a3, 0x6a
  101b50: 52e6a223     	sw	a4, 0x524(a3)
  101b54: 1782         	slli	a5, a5, 0x20
  101b56: 9381         	srli	a5, a5, 0x20
  101b58: 4701         	li	a4, 0x0
  101b5a: 4681         	li	a3, 0x0
  101b5c: 4601         	li	a2, 0x0
  101b5e: 4581         	li	a1, 0x0
  101b60: 03500513     	li	a0, 0x35
  101b64: 00002097     	auipc	ra, 0x2
  101b68: f0c080e7     	jalr	-0xf4(ra) <PT_LOAD#0+0x3a70>
  101b6c: 0006c597     	auipc	a1, 0x6c
  101b70: 3cc58593     	addi	a1, a1, 0x3cc
  101b74: 4505         	li	a0, 0x1
  101b76: fffff097     	auipc	ra, 0xfffff
  101b7a: f76080e7     	jalr	-0x8a(ra) <PT_LOAD#0+0xaec>
  101b7e: 00002097     	auipc	ra, 0x2
  101b82: f00080e7     	jalr	-0x100(ra) <PT_LOAD#0+0x3a7e>
  101b86: 1141         	addi	sp, sp, -0x10
  101b88: 0006c597     	auipc	a1, 0x6c
  101b8c: 3c858593     	addi	a1, a1, 0x3c8
  101b90: 4505         	li	a0, 0x1
  101b92: e406         	sd	ra, 0x8(sp)
  101b94: fffff097     	auipc	ra, 0xfffff
  101b98: f58080e7     	jalr	-0xa8(ra) <PT_LOAD#0+0xaec>
  101b9c: 00002097     	auipc	ra, 0x2
  101ba0: ee2080e7     	jalr	-0x11e(ra) <PT_LOAD#0+0x3a7e>
  101ba4: 1502         	slli	a0, a0, 0x20
  101ba6: 9101         	srli	a0, a0, 0x20
  101ba8: 00043717     	auipc	a4, 0x43
  101bac: 05870713     	addi	a4, a4, 0x58
  101bb0: 00b51813     	slli	a6, a0, 0xb
  101bb4: 983a         	add	a6, a6, a4
  101bb6: 00085683     	lhu	a3, 0x0(a6)
  101bba: 40d007b3     	neg	a5, a3
  101bbe: 8ff5         	and	a5, a5, a3
  101bc0: c3ad         	beqz	a5, 0x101c22 <PT_LOAD#0+0x1c22>
  101bc2: 00002617     	auipc	a2, 0x2
  101bc6: 38e63603     	ld	a2, 0x38e(a2)
  101bca: 02c78633     	<unknown>
  101bce: 00002897     	auipc	a7, 0x2
  101bd2: 1ba88893     	addi	a7, a7, 0x1ba
  101bd6: 051a         	slli	a0, a0, 0x6
  101bd8: fff7c793     	not	a5, a5
  101bdc: 8efd         	and	a3, a3, a5
  101bde: 9269         	srli	a2, a2, 0x3a
  101be0: 9646         	add	a2, a2, a7
  101be2: 00064603     	lbu	a2, 0x0(a2)
  101be6: 9532         	add	a0, a0, a2
  101be8: 0505         	addi	a0, a0, 0x1
  101bea: 0516         	slli	a0, a0, 0x5
  101bec: 972a         	add	a4, a4, a0
  101bee: 4b1c         	lw	a5, 0x10(a4)
  101bf0: e190         	sd	a2, 0x0(a1)
  101bf2: 00d81023     	sh	a3, 0x0(a6)
  101bf6: c395         	beqz	a5, 0x101c1a <PT_LOAD#0+0x1c1a>
  101bf8: 1141         	addi	sp, sp, -0x10
  101bfa: 0006c617     	auipc	a2, 0x6c
  101bfe: 36e60613     	addi	a2, a2, 0x36e
  101c02: 1c600593     	li	a1, 0x1c6
  101c06: 4509         	li	a0, 0x2
  101c08: e406         	sd	ra, 0x8(sp)
  101c0a: fffff097     	auipc	ra, 0xfffff
  101c0e: ee2080e7     	jalr	-0x11e(ra) <PT_LOAD#0+0xaec>
  101c12: 00000097     	auipc	ra, 0x0
  101c16: f74080e7     	jalr	-0x8c(ra) <PT_LOAD#0+0x1b86>
  101c1a: 4785         	li	a5, 0x1
  101c1c: cb1c         	sw	a5, 0x10(a4)
  101c1e: 4501         	li	a0, 0x0
  101c20: 8082         	ret
  101c22: 4519         	li	a0, 0x6
  101c24: 8082         	ret
  101c26: 1502         	slli	a0, a0, 0x20
  101c28: 9101         	srli	a0, a0, 0x20
  101c2a: 00043697     	auipc	a3, 0x43
  101c2e: fd668693     	addi	a3, a3, -0x2a
  101c32: 00b51813     	slli	a6, a0, 0xb
  101c36: 9836         	add	a6, a6, a3
  101c38: 00085603     	lhu	a2, 0x0(a6)
  101c3c: 0016579b     	srliw	a5, a2, 0x1
  101c40: 8ff1         	and	a5, a5, a2
  101c42: 40f00733     	neg	a4, a5
  101c46: 8f7d         	and	a4, a4, a5
  101c48: cf2d         	beqz	a4, 0x101cc2 <PT_LOAD#0+0x1cc2>
  101c4a: 00002797     	auipc	a5, 0x2
  101c4e: 3067b783     	ld	a5, 0x306(a5)
  101c52: 02f707b3     	<unknown>
  101c56: 00002897     	auipc	a7, 0x2
  101c5a: 13288893     	addi	a7, a7, 0x132
  101c5e: 051a         	slli	a0, a0, 0x6
  101c60: 93e9         	srli	a5, a5, 0x3a
  101c62: 97c6         	add	a5, a5, a7
  101c64: 0007c783     	lbu	a5, 0x0(a5)
  101c68: e19c         	sd	a5, 0x0(a1)
  101c6a: 458d         	li	a1, 0x3
  101c6c: 02b7073b     	<unknown>
  101c70: fff74713     	not	a4, a4
  101c74: 8e79         	and	a2, a2, a4
  101c76: 00f50733     	add	a4, a0, a5
  101c7a: 0705         	addi	a4, a4, 0x1
  101c7c: 0716         	slli	a4, a4, 0x5
  101c7e: 9736         	add	a4, a4, a3
  101c80: 00c81023     	sh	a2, 0x0(a6)
  101c84: 4b10         	lw	a2, 0x10(a4)
  101c86: e619         	bnez	a2, 0x101c94 <PT_LOAD#0+0x1c94>
  101c88: 97aa         	add	a5, a5, a0
  101c8a: 0789         	addi	a5, a5, 0x2
  101c8c: 0796         	slli	a5, a5, 0x5
  101c8e: 96be         	add	a3, a3, a5
  101c90: 4a9c         	lw	a5, 0x10(a3)
  101c92: c395         	beqz	a5, 0x101cb6 <PT_LOAD#0+0x1cb6>
  101c94: 1141         	addi	sp, sp, -0x10
  101c96: 0006c617     	auipc	a2, 0x6c
  101c9a: 2ea60613     	addi	a2, a2, 0x2ea
  101c9e: 1da00593     	li	a1, 0x1da
  101ca2: 4509         	li	a0, 0x2
  101ca4: e406         	sd	ra, 0x8(sp)
  101ca6: fffff097     	auipc	ra, 0xfffff
  101caa: e46080e7     	jalr	-0x1ba(ra) <PT_LOAD#0+0xaec>
  101cae: 00000097     	auipc	ra, 0x0
  101cb2: ed8080e7     	jalr	-0x128(ra) <PT_LOAD#0+0x1b86>
  101cb6: 4789         	li	a5, 0x2
  101cb8: cb1c         	sw	a5, 0x10(a4)
  101cba: 478d         	li	a5, 0x3
  101cbc: ca9c         	sw	a5, 0x10(a3)
  101cbe: 4501         	li	a0, 0x0
  101cc0: 8082         	ret
  101cc2: 4519         	li	a0, 0x6
  101cc4: 8082         	ret
  101cc6: 7139         	addi	sp, sp, -0x40
  101cc8: f426         	sd	s1, 0x28(sp)
  101cca: f04a         	sd	s2, 0x20(sp)
  101ccc: 84ae         	mv	s1, a1
  101cce: 8932         	mv	s2, a2
  101cd0: f822         	sd	s0, 0x30(sp)
  101cd2: 0030         	addi	a2, sp, 0x8
  101cd4: 842a         	mv	s0, a0
  101cd6: 85ca         	mv	a1, s2
  101cd8: 8526         	mv	a0, s1
  101cda: ec4e         	sd	s3, 0x18(sp)
  101cdc: fc06         	sd	ra, 0x38(sp)
  101cde: 89b6         	mv	s3, a3
  101ce0: fffff097     	auipc	ra, 0xfffff
  101ce4: 900080e7     	jalr	-0x700(ra) <PT_LOAD#0+0x5e0>
  101ce8: e105         	bnez	a0, 0x101d08 <PT_LOAD#0+0x1d08>
  101cea: 0006c617     	auipc	a2, 0x6c
  101cee: 2ae60613     	addi	a2, a2, 0x2ae
  101cf2: 25500593     	li	a1, 0x255
  101cf6: 4509         	li	a0, 0x2
  101cf8: fffff097     	auipc	ra, 0xfffff
  101cfc: df4080e7     	jalr	-0x20c(ra) <PT_LOAD#0+0xaec>
  101d00: 00000097     	auipc	ra, 0x0
  101d04: e86080e7     	jalr	-0x17a(ra) <PT_LOAD#0+0x1b86>
  101d08: 85ca         	mv	a1, s2
  101d0a: 8526         	mv	a0, s1
  101d0c: fffff097     	auipc	ra, 0xfffff
  101d10: 960080e7     	jalr	-0x6a0(ra) <PT_LOAD#0+0x66c>
  101d14: 858a         	mv	a1, sp
  101d16: cd39         	beqz	a0, 0x101d74 <PT_LOAD#0+0x1d74>
  101d18: 8522         	mv	a0, s0
  101d1a: 00000097     	auipc	ra, 0x0
  101d1e: e8a080e7     	jalr	-0x176(ra) <PT_LOAD#0+0x1ba4>
  101d22: e131         	bnez	a0, 0x101d66 <PT_LOAD#0+0x1d66>
  101d24: 6602         	ld	a2, 0x0(sp)
  101d26: 02041593     	slli	a1, s0, 0x20
  101d2a: 9181         	srli	a1, a1, 0x20
  101d2c: 00659793     	slli	a5, a1, 0x6
  101d30: 97b2         	add	a5, a5, a2
  101d32: 00043717     	auipc	a4, 0x43
  101d36: ece70713     	addi	a4, a4, -0x132
  101d3a: 00579693     	slli	a3, a5, 0x5
  101d3e: 0785         	addi	a5, a5, 0x1
  101d40: 96ba         	add	a3, a3, a4
  101d42: 0796         	slli	a5, a5, 0x5
  101d44: 6522         	ld	a0, 0x8(sp)
  101d46: 973e         	add	a4, a4, a5
  101d48: ee84         	sd	s1, 0x18(a3)
  101d4a: 0326b023     	sd	s2, 0x20(a3)
  101d4e: 02099693     	slli	a3, s3, 0x20
  101d52: 01372423     	sw	s3, 0x8(a4)
  101d56: 87ca         	mv	a5, s2
  101d58: 8726         	mv	a4, s1
  101d5a: 9281         	srli	a3, a3, 0x20
  101d5c: 00002097     	auipc	ra, 0x2
  101d60: d9c080e7     	jalr	-0x264(ra) <PT_LOAD#0+0x3af8>
  101d64: 4501         	li	a0, 0x0
  101d66: 70e2         	ld	ra, 0x38(sp)
  101d68: 7442         	ld	s0, 0x30(sp)
  101d6a: 74a2         	ld	s1, 0x28(sp)
  101d6c: 7902         	ld	s2, 0x20(sp)
  101d6e: 69e2         	ld	s3, 0x18(sp)
  101d70: 6121         	addi	sp, sp, 0x40
  101d72: 8082         	ret
  101d74: 8522         	mv	a0, s0
  101d76: 00000097     	auipc	ra, 0x0
  101d7a: eb0080e7     	jalr	-0x150(ra) <PT_LOAD#0+0x1c26>
  101d7e: f565         	bnez	a0, 0x101d66 <PT_LOAD#0+0x1d66>
  101d80: 6602         	ld	a2, 0x0(sp)
  101d82: 02041593     	slli	a1, s0, 0x20
  101d86: 9181         	srli	a1, a1, 0x20
  101d88: 00659793     	slli	a5, a1, 0x6
  101d8c: 97b2         	add	a5, a5, a2
  101d8e: 00043717     	auipc	a4, 0x43
  101d92: e7270713     	addi	a4, a4, -0x18e
  101d96: 00579693     	slli	a3, a5, 0x5
  101d9a: 0785         	addi	a5, a5, 0x1
  101d9c: 96ba         	add	a3, a3, a4
  101d9e: 0796         	slli	a5, a5, 0x5
  101da0: 6522         	ld	a0, 0x8(sp)
  101da2: 973e         	add	a4, a4, a5
  101da4: ee84         	sd	s1, 0x18(a3)
  101da6: 0326b023     	sd	s2, 0x20(a3)
  101daa: 02099693     	slli	a3, s3, 0x20
  101dae: 01372423     	sw	s3, 0x8(a4)
  101db2: 87ca         	mv	a5, s2
  101db4: 8726         	mv	a4, s1
  101db6: 9281         	srli	a3, a3, 0x20
  101db8: 00002097     	auipc	ra, 0x2
  101dbc: d04080e7     	jalr	-0x2fc(ra) <PT_LOAD#0+0x3abc>
  101dc0: b755         	j	0x101d64 <PT_LOAD#0+0x1d64>
  101dc2: 00002797     	auipc	a5, 0x2
  101dc6: 1ae7b783     	ld	a5, 0x1ae(a5)
  101dca: 0ff5f593     	zext.b	a1, a1
  101dce: 02f585b3     	<unknown>
  101dd2: 4691         	li	a3, 0x4
  101dd4: 87aa         	mv	a5, a0
  101dd6: 480d         	li	a6, 0x3
  101dd8: 489d         	li	a7, 0x7
  101dda: e211         	bnez	a2, 0x101dde <PT_LOAD#0+0x1dde>
  101ddc: 8082         	ret
  101dde: 0077f713     	andi	a4, a5, 0x7
  101de2: e719         	bnez	a4, 0x101df0 <PT_LOAD#0+0x1df0>
  101de4: 00c8fe63     	bgeu	a7, a2, 0x101e00 <PT_LOAD#0+0x1e00>
  101de8: e38c         	sd	a1, 0x0(a5)
  101dea: 1661         	addi	a2, a2, -0x8
  101dec: 07a1         	addi	a5, a5, 0x8
  101dee: b7f5         	j	0x101dda <PT_LOAD#0+0x1dda>
  101df0: 00d71863     	bne	a4, a3, 0x101e00 <PT_LOAD#0+0x1e00>
  101df4: 00c87663     	bgeu	a6, a2, 0x101e00 <PT_LOAD#0+0x1e00>
  101df8: c38c         	sw	a1, 0x0(a5)
  101dfa: 1671         	addi	a2, a2, -0x4
  101dfc: 0791         	addi	a5, a5, 0x4
  101dfe: bff1         	j	0x101dda <PT_LOAD#0+0x1dda>
  101e00: 00b78023     	sb	a1, 0x0(a5)
  101e04: 167d         	addi	a2, a2, -0x1
  101e06: 0785         	addi	a5, a5, 0x1
  101e08: bfc9         	j	0x101dda <PT_LOAD#0+0x1dda>
  101e0a: 9e010113     	addi	sp, sp, -0x620
  101e0e: 60813823     	sd	s0, 0x610(sp)
  101e12: 5f313c23     	sd	s3, 0x5f8(sp)
  101e16: 5f413823     	sd	s4, 0x5f0(sp)
  101e1a: 5f513423     	sd	s5, 0x5e8(sp)
  101e1e: 5f613023     	sd	s6, 0x5e0(sp)
  101e22: 5d713c23     	sd	s7, 0x5d8(sp)
  101e26: 5d813823     	sd	s8, 0x5d0(sp)
  101e2a: 60113c23     	sd	ra, 0x618(sp)
  101e2e: 60913423     	sd	s1, 0x608(sp)
  101e32: 61213023     	sd	s2, 0x600(sp)
  101e36: 5d913423     	sd	s9, 0x5c8(sp)
  101e3a: 5da13023     	sd	s10, 0x5c0(sp)
  101e3e: 5bb13c23     	sd	s11, 0x5b8(sp)
  101e42: 0001fb97     	auipc	s7, 0x1f
  101e46: 1d2b8b93     	addi	s7, s7, 0x1d2
  101e4a: 000bc783     	lbu	a5, 0x0(s7)
  101e4e: 8a3a         	mv	s4, a4
  101e50: 0006ab17     	auipc	s6, 0x6a
  101e54: 248b0b13     	addi	s6, s6, 0x248
  101e58: 00022417     	auipc	s0, 0x22
  101e5c: 1a840413     	addi	s0, s0, 0x1a8
  101e60: 0006aa97     	auipc	s5, 0x6a
  101e64: 230a8a93     	addi	s5, s5, 0x230
  101e68: 0006a997     	auipc	s3, 0x6a
  101e6c: 22098993     	addi	s3, s3, 0x220
  101e70: 2f010c13     	addi	s8, sp, 0x2f0
  101e74: 48078963     	beqz	a5, 0x102306 <PT_LOAD#0+0x2306>
  101e78: 00002797     	auipc	a5, 0x2
  101e7c: 1007b783     	ld	a5, 0x100(a5)
  101e80: 439c         	lw	a5, 0x0(a5)
  101e82: 8932         	mv	s2, a2
  101e84: 00ab3023     	sd	a0, 0x0(s6)
  101e88: 0007861b     	sext.w	a2, a5
  101e8c: 0187d79b     	srliw	a5, a5, 0x18
  101e90: 03f7f793     	andi	a5, a5, 0x3f
  101e94: 84aa         	mv	s1, a0
  101e96: 8cb6         	mv	s9, a3
  101e98: fe97871b     	addiw	a4, a5, -0x17
  101e9c: c901         	beqz	a0, 0x101eac <PT_LOAD#0+0x1eac>
  101e9e: 4914         	lw	a3, 0x10(a0)
  101ea0: 06c68563     	beq	a3, a2, 0x101f0a <PT_LOAD#0+0x1f0a>
  101ea4: 00002097     	auipc	ra, 0x2
  101ea8: bda080e7     	jalr	-0x426(ra) <PT_LOAD#0+0x3a7e>
  101eac: 9b75         	andi	a4, a4, -0x3
  101eae: 2701         	sext.w	a4, a4
  101eb0: fb75         	bnez	a4, 0x101ea4 <PT_LOAD#0+0x1ea4>
  101eb2: ffffe717     	auipc	a4, 0xffffe
  101eb6: 3a670713     	addi	a4, a4, 0x3a6
  101eba: 4ae43423     	sd	a4, 0x4a8(s0)
  101ebe: fffff717     	auipc	a4, 0xfffff
  101ec2: 6ea70713     	addi	a4, a4, 0x6ea
  101ec6: 4ae43823     	sd	a4, 0x4b0(s0)
  101eca: ffffe717     	auipc	a4, 0xffffe
  101ece: 2f670713     	addi	a4, a4, 0x2f6
  101ed2: 4ae43c23     	sd	a4, 0x4b8(s0)
  101ed6: ffffe717     	auipc	a4, 0xffffe
  101eda: 2f470713     	addi	a4, a4, 0x2f4
  101ede: 4ce43023     	sd	a4, 0x4c0(s0)
  101ee2: 179d         	addi	a5, a5, -0x19
  101ee4: ffffe717     	auipc	a4, 0xffffe
  101ee8: 47670713     	addi	a4, a4, 0x476
  101eec: 4ce43423     	sd	a4, 0x4c8(s0)
  101ef0: 0017b793     	seqz	a5, a5
  101ef4: ffffe717     	auipc	a4, 0xffffe
  101ef8: 2d870713     	addi	a4, a4, 0x2d8
  101efc: 4ce43823     	sd	a4, 0x4d0(s0)
  101f00: 0006a717     	auipc	a4, 0x6a
  101f04: 18f700a3     	sb	a5, 0x181(a4)
  101f08: a8bd         	j	0x101f86 <PT_LOAD#0+0x1f86>
  101f0a: 0146d69b     	srliw	a3, a3, 0x14
  101f0e: 0007061b     	sext.w	a2, a4
  101f12: 4595         	li	a1, 0x5
  101f14: 3ff6f693     	andi	a3, a3, 0x3ff
  101f18: f8c5e6e3     	bltu	a1, a2, 0x101ea4 <PT_LOAD#0+0x1ea4>
  101f1c: 02071613     	slli	a2, a4, 0x20
  101f20: 01e65713     	srli	a4, a2, 0x1e
  101f24: 00002617     	auipc	a2, 0x2
  101f28: dfc60613     	addi	a2, a2, -0x204
  101f2c: 9732         	add	a4, a4, a2
  101f2e: 4318         	lw	a4, 0x0(a4)
  101f30: 9732         	add	a4, a4, a2
  101f32: 8702         	jr	a4
  101f34: 85e6         	mv	a1, s9
  101f36: fffff097     	auipc	ra, 0xfffff
  101f3a: 416080e7     	jalr	0x416(ra) <PT_LOAD#0+0x134c>
  101f3e: ffffe797     	auipc	a5, 0xffffe
  101f42: 1a478793     	addi	a5, a5, 0x1a4
  101f46: 4af43c23     	sd	a5, 0x4b8(s0)
  101f4a: ffffe797     	auipc	a5, 0xffffe
  101f4e: 42c78793     	addi	a5, a5, 0x42c
  101f52: 4cf43423     	sd	a5, 0x4c8(s0)
  101f56: ffffe797     	auipc	a5, 0xffffe
  101f5a: 19678793     	addi	a5, a5, 0x196
  101f5e: 4cf43823     	sd	a5, 0x4d0(s0)
  101f62: fffff797     	auipc	a5, 0xfffff
  101f66: 59878793     	addi	a5, a5, 0x598
  101f6a: 4cf43023     	sd	a5, 0x4c0(s0)
  101f6e: 00000797     	auipc	a5, 0x0
  101f72: 8c078793     	addi	a5, a5, -0x740
  101f76: 4af43423     	sd	a5, 0x4a8(s0)
  101f7a: ffffe797     	auipc	a5, 0xffffe
  101f7e: 23678793     	addi	a5, a5, 0x236
  101f82: 4ef43023     	sd	a5, 0x4e0(s0)
  101f86: 02000613     	li	a2, 0x20
  101f8a: 4581         	li	a1, 0x0
  101f8c: 00022517     	auipc	a0, 0x22
  101f90: 58450513     	addi	a0, a0, 0x584
  101f94: 012ab023     	sd	s2, 0x0(s5)
  101f98: 00000097     	auipc	ra, 0x0
  101f9c: e2a080e7     	jalr	-0x1d6(ra) <PT_LOAD#0+0x1dc2>
  101fa0: 0f094703     	lbu	a4, 0xf0(s2)
  101fa4: 03000693     	li	a3, 0x30
  101fa8: 067007b7     	lui	a5, 0x6700
  101fac: 00d70763     	beq	a4, a3, 0x101fba <PT_LOAD#0+0x1fba>
  101fb0: 052007b7     	lui	a5, 0x5200
  101fb4: e319         	bnez	a4, 0x101fba <PT_LOAD#0+0x1fba>
  101fb6: 016007b7     	lui	a5, 0x1600
  101fba: 08093703     	ld	a4, 0x80(s2)
  101fbe: 002006b7     	lui	a3, 0x200
  101fc2: 50f43c23     	sd	a5, 0x518(s0)
  101fc6: 96be         	add	a3, a3, a5
  101fc8: ece6fee3     	bgeu	a3, a4, 0x101ea4 <PT_LOAD#0+0x1ea4>
  101fcc: 07893683     	ld	a3, 0x78(s2)
  101fd0: ffe00637     	lui	a2, 0xffe00
  101fd4: 10090913     	addi	s2, s2, 0x100
  101fd8: 9736         	add	a4, a4, a3
  101fda: 40f707b3     	sub	a5, a4, a5
  101fde: 8ff1         	and	a5, a5, a2
  101fe0: 8f1d         	sub	a4, a4, a5
  101fe2: 50f43823     	sd	a5, 0x510(s0)
  101fe6: 1a000613     	li	a2, 0x1a0
  101fea: 8f95         	sub	a5, a5, a3
  101fec: 4581         	li	a1, 0x0
  101fee: 854a         	mv	a0, s2
  101ff0: 50e43c23     	sd	a4, 0x518(s0)
  101ff4: 52d43023     	sd	a3, 0x520(s0)
  101ff8: 52f43423     	sd	a5, 0x528(s0)
  101ffc: 0129b023     	sd	s2, 0x0(s3)
  102000: 00000097     	auipc	ra, 0x0
  102004: dc2080e7     	jalr	-0x23e(ra) <PT_LOAD#0+0x1dc2>
  102008: 4a843783     	ld	a5, 0x4a8(s0)
  10200c: 85a6         	mv	a1, s1
  10200e: 8666         	mv	a2, s9
  102010: 854a         	mv	a0, s2
  102012: 9782         	jalr	a5
  102014: 000ab483     	ld	s1, 0x0(s5)
  102018: e80486e3     	beqz	s1, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10201c: 6098         	ld	a4, 0x0(s1)
  10201e: 00002797     	auipc	a5, 0x2
  102022: f627b783     	ld	a5, -0x9e(a5)
  102026: e6f71fe3     	bne	a4, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10202a: 0084b903     	ld	s2, 0x8(s1)
  10202e: 4785         	li	a5, 0x1
  102030: e6f91ae3     	bne	s2, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102034: 7cf8         	ld	a4, 0xf8(s1)
  102036: 00002797     	auipc	a5, 0x2
  10203a: f527b783     	ld	a5, -0xae(a5)
  10203e: e6f713e3     	bne	a4, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102042: 74dc         	ld	a5, 0xa8(s1)
  102044: 0704bc83     	ld	s9, 0x70(s1)
  102048: e4fcfee3     	bgeu	s9, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10204c: 7cb0         	ld	a2, 0x78(s1)
  10204e: 2a0c8713     	addi	a4, s9, 0x2a0
  102052: e4e669e3     	bltu	a2, a4, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102056: e4f677e3     	bgeu	a2, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10205a: 60d4         	ld	a3, 0x80(s1)
  10205c: 8f91         	sub	a5, a5, a2
  10205e: e4d7e3e3     	bltu	a5, a3, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102062: 0f04c783     	lbu	a5, 0xf0(s1)
  102066: 03000713     	li	a4, 0x30
  10206a: e2f76de3     	bltu	a4, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10206e: 02000713     	li	a4, 0x20
  102072: 32e78a63     	beq	a5, a4, 0x1023a6 <PT_LOAD#0+0x23a6>
  102076: 03000713     	li	a4, 0x30
  10207a: 1ae78863     	beq	a5, a4, 0x10222a <PT_LOAD#0+0x222a>
  10207e: 471d         	li	a4, 0x7
  102080: 32e79a63     	bne	a5, a4, 0x1023b4 <PT_LOAD#0+0x23b4>
  102084: 15f007b7     	lui	a5, 0x15f00
  102088: a60d         	j	0x1023aa <PT_LOAD#0+0x23aa>
  10208a: 1aa00793     	li	a5, 0x1aa
  10208e: 85e6         	mv	a1, s9
  102090: 06d7f563     	bgeu	a5, a3, 0x1020fa <PT_LOAD#0+0x20fa>
  102094: fffff097     	auipc	ra, 0xfffff
  102098: 2b8080e7     	jalr	0x2b8(ra) <PT_LOAD#0+0x134c>
  10209c: ffffe797     	auipc	a5, 0xffffe
  1020a0: 0e078793     	addi	a5, a5, 0xe0
  1020a4: 4af43c23     	sd	a5, 0x4b8(s0)
  1020a8: fffff797     	auipc	a5, 0xfffff
  1020ac: 7a478793     	addi	a5, a5, 0x7a4
  1020b0: 4af43423     	sd	a5, 0x4a8(s0)
  1020b4: 00000797     	auipc	a5, 0x0
  1020b8: 90a78793     	addi	a5, a5, -0x6f6
  1020bc: 4af43823     	sd	a5, 0x4b0(s0)
  1020c0: fffff797     	auipc	a5, 0xfffff
  1020c4: 21a78793     	addi	a5, a5, 0x21a
  1020c8: 4cf43023     	sd	a5, 0x4c0(s0)
  1020cc: ffffe797     	auipc	a5, 0xffffe
  1020d0: 31a78793     	addi	a5, a5, 0x31a
  1020d4: 4cf43423     	sd	a5, 0x4c8(s0)
  1020d8: ffffe797     	auipc	a5, 0xffffe
  1020dc: 01478793     	addi	a5, a5, 0x14
  1020e0: 4cf43823     	sd	a5, 0x4d0(s0)
  1020e4: fffff797     	auipc	a5, 0xfffff
  1020e8: 19c78793     	addi	a5, a5, 0x19c
  1020ec: 4cf43c23     	sd	a5, 0x4d8(s0)
  1020f0: ffffe797     	auipc	a5, 0xffffe
  1020f4: 36678793     	addi	a5, a5, 0x366
  1020f8: b569         	j	0x101f82 <PT_LOAD#0+0x1f82>
  1020fa: fffff097     	auipc	ra, 0xfffff
  1020fe: 252080e7     	jalr	0x252(ra) <PT_LOAD#0+0x134c>
  102102: b551         	j	0x101f86 <PT_LOAD#0+0x1f86>
  102104: 1ba00793     	li	a5, 0x1ba
  102108: ffffed17     	auipc	s10, 0xffffe
  10210c: fe4d0d13     	addi	s10, s10, -0x1c
  102110: 85e6         	mv	a1, s9
  102112: 06d7f163     	bgeu	a5, a3, 0x102174 <PT_LOAD#0+0x2174>
  102116: fffff097     	auipc	ra, 0xfffff
  10211a: 236080e7     	jalr	0x236(ra) <PT_LOAD#0+0x134c>
  10211e: 00000797     	auipc	a5, 0x0
  102122: 8a078793     	addi	a5, a5, -0x760
  102126: 4af43823     	sd	a5, 0x4b0(s0)
  10212a: fffff797     	auipc	a5, 0xfffff
  10212e: 1b078793     	addi	a5, a5, 0x1b0
  102132: 4cf43023     	sd	a5, 0x4c0(s0)
  102136: ffffe797     	auipc	a5, 0xffffe
  10213a: 2b078793     	addi	a5, a5, 0x2b0
  10213e: 4cf43423     	sd	a5, 0x4c8(s0)
  102142: fffff797     	auipc	a5, 0xfffff
  102146: 13e78793     	addi	a5, a5, 0x13e
  10214a: 4cf43c23     	sd	a5, 0x4d8(s0)
  10214e: ffffe797     	auipc	a5, 0xffffe
  102152: 03878793     	addi	a5, a5, 0x38
  102156: 4af43c23     	sd	a5, 0x4b8(s0)
  10215a: fffff797     	auipc	a5, 0xfffff
  10215e: 71878793     	addi	a5, a5, 0x718
  102162: 4af43423     	sd	a5, 0x4a8(s0)
  102166: 4da43823     	sd	s10, 0x4d0(s0)
  10216a: ffffe797     	auipc	a5, 0xffffe
  10216e: 2f078793     	addi	a5, a5, 0x2f0
  102172: bd01         	j	0x101f82 <PT_LOAD#0+0x1f82>
  102174: fffff097     	auipc	ra, 0xfffff
  102178: 1d8080e7     	jalr	0x1d8(ra) <PT_LOAD#0+0x134c>
  10217c: fffff797     	auipc	a5, 0xfffff
  102180: 72878793     	addi	a5, a5, 0x728
  102184: 4af43423     	sd	a5, 0x4a8(s0)
  102188: ffffe797     	auipc	a5, 0xffffe
  10218c: 00878793     	addi	a5, a5, 0x8
  102190: 4af43c23     	sd	a5, 0x4b8(s0)
  102194: fffff797     	auipc	a5, 0xfffff
  102198: 36678793     	addi	a5, a5, 0x366
  10219c: 4cf43023     	sd	a5, 0x4c0(s0)
  1021a0: ffffe797     	auipc	a5, 0xffffe
  1021a4: 1d678793     	addi	a5, a5, 0x1d6
  1021a8: 4cf43423     	sd	a5, 0x4c8(s0)
  1021ac: 4da43823     	sd	s10, 0x4d0(s0)
  1021b0: ffffe797     	auipc	a5, 0xffffe
  1021b4: 00878793     	addi	a5, a5, 0x8
  1021b8: b3e9         	j	0x101f82 <PT_LOAD#0+0x1f82>
  1021ba: fffff797     	auipc	a5, 0xfffff
  1021be: 55278793     	addi	a5, a5, 0x552
  1021c2: 4af43423     	sd	a5, 0x4a8(s0)
  1021c6: fffff797     	auipc	a5, 0xfffff
  1021ca: 23078793     	addi	a5, a5, 0x230
  1021ce: 4af43823     	sd	a5, 0x4b0(s0)
  1021d2: ffffe797     	auipc	a5, 0xffffe
  1021d6: fc878793     	addi	a5, a5, -0x38
  1021da: 4af43c23     	sd	a5, 0x4b8(s0)
  1021de: fffff797     	auipc	a5, 0xfffff
  1021e2: 31c78793     	addi	a5, a5, 0x31c
  1021e6: 4cf43023     	sd	a5, 0x4c0(s0)
  1021ea: ffffe797     	auipc	a5, 0xffffe
  1021ee: 18c78793     	addi	a5, a5, 0x18c
  1021f2: 4cf43423     	sd	a5, 0x4c8(s0)
  1021f6: ffffe797     	auipc	a5, 0xffffe
  1021fa: ef678793     	addi	a5, a5, -0x10a
  1021fe: 4cf43823     	sd	a5, 0x4d0(s0)
  102202: fffff797     	auipc	a5, 0xfffff
  102206: 2da78793     	addi	a5, a5, 0x2da
  10220a: 4cf43c23     	sd	a5, 0x4d8(s0)
  10220e: ffffe797     	auipc	a5, 0xffffe
  102212: f9678793     	addi	a5, a5, -0x6a
  102216: 4ef43023     	sd	a5, 0x4e0(s0)
  10221a: 617c         	ld	a5, 0xc0(a0)
  10221c: c997f4e3     	bgeu	a5, s9, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102220: 6578         	ld	a4, 0xc8(a0)
  102222: 97ba         	add	a5, a5, a4
  102224: d6fce1e3     	bltu	s9, a5, 0x101f86 <PT_LOAD#0+0x1f86>
  102228: b9b5         	j	0x101ea4 <PT_LOAD#0+0x1ea4>
  10222a: 10b00793     	li	a5, 0x10b
  10222e: 55800737     	lui	a4, 0x55800
  102232: 07de         	slli	a5, a5, 0x17
  102234: c6e6e8e3     	bltu	a3, a4, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102238: c6d7e6e3     	bltu	a5, a3, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10223c: 6c8c         	ld	a1, 0x18(s1)
  10223e: 64c8         	ld	a0, 0x88(s1)
  102240: e836         	sd	a3, 0x10(sp)
  102242: e432         	sd	a2, 0x8(sp)
  102244: ffffe097     	auipc	ra, 0xffffe
  102248: de4080e7     	jalr	-0x21c(ra) <PT_LOAD#0+0x28>
  10224c: c4051ce3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102250: 66c2         	ld	a3, 0x10(sp)
  102252: 6622         	ld	a2, 0x8(sp)
  102254: 748c         	ld	a1, 0x28(s1)
  102256: 68c8         	ld	a0, 0x90(s1)
  102258: ffffe097     	auipc	ra, 0xffffe
  10225c: dd0080e7     	jalr	-0x230(ra) <PT_LOAD#0+0x28>
  102260: c40512e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102264: 66c2         	ld	a3, 0x10(sp)
  102266: 6622         	ld	a2, 0x8(sp)
  102268: 70cc         	ld	a1, 0xa0(s1)
  10226a: 6cc8         	ld	a0, 0x98(s1)
  10226c: ffffe097     	auipc	ra, 0xffffe
  102270: dbc080e7     	jalr	-0x244(ra) <PT_LOAD#0+0x28>
  102274: c20518e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102278: 0009b783     	ld	a5, 0x0(s3)
  10227c: 8666         	mv	a2, s9
  10227e: 00002517     	auipc	a0, 0x2
  102282: 9da50513     	addi	a0, a0, -0x626
  102286: 1587b583     	ld	a1, 0x158(a5)
  10228a: fffff097     	auipc	ra, 0xfffff
  10228e: f30080e7     	jalr	-0xd0(ra) <PT_LOAD#0+0x11ba>
  102292: 0009b583     	ld	a1, 0x0(s3)
  102296: 000ab783     	ld	a5, 0x0(s5)
  10229a: 1585b703     	ld	a4, 0x158(a1)
  10229e: 7bbc         	ld	a5, 0x70(a5)
  1022a0: c0f712e3     	bne	a4, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1022a4: 4c843783     	ld	a5, 0x4c8(s0)
  1022a8: 8562         	mv	a0, s8
  1022aa: 56013823     	sd	zero, 0x570(sp)
  1022ae: 9782         	jalr	a5
  1022b0: 4d043783     	ld	a5, 0x4d0(s0)
  1022b4: 8562         	mv	a0, s8
  1022b6: 9782         	jalr	a5
  1022b8: 0009b583     	ld	a1, 0x0(s3)
  1022bc: 4c043783     	ld	a5, 0x4c0(s0)
  1022c0: 75a8         	ld	a0, 0x68(a1)
  1022c2: 9782         	jalr	a5
  1022c4: 0009b783     	ld	a5, 0x0(s3)
  1022c8: 4621         	li	a2, 0x8
  1022ca: 4ac40023     	sb	a2, 0x4a0(s0)
  1022ce: 7394         	ld	a3, 0x20(a5)
  1022d0: 7798         	ld	a4, 0x28(a5)
  1022d2: 463d         	li	a2, 0xf
  1022d4: 0036d793     	srli	a5, a3, 0x3
  1022d8: 48f43823     	sd	a5, 0x490(s0)
  1022dc: 48e43c23     	sd	a4, 0x498(s0)
  1022e0: 00d67863     	bgeu	a2, a3, 0x1022f0 <PT_LOAD#0+0x22f0>
  1022e4: 00073903     	ld	s2, 0x0(a4)
  1022e8: 17fd         	addi	a5, a5, -0x1
  1022ea: 02f97933     	<unknown>
  1022ee: 0905         	addi	s2, s2, 0x1
  1022f0: 0006c597     	auipc	a1, 0x6c
  1022f4: cc058593     	addi	a1, a1, -0x340
  1022f8: 4505         	li	a0, 0x1
  1022fa: 49243423     	sd	s2, 0x488(s0)
  1022fe: ffffe097     	auipc	ra, 0xffffe
  102302: 7ee080e7     	jalr	0x7ee(ra) <PT_LOAD#0+0xaec>
  102306: 0009b783     	ld	a5, 0x0(s3)
  10230a: b8078de3     	beqz	a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10230e: 0707c683     	lbu	a3, 0x70(a5)
  102312: 0ff00713     	li	a4, 0xff
  102316: 0717cc83     	lbu	s9, 0x71(a5)
  10231a: 0727cd03     	lbu	s10, 0x72(a5)
  10231e: b8e683e3     	beq	a3, a4, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102322: b8ec81e3     	beq	s9, a4, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102326: b6ed0fe3     	beq	s10, a4, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10232a: 0737c483     	lbu	s1, 0x73(a5)
  10232e: 00e49463     	bne	s1, a4, 0x102336 <PT_LOAD#0+0x2336>
  102332: 54fd         	li	s1, -0x1
  102334: 9081         	srli	s1, s1, 0x20
  102336: ea91         	bnez	a3, 0x10234a <PT_LOAD#0+0x234a>
  102338: ffffe597     	auipc	a1, 0xffffe
  10233c: cc858593     	addi	a1, a1, -0x338
  102340: 4501         	li	a0, 0x0
  102342: 00001097     	auipc	ra, 0x1
  102346: 744080e7     	jalr	0x744(ra) <PT_LOAD#0+0x3a86>
  10234a: 00001597     	auipc	a1, 0x1
  10234e: 6de58593     	addi	a1, a1, 0x6de
  102352: 8566         	mv	a0, s9
  102354: 00001097     	auipc	ra, 0x1
  102358: 732080e7     	jalr	0x732(ra) <PT_LOAD#0+0x3a86>
  10235c: 000bc783     	lbu	a5, 0x0(s7)
  102360: 0006a917     	auipc	s2, 0x6a
  102364: d2290913     	addi	s2, s2, -0x2de
  102368: efa9         	bnez	a5, 0x1023c2 <PT_LOAD#0+0x23c2>
  10236a: 00094503     	lbu	a0, 0x0(s2)
  10236e: 02b00793     	li	a5, 0x2b
  102372: 85e2         	mv	a1, s8
  102374: 2ef13823     	sd	a5, 0x2f0(sp)
  102378: 2e013c23     	sd	zero, 0x2f8(sp)
  10237c: 30013023     	sd	zero, 0x300(sp)
  102380: 30013423     	sd	zero, 0x308(sp)
  102384: 30013823     	sd	zero, 0x310(sp)
  102388: ffffe097     	auipc	ra, 0xffffe
  10238c: 0d6080e7     	jalr	0xd6(ra) <PT_LOAD#0+0x45e>
  102390: 87ea         	mv	a5, s10
  102392: 4701         	li	a4, 0x0
  102394: 4681         	li	a3, 0x0
  102396: 4601         	li	a2, 0x0
  102398: 4581         	li	a1, 0x0
  10239a: 03100513     	li	a0, 0x31
  10239e: 00001097     	auipc	ra, 0x1
  1023a2: 6d2080e7     	jalr	0x6d2(ra) <PT_LOAD#0+0x3a70>
  1023a6: 243007b7     	lui	a5, 0x24300
  1023aa: aef6ede3     	bltu	a3, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1023ae: 443007b7     	lui	a5, 0x44300
  1023b2: b559         	j	0x102238 <PT_LOAD#0+0x2238>
  1023b4: 056007b7     	lui	a5, 0x5600
  1023b8: aef6e6e3     	bltu	a3, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1023bc: 116007b7     	lui	a5, 0x11600
  1023c0: bda5         	j	0x102238 <PT_LOAD#0+0x2238>
  1023c2: 0009b583     	ld	a1, 0x0(s3)
  1023c6: 4c843883     	ld	a7, 0x4c8(s0)
  1023ca: 7d9c         	ld	a5, 0x38(a1)
  1023cc: 7988         	ld	a0, 0x30(a1)
  1023ce: 6190         	ld	a2, 0x0(a1)
  1023d0: 6594         	ld	a3, 0x8(a1)
  1023d2: 6998         	ld	a4, 0x10(a1)
  1023d4: 0185bd83     	ld	s11, 0x18(a1)
  1023d8: 0285b803     	ld	a6, 0x28(a1)
  1023dc: 963e         	add	a2, a2, a5
  1023de: 96be         	add	a3, a3, a5
  1023e0: 973e         	add	a4, a4, a5
  1023e2: 00a78d33     	add	s10, a5, a0
  1023e6: 9dbe         	add	s11, s11, a5
  1023e8: 719c         	ld	a5, 0x20(a1)
  1023ea: 10a8         	addi	a0, sp, 0x68
  1023ec: f432         	sd	a2, 0x28(sp)
  1023ee: f036         	sd	a3, 0x20(sp)
  1023f0: ec3a         	sd	a4, 0x18(sp)
  1023f2: e842         	sd	a6, 0x10(sp)
  1023f4: e43e         	sd	a5, 0x8(sp)
  1023f6: 9882         	jalr	a7
  1023f8: 7622         	ld	a2, 0x28(sp)
  1023fa: 67a2         	ld	a5, 0x8(sp)
  1023fc: 6842         	ld	a6, 0x10(sp)
  1023fe: 7682         	ld	a3, 0x20(sp)
  102400: 6762         	ld	a4, 0x18(sp)
  102402: 30c13023     	sd	a2, 0x300(sp)
  102406: 10ac         	addi	a1, sp, 0x68
  102408: 28800613     	li	a2, 0x288
  10240c: 1628         	addi	a0, sp, 0x328
  10240e: 2ef13c23     	sd	a5, 0x2f8(sp)
  102412: 2f013823     	sd	a6, 0x2f0(sp)
  102416: 30d13423     	sd	a3, 0x308(sp)
  10241a: 30e13823     	sd	a4, 0x310(sp)
  10241e: 31b13c23     	sd	s11, 0x318(sp)
  102422: 33a13023     	sd	s10, 0x320(sp)
  102426: 00000097     	auipc	ra, 0x0
  10242a: 5d0080e7     	jalr	0x5d0(ra) <PT_LOAD#0+0x29f6>
  10242e: 02000793     	li	a5, 0x20
  102432: 008c         	addi	a1, sp, 0x40
  102434: 8566         	mv	a0, s9
  102436: e0be         	sd	a5, 0x40(sp)
  102438: e4a6         	sd	s1, 0x48(sp)
  10243a: e8e2         	sd	s8, 0x50(sp)
  10243c: ec82         	sd	zero, 0x58(sp)
  10243e: f082         	sd	zero, 0x60(sp)
  102440: ffffe097     	auipc	ra, 0xffffe
  102444: 01e080e7     	jalr	0x1e(ra) <PT_LOAD#0+0x45e>
  102448: e119         	bnez	a0, 0x10244e <PT_LOAD#0+0x244e>
  10244a: 01990023     	sb	s9, 0x0(s2)
  10244e: 000ab783     	ld	a5, 0x0(s5)
  102452: 000b3503     	ld	a0, 0x0(s6)
  102456: 0f17c583     	lbu	a1, 0xf1(a5)
  10245a: 4b043783     	ld	a5, 0x4b0(s0)
  10245e: 8991         	andi	a1, a1, 0x4
  102460: 9782         	jalr	a5
  102462: 0009b483     	ld	s1, 0x0(s3)
  102466: 000ab983     	ld	s3, 0x0(s5)
  10246a: 02000713     	li	a4, 0x20
  10246e: 51843683     	ld	a3, 0x518(s0)
  102472: 0f09c783     	lbu	a5, 0xf0(s3)
  102476: 2ce78e63     	beq	a5, a4, 0x102752 <PT_LOAD#0+0x2752>
  10247a: 03000713     	li	a4, 0x30
  10247e: 00e78863     	beq	a5, a4, 0x10248e <PT_LOAD#0+0x248e>
  102482: 471d         	li	a4, 0x7
  102484: 2ce79d63     	bne	a5, a4, 0x10275e <PT_LOAD#0+0x275e>
  102488: 15f007b7     	lui	a5, 0x15f00
  10248c: a4e9         	j	0x102756 <PT_LOAD#0+0x2756>
  10248e: 558007b7     	lui	a5, 0x55800
  102492: 10b00713     	li	a4, 0x10b
  102496: 8f95         	sub	a5, a5, a3
  102498: 075e         	slli	a4, a4, 0x17
  10249a: 1984c583     	lbu	a1, 0x198(s1)
  10249e: 64b0         	ld	a2, 0x48(s1)
  1024a0: 8f15         	sub	a4, a4, a3
  1024a2: c191         	beqz	a1, 0x1024a6 <PT_LOAD#0+0x24a6>
  1024a4: 6cb0         	ld	a2, 0x58(s1)
  1024a6: 52043583     	ld	a1, 0x520(s0)
  1024aa: 16b4bc23     	sd	a1, 0x178(s1)
  1024ae: 52843583     	ld	a1, 0x528(s0)
  1024b2: 18b4b023     	sd	a1, 0x180(s1)
  1024b6: 9ef5e7e3     	bltu	a1, a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1024ba: 9eb765e3     	bltu	a4, a1, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1024be: 51043783     	ld	a5, 0x510(s0)
  1024c2: 00094c03     	lbu	s8, 0x0(s2)
  1024c6: 008c         	addi	a1, sp, 0x40
  1024c8: 963e         	add	a2, a2, a5
  1024ca: 02200793     	li	a5, 0x22
  1024ce: e0be         	sd	a5, 0x40(sp)
  1024d0: 8562         	mv	a0, s8
  1024d2: 57fd         	li	a5, -0x1
  1024d4: e482         	sd	zero, 0x48(sp)
  1024d6: e8b2         	sd	a2, 0x50(sp)
  1024d8: ecb6         	sd	a3, 0x58(sp)
  1024da: f0be         	sd	a5, 0x60(sp)
  1024dc: ffffe097     	auipc	ra, 0xffffe
  1024e0: f82080e7     	jalr	-0x7e(ra) <PT_LOAD#0+0x45e>
  1024e4: 9c0510e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1024e8: 04814783     	lbu	a5, 0x48(sp)
  1024ec: 9a079ce3     	bnez	a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1024f0: 000bc783     	lbu	a5, 0x0(s7)
  1024f4: c789         	beqz	a5, 0x1024fe <PT_LOAD#0+0x24fe>
  1024f6: 0001f797     	auipc	a5, 0x1f
  1024fa: b0078f23     	sb	zero, -0x4e2(a5)
  1024fe: 1484b783     	ld	a5, 0x148(s1)
  102502: 1284b603     	ld	a2, 0x128(s1)
  102506: 0724ca83     	lbu	s5, 0x72(s1)
  10250a: 963e         	add	a2, a2, a5
  10250c: 24078f63     	beqz	a5, 0x10276a <PT_LOAD#0+0x276a>
  102510: 1404b583     	ld	a1, 0x140(s1)
  102514: ca09         	beqz	a2, 0x102526 <PT_LOAD#0+0x2526>
  102516: 468d         	li	a3, 0x3
  102518: 8556         	mv	a0, s5
  10251a: ffffe097     	auipc	ra, 0xffffe
  10251e: 05e080e7     	jalr	0x5e(ra) <PT_LOAD#0+0x578>
  102522: 980511e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102526: 1484b703     	ld	a4, 0x148(s1)
  10252a: 1084b783     	ld	a5, 0x108(s1)
  10252e: 00f766b3     	or	a3, a4, a5
  102532: ca85         	beqz	a3, 0x102562 <PT_LOAD#0+0x2562>
  102534: 1404b603     	ld	a2, 0x140(s1)
  102538: 1004b683     	ld	a3, 0x100(s1)
  10253c: 02a00593     	li	a1, 0x2a
  102540: e0ae         	sd	a1, 0x40(sp)
  102542: 8562         	mv	a0, s8
  102544: 008c         	addi	a1, sp, 0x40
  102546: e4b2         	sd	a2, 0x48(sp)
  102548: e8ba         	sd	a4, 0x50(sp)
  10254a: ecb6         	sd	a3, 0x58(sp)
  10254c: f0be         	sd	a5, 0x60(sp)
  10254e: ffffe097     	auipc	ra, 0xffffe
  102552: f10080e7     	jalr	-0xf0(ra) <PT_LOAD#0+0x45e>
  102556: 940517e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10255a: 04814783     	lbu	a5, 0x48(sp)
  10255e: 940793e3     	bnez	a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102562: 1184b603     	ld	a2, 0x118(s1)
  102566: ca19         	beqz	a2, 0x10257c <PT_LOAD#0+0x257c>
  102568: 1104b583     	ld	a1, 0x110(s1)
  10256c: 468d         	li	a3, 0x3
  10256e: 8556         	mv	a0, s5
  102570: ffffe097     	auipc	ra, 0xffffe
  102574: 008080e7     	jalr	0x8(ra) <PT_LOAD#0+0x578>
  102578: 920516e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10257c: 1984c783     	lbu	a5, 0x198(s1)
  102580: 469d         	li	a3, 0x7
  102582: e391         	bnez	a5, 0x102586 <PT_LOAD#0+0x2586>
  102584: 468d         	li	a3, 0x3
  102586: 70b0         	ld	a2, 0x60(s1)
  102588: 6cac         	ld	a1, 0x58(s1)
  10258a: 8556         	mv	a0, s5
  10258c: ffffe097     	auipc	ra, 0xffffe
  102590: fec080e7     	jalr	-0x14(ra) <PT_LOAD#0+0x578>
  102594: 900518e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102598: 1984c783     	lbu	a5, 0x198(s1)
  10259c: eb99         	bnez	a5, 0x1025b2 <PT_LOAD#0+0x25b2>
  10259e: 68b0         	ld	a2, 0x50(s1)
  1025a0: 64ac         	ld	a1, 0x48(s1)
  1025a2: 469d         	li	a3, 0x7
  1025a4: 8556         	mv	a0, s5
  1025a6: ffffe097     	auipc	ra, 0xffffe
  1025aa: fd2080e7     	jalr	-0x2e(ra) <PT_LOAD#0+0x578>
  1025ae: 8e051be3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1025b2: 74d0         	ld	a2, 0xa8(s1)
  1025b4: 70cc         	ld	a1, 0xa0(s1)
  1025b6: 468d         	li	a3, 0x3
  1025b8: 8556         	mv	a0, s5
  1025ba: ffffe097     	auipc	ra, 0xffffe
  1025be: fbe080e7     	jalr	-0x42(ra) <PT_LOAD#0+0x578>
  1025c2: 8e0511e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1025c6: 6cf0         	ld	a2, 0xd8(s1)
  1025c8: ca11         	beqz	a2, 0x1025dc <PT_LOAD#0+0x25dc>
  1025ca: 68ec         	ld	a1, 0xd0(s1)
  1025cc: 468d         	li	a3, 0x3
  1025ce: 8556         	mv	a0, s5
  1025d0: ffffe097     	auipc	ra, 0xffffe
  1025d4: fa8080e7     	jalr	-0x58(ra) <PT_LOAD#0+0x578>
  1025d8: 8c0516e3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  1025dc: 0f09c783     	lbu	a5, 0xf0(s3)
  1025e0: 000b3c03     	ld	s8, 0x0(s6)
  1025e4: 00a00b37     	lui	s6, 0xa00
  1025e8: c399         	beqz	a5, 0x1025ee <PT_LOAD#0+0x25ee>
  1025ea: 01000b37     	lui	s6, 0x1000
  1025ee: 4b843783     	ld	a5, 0x4b8(s0)
  1025f2: 0724ca83     	lbu	s5, 0x72(s1)
  1025f6: 9782         	jalr	a5
  1025f8: 85aa         	mv	a1, a0
  1025fa: 4701         	li	a4, 0x0
  1025fc: 4681         	li	a3, 0x0
  1025fe: 1810         	addi	a2, sp, 0x30
  102600: 8552         	mv	a0, s4
  102602: fc02         	sd	zero, 0x38(sp)
  102604: ffffe097     	auipc	ra, 0xffffe
  102608: a6a080e7     	jalr	-0x596(ra) <PT_LOAD#0+0x6e>
  10260c: 88050ce3     	beqz	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102610: 4701         	li	a4, 0x0
  102612: 16848693     	addi	a3, s1, 0x168
  102616: 4601         	li	a2, 0x0
  102618: 00001597     	auipc	a1, 0x1
  10261c: 66058593     	addi	a1, a1, 0x660
  102620: 8552         	mv	a0, s4
  102622: ffffe097     	auipc	ra, 0xffffe
  102626: a4c080e7     	jalr	-0x5b4(ra) <PT_LOAD#0+0x6e>
  10262a: 86050de3     	beqz	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10262e: 1838         	addi	a4, sp, 0x38
  102630: 4681         	li	a3, 0x0
  102632: 4601         	li	a2, 0x0
  102634: 00001597     	auipc	a1, 0x1
  102638: 65458593     	addi	a1, a1, 0x654
  10263c: 8552         	mv	a0, s4
  10263e: ffffe097     	auipc	ra, 0xffffe
  102642: a30080e7     	jalr	-0x5d0(ra) <PT_LOAD#0+0x6e>
  102646: 84050fe3     	beqz	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10264a: 77e2         	ld	a5, 0x38(sp)
  10264c: 4619         	li	a2, 0x6
  10264e: 8552         	mv	a0, s4
  102650: 678c         	ld	a1, 0x8(a5)
  102652: ffffe097     	auipc	ra, 0xffffe
  102656: 456080e7     	jalr	0x456(ra) <PT_LOAD#0+0xaa8>
  10265a: 840505e3     	beqz	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10265e: 7118         	ld	a4, 0x20(a0)
  102660: 004007b7     	lui	a5, 0x400
  102664: 84e7e0e3     	bltu	a5, a4, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102668: 02300793     	li	a5, 0x23
  10266c: 00094503     	lbu	a0, 0x0(s2)
  102670: e0be         	sd	a5, 0x40(sp)
  102672: 002007b7     	lui	a5, 0x200
  102676: ecbe         	sd	a5, 0x58(sp)
  102678: 008c         	addi	a1, sp, 0x40
  10267a: 478d         	li	a5, 0x3
  10267c: e4d6         	sd	s5, 0x48(sp)
  10267e: e8da         	sd	s6, 0x50(sp)
  102680: f0be         	sd	a5, 0x60(sp)
  102682: ffffe097     	auipc	ra, 0xffffe
  102686: ddc080e7     	jalr	-0x224(ra) <PT_LOAD#0+0x45e>
  10268a: 80051de3     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10268e: 04814783     	lbu	a5, 0x48(sp)
  102692: 6bc6         	ld	s7, 0x50(sp)
  102694: 800798e3     	bnez	a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102698: 020c3783     	ld	a5, 0x20(s8)
  10269c: 8b85         	andi	a5, a5, 0x1
  10269e: e3a9         	bnez	a5, 0x1026e0 <PT_LOAD#0+0x26e0>
  1026a0: 0e09bc83     	ld	s9, 0xe0(s3)
  1026a4: 0c0c8663     	beqz	s9, 0x102770 <PT_LOAD#0+0x2770>
  1026a8: 0e89a403     	lw	s0, 0xe8(s3)
  1026ac: c071         	beqz	s0, 0x102770 <PT_LOAD#0+0x2770>
  1026ae: 1402         	slli	s0, s0, 0x20
  1026b0: 9001         	srli	s0, s0, 0x20
  1026b2: 00022797     	auipc	a5, 0x22
  1026b6: e267b783     	ld	a5, -0x1da(a5)
  1026ba: 8626         	mv	a2, s1
  1026bc: 85a2         	mv	a1, s0
  1026be: 8566         	mv	a0, s9
  1026c0: 9782         	jalr	a5
  1026c2: 4781         	li	a5, 0x0
  1026c4: f0aa         	sd	a0, 0x60(sp)
  1026c6: 00094503     	lbu	a0, 0x0(s2)
  1026ca: 02e00713     	li	a4, 0x2e
  1026ce: 008c         	addi	a1, sp, 0x40
  1026d0: e0ba         	sd	a4, 0x40(sp)
  1026d2: e4be         	sd	a5, 0x48(sp)
  1026d4: e8e6         	sd	s9, 0x50(sp)
  1026d6: eca2         	sd	s0, 0x58(sp)
  1026d8: ffffe097     	auipc	ra, 0xffffe
  1026dc: d86080e7     	jalr	-0x27a(ra) <PT_LOAD#0+0x45e>
  1026e0: 74b4         	ld	a3, 0x68(s1)
  1026e2: 020c3703     	ld	a4, 0x20(s8)
  1026e6: 02500793     	li	a5, 0x25
  1026ea: 567d         	li	a2, -0x1
  1026ec: e0be         	sd	a5, 0x40(sp)
  1026ee: 00066797     	auipc	a5, 0x66
  1026f2: 91278793     	addi	a5, a5, -0x6ee
  1026f6: 46c7b023     	sd	a2, 0x460(a5)
  1026fa: 00094503     	lbu	a0, 0x0(s2)
  1026fe: 7642         	ld	a2, 0x30(sp)
  102700: 830d         	srli	a4, a4, 0x3
  102702: 48d7b423     	sd	a3, 0x488(a5)
  102706: 46bd         	li	a3, 0xf
  102708: 8b05         	andi	a4, a4, 0x1
  10270a: 4ad7a023     	sw	a3, 0x4a0(a5)
  10270e: 008c         	addi	a1, sp, 0x40
  102710: 4685         	li	a3, 0x1
  102712: 46c7b423     	sd	a2, 0x468(a5)
  102716: e4d6         	sd	s5, 0x48(sp)
  102718: e8d2         	sd	s4, 0x50(sp)
  10271a: ecde         	sd	s7, 0x58(sp)
  10271c: f0da         	sd	s6, 0x60(sp)
  10271e: 00066617     	auipc	a2, 0x66
  102722: d4063d23     	sd	zero, -0x2a6(a2)
  102726: 00066617     	auipc	a2, 0x66
  10272a: d0063d23     	sd	zero, -0x2e6(a2)
  10272e: 4497b423     	sd	s1, 0x448(a5)
  102732: 4ad78223     	sb	a3, 0x4a4(a5)
  102736: 4ae782a3     	sb	a4, 0x4a5(a5)
  10273a: ffffe097     	auipc	ra, 0xffffe
  10273e: d24080e7     	jalr	-0x2dc(ra) <PT_LOAD#0+0x45e>
  102742: f6051163     	bnez	a0, 0x101ea4 <PT_LOAD#0+0x1ea4>
  102746: 04814783     	lbu	a5, 0x48(sp)
  10274a: f4079d63     	bnez	a5, 0x101ea4 <PT_LOAD#0+0x1ea4>
  10274e: 87d6         	mv	a5, s5
  102750: b189         	j	0x102392 <PT_LOAD#0+0x2392>
  102752: 243007b7     	lui	a5, 0x24300
  102756: 8f95         	sub	a5, a5, a3
  102758: 44300737     	lui	a4, 0x44300
  10275c: bb3d         	j	0x10249a <PT_LOAD#0+0x249a>
  10275e: 056007b7     	lui	a5, 0x5600
  102762: 8f95         	sub	a5, a5, a3
  102764: 11600737     	lui	a4, 0x11600
  102768: bb0d         	j	0x10249a <PT_LOAD#0+0x249a>
  10276a: 1204b583     	ld	a1, 0x120(s1)
  10276e: b35d         	j	0x102514 <PT_LOAD#0+0x2514>
  102770: 60e8         	ld	a0, 0xc0(s1)
  102772: 4c81         	li	s9, 0x0
  102774: 6405         	lui	s0, 0x1
  102776: 478d         	li	a5, 0x3
  102778: b7b1         	j	0x1026c4 <PT_LOAD#0+0x26c4>
  10277a: 7135         	addi	sp, sp, -0xa0
  10277c: 00042797     	auipc	a5, 0x42
  102780: 48478793     	addi	a5, a5, 0x484
  102784: 6705         	lui	a4, 0x1
  102786: e922         	sd	s0, 0x90(sp)
  102788: fcce         	sd	s3, 0x78(sp)
  10278a: ed06         	sd	ra, 0x98(sp)
  10278c: e526         	sd	s1, 0x88(sp)
  10278e: e14a         	sd	s2, 0x80(sp)
  102790: f8d2         	sd	s4, 0x70(sp)
  102792: f4d6         	sd	s5, 0x68(sp)
  102794: f0da         	sd	s6, 0x60(sp)
  102796: ecde         	sd	s7, 0x58(sp)
  102798: e8e2         	sd	s8, 0x50(sp)
  10279a: e4e6         	sd	s9, 0x48(sp)
  10279c: e0ea         	sd	s10, 0x40(sp)
  10279e: fc6e         	sd	s11, 0x38(sp)
  1027a0: 842a         	mv	s0, a0
  1027a2: 00062697     	auipc	a3, 0x62
  1027a6: 45e68693     	addi	a3, a3, 0x45e
  1027aa: 89be         	mv	s3, a5
  1027ac: 80070713     	addi	a4, a4, -0x800
  1027b0: 0107c603     	lbu	a2, 0x10(a5)
  1027b4: c619         	beqz	a2, 0x1027c2 <PT_LOAD#0+0x27c2>
  1027b6: 0117c603     	lbu	a2, 0x11(a5)
  1027ba: 00861463     	bne	a2, s0, 0x1027c2 <PT_LOAD#0+0x27c2>
  1027be: 00078823     	sb	zero, 0x10(a5)
  1027c2: 97ba         	add	a5, a5, a4
  1027c4: fed796e3     	bne	a5, a3, 0x1027b0 <PT_LOAD#0+0x27b0>
  1027c8: 6a89         	lui	s5, 0x2
  1027ca: 4905         	li	s2, 0x1
  1027cc: 00b41b13     	slli	s6, s0, 0xb
  1027d0: 00891933     	sll	s2, s2, s0
  1027d4: 01698d33     	add	s10, s3, s6
  1027d8: 4a3d         	li	s4, 0xf
  1027da: 018a8b93     	addi	s7, s5, 0x18
  1027de: 020a8c13     	addi	s8, s5, 0x20
  1027e2: 028a8c93     	addi	s9, s5, 0x28
  1027e6: 210d2783     	lw	a5, 0x210(s10)
  1027ea: 4705         	li	a4, 0x1
  1027ec: fff7869b     	addiw	a3, a5, -0x1
  1027f0: 0cd76a63     	bltu	a4, a3, 0x1028c4 <PT_LOAD#0+0x28c4>
  1027f4: 1f8d3703     	ld	a4, 0x1f8(s10)
  1027f8: 200d3603     	ld	a2, 0x200(s10)
  1027fc: 00022797     	auipc	a5, 0x22
  102800: fb478793     	addi	a5, a5, -0x4c
  102804: 4481         	li	s1, 0x0
  102806: 8dbe         	mv	s11, a5
  102808: 00c705b3     	add	a1, a4, a2
  10280c: 4541         	li	a0, 0x10
  10280e: 6394         	ld	a3, 0x0(a5)
  102810: 00d976b3     	and	a3, s2, a3
  102814: c2dd         	beqz	a3, 0x1028ba <PT_LOAD#0+0x28ba>
  102816: 0ae5e263     	bltu	a1, a4, 0x1028ba <PT_LOAD#0+0x28ba>
  10281a: 017786b3     	add	a3, a5, s7
  10281e: 6294         	ld	a3, 0x0(a3)
  102820: 08d76d63     	bltu	a4, a3, 0x1028ba <PT_LOAD#0+0x28ba>
  102824: 018786b3     	add	a3, a5, s8
  102828: 6294         	ld	a3, 0x0(a3)
  10282a: 08b6e863     	bltu	a3, a1, 0x1028ba <PT_LOAD#0+0x28ba>
  10282e: 4581         	li	a1, 0x0
  102830: 853a         	mv	a0, a4
  102832: e432         	sd	a2, 0x8(sp)
  102834: e03a         	sd	a4, 0x0(sp)
  102836: 1482         	slli	s1, s1, 0x20
  102838: fffff097     	auipc	ra, 0xfffff
  10283c: 58a080e7     	jalr	0x58a(ra) <PT_LOAD#0+0x1dc2>
  102840: 028a8793     	addi	a5, s5, 0x28
  102844: 9081         	srli	s1, s1, 0x20
  102846: 02f484b3     	<unknown>
  10284a: 6622         	ld	a2, 0x8(sp)
  10284c: 6702         	ld	a4, 0x0(sp)
  10284e: 009d87b3     	add	a5, s11, s1
  102852: 97d6         	add	a5, a5, s5
  102854: 6f8c         	ld	a1, 0x18(a5)
  102856: 67c1         	lui	a5, 0x10
  102858: 17fd         	addi	a5, a5, -0x1
  10285a: 963e         	add	a2, a2, a5
  10285c: 40b705b3     	sub	a1, a4, a1
  102860: 8241         	srli	a2, a2, 0x10
  102862: 81c1         	srli	a1, a1, 0x10
  102864: 167d         	addi	a2, a2, -0x1
  102866: 04a1         	addi	s1, s1, 0x8
  102868: 962e         	add	a2, a2, a1
  10286a: 009d8533     	add	a0, s11, s1
  10286e: ffffe097     	auipc	ra, 0xffffe
  102872: e64080e7     	jalr	-0x19c(ra) <PT_LOAD#0+0x6d2>
  102876: 1e0d3c23     	sd	zero, 0x1f8(s10)
  10287a: 200d3023     	sd	zero, 0x200(s10)
  10287e: 200d2823     	sw	zero, 0x210(s10)
  102882: 4681         	li	a3, 0x0
  102884: 1010         	addi	a2, sp, 0x20
  102886: 45a1         	li	a1, 0x8
  102888: 00065517     	auipc	a0, 0x65
  10288c: 77850513     	addi	a0, a0, 0x778
  102890: ffffe097     	auipc	ra, 0xffffe
  102894: d50080e7     	jalr	-0x2b0(ra) <PT_LOAD#0+0x5e0>
  102898: 10051263     	bnez	a0, 0x10299c <PT_LOAD#0+0x299c>
  10289c: 0006b617     	auipc	a2, 0x6b
  1028a0: 72c60613     	addi	a2, a2, 0x72c
  1028a4: 3f900593     	li	a1, 0x3f9
  1028a8: 4509         	li	a0, 0x2
  1028aa: ffffe097     	auipc	ra, 0xffffe
  1028ae: 242080e7     	jalr	0x242(ra) <PT_LOAD#0+0xaec>
  1028b2: fffff097     	auipc	ra, 0xfffff
  1028b6: 2d4080e7     	jalr	0x2d4(ra) <PT_LOAD#0+0x1b86>
  1028ba: 2485         	addiw	s1, s1, 0x1
  1028bc: 97e6         	add	a5, a5, s9
  1028be: f4a498e3     	bne	s1, a0, 0x10280e <PT_LOAD#0+0x280e>
  1028c2: bf55         	j	0x102876 <PT_LOAD#0+0x2876>
  1028c4: fbcd         	bnez	a5, 0x102876 <PT_LOAD#0+0x2876>
  1028c6: 1a7d         	addi	s4, s4, -0x1
  1028c8: 57fd         	li	a5, -0x1
  1028ca: 1d01         	addi	s10, s10, -0x20
  1028cc: f0fa1de3     	bne	s4, a5, 0x1027e6 <PT_LOAD#0+0x27e6>
  1028d0: 4581         	li	a1, 0x0
  1028d2: 8522         	mv	a0, s0
  1028d4: 00001097     	auipc	ra, 0x1
  1028d8: 1b2080e7     	jalr	0x1b2(ra) <PT_LOAD#0+0x3a86>
  1028dc: 00065497     	auipc	s1, 0x65
  1028e0: 72448493     	addi	s1, s1, 0x724
  1028e4: 2084b783     	ld	a5, 0x208(s1)
  1028e8: fff94913     	not	s2, s2
  1028ec: 99da         	add	s3, s3, s6
  1028ee: 0127f7b3     	and	a5, a5, s2
  1028f2: 20f4b423     	sd	a5, 0x208(s1)
  1028f6: 01499023     	sh	s4, 0x0(s3)
  1028fa: 0009aa23     	sw	zero, 0x14(s3)
  1028fe: 00066797     	auipc	a5, 0x66
  102902: 62a7c783     	lbu	a5, 0x62a(a5)
  102906: 00879e63     	bne	a5, s0, 0x102922 <PT_LOAD#0+0x2922>
  10290a: 00066797     	auipc	a5, 0x66
  10290e: 60078f23     	sb	zero, 0x61e(a5)
  102912: 00066797     	auipc	a5, 0x66
  102916: 6007ad23     	sw	zero, 0x61a(a5)
  10291a: 00066797     	auipc	a5, 0x66
  10291e: 6007ab23     	sw	zero, 0x616(a5)
  102922: 00066797     	auipc	a5, 0x66
  102926: b8678793     	addi	a5, a5, -0x47a
  10292a: 00066717     	auipc	a4, 0x66
  10292e: f7e70713     	addi	a4, a4, -0x82
  102932: 85a2         	mv	a1, s0
  102934: f03e         	sd	a5, 0x20(sp)
  102936: 1008         	addi	a0, sp, 0x20
  102938: 04000793     	li	a5, 0x40
  10293c: f43e         	sd	a5, 0x28(sp)
  10293e: e83a         	sd	a4, 0x10(sp)
  102940: ec3e         	sd	a5, 0x18(sp)
  102942: 00001097     	auipc	ra, 0x1
  102946: 0f2080e7     	jalr	0xf2(ra) <PT_LOAD#0+0x3a34>
  10294a: 85a2         	mv	a1, s0
  10294c: 0808         	addi	a0, sp, 0x10
  10294e: 00001097     	auipc	ra, 0x1
  102952: 0e6080e7     	jalr	0xe6(ra) <PT_LOAD#0+0x3a34>
  102956: 00069617     	auipc	a2, 0x69
  10295a: 71a60613     	addi	a2, a2, 0x71a
  10295e: 9426         	add	s0, s0, s1
  102960: 6785         	lui	a5, 0x1
  102962: 4218         	lw	a4, 0x0(a2)
  102964: 97a2         	add	a5, a5, s0
  102966: ee078423     	sb	zero, -0x118(a5)
  10296a: 4791         	li	a5, 0x4
  10296c: 04f71663     	bne	a4, a5, 0x1029b8 <PT_LOAD#0+0x29b8>
  102970: 0001e717     	auipc	a4, 0x1e
  102974: 6a070713     	addi	a4, a4, 0x6a0
  102978: 431c         	lw	a5, 0x0(a4)
  10297a: 56fd         	li	a3, -0x1
  10297c: 02d78e63     	beq	a5, a3, 0x1029b8 <PT_LOAD#0+0x29b8>
  102980: 4585         	li	a1, 0x1
  102982: 1782         	slli	a5, a5, 0x20
  102984: c20c         	sw	a1, 0x0(a2)
  102986: c314         	sw	a3, 0x0(a4)
  102988: 9381         	srli	a5, a5, 0x20
  10298a: 4701         	li	a4, 0x0
  10298c: 4681         	li	a3, 0x0
  10298e: 4601         	li	a2, 0x0
  102990: 4581         	li	a1, 0x0
  102992: 4541         	li	a0, 0x10
  102994: 00001097     	auipc	ra, 0x1
  102998: 0dc080e7     	jalr	0xdc(ra) <PT_LOAD#0+0x3a70>
  10299c: 7502         	ld	a0, 0x20(sp)
  10299e: 47a1         	li	a5, 0x8
  1029a0: 00065717     	auipc	a4, 0x65
  1029a4: 66070713     	addi	a4, a4, 0x660
  1029a8: 4681         	li	a3, 0x0
  1029aa: 8652         	mv	a2, s4
  1029ac: 85a2         	mv	a1, s0
  1029ae: 00001097     	auipc	ra, 0x1
  1029b2: 14a080e7     	jalr	0x14a(ra) <PT_LOAD#0+0x3af8>
  1029b6: bf01         	j	0x1028c6 <PT_LOAD#0+0x28c6>
  1029b8: 2084b703     	ld	a4, 0x208(s1)
  1029bc: e709         	bnez	a4, 0x1029c6 <PT_LOAD#0+0x29c6>
  1029be: 00001097     	auipc	ra, 0x1
  1029c2: 0c0080e7     	jalr	0xc0(ra) <PT_LOAD#0+0x3a7e>
  1029c6: 40e007b3     	neg	a5, a4
  1029ca: 8ff9         	and	a5, a5, a4
  1029cc: 00001717     	auipc	a4, 0x1
  1029d0: 58473703     	ld	a4, 0x584(a4)
  1029d4: 02e787b3     	<unknown>
  1029d8: 00001717     	auipc	a4, 0x1
  1029dc: 3b070713     	addi	a4, a4, 0x3b0
  1029e0: 4681         	li	a3, 0x0
  1029e2: 4601         	li	a2, 0x0
  1029e4: 4581         	li	a1, 0x0
  1029e6: 03100513     	li	a0, 0x31
  1029ea: 93e9         	srli	a5, a5, 0x3a
  1029ec: 97ba         	add	a5, a5, a4
  1029ee: 0007c783     	lbu	a5, 0x0(a5)
  1029f2: 4701         	li	a4, 0x0
  1029f4: b745         	j	0x102994 <PT_LOAD#0+0x2994>
  1029f6: 479d         	li	a5, 0x7
  1029f8: 00c506b3     	add	a3, a0, a2
  1029fc: 06c7e163     	bltu	a5, a2, 0x102a5e <PT_LOAD#0+0x2a5e>
  102a00: 87aa         	mv	a5, a0
  102a02: 0ad79c63     	bne	a5, a3, 0x102aba <PT_LOAD#0+0x2aba>
  102a06: 8082         	ret
  102a08: 0005c703     	lbu	a4, 0x0(a1)
  102a0c: 0585         	addi	a1, a1, 0x1
  102a0e: 0785         	addi	a5, a5, 0x1
  102a10: fee78fa3     	sb	a4, -0x1(a5)
  102a14: 0077f613     	andi	a2, a5, 0x7
  102a18: fa65         	bnez	a2, 0x102a08 <PT_LOAD#0+0x2a08>
  102a1a: 0075f713     	andi	a4, a1, 0x7
  102a1e: c735         	beqz	a4, 0x102a8a <PT_LOAD#0+0x2a8a>
  102a20: 4701         	li	a4, 0x0
  102a22: 0075f813     	andi	a6, a1, 0x7
  102a26: 06081563     	bnez	a6, 0x102a90 <PT_LOAD#0+0x2a90>
  102a2a: 04000313     	li	t1, 0x40
  102a2e: 88ae         	mv	a7, a1
  102a30: 883e         	mv	a6, a5
  102a32: 00070f1b     	sext.w	t5, a4
  102a36: 40e3033b     	subw	t1, t1, a4
  102a3a: 0821         	addi	a6, a6, 0x8
  102a3c: 0706f363     	bgeu	a3, a6, 0x102aa2 <PT_LOAD#0+0x2aa2>
  102a40: 00178893     	addi	a7, a5, 0x1
  102a44: 00168813     	addi	a6, a3, 0x1
  102a48: 4601         	li	a2, 0x0
  102a4a: 01186563     	bltu	a6, a7, 0x102a54 <PT_LOAD#0+0x2a54>
  102a4e: 40f68633     	sub	a2, a3, a5
  102a52: 9a61         	andi	a2, a2, -0x8
  102a54: 830d         	srli	a4, a4, 0x3
  102a56: 97b2         	add	a5, a5, a2
  102a58: 8e19         	sub	a2, a2, a4
  102a5a: 95b2         	add	a1, a1, a2
  102a5c: b75d         	j	0x102a02 <PT_LOAD#0+0x2a02>
  102a5e: 87aa         	mv	a5, a0
  102a60: bf55         	j	0x102a14 <PT_LOAD#0+0x2a14>
  102a62: 00063803     	ld	a6, 0x0(a2)
  102a66: 0621         	addi	a2, a2, 0x8
  102a68: ff073c23     	sd	a6, -0x8(a4)
  102a6c: 0721         	addi	a4, a4, 0x8
  102a6e: fed76ae3     	bltu	a4, a3, 0x102a62 <PT_LOAD#0+0x2a62>
  102a72: 00178613     	addi	a2, a5, 0x1
  102a76: 4701         	li	a4, 0x0
  102a78: 00c6e663     	bltu	a3, a2, 0x102a84 <PT_LOAD#0+0x2a84>
  102a7c: fff68713     	addi	a4, a3, -0x1
  102a80: 8f1d         	sub	a4, a4, a5
  102a82: 9b61         	andi	a4, a4, -0x8
  102a84: 97ba         	add	a5, a5, a4
  102a86: 95ba         	add	a1, a1, a4
  102a88: bfad         	j	0x102a02 <PT_LOAD#0+0x2a02>
  102a8a: 862e         	mv	a2, a1
  102a8c: 873e         	mv	a4, a5
  102a8e: bff9         	j	0x102a6c <PT_LOAD#0+0x2a6c>
  102a90: 0005c803     	lbu	a6, 0x0(a1)
  102a94: 0585         	addi	a1, a1, 0x1
  102a96: 00e81833     	sll	a6, a6, a4
  102a9a: 01066633     	or	a2, a2, a6
  102a9e: 0721         	addi	a4, a4, 0x8
  102aa0: b749         	j	0x102a22 <PT_LOAD#0+0x2a22>
  102aa2: 0008be83     	ld	t4, 0x0(a7)
  102aa6: 08a1         	addi	a7, a7, 0x8
  102aa8: 01ee9e33     	sll	t3, t4, t5
  102aac: 00ce6e33     	or	t3, t3, a2
  102ab0: ffc83c23     	sd	t3, -0x8(a6)
  102ab4: 006ed633     	srl	a2, t4, t1
  102ab8: b749         	j	0x102a3a <PT_LOAD#0+0x2a3a>
  102aba: 0005c703     	lbu	a4, 0x0(a1)
  102abe: 0585         	addi	a1, a1, 0x1
  102ac0: 0785         	addi	a5, a5, 0x1
  102ac2: fee78fa3     	sb	a4, -0x1(a5)
  102ac6: bf35         	j	0x102a02 <PT_LOAD#0+0x2a02>
  102ac8: 7159         	addi	sp, sp, -0x70
  102aca: 468d         	li	a3, 0x3
  102acc: f0a2         	sd	s0, 0x60(sp)
  102ace: eca6         	sd	s1, 0x58(sp)
  102ad0: e8ca         	sd	s2, 0x50(sp)
  102ad2: f486         	sd	ra, 0x68(sp)
  102ad4: e4ce         	sd	s3, 0x48(sp)
  102ad6: e0d2         	sd	s4, 0x40(sp)
  102ad8: fc56         	sd	s5, 0x38(sp)
  102ada: f85a         	sd	s6, 0x30(sp)
  102adc: f45e         	sd	s7, 0x28(sp)
  102ade: f062         	sd	s8, 0x20(sp)
  102ae0: ec66         	sd	s9, 0x18(sp)
  102ae2: 84aa         	mv	s1, a0
  102ae4: 892e         	mv	s2, a1
  102ae6: 8432         	mv	s0, a2
  102ae8: ffffe097     	auipc	ra, 0xffffe
  102aec: b3c080e7     	jalr	-0x4c4(ra) <PT_LOAD#0+0x624>
  102af0: e915         	bnez	a0, 0x102b24 <PT_LOAD#0+0x2b24>
  102af2: 450d         	li	a0, 0x3
  102af4: 0006b697     	auipc	a3, 0x6b
  102af8: 4ec68693     	addi	a3, a3, 0x4ec
  102afc: 8626         	mv	a2, s1
  102afe: 85ca         	mv	a1, s2
  102b00: ffffe097     	auipc	ra, 0xffffe
  102b04: fec080e7     	jalr	-0x14(ra) <PT_LOAD#0+0xaec>
  102b08: 4505         	li	a0, 0x1
  102b0a: 70a6         	ld	ra, 0x68(sp)
  102b0c: 7406         	ld	s0, 0x60(sp)
  102b0e: 64e6         	ld	s1, 0x58(sp)
  102b10: 6946         	ld	s2, 0x50(sp)
  102b12: 69a6         	ld	s3, 0x48(sp)
  102b14: 6a06         	ld	s4, 0x40(sp)
  102b16: 7ae2         	ld	s5, 0x38(sp)
  102b18: 7b42         	ld	s6, 0x30(sp)
  102b1a: 7ba2         	ld	s7, 0x28(sp)
  102b1c: 7c02         	ld	s8, 0x20(sp)
  102b1e: 6ce2         	ld	s9, 0x18(sp)
  102b20: 6165         	addi	sp, sp, 0x70
  102b22: 8082         	ret
  102b24: 00069b17     	auipc	s6, 0x69
  102b28: 544b3b03     	ld	s6, 0x544(s6)
  102b2c: 84ca         	mv	s1, s2
  102b2e: 020b0763     	beqz	s6, 0x102b5c <PT_LOAD#0+0x2b5c>
  102b32: 6a41         	lui	s4, 0x10
  102b34: 6ab9         	lui	s5, 0xe
  102b36: 1a7d         	addi	s4, s4, -0x1
  102b38: eada8a93     	addi	s5, s5, -0x153
  102b3c: 412485b3     	sub	a1, s1, s2
  102b40: 00858993     	addi	s3, a1, 0x8
  102b44: 0289e763     	bltu	s3, s0, 0x102b72 <PT_LOAD#0+0x2b72>
  102b48: 00890633     	add	a2, s2, s0
  102b4c: 08960363     	beq	a2, s1, 0x102bd2 <PT_LOAD#0+0x2bd2>
  102b50: 0006b697     	auipc	a3, 0x6b
  102b54: 4f068693     	addi	a3, a3, 0x4f0
  102b58: 85a6         	mv	a1, s1
  102b5a: a81d         	j	0x102b90 <PT_LOAD#0+0x2b90>
  102b5c: 0006b597     	auipc	a1, 0x6b
  102b60: 49c58593     	addi	a1, a1, 0x49c
  102b64: 4505         	li	a0, 0x1
  102b66: ffffe097     	auipc	ra, 0xffffe
  102b6a: f86080e7     	jalr	-0x7a(ra) <PT_LOAD#0+0xaec>
  102b6e: 4501         	li	a0, 0x0
  102b70: bf69         	j	0x102b0a <PT_LOAD#0+0x2b0a>
  102b72: 6090         	ld	a2, 0x0(s1)
  102b74: 014677b3     	and	a5, a2, s4
  102b78: 01579863     	bne	a5, s5, 0x102b88 <PT_LOAD#0+0x2b88>
  102b7c: 01065793     	srli	a5, a2, 0x10
  102b80: 0007871b     	sext.w	a4, a5
  102b84: 8bbd         	andi	a5, a5, 0xf
  102b86: ef81         	bnez	a5, 0x102b9e <PT_LOAD#0+0x2b9e>
  102b88: 0006b697     	auipc	a3, 0x6b
  102b8c: 48868693     	addi	a3, a3, 0x488
  102b90: 450d         	li	a0, 0x3
  102b92: ffffe097     	auipc	ra, 0xffffe
  102b96: f5a080e7     	jalr	-0xa6(ra) <PT_LOAD#0+0xaec>
  102b9a: 4511         	li	a0, 0x4
  102b9c: b7bd         	j	0x102b0a <PT_LOAD#0+0x2b0a>
  102b9e: 00e77793     	andi	a5, a4, 0xe
  102ba2: f3fd         	bnez	a5, 0x102b88 <PT_LOAD#0+0x2b88>
  102ba4: 8532         	mv	a0, a2
  102ba6: e42e         	sd	a1, 0x8(sp)
  102ba8: e032         	sd	a2, 0x0(sp)
  102baa: ffffe097     	auipc	ra, 0xffffe
  102bae: a02080e7     	jalr	-0x5fe(ra) <PT_LOAD#0+0x5ac>
  102bb2: 6602         	ld	a2, 0x0(sp)
  102bb4: 65a2         	ld	a1, 0x8(sp)
  102bb6: d969         	beqz	a0, 0x102b88 <PT_LOAD#0+0x2b88>
  102bb8: 99aa         	add	s3, s3, a0
  102bba: 01347963     	bgeu	s0, s3, 0x102bcc <PT_LOAD#0+0x2bcc>
  102bbe: 0006b697     	auipc	a3, 0x6b
  102bc2: 46a68693     	addi	a3, a3, 0x46a
  102bc6: 8622         	mv	a2, s0
  102bc8: 85aa         	mv	a1, a0
  102bca: b7d9         	j	0x102b90 <PT_LOAD#0+0x2b90>
  102bcc: 0521         	addi	a0, a0, 0x8
  102bce: 94aa         	add	s1, s1, a0
  102bd0: b7b5         	j	0x102b3c <PT_LOAD#0+0x2b3c>
  102bd2: 00069c17     	auipc	s8, 0x69
  102bd6: 492c0c13     	addi	s8, s8, 0x492
  102bda: 000c4783     	lbu	a5, 0x0(s8)
  102bde: 00021b97     	auipc	s7, 0x21
  102be2: 422b8b93     	addi	s7, s7, 0x422
  102be6: 508baa83     	lw	s5, 0x508(s7)
  102bea: 500bba03     	ld	s4, 0x500(s7)
  102bee: 4f0bb983     	ld	s3, 0x4f0(s7)
  102bf2: e3c1         	bnez	a5, 0x102c72 <PT_LOAD#0+0x2c72>
  102bf4: 00069497     	auipc	s1, 0x69
  102bf8: 46c4a483     	lw	s1, 0x46c(s1)
  102bfc: 00069c97     	auipc	s9, 0x69
  102c00: 45ccbc83     	ld	s9, 0x45c(s9)
  102c04: 02049593     	slli	a1, s1, 0x20
  102c08: 0006b717     	auipc	a4, 0x6b
  102c0c: 45070713     	addi	a4, a4, 0x450
  102c10: 86e6         	mv	a3, s9
  102c12: 865a         	mv	a2, s6
  102c14: 9181         	srli	a1, a1, 0x20
  102c16: 4511         	li	a0, 0x4
  102c18: ffffe097     	auipc	ra, 0xffffe
  102c1c: ed4080e7     	jalr	-0x12c(ra) <PT_LOAD#0+0xaec>
  102c20: 00ab5793     	srli	a5, s6, 0xa
  102c24: 0ff7f793     	zext.b	a5, a5
  102c28: 889d         	andi	s1, s1, 0x7
  102c2a: 37fd         	addiw	a5, a5, -0x1
  102c2c: 0084e493     	ori	s1, s1, 0x8
  102c30: c00cfc93     	andi	s9, s9, -0x400
  102c34: 079a         	slli	a5, a5, 0x6
  102c36: 3c07f793     	andi	a5, a5, 0x3c0
  102c3a: 0194e4b3     	or	s1, s1, s9
  102c3e: 8cdd         	or	s1, s1, a5
  102c40: 0004879b     	sext.w	a5, s1
  102c44: 00f9a023     	sw	a5, 0x0(s3)
  102c48: 4f8bb783     	ld	a5, 0x4f8(s7)
  102c4c: 4e8bb703     	ld	a4, 0x4e8(s7)
  102c50: 9481         	srai	s1, s1, 0x20
  102c52: c384         	sw	s1, 0x0(a5)
  102c54: 0011e7b7     	lui	a5, 0x11e
  102c58: ead78793     	addi	a5, a5, -0x153
  102c5c: c31c         	sw	a5, 0x0(a4)
  102c5e: 015a2023     	sw	s5, 0x0(s4)
  102c62: 431c         	lw	a5, 0x0(a4)
  102c64: 0147d79b     	srliw	a5, a5, 0x14
  102c68: 8b9d         	andi	a5, a5, 0x7
  102c6a: ffe5         	bnez	a5, 0x102c62 <PT_LOAD#0+0x2c62>
  102c6c: 4785         	li	a5, 0x1
  102c6e: 00fc0023     	sb	a5, 0x0(s8)
  102c72: 00069b97     	auipc	s7, 0x69
  102c76: 3deb8b93     	addi	s7, s7, 0x3de
  102c7a: 000bb503     	ld	a0, 0x0(s7)
  102c7e: 0005071b     	sext.w	a4, a0
  102c82: 0009a603     	lw	a2, 0x0(s3)
  102c86: 40e607bb     	subw	a5, a2, a4
  102c8a: 00c76463     	bltu	a4, a2, 0x102c92 <PT_LOAD#0+0x2c92>
  102c8e: 016787bb     	addw	a5, a5, s6
  102c92: 1782         	slli	a5, a5, 0x20
  102c94: 9381         	srli	a5, a5, 0x20
  102c96: fe87e6e3     	bltu	a5, s0, 0x102c82 <PT_LOAD#0+0x2c82>
  102c9a: 008507b3     	add	a5, a0, s0
  102c9e: 00069c17     	auipc	s8, 0x69
  102ca2: 3aac3c03     	ld	s8, 0x3aa(s8)
  102ca6: 0367f4b3     	<unknown>
  102caa: 9562         	add	a0, a0, s8
  102cac: 02fb7a63     	bgeu	s6, a5, 0x102ce0 <PT_LOAD#0+0x2ce0>
  102cb0: 40940633     	sub	a2, s0, s1
  102cb4: 85ca         	mv	a1, s2
  102cb6: 01260433     	add	s0, a2, s2
  102cba: 00000097     	auipc	ra, 0x0
  102cbe: d3c080e7     	jalr	-0x2c4(ra) <PT_LOAD#0+0x29f6>
  102cc2: 8626         	mv	a2, s1
  102cc4: 85a2         	mv	a1, s0
  102cc6: 8562         	mv	a0, s8
  102cc8: 00000097     	auipc	ra, 0x0
  102ccc: d2e080e7     	jalr	-0x2d2(ra) <PT_LOAD#0+0x29f6>
  102cd0: 009bb023     	sd	s1, 0x0(s7)
  102cd4: 2481         	sext.w	s1, s1
  102cd6: 0099a023     	sw	s1, 0x0(s3)
  102cda: 015a2023     	sw	s5, 0x0(s4)
  102cde: bd41         	j	0x102b6e <PT_LOAD#0+0x2b6e>
  102ce0: 8622         	mv	a2, s0
  102ce2: 85ca         	mv	a1, s2
  102ce4: b7d5         	j	0x102cc8 <PT_LOAD#0+0x2cc8>
  102ce6: 7171         	addi	sp, sp, -0xb0
  102ce8: f122         	sd	s0, 0xa0(sp)
  102cea: ed26         	sd	s1, 0x98(sp)
  102cec: e94a         	sd	s2, 0x90(sp)
  102cee: e54e         	sd	s3, 0x88(sp)
  102cf0: e152         	sd	s4, 0x80(sp)
  102cf2: fcd6         	sd	s5, 0x78(sp)
  102cf4: f4de         	sd	s7, 0x68(sp)
  102cf6: e4ee         	sd	s11, 0x48(sp)
  102cf8: 8a3a         	mv	s4, a4
  102cfa: 843e         	mv	s0, a5
  102cfc: f506         	sd	ra, 0xa8(sp)
  102cfe: f8da         	sd	s6, 0x70(sp)
  102d00: f0e2         	sd	s8, 0x60(sp)
  102d02: ece6         	sd	s9, 0x58(sp)
  102d04: e8ea         	sd	s10, 0x50(sp)
  102d06: 8baa         	mv	s7, a0
  102d08: 84ae         	mv	s1, a1
  102d0a: 8932         	mv	s2, a2
  102d0c: 89b6         	mv	s3, a3
  102d0e: 00050a9b     	sext.w	s5, a0
  102d12: 00069d97     	auipc	s11, 0x69
  102d16: 35ed8d93     	addi	s11, s11, 0x35e
  102d1a: ffffe097     	auipc	ra, 0xffffe
  102d1e: cfa080e7     	jalr	-0x306(ra) <PT_LOAD#0+0xa14>
  102d22: 000da703     	lw	a4, 0x0(s11)
  102d26: 4791         	li	a5, 0x4
  102d28: 4ee7e7e3     	bltu	a5, a4, 0x103a16 <PT_LOAD#0+0x3a16>
  102d2c: 000de783     	lwu	a5, 0x0(s11)
  102d30: 00001717     	auipc	a4, 0x1
  102d34: 00870713     	addi	a4, a4, 0x8
  102d38: 00069b17     	auipc	s6, 0x69
  102d3c: 340b0b13     	addi	s6, s6, 0x340
  102d40: 078a         	slli	a5, a5, 0x2
  102d42: 97ba         	add	a5, a5, a4
  102d44: 439c         	lw	a5, 0x0(a5)
  102d46: 97ba         	add	a5, a5, a4
  102d48: 8782         	jr	a5
  102d4a: 02000793     	li	a5, 0x20
  102d4e: 00fb8e63     	beq	s7, a5, 0x102d6a <PT_LOAD#0+0x2d6a>
  102d52: 0006b617     	auipc	a2, 0x6b
  102d56: 31e60613     	addi	a2, a2, 0x31e
  102d5a: 65e00593     	li	a1, 0x65e
  102d5e: 4509         	li	a0, 0x2
  102d60: ffffe097     	auipc	ra, 0xffffe
  102d64: d8c080e7     	jalr	-0x274(ra) <PT_LOAD#0+0xaec>
  102d68: a499         	j	0x102fae <PT_LOAD#0+0x2fae>
  102d6a: 02800613     	li	a2, 0x28
  102d6e: 01090593     	addi	a1, s2, 0x10
  102d72: 00021517     	auipc	a0, 0x21
  102d76: 77650513     	addi	a0, a0, 0x776
  102d7a: 0001e797     	auipc	a5, 0x1e
  102d7e: 2897b323     	sd	s1, 0x286(a5)
  102d82: 00000097     	auipc	ra, 0x0
  102d86: c74080e7     	jalr	-0x38c(ra) <PT_LOAD#0+0x29f6>
  102d8a: 28800613     	li	a2, 0x288
  102d8e: 03890593     	addi	a1, s2, 0x38
  102d92: 00021517     	auipc	a0, 0x21
  102d96: 46e50513     	addi	a0, a0, 0x46e
  102d9a: 00000097     	auipc	ra, 0x0
  102d9e: c5c080e7     	jalr	-0x3a4(ra) <PT_LOAD#0+0x29f6>
  102da2: ffffe097     	auipc	ra, 0xffffe
  102da6: c72080e7     	jalr	-0x38e(ra) <PT_LOAD#0+0xa14>
  102daa: 0006b597     	auipc	a1, 0x6b
  102dae: 2de58593     	addi	a1, a1, 0x2de
  102db2: 4505         	li	a0, 0x1
  102db4: ffffe097     	auipc	ra, 0xffffe
  102db8: d38080e7     	jalr	-0x2c8(ra) <PT_LOAD#0+0xaec>
  102dbc: 6611         	lui	a2, 0x4
  102dbe: 4581         	li	a1, 0x0
  102dc0: 00065517     	auipc	a0, 0x65
  102dc4: 24050513     	addi	a0, a0, 0x240
  102dc8: fffff097     	auipc	ra, 0xfffff
  102dcc: ffa080e7     	jalr	-0x6(ra) <PT_LOAD#0+0x1dc2>
  102dd0: 00042797     	auipc	a5, 0x42
  102dd4: e3078793     	addi	a5, a5, -0x1d0
  102dd8: 6685         	lui	a3, 0x1
  102dda: 008b3023     	sd	s0, 0x0(s6)
  102dde: 00062597     	auipc	a1, 0x62
  102de2: e2258593     	addi	a1, a1, -0x1de
  102de6: 873e         	mv	a4, a5
  102de8: 567d         	li	a2, -0x1
  102dea: 80068693     	addi	a3, a3, -0x800
  102dee: 00c79023     	sh	a2, 0x0(a5)
  102df2: 97b6         	add	a5, a5, a3
  102df4: feb79de3     	bne	a5, a1, 0x102dee <PT_LOAD#0+0x2dee>
  102df8: 00b41793     	slli	a5, s0, 0xb
  102dfc: 97ba         	add	a5, a5, a4
  102dfe: e790         	sd	a2, 0x8(a5)
  102e00: 4581         	li	a1, 0x0
  102e02: 6611         	lui	a2, 0x4
  102e04: 00065517     	auipc	a0, 0x65
  102e08: 1fc50513     	addi	a0, a0, 0x1fc
  102e0c: fffff097     	auipc	ra, 0xfffff
  102e10: fb6080e7     	jalr	-0x4a(ra) <PT_LOAD#0+0x1dc2>
  102e14: 03f00613     	li	a2, 0x3f
  102e18: 4581         	li	a1, 0x0
  102e1a: 00065517     	auipc	a0, 0x65
  102e1e: 3e650513     	addi	a0, a0, 0x3e6
  102e22: ffffe097     	auipc	ra, 0xffffe
  102e26: 912080e7     	jalr	-0x6ee(ra) <PT_LOAD#0+0x734>
  102e2a: 00065717     	auipc	a4, 0x65
  102e2e: 5d670713     	addi	a4, a4, 0x5d6
  102e32: 00065797     	auipc	a5, 0x65
  102e36: 1ce78793     	addi	a5, a5, 0x1ce
  102e3a: 56fd         	li	a3, -0x1
  102e3c: 4ad7b423     	sd	a3, 0x4a8(a5)
  102e40: 07a1         	addi	a5, a5, 0x8
  102e42: fef71de3     	bne	a4, a5, 0x102e3c <PT_LOAD#0+0x2e3c>
  102e46: 00066797     	auipc	a5, 0x66
  102e4a: a6278793     	addi	a5, a5, -0x59e
  102e4e: 00066717     	auipc	a4, 0x66
  102e52: e5a70713     	addi	a4, a4, -0x1a6
  102e56: 56fd         	li	a3, -0x1
  102e58: e394         	sd	a3, 0x0(a5)
  102e5a: 07a1         	addi	a5, a5, 0x8
  102e5c: fee79ee3     	bne	a5, a4, 0x102e58 <PT_LOAD#0+0x2e58>
  102e60: 4785         	li	a5, 0x1
  102e62: 00fda023     	sw	a5, 0x0(s11)
  102e66: 87a2         	mv	a5, s0
  102e68: 4701         	li	a4, 0x0
  102e6a: 4681         	li	a3, 0x0
  102e6c: 4601         	li	a2, 0x0
  102e6e: 4581         	li	a1, 0x0
  102e70: a881         	j	0x102ec0 <PT_LOAD#0+0x2ec0>
  102e72: 02f00793     	li	a5, 0x2f
  102e76: 0357ea63     	bltu	a5, s5, 0x102eaa <PT_LOAD#0+0x2eaa>
  102e7a: 02000793     	li	a5, 0x20
  102e7e: 0357fc63     	bgeu	a5, s5, 0x102eb6 <PT_LOAD#0+0x2eb6>
  102e82: fdfa8a9b     	addiw	s5, s5, -0x21
  102e86: 000a871b     	sext.w	a4, s5
  102e8a: 47b9         	li	a5, 0xe
  102e8c: 02e7e563     	bltu	a5, a4, 0x102eb6 <PT_LOAD#0+0x2eb6>
  102e90: 020a9793     	slli	a5, s5, 0x20
  102e94: 01e7da93     	srli	s5, a5, 0x1e
  102e98: 00001717     	auipc	a4, 0x1
  102e9c: eb470713     	addi	a4, a4, -0x14c
  102ea0: 9aba         	add	s5, s5, a4
  102ea2: 000aa783     	lw	a5, 0x0(s5)
  102ea6: 97ba         	add	a5, a5, a4
  102ea8: 8782         	jr	a5
  102eaa: 005747b7     	lui	a5, 0x574
  102eae: 45478793     	addi	a5, a5, 0x454
  102eb2: 24fa88e3     	beq	s5, a5, 0x103902 <PT_LOAD#0+0x3902>
  102eb6: 87a2         	mv	a5, s0
  102eb8: 4701         	li	a4, 0x0
  102eba: 4681         	li	a3, 0x0
  102ebc: 4601         	li	a2, 0x0
  102ebe: 4589         	li	a1, 0x2
  102ec0: 4541         	li	a0, 0x10
  102ec2: 00001097     	auipc	ra, 0x1
  102ec6: bae080e7     	jalr	-0x452(ra) <PT_LOAD#0+0x3a70>
  102eca: 000b3783     	ld	a5, 0x0(s6)
  102ece: fef414e3     	bne	s0, a5, 0x102eb6 <PT_LOAD#0+0x2eb6>
  102ed2: 47bd         	li	a5, 0xf
  102ed4: 4585         	li	a1, 0x1
  102ed6: 1497ee63     	bltu	a5, s1, 0x103032 <PT_LOAD#0+0x3032>
  102eda: 0496         	slli	s1, s1, 0x5
  102edc: 00021797     	auipc	a5, 0x21
  102ee0: 12478793     	addi	a5, a5, 0x124
  102ee4: 94be         	add	s1, s1, a5
  102ee6: 0124b023     	sd	s2, 0x0(s1)
  102eea: 0134b423     	sd	s3, 0x8(s1)
  102eee: 0144a823     	sw	s4, 0x10(s1)
  102ef2: 4581         	li	a1, 0x0
  102ef4: aa3d         	j	0x103032 <PT_LOAD#0+0x3032>
  102ef6: 000b3783     	ld	a5, 0x0(s6)
  102efa: faf41ee3     	bne	s0, a5, 0x102eb6 <PT_LOAD#0+0x2eb6>
  102efe: 00069617     	auipc	a2, 0x69
  102f02: 13260613     	addi	a2, a2, 0x132
  102f06: 00064783     	lbu	a5, 0x0(a2)
  102f0a: 473d         	li	a4, 0xf
  102f0c: 4585         	li	a1, 0x1
  102f0e: 12f76263     	bltu	a4, a5, 0x103032 <PT_LOAD#0+0x3032>
  102f12: 46e1         	li	a3, 0x18
  102f14: 02d786b3     	<unknown>
  102f18: 00021717     	auipc	a4, 0x21
  102f1c: 0e870713     	addi	a4, a4, 0xe8
  102f20: 2785         	addiw	a5, a5, 0x1
  102f22: 00f60023     	sb	a5, 0x0(a2)
  102f26: 9736         	add	a4, a4, a3
  102f28: 52970823     	sb	s1, 0x530(a4)
  102f2c: 53273c23     	sd	s2, 0x538(a4)
  102f30: 55373023     	sd	s3, 0x540(a4)
  102f34: bf7d         	j	0x102ef2 <PT_LOAD#0+0x2ef2>
  102f36: 000b3783     	ld	a5, 0x0(s6)
  102f3a: f6f41ee3     	bne	s0, a5, 0x102eb6 <PT_LOAD#0+0x2eb6>
  102f3e: 09000ab7     	lui	s5, 0x9000
  102f42: 6b05         	lui	s6, 0x1
  102f44: 00042a17     	auipc	s4, 0x42
  102f48: cbca0a13     	addi	s4, s4, -0x344
  102f4c: 4981         	li	s3, 0x0
  102f4e: 00069d97     	auipc	s11, 0x69
  102f52: 0dad8d93     	addi	s11, s11, 0xda
  102f56: 1eba8a93     	addi	s5, s5, 0x1eb
  102f5a: 800b0b13     	addi	s6, s6, -0x800
  102f5e: 014a2703     	lw	a4, 0x14(s4)
  102f62: 4785         	li	a5, 0x1
  102f64: 00f70963     	beq	a4, a5, 0x102f76 <PT_LOAD#0+0x2f76>
  102f68: 0985         	addi	s3, s3, 0x1
  102f6a: 04000793     	li	a5, 0x40
  102f6e: 9a5a         	add	s4, s4, s6
  102f70: fef997e3     	bne	s3, a5, 0x102f5e <PT_LOAD#0+0x2f5e>
  102f74: bfbd         	j	0x102ef2 <PT_LOAD#0+0x2ef2>
  102f76: 400a0593     	addi	a1, s4, 0x400
  102f7a: 854e         	mv	a0, s3
  102f7c: 00001097     	auipc	ra, 0x1
  102f80: b0a080e7     	jalr	-0x4f6(ra) <PT_LOAD#0+0x3a86>
  102f84: 000db483     	ld	s1, 0x0(s11)
  102f88: 468d         	li	a3, 0x3
  102f8a: 1810         	addi	a2, sp, 0x30
  102f8c: 008005b7     	lui	a1, 0x800
  102f90: 8526         	mv	a0, s1
  102f92: ffffd097     	auipc	ra, 0xffffd
  102f96: 64e080e7     	jalr	0x64e(ra) <PT_LOAD#0+0x5e0>
  102f9a: ed11         	bnez	a0, 0x102fb6 <PT_LOAD#0+0x2fb6>
  102f9c: 0006b597     	auipc	a1, 0x6b
  102fa0: 10458593     	addi	a1, a1, 0x104
  102fa4: 4505         	li	a0, 0x1
  102fa6: ffffe097     	auipc	ra, 0xffffe
  102faa: b46080e7     	jalr	-0x4ba(ra) <PT_LOAD#0+0xaec>
  102fae: fffff097     	auipc	ra, 0xfffff
  102fb2: bd8080e7     	jalr	-0x428(ra) <PT_LOAD#0+0x1b86>
  102fb6: 76c2         	ld	a3, 0x30(sp)
  102fb8: 88d6         	mv	a7, s5
  102fba: 4829         	li	a6, 0xa
  102fbc: 8526         	mv	a0, s1
  102fbe: 04000593     	li	a1, 0x40
  102fc2: 00020637     	lui	a2, 0x20
  102fc6: 470d         	li	a4, 0x3
  102fc8: 00000073     	ecall
  102fcc: 892a         	mv	s2, a0
  102fce: cd01         	beqz	a0, 0x102fe6 <PT_LOAD#0+0x2fe6>
  102fd0: 0a900593     	li	a1, 0xa9
  102fd4: 00001517     	auipc	a0, 0x1
  102fd8: c2450513     	addi	a0, a0, -0x3dc
  102fdc: ffffe097     	auipc	ra, 0xffffe
  102fe0: 1de080e7     	jalr	0x1de(ra) <PT_LOAD#0+0x11ba>
  102fe4: b7e9         	j	0x102fae <PT_LOAD#0+0x2fae>
  102fe6: 84d2         	mv	s1, s4
  102fe8: 4c05         	li	s8, 0x1
  102fea: 4c89         	li	s9, 0x2
  102fec: 4d41         	li	s10, 0x10
  102fee: 5494         	lw	a3, 0x28(s1)
  102ff0: 6c98         	ld	a4, 0x18(s1)
  102ff2: 709c         	ld	a5, 0x20(s1)
  102ff4: 02069613     	slli	a2, a3, 0x20
  102ff8: 9201         	srli	a2, a2, 0x20
  102ffa: e032         	sd	a2, 0x0(sp)
  102ffc: 00f76633     	or	a2, a4, a5
  103000: 0304ab83     	lw	s7, 0x30(s1)
  103004: ea11         	bnez	a2, 0x103018 <PT_LOAD#0+0x3018>
  103006: 0176e633     	or	a2, a3, s7
  10300a: e619         	bnez	a2, 0x103018 <PT_LOAD#0+0x3018>
  10300c: 0905         	addi	s2, s2, 0x1
  10300e: 02048493     	addi	s1, s1, 0x20
  103012: fda91ee3     	bne	s2, s10, 0x102fee <PT_LOAD#0+0x2fee>
  103016: bf89         	j	0x102f68 <PT_LOAD#0+0x2f68>
  103018: 85be         	mv	a1, a5
  10301a: 853a         	mv	a0, a4
  10301c: 1830         	addi	a2, sp, 0x38
  10301e: e83e         	sd	a5, 0x10(sp)
  103020: e43a         	sd	a4, 0x8(sp)
  103022: ffffd097     	auipc	ra, 0xffffd
  103026: 5be080e7     	jalr	0x5be(ra) <PT_LOAD#0+0x5e0>
  10302a: 6722         	ld	a4, 0x8(sp)
  10302c: 67c2         	ld	a5, 0x10(sp)
  10302e: e519         	bnez	a0, 0x10303c <PT_LOAD#0+0x303c>
  103030: 4595         	li	a1, 0x5
  103032: 87a2         	mv	a5, s0
  103034: 4701         	li	a4, 0x0
  103036: 4681         	li	a3, 0x0
  103038: 4601         	li	a2, 0x0
  10303a: b559         	j	0x102ec0 <PT_LOAD#0+0x2ec0>
  10303c: 018b9b63     	bne	s7, s8, 0x103052 <PT_LOAD#0+0x3052>
  103040: 6682         	ld	a3, 0x0(sp)
  103042: 7562         	ld	a0, 0x38(sp)
  103044: 864a         	mv	a2, s2
  103046: 85ce         	mv	a1, s3
  103048: 00001097     	auipc	ra, 0x1
  10304c: ab0080e7     	jalr	-0x550(ra) <PT_LOAD#0+0x3af8>
  103050: bf75         	j	0x10300c <PT_LOAD#0+0x300c>
  103052: fb9b9de3     	bne	s7, s9, 0x10300c <PT_LOAD#0+0x300c>
  103056: 6682         	ld	a3, 0x0(sp)
  103058: 7562         	ld	a0, 0x38(sp)
  10305a: 864a         	mv	a2, s2
  10305c: 85ce         	mv	a1, s3
  10305e: 00001097     	auipc	ra, 0x1
  103062: a5e080e7     	jalr	-0x5a2(ra) <PT_LOAD#0+0x3abc>
  103066: b75d         	j	0x10300c <PT_LOAD#0+0x300c>
  103068: 000b3783     	ld	a5, 0x0(s6)
  10306c: e4f415e3     	bne	s0, a5, 0x102eb6 <PT_LOAD#0+0x2eb6>
  103070: 0ff4f793     	zext.b	a5, s1
  103074: 473d         	li	a4, 0xf
  103076: 00f77963     	bgeu	a4, a5, 0x103088 <PT_LOAD#0+0x3088>
  10307a: 0006b617     	auipc	a2, 0x6b
  10307e: 03e60613     	addi	a2, a2, 0x3e
  103082: 19f00593     	li	a1, 0x19f
  103086: b9e1         	j	0x102d5e <PT_LOAD#0+0x2d5e>
  103088: 6709         	lui	a4, 0x2
  10308a: 02870693     	addi	a3, a4, 0x28
  10308e: 00078c9b     	sext.w	s9, a5
  103092: 02d787b3     	<unknown>
  103096: 00021c17     	auipc	s8, 0x21
  10309a: 71ac0c13     	addi	s8, s8, 0x71a
  10309e: 97e2         	add	a5, a5, s8
  1030a0: 973e         	add	a4, a4, a5
  1030a2: 01074b03     	lbu	s6, 0x10(a4)
  1030a6: 100b1f63     	bnez	s6, 0x1031c4 <PT_LOAD#0+0x31c4>
  1030aa: 6ac1         	lui	s5, 0x10
  1030ac: 1afd         	addi	s5, s5, -0x1
  1030ae: 9ace         	add	s5, s5, s3
  1030b0: 010ada93     	srli	s5, s5, 0x10
  1030b4: 03fa8b93     	addi	s7, s5, 0x3f
  1030b8: 006bdb93     	srli	s7, s7, 0x6
  1030bc: 40000613     	li	a2, 0x400
  1030c0: 11766463     	bltu	a2, s7, 0x1031c8 <PT_LOAD#0+0x31c8>
  1030c4: 0ff4f493     	zext.b	s1, s1
  1030c8: 02d484b3     	<unknown>
  1030cc: 01273c23     	sd	s2, 0x18(a4)
  1030d0: 003b9613     	slli	a2, s7, 0x3
  1030d4: 994e         	add	s2, s2, s3
  1030d6: 4581         	li	a1, 0x0
  1030d8: 03273023     	sd	s2, 0x20(a4)
  1030dc: 0147b023     	sd	s4, 0x0(a5)
  1030e0: 01573423     	sd	s5, 0x8(a4)
  1030e4: 0b9a         	slli	s7, s7, 0x6
  1030e6: 04a1         	addi	s1, s1, 0x8
  1030e8: 94e2         	add	s1, s1, s8
  1030ea: 8526         	mv	a0, s1
  1030ec: fffff097     	auipc	ra, 0xfffff
  1030f0: cd6080e7     	jalr	-0x32a(ra) <PT_LOAD#0+0x1dc2>
  1030f4: 4685         	li	a3, 0x1
  1030f6: 0b7aec63     	bltu	s5, s7, 0x1031ae <PT_LOAD#0+0x31ae>
  1030fa: 00069997     	auipc	s3, 0x69
  1030fe: f2698993     	addi	s3, s3, -0xda
  103102: 0009c783     	lbu	a5, 0x0(s3)
  103106: efd1         	bnez	a5, 0x1031a2 <PT_LOAD#0+0x31a2>
  103108: 6909         	lui	s2, 0x2
  10310a: 02890793     	addi	a5, s2, 0x28
  10310e: 02fc8cb3     	<unknown>
  103112: 4589         	li	a1, 0x2
  103114: 08000693     	li	a3, 0x80
  103118: 8526         	mv	a0, s1
  10311a: 019c07b3     	add	a5, s8, s9
  10311e: 993e         	add	s2, s2, a5
  103120: 00893703     	ld	a4, 0x8(s2)
  103124: 01893603     	ld	a2, 0x18(s2)
  103128: 177d         	addi	a4, a4, -0x1
  10312a: 8241         	srli	a2, a2, 0x10
  10312c: ffffd097     	auipc	ra, 0xffffd
  103130: 6ec080e7     	jalr	0x6ec(ra) <PT_LOAD#0+0x818>
  103134: 57fd         	li	a5, -0x1
  103136: 0006b597     	auipc	a1, 0x6b
  10313a: f9a58593     	addi	a1, a1, -0x66
  10313e: e6f503e3     	beq	a0, a5, 0x102fa4 <PT_LOAD#0+0x2fa4>
  103142: 01893783     	ld	a5, 0x18(s2)
  103146: 0542         	slli	a0, a0, 0x10
  103148: 008005b7     	lui	a1, 0x800
  10314c: 00f504b3     	add	s1, a0, a5
  103150: 468d         	li	a3, 0x3
  103152: 1830         	addi	a2, sp, 0x38
  103154: 8526         	mv	a0, s1
  103156: ffffd097     	auipc	ra, 0xffffd
  10315a: 48a080e7     	jalr	0x48a(ra) <PT_LOAD#0+0x5e0>
  10315e: 0006b597     	auipc	a1, 0x6b
  103162: f8a58593     	addi	a1, a1, -0x76
  103166: e2050fe3     	beqz	a0, 0x102fa4 <PT_LOAD#0+0x2fa4>
  10316a: 01094783     	lbu	a5, 0x10(s2)
  10316e: 090008b7     	lui	a7, 0x9000
  103172: 76e2         	ld	a3, 0x38(sp)
  103174: 2785         	addiw	a5, a5, 0x1
  103176: 00f90823     	sb	a5, 0x10(s2)
  10317a: 1eb88893     	addi	a7, a7, 0x1eb
  10317e: 4829         	li	a6, 0xa
  103180: 8526         	mv	a0, s1
  103182: 04000593     	li	a1, 0x40
  103186: 00020637     	lui	a2, 0x20
  10318a: 470d         	li	a4, 0x3
  10318c: 00000073     	ecall
  103190: e40510e3     	bnez	a0, 0x102fd0 <PT_LOAD#0+0x2fd0>
  103194: 00069797     	auipc	a5, 0x69
  103198: e897ba23     	sd	s1, -0x16c(a5)
  10319c: 4785         	li	a5, 0x1
  10319e: 00f98023     	sb	a5, 0x0(s3)
  1031a2: 87a2         	mv	a5, s0
  1031a4: 4701         	li	a4, 0x0
  1031a6: 4681         	li	a3, 0x0
  1031a8: 4601         	li	a2, 0x0
  1031aa: 85da         	mv	a1, s6
  1031ac: bb11         	j	0x102ec0 <PT_LOAD#0+0x2ec0>
  1031ae: 006ad793     	srli	a5, s5, 0x6
  1031b2: 078e         	slli	a5, a5, 0x3
  1031b4: 97a6         	add	a5, a5, s1
  1031b6: 6398         	ld	a4, 0x0(a5)
  1031b8: 01569633     	sll	a2, a3, s5
  1031bc: 0a85         	addi	s5, s5, 0x1
  1031be: 8f51         	or	a4, a4, a2
  1031c0: e398         	sd	a4, 0x0(a5)
  1031c2: bf15         	j	0x1030f6 <PT_LOAD#0+0x30f6>
  1031c4: 4b09         	li	s6, 0x2
  1031c6: bff1         	j	0x1031a2 <PT_LOAD#0+0x31a2>
  1031c8: 4b19         	li	s6, 0x6
  1031ca: bfe1         	j	0x1031a2 <PT_LOAD#0+0x31a2>
  1031cc: 000b3783     	ld	a5, 0x0(s6)
  1031d0: cef413e3     	bne	s0, a5, 0x102eb6 <PT_LOAD#0+0x2eb6>
  1031d4: 00069697     	auipc	a3, 0x69
  1031d8: e4468693     	addi	a3, a3, -0x1bc
  1031dc: 00069717     	auipc	a4, 0x69
  1031e0: e3470713     	addi	a4, a4, -0x1cc
  1031e4: 629c         	ld	a5, 0x0(a3)
  1031e6: 6310         	ld	a2, 0x0(a4)
  1031e8: 0006b597     	auipc	a1, 0x6b
  1031ec: f1858593     	addi	a1, a1, -0xe8
  1031f0: 8fd1         	or	a5, a5, a2
  1031f2: da0799e3     	bnez	a5, 0x102fa4 <PT_LOAD#0+0x2fa4>
  1031f6: 00069797     	auipc	a5, 0x69
  1031fa: e097b923     	sd	s1, -0x1ee(a5)
  1031fe: 0126b023     	sd	s2, 0x0(a3)
  103202: 00069797     	auipc	a5, 0x69
  103206: df37bf23     	sd	s3, -0x202(a5)
  10320a: 01473023     	sd	s4, 0x0(a4)
  10320e: 02090063     	beqz	s2, 0x10322e <PT_LOAD#0+0x322e>
  103212: 85ca         	mv	a1, s2
  103214: 468d         	li	a3, 0x3
  103216: 1830         	addi	a2, sp, 0x38
  103218: 8526         	mv	a0, s1
  10321a: ffffd097     	auipc	ra, 0xffffd
  10321e: 3c6080e7     	jalr	0x3c6(ra) <PT_LOAD#0+0x5e0>
  103222: 0006b597     	auipc	a1, 0x6b
  103226: ef658593     	addi	a1, a1, -0x10a
  10322a: d6050de3     	beqz	a0, 0x102fa4 <PT_LOAD#0+0x2fa4>
  10322e: c20a0ce3     	beqz	s4, 0x102e66 <PT_LOAD#0+0x2e66>
  103232: 85d2         	mv	a1, s4
  103234: 4695         	li	a3, 0x5
  103236: 1830         	addi	a2, sp, 0x38
  103238: 854e         	mv	a0, s3
  10323a: ffffd097     	auipc	ra, 0xffffd
  10323e: 3a6080e7     	jalr	0x3a6(ra) <PT_LOAD#0+0x5e0>
  103242: 0006b597     	auipc	a1, 0x6b
  103246: eee58593     	addi	a1, a1, -0x112
  10324a: c0051ee3     	bnez	a0, 0x102e66 <PT_LOAD#0+0x2e66>
  10324e: bb99         	j	0x102fa4 <PT_LOAD#0+0x2fa4>
  103250: 00048c1b     	sext.w	s8, s1
  103254: 03f00793     	li	a5, 0x3f
  103258: 1b87e063     	bltu	a5, s8, 0x1033f8 <PT_LOAD#0+0x33f8>
  10325c: 000b3703     	ld	a4, 0x0(s6)
  103260: 02041793     	slli	a5, s0, 0x20
  103264: 020c1b13     	slli	s6, s8, 0x20
  103268: 9381         	srli	a5, a5, 0x20
  10326a: 00042c97     	auipc	s9, 0x42
  10326e: 996c8c93     	addi	s9, s9, -0x66a
  103272: 020b5b13     	srli	s6, s6, 0x20
  103276: 00f70f63     	beq	a4, a5, 0x103294 <PT_LOAD#0+0x3294>
  10327a: 00bb1793     	slli	a5, s6, 0xb
  10327e: 97e6         	add	a5, a5, s9
  103280: 0107c703     	lbu	a4, 0x10(a5)
  103284: 16070763     	beqz	a4, 0x1033f2 <PT_LOAD#0+0x33f2>
  103288: 0117c703     	lbu	a4, 0x11(a5)
  10328c: 0004079b     	sext.w	a5, s0
  103290: 16f71163     	bne	a4, a5, 0x1033f2 <PT_LOAD#0+0x33f2>
  103294: 00bb1793     	slli	a5, s6, 0xb
  103298: 97e6         	add	a5, a5, s9
  10329a: 4bdc         	lw	a5, 0x14(a5)
  10329c: 14079e63     	bnez	a5, 0x1033f8 <PT_LOAD#0+0x33f8>
  1032a0: 7781         	lui	a5, 0xfffe0
  1032a2: fff90713     	addi	a4, s2, -0x1
  1032a6: 83c1         	srli	a5, a5, 0x10
  1032a8: 14e7e863     	bltu	a5, a4, 0x1033f8 <PT_LOAD#0+0x33f8>
  1032ac: 4785         	li	a5, 0x1
  1032ae: 018797b3     	sll	a5, a5, s8
  1032b2: fff98713     	addi	a4, s3, -0x1
  1032b6: ec3e         	sd	a5, 0x18(sp)
  1032b8: 013777b3     	and	a5, a4, s3
  1032bc: 6709         	lui	a4, 0x2
  1032be: f03e         	sd	a5, 0x20(sp)
  1032c0: 02870793     	addi	a5, a4, 0x28
  1032c4: 00023d17     	auipc	s10, 0x23
  1032c8: 4f4d0d13     	addi	s10, s10, 0x4f4
  1032cc: f43e         	sd	a5, 0x28(sp)
  1032ce: 77f9         	lui	a5, 0xffffe
  1032d0: ff878713     	addi	a4, a5, -0x8
  1032d4: 976a         	add	a4, a4, s10
  1032d6: 6318         	ld	a4, 0x0(a4)
  1032d8: 66e2         	ld	a3, 0x18(sp)
  1032da: 8f75         	and	a4, a4, a3
  1032dc: cf35         	beqz	a4, 0x103358 <PT_LOAD#0+0x3358>
  1032de: 6741         	lui	a4, 0x10
  1032e0: 06e9ec63     	bltu	s3, a4, 0x103358 <PT_LOAD#0+0x3358>
  1032e4: 7682         	ld	a3, 0x20(sp)
  1032e6: eaad         	bnez	a3, 0x103358 <PT_LOAD#0+0x3358>
  1032e8: 177d         	addi	a4, a4, -0x1
  1032ea: 974a         	add	a4, a4, s2
  1032ec: 8341         	srli	a4, a4, 0x10
  1032ee: e03a         	sd	a4, 0x0(sp)
  1032f0: 010d3603     	ld	a2, 0x10(s10)
  1032f4: 000d3703     	ld	a4, 0x0(s10)
  1032f8: 6682         	ld	a3, 0x0(sp)
  1032fa: 97ea         	add	a5, a5, s10
  1032fc: 177d         	addi	a4, a4, -0x1
  1032fe: 8241         	srli	a2, a2, 0x10
  103300: 0109d593     	srli	a1, s3, 0x10
  103304: 853e         	mv	a0, a5
  103306: e43e         	sd	a5, 0x8(sp)
  103308: ffffd097     	auipc	ra, 0xffffd
  10330c: 510080e7     	jalr	0x510(ra) <PT_LOAD#0+0x818>
  103310: 577d         	li	a4, -0x1
  103312: 8baa         	mv	s7, a0
  103314: 04e50263     	beq	a0, a4, 0x103358 <PT_LOAD#0+0x3358>
  103318: 010d3703     	ld	a4, 0x10(s10)
  10331c: 01051a93     	slli	s5, a0, 0x10
  103320: 85ca         	mv	a1, s2
  103322: 9aba         	add	s5, s5, a4
  103324: 8556         	mv	a0, s5
  103326: ffffd097     	auipc	ra, 0xffffd
  10332a: 346080e7     	jalr	0x346(ra) <PT_LOAD#0+0x66c>
  10332e: e82a         	sd	a0, 0x10(sp)
  103330: 87aa         	mv	a5, a0
  103332: 180c         	addi	a1, sp, 0x30
  103334: 8562         	mv	a0, s8
  103336: cf85         	beqz	a5, 0x10336e <PT_LOAD#0+0x336e>
  103338: fffff097     	auipc	ra, 0xfffff
  10333c: 86c080e7     	jalr	-0x794(ra) <PT_LOAD#0+0x1ba4>
  103340: 8daa         	mv	s11, a0
  103342: c91d         	beqz	a0, 0x103378 <PT_LOAD#0+0x3378>
  103344: 6782         	ld	a5, 0x0(sp)
  103346: 6522         	ld	a0, 0x8(sp)
  103348: 85de         	mv	a1, s7
  10334a: fff78613     	addi	a2, a5, -0x1
  10334e: 965e         	add	a2, a2, s7
  103350: ffffd097     	auipc	ra, 0xffffd
  103354: 382080e7     	jalr	0x382(ra) <PT_LOAD#0+0x6d2>
  103358: 77a2         	ld	a5, 0x28(sp)
  10335a: 9d3e         	add	s10, s10, a5
  10335c: 00043797     	auipc	a5, 0x43
  103360: 6dc78793     	addi	a5, a5, 0x6dc
  103364: f6fd15e3     	bne	s10, a5, 0x1032ce <PT_LOAD#0+0x32ce>
  103368: 4a81         	li	s5, 0x0
  10336a: 4d99         	li	s11, 0x6
  10336c: a0b5         	j	0x1033d8 <PT_LOAD#0+0x33d8>
  10336e: fffff097     	auipc	ra, 0xfffff
  103372: 8b8080e7     	jalr	-0x748(ra) <PT_LOAD#0+0x1c26>
  103376: b7e9         	j	0x103340 <PT_LOAD#0+0x3340>
  103378: 000a099b     	sext.w	s3, s4
  10337c: 86ce         	mv	a3, s3
  10337e: 1830         	addi	a2, sp, 0x38
  103380: 85ca         	mv	a1, s2
  103382: 8556         	mv	a0, s5
  103384: ffffd097     	auipc	ra, 0xffffd
  103388: 25c080e7     	jalr	0x25c(ra) <PT_LOAD#0+0x5e0>
  10338c: e901         	bnez	a0, 0x10339c <PT_LOAD#0+0x339c>
  10338e: 0006b617     	auipc	a2, 0x6b
  103392: dba60613     	addi	a2, a2, -0x246
  103396: 23200593     	li	a1, 0x232
  10339a: b2d1         	j	0x102d5e <PT_LOAD#0+0x2d5e>
  10339c: 7642         	ld	a2, 0x30(sp)
  10339e: 0b1a         	slli	s6, s6, 0x6
  1033a0: 56fd         	li	a3, -0x1
  1033a2: 9b32         	add	s6, s6, a2
  1033a4: 005b1793     	slli	a5, s6, 0x5
  1033a8: 97e6         	add	a5, a5, s9
  1033aa: 0b05         	addi	s6, s6, 0x1
  1033ac: 0157bc23     	sd	s5, 0x18(a5)
  1033b0: 0327b023     	sd	s2, 0x20(a5)
  1033b4: 0b16         	slli	s6, s6, 0x5
  1033b6: 67c2         	ld	a5, 0x10(sp)
  1033b8: 9b66         	add	s6, s6, s9
  1033ba: 9281         	srli	a3, a3, 0x20
  1033bc: 013b2423     	sw	s3, 0x8(s6)
  1033c0: 00d4f5b3     	and	a1, s1, a3
  1033c4: 7562         	ld	a0, 0x38(sp)
  1033c6: 00da76b3     	and	a3, s4, a3
  1033ca: cf89         	beqz	a5, 0x1033e4 <PT_LOAD#0+0x33e4>
  1033cc: 87ca         	mv	a5, s2
  1033ce: 8756         	mv	a4, s5
  1033d0: 00000097     	auipc	ra, 0x0
  1033d4: 728080e7     	jalr	0x728(ra) <PT_LOAD#0+0x3af8>
  1033d8: 87a2         	mv	a5, s0
  1033da: 4701         	li	a4, 0x0
  1033dc: 4681         	li	a3, 0x0
  1033de: 8656         	mv	a2, s5
  1033e0: 85ee         	mv	a1, s11
  1033e2: bcf9         	j	0x102ec0 <PT_LOAD#0+0x2ec0>
  1033e4: 87ca         	mv	a5, s2
  1033e6: 8756         	mv	a4, s5
  1033e8: 00000097     	auipc	ra, 0x0
  1033ec: 6d4080e7     	jalr	0x6d4(ra) <PT_LOAD#0+0x3abc>
  1033f0: b7e5         	j	0x1033d8 <PT_LOAD#0+0x33d8>
  1033f2: 4a81         	li	s5, 0x0
  1033f4: 4d89         	li	s11, 0x2
  1033f6: b7cd         	j	0x1033d8 <PT_LOAD#0+0x33d8>
  1033f8: 4a81         	li	s5, 0x0
  1033fa: 4d85         	li	s11, 0x1
  1033fc: bff1         	j	0x1033d8 <PT_LOAD#0+0x33d8>
  1033fe: 2481         	sext.w	s1, s1
  103400: 03f00793     	li	a5, 0x3f
  103404: 4585         	li	a1, 0x1
  103406: c297e6e3     	bltu	a5, s1, 0x103032 <PT_LOAD#0+0x3032>
  10340a: 000b3683     	ld	a3, 0x0(s6)
  10340e: 02049713     	slli	a4, s1, 0x20
  103412: 00041797     	auipc	a5, 0x41
  103416: 7ee78793     	addi	a5, a5, 0x7ee
  10341a: 9301         	srli	a4, a4, 0x20
  10341c: 00d40e63     	beq	s0, a3, 0x103438 <PT_LOAD#0+0x3438>
  103420: 00b71693     	slli	a3, a4, 0xb
  103424: 96be         	add	a3, a3, a5
  103426: 0106c603     	lbu	a2, 0x10(a3)
  10342a: 4589         	li	a1, 0x2
  10342c: c00603e3     	beqz	a2, 0x103032 <PT_LOAD#0+0x3032>
  103430: 0116c683     	lbu	a3, 0x11(a3)
  103434: bed41fe3     	bne	s0, a3, 0x103032 <PT_LOAD#0+0x3032>
  103438: 072e         	slli	a4, a4, 0xb
  10343a: 97ba         	add	a5, a5, a4
  10343c: 4bdc         	lw	a5, 0x14(a5)
  10343e: 4585         	li	a1, 0x1
  103440: be0799e3     	bnez	a5, 0x103032 <PT_LOAD#0+0x3032>
  103444: 000a069b     	sext.w	a3, s4
  103448: 85ca         	mv	a1, s2
  10344a: 864e         	mv	a2, s3
  10344c: 8522         	mv	a0, s0
  10344e: e036         	sd	a3, 0x0(sp)
  103450: ffffd097     	auipc	ra, 0xffffd
  103454: 1d4080e7     	jalr	0x1d4(ra) <PT_LOAD#0+0x624>
  103458: 4589         	li	a1, 0x2
  10345a: bc050ce3     	beqz	a0, 0x103032 <PT_LOAD#0+0x3032>
  10345e: 6682         	ld	a3, 0x0(sp)
  103460: 864e         	mv	a2, s3
  103462: 85ca         	mv	a1, s2
  103464: 8526         	mv	a0, s1
  103466: fffff097     	auipc	ra, 0xfffff
  10346a: 860080e7     	jalr	-0x7a0(ra) <PT_LOAD#0+0x1cc6>
  10346e: 85aa         	mv	a1, a0
  103470: b6c9         	j	0x103032 <PT_LOAD#0+0x3032>
  103472: 03f00793     	li	a5, 0x3f
  103476: 0297ea63     	bltu	a5, s1, 0x1034aa <PT_LOAD#0+0x34aa>
  10347a: 000b3783     	ld	a5, 0x0(s6)
  10347e: 00041c17     	auipc	s8, 0x41
  103482: 782c0c13     	addi	s8, s8, 0x782
  103486: 00b49b13     	slli	s6, s1, 0xb
  10348a: 00f40b63     	beq	s0, a5, 0x1034a0 <PT_LOAD#0+0x34a0>
  10348e: 016c07b3     	add	a5, s8, s6
  103492: 0107c703     	lbu	a4, 0x10(a5)
  103496: cb69         	beqz	a4, 0x103568 <PT_LOAD#0+0x3568>
  103498: 0117c783     	lbu	a5, 0x11(a5)
  10349c: 0cf41663     	bne	s0, a5, 0x103568 <PT_LOAD#0+0x3568>
  1034a0: 016c0cb3     	add	s9, s8, s6
  1034a4: 014ca783     	lw	a5, 0x14(s9)
  1034a8: cb81         	beqz	a5, 0x1034b8 <PT_LOAD#0+0x34b8>
  1034aa: 4a85         	li	s5, 0x1
  1034ac: 87a2         	mv	a5, s0
  1034ae: 4701         	li	a4, 0x0
  1034b0: 4681         	li	a3, 0x0
  1034b2: 4601         	li	a2, 0x0
  1034b4: 85d6         	mv	a1, s5
  1034b6: b429         	j	0x102ec0 <PT_LOAD#0+0x2ec0>
  1034b8: 03491793     	slli	a5, s2, 0x34
  1034bc: 0347db93     	srli	s7, a5, 0x34
  1034c0: 0006b597     	auipc	a1, 0x6b
  1034c4: ca058593     	addi	a1, a1, -0x360
  1034c8: ef91         	bnez	a5, 0x1034e4 <PT_LOAD#0+0x34e4>
  1034ca: 4695         	li	a3, 0x5
  1034cc: 6605         	lui	a2, 0x1
  1034ce: 85ca         	mv	a1, s2
  1034d0: 8522         	mv	a0, s0
  1034d2: ffffd097     	auipc	ra, 0xffffd
  1034d6: 152080e7     	jalr	0x152(ra) <PT_LOAD#0+0x624>
  1034da: e919         	bnez	a0, 0x1034f0 <PT_LOAD#0+0x34f0>
  1034dc: 0006b597     	auipc	a1, 0x6b
  1034e0: c9c58593     	addi	a1, a1, -0x364
  1034e4: 4505         	li	a0, 0x1
  1034e6: ffffd097     	auipc	ra, 0xffffd
  1034ea: 606080e7     	jalr	0x606(ra) <PT_LOAD#0+0xaec>
  1034ee: bf75         	j	0x1034aa <PT_LOAD#0+0x34aa>
  1034f0: 01093a83     	ld	s5, 0x10(s2)
  1034f4: 4695         	li	a3, 0x5
  1034f6: 85ca         	mv	a1, s2
  1034f8: 8656         	mv	a2, s5
  1034fa: 8522         	mv	a0, s0
  1034fc: ffffd097     	auipc	ra, 0xffffd
  103500: 128080e7     	jalr	0x128(ra) <PT_LOAD#0+0x624>
  103504: d15d         	beqz	a0, 0x1034aa <PT_LOAD#0+0x34aa>
  103506: 85ce         	mv	a1, s3
  103508: 468d         	li	a3, 0x3
  10350a: 8652         	mv	a2, s4
  10350c: 8526         	mv	a0, s1
  10350e: ffffd097     	auipc	ra, 0xffffd
  103512: 116080e7     	jalr	0x116(ra) <PT_LOAD#0+0x624>
  103516: 0006b597     	auipc	a1, 0x6b
  10351a: c7a58593     	addi	a1, a1, -0x386
  10351e: c121         	beqz	a0, 0x10355e <PT_LOAD#0+0x355e>
  103520: 4695         	li	a3, 0x5
  103522: 8656         	mv	a2, s5
  103524: 85ca         	mv	a1, s2
  103526: 8526         	mv	a0, s1
  103528: ffffd097     	auipc	ra, 0xffffd
  10352c: 0fc080e7     	jalr	0xfc(ra) <PT_LOAD#0+0x624>
  103530: 0004879b     	sext.w	a5, s1
  103534: e03e         	sd	a5, 0x0(sp)
  103536: e91d         	bnez	a0, 0x10356c <PT_LOAD#0+0x356c>
  103538: 8656         	mv	a2, s5
  10353a: 4695         	li	a3, 0x5
  10353c: 85ca         	mv	a1, s2
  10353e: 853e         	mv	a0, a5
  103540: ffffe097     	auipc	ra, 0xffffe
  103544: 786080e7     	jalr	0x786(ra) <PT_LOAD#0+0x1cc6>
  103548: 8aaa         	mv	s5, a0
  10354a: f12d         	bnez	a0, 0x1034ac <PT_LOAD#0+0x34ac>
  10354c: 014ca703     	lw	a4, 0x14(s9)
  103550: 4785         	li	a5, 0x1
  103552: 00f71d63     	bne	a4, a5, 0x10356c <PT_LOAD#0+0x356c>
  103556: 0006b597     	auipc	a1, 0x6b
  10355a: c5258593     	addi	a1, a1, -0x3ae
  10355e: 4505         	li	a0, 0x1
  103560: ffffd097     	auipc	ra, 0xffffd
  103564: 58c080e7     	jalr	0x58c(ra) <PT_LOAD#0+0xaec>
  103568: 4a89         	li	s5, 0x2
  10356a: b789         	j	0x1034ac <PT_LOAD#0+0x34ac>
  10356c: 00065d17     	auipc	s10, 0x65
  103570: a94d0d13     	addi	s10, s10, -0x56c
  103574: 460d3683     	ld	a3, 0x460(s10)
  103578: 016c0733     	add	a4, s8, s6
  10357c: 85ea         	mv	a1, s10
  10357e: e714         	sd	a3, 0x8(a4)
  103580: 4685         	li	a3, 0x1
  103582: cb54         	sw	a3, 0x14(a4)
  103584: 6611         	lui	a2, 0x4
  103586: 468d         	li	a3, 0x3
  103588: 0004851b     	sext.w	a0, s1
  10358c: ffffe097     	auipc	ra, 0xffffe
  103590: 73a080e7     	jalr	0x73a(ra) <PT_LOAD#0+0x1cc6>
  103594: 8aaa         	mv	s5, a0
  103596: 0006b597     	auipc	a1, 0x6b
  10359a: c2a58593     	addi	a1, a1, -0x3d6
  10359e: e505         	bnez	a0, 0x1035c6 <PT_LOAD#0+0x35c6>
  1035a0: 400b0c93     	addi	s9, s6, 0x400
  1035a4: 9ce2         	add	s9, s9, s8
  1035a6: 4695         	li	a3, 0x5
  1035a8: 40000613     	li	a2, 0x400
  1035ac: 85e6         	mv	a1, s9
  1035ae: 0004851b     	sext.w	a0, s1
  1035b2: ffffe097     	auipc	ra, 0xffffe
  1035b6: 714080e7     	jalr	0x714(ra) <PT_LOAD#0+0x1cc6>
  1035ba: 8aaa         	mv	s5, a0
  1035bc: c919         	beqz	a0, 0x1035d2 <PT_LOAD#0+0x35d2>
  1035be: 0006b597     	auipc	a1, 0x6b
  1035c2: c1a58593     	addi	a1, a1, -0x3e6
  1035c6: 4505         	li	a0, 0x1
  1035c8: ffffd097     	auipc	ra, 0xffffd
  1035cc: 524080e7     	jalr	0x524(ra) <PT_LOAD#0+0xaec>
  1035d0: bdf1         	j	0x1034ac <PT_LOAD#0+0x34ac>
  1035d2: 85e6         	mv	a1, s9
  1035d4: 8526         	mv	a0, s1
  1035d6: 00000097     	auipc	ra, 0x0
  1035da: 4b0080e7     	jalr	0x4b0(ra) <PT_LOAD#0+0x3a86>
  1035de: 4709         	li	a4, 0x2
  1035e0: 00eda023     	sw	a4, 0x0(s11)
  1035e4: 00069717     	auipc	a4, 0x69
  1035e8: a4873a23     	sd	s0, -0x5ac(a4)
  1035ec: 00069717     	auipc	a4, 0x69
  1035f0: a4973a23     	sd	s1, -0x5ac(a4)
  1035f4: 00069717     	auipc	a4, 0x69
  1035f8: a3473703     	ld	a4, -0x5cc(a4)
  1035fc: 48ed3023     	sd	a4, 0x480(s10)
  103600: 00069717     	auipc	a4, 0x69
  103604: a0073703     	ld	a4, -0x600(a4)
  103608: 00069597     	auipc	a1, 0x69
  10360c: a005b583     	ld	a1, -0x600(a1)
  103610: 00069617     	auipc	a2, 0x69
  103614: a0863603     	ld	a2, -0x5f8(a2)
  103618: 42ed3823     	sd	a4, 0x430(s10)
  10361c: 00069717     	auipc	a4, 0x69
  103620: 9f473703     	ld	a4, -0x60c(a4)
  103624: 40bd3823     	sd	a1, 0x410(s10)
  103628: 40cd3c23     	sd	a2, 0x418(s10)
  10362c: 42bd3023     	sd	a1, 0x420(s10)
  103630: 42cd3423     	sd	a2, 0x428(s10)
  103634: 42ed3c23     	sd	a4, 0x438(s10)
  103638: c20d         	beqz	a2, 0x10365a <PT_LOAD#0+0x365a>
  10363a: 4a4d4703     	lbu	a4, 0x4a4(s10)
  10363e: cf11         	beqz	a4, 0x10365a <PT_LOAD#0+0x365a>
  103640: 468d         	li	a3, 0x3
  103642: 0004851b     	sext.w	a0, s1
  103646: ffffe097     	auipc	ra, 0xffffe
  10364a: 680080e7     	jalr	0x680(ra) <PT_LOAD#0+0x1cc6>
  10364e: 8aaa         	mv	s5, a0
  103650: 0006b597     	auipc	a1, 0x6b
  103654: ba058593     	addi	a1, a1, -0x460
  103658: f53d         	bnez	a0, 0x1035c6 <PT_LOAD#0+0x35c6>
  10365a: 00093603     	ld	a2, 0x0(s2)
  10365e: 6a85         	lui	s5, 0x1
  103660: 00001697     	auipc	a3, 0x1
  103664: 8d86b683     	ld	a3, -0x728(a3)
  103668: 9ace         	add	s5, s5, s3
  10366a: 468d3703     	ld	a4, 0x468(s10)
  10366e: 4981         	li	s3, 0x0
  103670: 00d61563     	bne	a2, a3, 0x10367a <PT_LOAD#0+0x367a>
  103674: 00893983     	ld	s3, 0x8(s2)
  103678: 99ca         	add	s3, s3, s2
  10367a: 02098d63     	beqz	s3, 0x1036b4 <PT_LOAD#0+0x36b4>
  10367e: 03771663     	bne	a4, s7, 0x1036aa <PT_LOAD#0+0x36aa>
  103682: 0089b583     	ld	a1, 0x8(s3)
  103686: 4615         	li	a2, 0x5
  103688: 854a         	mv	a0, s2
  10368a: e42e         	sd	a1, 0x8(sp)
  10368c: ffffd097     	auipc	ra, 0xffffd
  103690: 41c080e7     	jalr	0x41c(ra) <PT_LOAD#0+0xaa8>
  103694: 65a2         	ld	a1, 0x8(sp)
  103696: 8daa         	mv	s11, a0
  103698: e121         	bnez	a0, 0x1036d8 <PT_LOAD#0+0x36d8>
  10369a: 0006b617     	auipc	a2, 0x6b
  10369e: b9e60613     	addi	a2, a2, -0x462
  1036a2: 38f00593     	li	a1, 0x38f
  1036a6: eb8ff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  1036aa: 0109b983     	ld	s3, 0x10(s3)
  1036ae: 0b85         	addi	s7, s7, 0x1
  1036b0: fc0994e3     	bnez	s3, 0x103678 <PT_LOAD#0+0x3678>
  1036b4: 01771a63     	bne	a4, s7, 0x1036c8 <PT_LOAD#0+0x36c8>
  1036b8: 0006b617     	auipc	a2, 0x6b
  1036bc: b6860613     	addi	a2, a2, -0x498
  1036c0: 38c00593     	li	a1, 0x38c
  1036c4: e9aff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  1036c8: 0006b617     	auipc	a2, 0x6b
  1036cc: b4060613     	addi	a2, a2, -0x4c0
  1036d0: 38b00593     	li	a1, 0x38b
  1036d4: e8aff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  1036d8: 4619         	li	a2, 0x6
  1036da: 854a         	mv	a0, s2
  1036dc: ffffd097     	auipc	ra, 0xffffd
  1036e0: 3cc080e7     	jalr	0x3cc(ra) <PT_LOAD#0+0xaa8>
  1036e4: 8baa         	mv	s7, a0
  1036e6: e909         	bnez	a0, 0x1036f8 <PT_LOAD#0+0x36f8>
  1036e8: 0006b617     	auipc	a2, 0x6b
  1036ec: b6860613     	addi	a2, a2, -0x498
  1036f0: 39100593     	li	a1, 0x391
  1036f4: e6aff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  1036f8: 6d0c         	ld	a1, 0x18(a0)
  1036fa: 7110         	ld	a2, 0x20(a0)
  1036fc: 8556         	mv	a0, s5
  1036fe: 95ca         	add	a1, a1, s2
  103700: fffff097     	auipc	ra, 0xfffff
  103704: 2f6080e7     	jalr	0x2f6(ra) <PT_LOAD#0+0x29f6>
  103708: 0089b583     	ld	a1, 0x8(s3)
  10370c: 4615         	li	a2, 0x5
  10370e: 854a         	mv	a0, s2
  103710: 020bbb83     	ld	s7, 0x20(s7)
  103714: ffffd097     	auipc	ra, 0xffffd
  103718: 394080e7     	jalr	0x394(ra) <PT_LOAD#0+0xaa8>
  10371c: c57d         	beqz	a0, 0x10380a <PT_LOAD#0+0x380a>
  10371e: 6d18         	ld	a4, 0x18(a0)
  103720: 464c46b7     	lui	a3, 0x464c4
  103724: 57f68693     	addi	a3, a3, 0x57f
  103728: 974a         	add	a4, a4, s2
  10372a: 00076603     	lwu	a2, 0x0(a4)
  10372e: 0cd61e63     	bne	a2, a3, 0x10380a <PT_LOAD#0+0x380a>
  103732: 7110         	ld	a2, 0x20(a0)
  103734: 03f00693     	li	a3, 0x3f
  103738: 0cc6f963     	bgeu	a3, a2, 0x10380a <PT_LOAD#0+0x380a>
  10373c: 018db983     	ld	s3, 0x18(s11)
  103740: 000db683     	ld	a3, 0x0(s11)
  103744: 6f18         	ld	a4, 0x18(a4)
  103746: 99ca         	add	s3, s3, s2
  103748: 40d989b3     	sub	s3, s3, a3
  10374c: 99ba         	add	s3, s3, a4
  10374e: ffffd597     	auipc	a1, 0xffffd
  103752: f3a58593     	addi	a1, a1, -0xc6
  103756: ffffd717     	auipc	a4, 0xffffd
  10375a: f7a70713     	addi	a4, a4, -0x86
  10375e: 449d0c23     	sb	s1, 0x458(s10)
  103762: 448d0ca3     	sb	s0, 0x459(s10)
  103766: 452d3823     	sd	s2, 0x450(s10)
  10376a: 473d3823     	sd	s3, 0x470(s10)
  10376e: 8f0d         	sub	a4, a4, a1
  103770: 08000693     	li	a3, 0x80
  103774: 0ae6e363     	bltu	a3, a4, 0x10381a <PT_LOAD#0+0x381a>
  103778: ffffd617     	auipc	a2, 0xffffd
  10377c: f3060613     	addi	a2, a2, -0xd0
  103780: 40b60433     	sub	s0, a2, a1
  103784: 8622         	mv	a2, s0
  103786: 8566         	mv	a0, s9
  103788: fffff097     	auipc	ra, 0xfffff
  10378c: 26e080e7     	jalr	0x26e(ra) <PT_LOAD#0+0x29f6>
  103790: 480b0913     	addi	s2, s6, 0x480
  103794: 9962         	add	s2, s2, s8
  103796: 018b0593     	addi	a1, s6, 0x18
  10379a: 20000613     	li	a2, 0x200
  10379e: 95e2         	add	a1, a1, s8
  1037a0: 854a         	mv	a0, s2
  1037a2: fffff097     	auipc	ra, 0xfffff
  1037a6: 254080e7     	jalr	0x254(ra) <PT_LOAD#0+0x29f6>
  1037aa: 680b0513     	addi	a0, s6, 0x680
  1037ae: 18000613     	li	a2, 0x180
  1037b2: 00021597     	auipc	a1, 0x21
  1037b6: d7e58593     	addi	a1, a1, -0x282
  1037ba: 9562         	add	a0, a0, s8
  1037bc: fffff097     	auipc	ra, 0xfffff
  1037c0: 23a080e7     	jalr	0x23a(ra) <PT_LOAD#0+0x29f6>
  1037c4: 6782         	ld	a5, 0x0(sp)
  1037c6: 208d3703     	ld	a4, 0x208(s10)
  1037ca: 008c8633     	add	a2, s9, s0
  1037ce: 4685         	li	a3, 0x1
  1037d0: 00f696b3     	sll	a3, a3, a5
  1037d4: 01563023     	sd	s5, 0x0(a2)
  1037d8: 01563423     	sd	s5, 0x8(a2)
  1037dc: 01363823     	sd	s3, 0x10(a2)
  1037e0: 01263c23     	sd	s2, 0x18(a2)
  1037e4: 767d         	lui	a2, 0xfffff
  1037e6: 8f55         	or	a4, a4, a3
  1037e8: 9652         	add	a2, a2, s4
  1037ea: 20ed3423     	sd	a4, 0x208(s10)
  1037ee: 87a6         	mv	a5, s1
  1037f0: 6711         	lui	a4, 0x4
  1037f2: 00065697     	auipc	a3, 0x65
  1037f6: 80e68693     	addi	a3, a3, -0x7f2
  1037fa: 41760633     	sub	a2, a2, s7
  1037fe: 017a85b3     	add	a1, s5, s7
  103802: 03000513     	li	a0, 0x30
  103806: ebcff06f     	j	0x102ec2 <PT_LOAD#0+0x2ec2>
  10380a: 0006b617     	auipc	a2, 0x6b
  10380e: a5e60613     	addi	a2, a2, -0x5a2
  103812: 3a000593     	li	a1, 0x3a0
  103816: d48ff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  10381a: 0006b617     	auipc	a2, 0x6b
  10381e: a6660613     	addi	a2, a2, -0x59a
  103822: 3ac00593     	li	a1, 0x3ac
  103826: d38ff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  10382a: 03f00793     	li	a5, 0x3f
  10382e: 0297e363     	bltu	a5, s1, 0x103854 <PT_LOAD#0+0x3854>
  103832: 00041797     	auipc	a5, 0x41
  103836: 3ce78793     	addi	a5, a5, 0x3ce
  10383a: 00b41713     	slli	a4, s0, 0xb
  10383e: 973e         	add	a4, a4, a5
  103840: 6718         	ld	a4, 0x8(a4)
  103842: 00975733     	srl	a4, a4, s1
  103846: 8b05         	andi	a4, a4, 0x1
  103848: c711         	beqz	a4, 0x103854 <PT_LOAD#0+0x3854>
  10384a: 04ae         	slli	s1, s1, 0xb
  10384c: 94be         	add	s1, s1, a5
  10384e: 0104c783     	lbu	a5, 0x10(s1)
  103852: cf81         	beqz	a5, 0x10386a <PT_LOAD#0+0x386a>
  103854: 0006b597     	auipc	a1, 0x6b
  103858: a4458593     	addi	a1, a1, -0x5bc
  10385c: 4505         	li	a0, 0x1
  10385e: ffffd097     	auipc	ra, 0xffffd
  103862: 28e080e7     	jalr	0x28e(ra) <PT_LOAD#0+0xaec>
  103866: e50ff06f     	j	0x102eb6 <PT_LOAD#0+0x2eb6>
  10386a: 4785         	li	a5, 0x1
  10386c: 00f48823     	sb	a5, 0x10(s1)
  103870: 008488a3     	sb	s0, 0x11(s1)
  103874: df2ff06f     	j	0x102e66 <PT_LOAD#0+0x2e66>
  103878: 03f00793     	li	a5, 0x3f
  10387c: 0297e063     	bltu	a5, s1, 0x10389c <PT_LOAD#0+0x389c>
  103880: 00b49713     	slli	a4, s1, 0xb
  103884: 00041797     	auipc	a5, 0x41
  103888: 37c78793     	addi	a5, a5, 0x37c
  10388c: 97ba         	add	a5, a5, a4
  10388e: 0107c703     	lbu	a4, 0x10(a5)
  103892: c709         	beqz	a4, 0x10389c <PT_LOAD#0+0x389c>
  103894: 0117c703     	lbu	a4, 0x11(a5)
  103898: 00e40763     	beq	s0, a4, 0x1038a6 <PT_LOAD#0+0x38a6>
  10389c: 0006b597     	auipc	a1, 0x6b
  1038a0: a1458593     	addi	a1, a1, -0x5ec
  1038a4: bf65         	j	0x10385c <PT_LOAD#0+0x385c>
  1038a6: 00079823     	sh	zero, 0x10(a5)
  1038aa: 00065797     	auipc	a5, 0x65
  1038ae: 95e7b783     	ld	a5, -0x6a2(a5)
  1038b2: 0097d7b3     	srl	a5, a5, s1
  1038b6: 8b85         	andi	a5, a5, 0x1
  1038b8: e791         	bnez	a5, 0x1038c4 <PT_LOAD#0+0x38c4>
  1038ba: 0006b597     	auipc	a1, 0x6b
  1038be: a0e58593     	addi	a1, a1, -0x5f2
  1038c2: bf69         	j	0x10385c <PT_LOAD#0+0x385c>
  1038c4: 4791         	li	a5, 0x4
  1038c6: 2401         	sext.w	s0, s0
  1038c8: 00fda023     	sw	a5, 0x0(s11)
  1038cc: 4585         	li	a1, 0x1
  1038ce: 0001d797     	auipc	a5, 0x1d
  1038d2: 7487a123     	sw	s0, 0x742(a5)
  1038d6: 87a6         	mv	a5, s1
  1038d8: 4701         	li	a4, 0x0
  1038da: 4681         	li	a3, 0x0
  1038dc: 4605         	li	a2, 0x1
  1038de: 008595b3     	sll	a1, a1, s0
  1038e2: 03600513     	li	a0, 0x36
  1038e6: ddcff06f     	j	0x102ec2 <PT_LOAD#0+0x2ec2>
  1038ea: 0001d797     	auipc	a5, 0x1d
  1038ee: 7007af23     	sw	zero, 0x71e(a5)
  1038f2: 0001d797     	auipc	a5, 0x1d
  1038f6: 7087ad23     	sw	s0, 0x71a(a5)
  1038fa: ffffe097     	auipc	ra, 0xffffe
  1038fe: 1aa080e7     	jalr	0x1aa(ra) <PT_LOAD#0+0x1aa4>
  103902: 0006b717     	auipc	a4, 0x6b
  103906: 9de70713     	addi	a4, a4, -0x622
  10390a: 86a2         	mv	a3, s0
  10390c: 864a         	mv	a2, s2
  10390e: 85a6         	mv	a1, s1
  103910: 4511         	li	a0, 0x4
  103912: ffffd097     	auipc	ra, 0xffffd
  103916: 1da080e7     	jalr	0x1da(ra) <PT_LOAD#0+0xaec>
  10391a: 57fd         	li	a5, -0x1
  10391c: d8f41d63     	bne	s0, a5, 0x102eb6 <PT_LOAD#0+0x2eb6>
  103920: 00065797     	auipc	a5, 0x65
  103924: 8e87b783     	ld	a5, -0x718(a5)
  103928: 0097d7b3     	srl	a5, a5, s1
  10392c: 8b85         	andi	a5, a5, 0x1
  10392e: e8078063     	beqz	a5, 0x102fae <PT_LOAD#0+0x2fae>
  103932: 87a6         	mv	a5, s1
  103934: 4701         	li	a4, 0x0
  103936: 4685         	li	a3, 0x1
  103938: 4605         	li	a2, 0x1
  10393a: 4581         	li	a1, 0x0
  10393c: b75d         	j	0x1038e2 <PT_LOAD#0+0x38e2>
  10393e: 000b3783     	ld	a5, 0x0(s6)
  103942: 4589         	li	a1, 0x2
  103944: eef41763     	bne	s0, a5, 0x103032 <PT_LOAD#0+0x3032>
  103948: 00068797     	auipc	a5, 0x68
  10394c: 7147b023     	sd	s4, 0x700(a5)
  103950: 00068797     	auipc	a5, 0x68
  103954: 7097a823     	sw	s1, 0x710(a5)
  103958: 00068797     	auipc	a5, 0x68
  10395c: 7127b023     	sd	s2, 0x700(a5)
  103960: 00068797     	auipc	a5, 0x68
  103964: 7137b423     	sd	s3, 0x708(a5)
  103968: d8aff06f     	j	0x102ef2 <PT_LOAD#0+0x2ef2>
  10396c: 864a         	mv	a2, s2
  10396e: 85a6         	mv	a1, s1
  103970: 8522         	mv	a0, s0
  103972: fffff097     	auipc	ra, 0xfffff
  103976: 156080e7     	jalr	0x156(ra) <PT_LOAD#0+0x2ac8>
  10397a: bcd5         	j	0x10346e <PT_LOAD#0+0x346e>
  10397c: 00068797     	auipc	a5, 0x68
  103980: 6c47b783     	ld	a5, 0x6c4(a5)
  103984: 02878363     	beq	a5, s0, 0x1039aa <PT_LOAD#0+0x39aa>
  103988: 0006b597     	auipc	a1, 0x6b
  10398c: 97058593     	addi	a1, a1, -0x690
  103990: 4505         	li	a0, 0x1
  103992: ffffd097     	auipc	ra, 0xffffd
  103996: 15a080e7     	jalr	0x15a(ra) <PT_LOAD#0+0xaec>
  10399a: 0006b617     	auipc	a2, 0x6b
  10399e: 97660613     	addi	a2, a2, -0x68a
  1039a2: 68500593     	li	a1, 0x685
  1039a6: bb8ff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  1039aa: 02900793     	li	a5, 0x29
  1039ae: 04fa8c63     	beq	s5, a5, 0x103a06 <PT_LOAD#0+0x3a06>
  1039b2: 02f00793     	li	a5, 0x2f
  1039b6: fafa8be3     	beq	s5, a5, 0x10396c <PT_LOAD#0+0x396c>
  1039ba: 02600793     	li	a5, 0x26
  1039be: 02fa9c63     	bne	s5, a5, 0x1039f6 <PT_LOAD#0+0x39f6>
  1039c2: 4785         	li	a5, 0x1
  1039c4: 00fda023     	sw	a5, 0x0(s11)
  1039c8: ffffd717     	auipc	a4, 0xffffd
  1039cc: cc070713     	addi	a4, a4, -0x340
  1039d0: ffffd797     	auipc	a5, 0xffffd
  1039d4: cd878793     	addi	a5, a5, -0x328
  1039d8: 8f99         	sub	a5, a5, a4
  1039da: 042e         	slli	s0, s0, 0xb
  1039dc: 943e         	add	s0, s0, a5
  1039de: 00041797     	auipc	a5, 0x41
  1039e2: 62278793     	addi	a5, a5, 0x622
  1039e6: 943e         	add	s0, s0, a5
  1039e8: e804         	sd	s1, 0x10(s0)
  1039ea: 00068797     	auipc	a5, 0x68
  1039ee: 64e7b783     	ld	a5, 0x64e(a5)
  1039f2: c76ff06f     	j	0x102e68 <PT_LOAD#0+0x2e68>
  1039f6: 0006b617     	auipc	a2, 0x6b
  1039fa: 93260613     	addi	a2, a2, -0x6ce
  1039fe: 69300593     	li	a1, 0x693
  103a02: b5cff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  103a06: 4785         	li	a5, 0x1
  103a08: 00fda023     	sw	a5, 0x0(s11)
  103a0c: 8522         	mv	a0, s0
  103a0e: fffff097     	auipc	ra, 0xfffff
  103a12: d6c080e7     	jalr	-0x294(ra) <PT_LOAD#0+0x277a>
  103a16: 0006b617     	auipc	a2, 0x6b
  103a1a: 92a60613     	addi	a2, a2, -0x6d6
  103a1e: 6b900593     	li	a1, 0x6b9
  103a22: b3cff06f     	j	0x102d5e <PT_LOAD#0+0x2d5e>
  103a26: 0001         	nop
  103a28: 0001d117     	auipc	sp, 0x1d
  103a2c: 5d810113     	addi	sp, sp, 0x5d8
  103a30: ab6ff06f     	j	0x102ce6 <PT_LOAD#0+0x2ce6>
  103a34: 651c         	ld	a5, 0x8(a0)
  103a36: 6118         	ld	a4, 0x0(a0)
  103a38: 56fd         	li	a3, -0x1
  103a3a: 95be         	add	a1, a1, a5
  103a3c: 00359793     	slli	a5, a1, 0x3
  103a40: 97ba         	add	a5, a5, a4
  103a42: e394         	sd	a3, 0x0(a5)
  103a44: 4505         	li	a0, 0x1
  103a46: 0015c793     	xori	a5, a1, 0x1
  103a4a: 00359693     	slli	a3, a1, 0x3
  103a4e: 078e         	slli	a5, a5, 0x3
  103a50: 97ba         	add	a5, a5, a4
  103a52: 96ba         	add	a3, a3, a4
  103a54: 6390         	ld	a2, 0x0(a5)
  103a56: 6294         	ld	a3, 0x0(a3)
  103a58: 882e         	mv	a6, a1
  103a5a: 8185         	srli	a1, a1, 0x1
  103a5c: 00359793     	slli	a5, a1, 0x3
  103a60: 97ba         	add	a5, a5, a4
  103a62: 00d67363     	bgeu	a2, a3, 0x103a68 <PT_LOAD#0+0x3a68>
  103a66: 86b2         	mv	a3, a2
  103a68: e394         	sd	a3, 0x0(a5)
  103a6a: fd056ee3     	bltu	a0, a6, 0x103a46 <PT_LOAD#0+0x3a46>
  103a6e: 8082         	ret
  103a70: 090008b7     	lui	a7, 0x9000
  103a74: 4801         	li	a6, 0x0
  103a76: 1eb88893     	addi	a7, a7, 0x1eb
  103a7a: 00000073     	ecall
  103a7e: 48a1         	li	a7, 0x8
  103a80: 4801         	li	a6, 0x0
  103a82: 00000073     	ecall
  103a86: 1141         	addi	sp, sp, -0x10
  103a88: 090008b7     	lui	a7, 0x9000
  103a8c: e406         	sd	ra, 0x8(sp)
  103a8e: 1eb88893     	addi	a7, a7, 0x1eb
  103a92: 481d         	li	a6, 0x7
  103a94: 00000073     	ecall
  103a98: cd19         	beqz	a0, 0x103ab6 <PT_LOAD#0+0x3ab6>
  103a9a: 04400593     	li	a1, 0x44
  103a9e: 00000517     	auipc	a0, 0x0
  103aa2: 15a50513     	addi	a0, a0, 0x15a
  103aa6: ffffd097     	auipc	ra, 0xffffd
  103aaa: 714080e7     	jalr	0x714(ra) <PT_LOAD#0+0x11ba>
  103aae: ffffe097     	auipc	ra, 0xffffe
  103ab2: 0d8080e7     	jalr	0xd8(ra) <PT_LOAD#0+0x1b86>
  103ab6: 60a2         	ld	ra, 0x8(sp)
  103ab8: 0141         	addi	sp, sp, 0x10
  103aba: 8082         	ret
  103abc: 832a         	mv	t1, a0
  103abe: 1141         	addi	sp, sp, -0x10
  103ac0: 090008b7     	lui	a7, 0x9000
  103ac4: 852e         	mv	a0, a1
  103ac6: e406         	sd	ra, 0x8(sp)
  103ac8: 1eb88893     	addi	a7, a7, 0x1eb
  103acc: 4821         	li	a6, 0x8
  103ace: 859a         	mv	a1, t1
  103ad0: 00000073     	ecall
  103ad4: cd19         	beqz	a0, 0x103af2 <PT_LOAD#0+0x3af2>
  103ad6: 07900593     	li	a1, 0x79
  103ada: 00000517     	auipc	a0, 0x0
  103ade: 11e50513     	addi	a0, a0, 0x11e
  103ae2: ffffd097     	auipc	ra, 0xffffd
  103ae6: 6d8080e7     	jalr	0x6d8(ra) <PT_LOAD#0+0x11ba>
  103aea: ffffe097     	auipc	ra, 0xffffe
  103aee: 09c080e7     	jalr	0x9c(ra) <PT_LOAD#0+0x1b86>
  103af2: 60a2         	ld	ra, 0x8(sp)
  103af4: 0141         	addi	sp, sp, 0x10
  103af6: 8082         	ret
  103af8: 832a         	mv	t1, a0
  103afa: 1141         	addi	sp, sp, -0x10
  103afc: 090008b7     	lui	a7, 0x9000
  103b00: 852e         	mv	a0, a1
  103b02: e406         	sd	ra, 0x8(sp)
  103b04: 1eb88893     	addi	a7, a7, 0x1eb
  103b08: 4825         	li	a6, 0x9
  103b0a: 859a         	mv	a1, t1
  103b0c: 00000073     	ecall
  103b10: cd19         	beqz	a0, 0x103b2e <PT_LOAD#0+0x3b2e>
  103b12: 09200593     	li	a1, 0x92
  103b16: 00000517     	auipc	a0, 0x0
  103b1a: 0e250513     	addi	a0, a0, 0xe2
  103b1e: ffffd097     	auipc	ra, 0xffffd
  103b22: 69c080e7     	jalr	0x69c(ra) <PT_LOAD#0+0x11ba>
  103b26: ffffe097     	auipc	ra, 0xffffe
  103b2a: 060080e7     	jalr	0x60(ra) <PT_LOAD#0+0x1b86>
  103b2e: 60a2         	ld	ra, 0x8(sp)
  103b30: 0141         	addi	sp, sp, 0x10
  103b32: 8082         	ret
  103b34: 0000         	unimp
  103b36: 0000         	unimp
  103b38: 6e72656b     	<unknown>
  103b3c: 6c65         	lui	s8, 0x19
  103b3e: 675f 3172 7830       	<unknown>
  103b44: 652e         	ld	a0, 0xc8(sp)
  103b46: 666c         	ld	a1, 0xc8(a2)
		...
  103b50: 6e72656b     	<unknown>
  103b54: 6c65         	lui	s8, 0x19
  103b56: 675f 3162 7930       	<unknown>
  103b5c: 652e         	ld	a0, 0xc8(sp)
  103b5e: 666c         	ld	a1, 0xc8(a2)
		...
  103b68: 6e72656b     	<unknown>
  103b6c: 6c65         	lui	s8, 0x19
  103b6e: 675f 3262 7930       	<unknown>
  103b74: 652e         	ld	a0, 0xc8(sp)
  103b76: 666c         	ld	a1, 0xc8(a2)
		...
  103b80: 6e72656b     	<unknown>
  103b84: 6c65         	lui	s8, 0x19
  103b86: 675f 3262 7830       	<unknown>
  103b8c: 652e         	ld	a0, 0xc8(sp)
  103b8e: 666c         	ld	a1, 0xc8(a2)
		...
  103b98: 6e72656b     	<unknown>
  103b9c: 6c65         	lui	s8, 0x19
  103b9e: 675f 3168 3030       	<unknown>
  103ba4: 652e         	ld	a0, 0xc8(sp)
  103ba6: 666c         	ld	a1, 0xc8(a2)
		...
  103bb0: 6e72656b     	<unknown>
  103bb4: 6c65         	lui	s8, 0x19
  103bb6: 675f 3161 7830       	<unknown>
  103bbc: 652e         	ld	a0, 0xc8(sp)
  103bbe: 666c         	ld	a1, 0xc8(a2)
		...
  103bc8: 6e72656b     	<unknown>
  103bcc: 6c65         	lui	s8, 0x19
  103bce: 675f 3162 7830       	<unknown>
  103bd4: 652e         	ld	a0, 0xc8(sp)
  103bd6: 666c         	ld	a1, 0xc8(a2)
		...
  103be0: 2b2d         	addiw	s6, s6, 0xb
  103be2: 2020         	<unknown>
  103be4: 3020         	<unknown>
  103be6: 3058         	<unknown>
  103be8: 0078         	addi	a4, sp, 0xc
  103bea: 0000         	unimp
  103bec: 0000         	unimp
  103bee: 0000         	unimp
  103bf0: 6e28         	ld	a0, 0x58(a2)
  103bf2: 6c75         	lui	s8, 0x1d
  103bf4: 296c         	<unknown>
  103bf6: 0000         	unimp
  103bf8: 7552         	ld	a0, 0x130(sp)
  103bfa: 746e         	ld	s0, 0xf8(sp)
  103bfc: 6d69         	lui	s10, 0x1a
  103bfe: 2065         	<unknown>
  103c00: 6166         	ld	sp, 0x58(sp)
  103c02: 6c69         	lui	s8, 0x1a
  103c04: 7275         	lui	tp, 0xffffd
  103c06: 3a65         	addiw	s4, s4, -0x7
  103c08: 6120         	ld	s0, 0x40(a0)
  103c0a: 2030         	<unknown>
  103c0c: 3d3d         	addiw	s10, s10, -0x11
  103c0e: 3020         	<unknown>
  103c10: 4020         	lw	s0, 0x40(s0)
  103c12: 2f20         	<unknown>
  103c14: 5f757067     	<unknown>
  103c18: 7264         	ld	s1, 0xe0(a2)
  103c1a: 2f76         	<unknown>
  103c1c: 7075         	c.lui	zero, 0xffffd
  103c1e: 6f72         	ld	t5, 0x118(sp)
  103c20: 736f2f63     	<unknown>
  103c24: 62696c2f     	<unknown>
  103c28: 762d736f     	jal	t1, 0x1db38a <PT_LOAD#0+0xdb38a>
  103c2c: 2e312e33     	<unknown>
  103c30: 2f30         	<unknown>
  103c32: 2f637273     	csrrci	tp, 0x2f6, 0x6
  103c36: 6d6d6f63     	bltu	s10, s6, 0x104314 <PT_LOAD#0+0x4314>
  103c3a: 6e2f6e6f     	jal	t3, 0x1fa31c <PT_LOAD#0+0xfa31c>
  103c3e: 7276         	ld	tp, 0x178(sp)
  103c40: 7369         	lui	t1, 0xffffa
  103c42: 322d7663     	bgeu	s10, sp, 0x103f6e <PT_LOAD#0+0x3f6e>
  103c46: 302e         	<unknown>
  103c48: 6962732f     	<unknown>
  103c4c: 632e         	ld	t1, 0xc8(sp)
  103c4e: 253a         	<unknown>
  103c50: 0a64         	addi	s1, sp, 0x11c
  103c52: 0000         	unimp
  103c54: 0000         	unimp
  103c56: 0000         	unimp
  103c58: 4246         	lw	tp, 0x50(sp)
  103c5a: 6f20         	ld	s0, 0x58(a4)
  103c5c: 6666         	ld	a2, 0x58(sp)
  103c5e: 20746573     	csrrsi	a0, 0x207, 0x8
  103c62: 6c25         	lui	s8, 0x9
  103c64: 786c         	ld	a1, 0xf0(s0)
  103c66: 6620         	ld	s0, 0x48(a2)
  103c68: 72705777     	<unknown>
  103c6c: 72617453     	<unknown>
  103c70: 2074         	<unknown>
  103c72: 6c25         	lui	s8, 0x9
  103c74: 786c         	ld	a1, 0xf0(s0)
  103c76: 000a         	c.slli	zero, 0x2
  103c78: 6d72         	ld	s10, 0x118(sp)
  103c7a: 622e         	ld	tp, 0xc8(sp)
  103c7c: 6e69         	lui	t3, 0x1a
  103c7e: 6164         	ld	s1, 0xc0(a0)
  103c80: 6174         	ld	a3, 0xc0(a0)
  103c82: 622e         	ld	tp, 0xc8(sp)
  103c84: 6e69         	lui	t3, 0x1a
  103c86: 0000         	unimp
  103c88: 6d72         	ld	s10, 0x118(sp)
  103c8a: 652e         	ld	a0, 0xc8(sp)
  103c8c: 666c         	ld	a1, 0xc8(a2)
  103c8e: 0000         	unimp
  103c90: cf54         	sw	a3, 0x1c(a4)
  103c92: ff           	<unknown>
  103c93: 6cff ffcf 60ff ffcf 78ff ffcf 3eff ffcf 32ff ffcf 48ff       	<unknown>
  103ca9: 32ffffcf     	<unknown>
  103cad: 34ffffcf     	<unknown>
  103cb1: ffd4         	sd	a3, 0xb8(a5)
  103cb3: c4ff ffd3 98ff ffd4 98ff ffd4 98ff ffd4 98ff 	<unknown>
  103cc5: ffd4         	sd	a3, 0xb8(a5)
  103cc7: c4ff ffd3 98ff ffd4 98ff ffd4 98ff ffd4 98ff 	<unknown>
  103cd9: ffd4         	sd	a3, 0xb8(a5)
  103cdb: ffd21eff ffd3b2ff ffd250ff   	<unknown>
  103ce7: ffd498ff ffd498ff ffd452ff   	<unknown>
  103cf3: ffd498ff ffd3ceff ffd498ff   	<unknown>
  103cff: ffd498ff ffd356ff ffd1e0ff   	<unknown>
  103d0b: e6ff ffd1 e6ff ffd1 ecff ffd1 f2ff ffd1 e6ff ffd1 92ff       	<unknown>
  103d21: ffe1         	bnez	a5, 0x103cf9 <PT_LOAD#0+0x3cf9>
  103d23: ffe49aff ffe192ff ffe36aff   	<unknown>
  103d2f: e4ff ffe3 14ff ffe2 12ff fff0 3aff fff1 44ff fffc c2ff       	<unknown>
  103d45: 3afffffb     	<unknown>
  103d49: fff1         	bnez	a5, 0x103d25 <PT_LOAD#0+0x3d25>
  103d4b: ff           	<unknown>
  103d4c: f17e         	sd	t6, 0xa0(sp)
  103d4e: ff           	<unknown>
  103d4f: fff31cff fff504ff fff6b2ff   	<unknown>
  103d5b: 26ff fff7 6aff fff1 deff fffa 2cff   	<unknown>
  103d69: c0fffffb     	<unknown>
  103d6d: fffc         	sd	a5, 0xf8(a5)
  103d6f: 80ff fff4 eaff fff1 9eff     	<unknown>
  103d79: aafffffb     	<unknown>
  103d7d: fff1         	bnez	a5, 0x103d59 <PT_LOAD#0+0x3d59>
  103d7f: ff           	<unknown>
  103d80: fbf2         	sd	t3, 0x1f0(sp)
  103d82: ff           	<unknown>
  103d83: 20ff fffc 00ff 0201 0335 3607 041b   	<unknown>
  103d91: 2926         	<unknown>
  103d93: 2208         	<unknown>
  103d95: 3e1c3037     	lui	zero, 0x3e1c3
  103d99: 2705         	addiw	a4, a4, 0x1
  103d9b: 2c2e         	<unknown>
  103d9d: 162a         	slli	a2, a2, 0x2a
  103d9f: 1809         	addi	a6, a6, -0x1e
  103da1: 31383b23     	sd	s3, 0x316(a6)
  103da5: 1d12         	slli	s10, s10, 0x24
  103da7: 06343f0b     	<unknown>
  103dab: 251a         	<unknown>
  103dad: 2128         	<unknown>
  103daf: 2b2d3d2f     	<unknown>
  103db3: 1715         	addi	a4, a4, -0x1b
  103db5: 113a         	slli	sp, sp, 0x2e
  103db7: 330a         	<unknown>
  103db9: 2419         	addiw	s0, s0, 0x6
  103dbb: 3c20         	<unknown>
  103dbd: 3914         	<unknown>
  103dbf: 3210         	<unknown>
  103dc1: 131f 1e0f 0d0e       	<unknown>
  103dc7: 000c         	<unknown>
  103dc9: 0b00         	addi	s0, sp, 0x190
		...
  103dd7: 0000         	unimp
  103dd9: 0c00         	addi	s0, sp, 0x210
  103ddb: 0000         	unimp
  103ddd: 0000         	unimp
  103ddf: 000d         	c.nop	0x3
		...
  103de9: 0a00         	addi	s0, sp, 0x110
  103deb: 0000000b     	<unknown>
  103def: 00050b03     	lb	s6, 0x0(a0)
  103df3: 0001         	nop
  103df5: 0d0c         	addi	a1, sp, 0x290
  103df7: 000e         	c.slli	zero, 0x3
  103df9: 0c00         	addi	s0, sp, 0x210
  103dfb: 0d05         	addi	s10, s10, 0x1
  103dfd: 0000         	unimp
  103dff: 000d         	c.nop	0x3
  103e01: 0005         	c.nop	0x1
		...
  103e17: 0000         	unimp
  103e19: 000e         	c.slli	zero, 0x3
		...
  103e23: 0b00         	addi	s0, sp, 0x190
  103e25: 000c         	<unknown>
  103e27: 0000         	unimp
  103e29: 0c00         	addi	s0, sp, 0x210
  103e2b: 0000         	unimp
  103e2d: 0002         	c.slli	zero, 0x0
  103e2f: 0e0c         	addi	a1, sp, 0x310
  103e31: 0000         	unimp
  103e33: 0c00         	addi	s0, sp, 0x210
  103e35: 0e00         	addi	s0, sp, 0x310
  103e37: 0000         	unimp
  103e39: 000e         	c.slli	zero, 0x3
		...
  103e53: 000e         	c.slli	zero, 0x3
		...
  103e5d: 0000         	unimp
  103e5f: 000c         	<unknown>
  103e61: 0000         	unimp
  103e63: 0c00         	addi	s0, sp, 0x210
  103e65: 0000         	unimp
  103e67: 0000         	unimp
  103e69: 0e0c         	addi	a1, sp, 0x310
  103e6b: 0000         	unimp
  103e6d: 0000         	unimp
  103e6f: 0e00         	addi	s0, sp, 0x310
  103e71: 0000         	unimp
  103e73: 000e         	c.slli	zero, 0x3
		...
  103e8d: 0009         	c.nop	0x2
		...
  103e97: 0000         	unimp
  103e99: 00000007     	<unknown>
  103e9d: 0704         	addi	s1, sp, 0x380
  103e9f: 0000         	unimp
  103ea1: 0000         	unimp
  103ea3: 090c         	addi	a1, sp, 0x90
  103ea5: 0000         	unimp
  103ea7: 0000         	unimp
  103ea9: 0900         	addi	s0, sp, 0x90
  103eab: 0000         	unimp
  103ead: 0009         	c.nop	0x2
		...
  103ec7: 0008         	<unknown>
		...
  103ed1: 0000         	unimp
  103ed3: 000a         	c.slli	zero, 0x2
  103ed5: 0000         	unimp
  103ed7: 0a00         	addi	s0, sp, 0x110
  103ed9: 0000         	unimp
  103edb: 0000         	unimp
  103edd: 080c         	addi	a1, sp, 0x10
  103edf: 0000         	unimp
  103ee1: 0000         	unimp
  103ee3: 0800         	addi	s0, sp, 0x10
  103ee5: 0000         	unimp
  103ee7: 0008         	<unknown>
		...
  103f01: 000e         	c.slli	zero, 0x3
		...
  103f0b: 0000         	unimp
  103f0d: 000c         	<unknown>
  103f0f: 0000         	unimp
  103f11: 0c00         	addi	s0, sp, 0x210
  103f13: 0000         	unimp
  103f15: 0000         	unimp
  103f17: 0e0c         	addi	a1, sp, 0x310
  103f19: 0000         	unimp
  103f1b: 0000         	unimp
  103f1d: 0e00         	addi	s0, sp, 0x310
  103f1f: 0000         	unimp
  103f21: 000e         	c.slli	zero, 0x3
  103f23: 0000         	unimp
  103f25: 0000         	unimp
  103f27: 3000         	<unknown>
  103f29: 3231         	addiw	tp, tp, -0x14
  103f2b: 36353433     	<unknown>
  103f2f: 41393837     	lui	a6, 0x41393
  103f33: 4342         	lw	t1, 0x10(sp)
  103f35: 4544         	lw	s1, 0xc(a0)
  103f37: 4d46         	lw	s10, 0x50(sp)
  103f39: 10e1         	addi	ra, ra, -0x8
  103f3b: 705c         	ld	a5, 0xa0(s0)
  103f3d: b26a         	<unknown>
  103f3f: 2481         	sext.w	s1, s1
  103f41: 1fa8         	addi	a0, sp, 0x3f8
  103f43: 0000         	unimp
  103f45: 0000         	unimp
  103f47: 2820         	<unknown>
  103f49: 1fa8         	addi	a0, sp, 0x3f8
  103f4b: 0000         	unimp
  103f4d: 0000         	unimp
  103f4f: 6d20         	ld	s0, 0x58(a0)
  103f51: 9538         	<unknown>
  103f53: 63cc         	ld	a1, 0x80(a5)
  103f55: 2fdd         	addiw	t6, t6, 0x17
  103f57: 5402         	lw	s0, 0x20(sp)
  103f59: 47524f4f     	<unknown>
  103f5d: cc004c4f     	<unknown>
  103f61: 1182         	slli	gp, gp, 0x20
  103f63: 0000         	unimp
  103f65: 0000         	unimp
  103f67: 8820         	<unknown>
  103f69: 1f90         	addi	a2, sp, 0x3f0
  103f6b: 0000         	unimp
  103f6d: 0000         	unimp
  103f6f: 0120         	addi	s0, sp, 0x88
  103f71: 0101         	c.addi	sp, 0x0
  103f73: 0101         	c.addi	sp, 0x0
  103f75: 0101         	c.addi	sp, 0x0
  103f77: 0001         	nop
  103f79: 000a         	c.slli	zero, 0x2
  103f7b: 0000         	unimp
  103f7d: 0000         	unimp
  103f7f: b320         	<unknown>
  103f81: 1a60         	addi	s0, sp, 0x13c
  103f83: 3aae2137     	lui	sp, 0x3aae2
  103f87: a0dc         	<unknown>
  103f89: a0a0         	<unknown>
  103f8b: a0a0         	<unknown>
  103f8d: a0a0         	<unknown>
  103f8f: 0aa0         	addi	s0, sp, 0x158
  103f91: 100c         	addi	a1, sp, 0x20
		...
  120fff: ff00         	sd	s0, 0x38(a4)
  121001: ff           	<unknown>
  121002: ff           	<unknown>
  121003: 00ff 0000 ff00 ffff ffff     	<unknown>
  12100d: ff           	<unknown>
  12100e: ff           	<unknown>
  12100f: ff           	<unknown>
  121010: ff           	<unknown>
  121011: ff           	<unknown>
  121012: ff           	<unknown>
  121013: 01ff 0000 0000 0000 0000     	<unknown>
		...
  16cffd: 0000         	unimp
  16cfff: 00           	<unknown>
