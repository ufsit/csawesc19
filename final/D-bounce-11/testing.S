.section .text
.align 2
.syntax unified


@adr r7, print
@ldrh r7, [r7]
@
@adr r0, serial
@ldr r0, [r0]
@adr r1, hacked
@blx r7

adr r7, putchar
ldrh r7, [r7]

adr r6, hacked

looper:
  ldrb r0, [r6]
  blx r7
  ldrb r0, [r6, #1]
  blx r7

  @adr r1, watchdog
  @ldr r1, [r1]
  @movw r2, #0xa602
  @strh r2, [r1]
  @movw r2, #0xb480
  @strh r2, [r1]
b looper

@adr r7, serial_write
@ldrh r7, [r7]
@
@adr r0, hacked
@mov r1, hacked_sz-hacked
@blx r7

@adr r0, chal_solve
@ldrh r0, [r0]
@bx r0
@
@chal_solve:
@.word 0x71d

putchar:
.word 0x3dad

watchdog:
.word 0x4005200c

@serial_write:
@.word 0x3ca5

@serial:
@.int 0x1fff8e34

hacked:
.ascii "HACKED\n"
@hacked_sz:
