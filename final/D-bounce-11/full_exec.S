.section .text
.align 2
.syntax unified


adr r7, putchar
ldrh r7, [r7]

adr r6, hacked

looper:
  ldrb r0, [r6]
  blx r7
  ldrb r0, [r6, #1]
  blx r7

b looper

putchar:
.word 0x3dad

hacked:
.ascii "HACKED\n"
