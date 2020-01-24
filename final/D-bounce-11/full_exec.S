.section .text
.align 2
.syntax unified

_start:
adr r7, putchar
ldrh r7, [r7]

adr r6, hacked

looper:
  movs r5, #0
  puts:
    ldrb r0, [r6, r5]
    blx r7
    adds r5, #1
    cmp r5, hacked_size
  bne puts

b looper

putchar:
.word 0x3dad

@ skip past the dead region
.balign 16
nop
.balign 16

hacked: .ascii "~~~~ HACKED BY KERNEL SANDERS ~~~~\n"
.equ hacked_size, . - hacked
