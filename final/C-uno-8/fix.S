; A, B, C are integers and are treated as addresses
; MEM[B] = MEM[B] - MEM[A]
; if (MEM[B] < 1)
;   PC = C

; for(int i = 0; i < 31; i++) {
;   MEM[0x40+i] = MEM[0x40+i] - 3;
;   output(MEM[0x40]);
; }
;

loop:
    subleq 0x40, pos3, -1 ; table[i] -= 3
loop2:
    subleq -1, 0x40, -1   ; output(MEM[i])
    subleq 1, neg1, -1    ; self-modifying code
    subleq 3, neg1, -1    ; self-modifying code
    subleq TA, TA, next   ; TA = 0
next:
    subleq TA, tablemax, next2  ; TA = -tablemax
next2:
    subleq TB, TA, next3  ; TB = -TA
next3:
    subleq TB, loop, end  ; tablemax - MEM[0]
    subleq TB, TB, loop   ; goto loop
end:
    subleq -1, -1, -1     ; exit program

; Data region
pos3:
  dd 3
neg1:
  dd -1
tablemax:
  dd 0x5f
TA:
  dd 0
TB:
  dd 0
