; .origin 0x00
; A, B, C are integers and are treated as addresses
; MEM[B] = MEM[B] - MEM[A]
; if (MEM[B] < 1)
;   PC = C

; for(int i = 0; i < 31; i++) {
;   MEM[0x40+i] = MEM[0x40+i] - 3;
; }
;

 loop:
        subleq 0x40, pos3, -1   ; table[0] -= 3
loop2:
        subleq -1, 0x40, -1     ; print(table[0])
        subleq 1, neg1, -1   ; self-modifying code
        subleq 3, neg1, -1  ; self-modifying code
        subleq TA, TA, next
next:
        subleq TA, tablemax, next2 
next2:
        subleq TB, TA, next3
next3:  subleq TB, loop, end
        subleq TB, TB, loop
end:
        subleq -1, -1, -1            ; end

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
