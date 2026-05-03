; simpleGuest.asm, a simple example -> parse a byte buffer and HLT
BITS 16
ORG 0x1000

; Set up the stack
    mov si, 0x2000 ; Ptr to fuzz input buffer at GPA 0x2000
    mov al, [si] ; read first byte
    cmp al, 0x41 ; is the output A?
    je .interesting ; if so, jump to interesting code
    hlt ; otherwise, halt

.interesting:
    in al, 0x60 ; read from keyboard controller
    hlt