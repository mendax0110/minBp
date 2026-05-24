; simpleGuest.asm, a simple example -> parse a byte buffer and HLT
BITS 16
ORG 0x1000

start:
    ; Read MMIO magic (DS:BX = 0x8000:0x0000 -> 0x80000)
    mov ax, 0x8000
    mov ds, ax
    xor bx, bx
    mov ax, [bx]

    ; write to MMIO input (0x80008)
    mov word [bx + 0x08], 0x0042

    ; read MMIO status (0x80010)
    mov ax, [bx + 0x10]

    cli
    hlt