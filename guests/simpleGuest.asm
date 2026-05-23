; simpleGuest.asm, a simple example -> parse a byte buffer and HLT
BITS 16
ORG 0x1000

start:
    ; Read MMIO magic
    xor dx, dx
    mov ds, dx
    mov ax, 0x8000
    mov ds, ax
    xor eax, eax
    mov ebx, [eax]

    ; write to MMIO input
    mov dword [eax + 0x08], 0x42

    ; read MMIO status
    mov ebx, [eax + 0x10]

    cli
    hlt