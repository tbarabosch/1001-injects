; taken from https://github.com/govolution/moreshellcode/blob/master/hello64.asm
; and slightly modified 
global _start

_start:
    ; some NOPs to recognize the .text section in memory dumps quickly  
    db 90h, 90h, 90h, 90h, 90h, 90
    jmp MESSAGE

GOBACK:
    xor rax,rax
    mov al, 1  
    mov rdi, rax
    pop rsi   
          
    xor rdx, rdx   
    add rdx, 0xF
    syscall

ENDLESS:	
    jmp ENDLESS

MESSAGE:
    call GOBACK
    db "Injected!", 0dh, 0ah
