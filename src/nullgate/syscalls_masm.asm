.code

nullgate_trampoline proc
    mov rax, [rcx]      ; get system call number
    mov r11, [rcx+8]    ; get system call address
    mov r10, [rcx+16]   ; get original first argument
    jmp r11             ; insanity
nullgate_trampoline endp

END
