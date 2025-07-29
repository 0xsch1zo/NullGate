.intel_syntax noprefix
.section .text
.code64

.global nullgate_trampoline 
nullgate_trampoline:
        mov rax, [rcx]      # get system call number
        mov r11, [rcx+8]    # get system call address
        mov r10, [rcx+16]   # get original first argument
        jmp r11             # insanity
