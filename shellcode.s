; push /snap/bin/gnome-calculator to the stack
mov rax, 0x00726f74616c7563
push rax

mov rax, 0x6c61632d656d6f6e
push rax

mov rax, 0x672f6e69622f7061
push rax

mov rax, 0x6e732f2f2f2f2f2f
push rax

; store this pointer in rdi
mov rdi, rsp

; push DISPLAY=:0 to the stack, this is an environment variable that is needed by gnome-calculator
mov rax, 0x000000000000303a
push rax

mov rax, 0x3d59414c50534944
push rax
; store this pointer in rcx
mov rcx, rsp

; push NULL, followed by the pointer to DISPLAY=:0
; this sets up our envp argument to exec
mov rax, 0
push rax
push rcx
; store envp array in rdx
mov rdx, rsp
; push NULL, followed by pointer to /snap/bin/gnome-calculator
; this sets up argv array
push rax
push rdi

; store it in rsi
mov rsi, rsp

;call exec syscall
mov rax, 0x3b
syscall

