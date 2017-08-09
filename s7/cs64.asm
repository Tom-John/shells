

    bits 64
    
    global __chkstk
    global __alloca_probe
    
__chkstk:
__alloca_probe:

%define r10_t -16
%define r11_t  -8
%define arg_0   8

    sub rsp, 10h
    mov [rsp+10h+r10_t], r10
    mov [rsp+10h+r11_t], r11
    xor r11, r11
    lea r10, [rsp+10h+arg_0]
    sub r10, rax
    cmovb r10, r11
    mov r11, [gs:10h]          ; get stack limit
    cmp r10, r11
    jnb cs20
    and r10w, 0F000h

cs10:
    lea r11, [r11-1000h]
    mov byte [r11], 0
    cmp r10, r11
    jnz cs10

cs20:
    mov r10, [rsp+10h+r10_t]
    mov r11, [rsp+10h+r11_t]
    add rsp, 10h
    ret
