
%define O_RDONLY             00
%define O_WRONLY             01
%define O_RDWR               02

%define SYS_read          0x003
%define SYS_open          0x005
%define SYS_close         0x006

%define EINTR                 4

randomx:
    pushad
    mov    ebp, [esp+32+8] ; outlen
    mov    edi, [esp+32+4] ; out
    
    ; f = open("/dev/urandom", O_RDONLY);
    push   SYS_open
    pop    eax
    @pushz "/dev/urandom"
    pop    ebx
    push   O_RDONLY
    pop    ecx    
    int    0x80
    ; if (f >= 0)
    test   eax, eax
    jl     exit_rnd
    
    ; for (u=0; u<outlen;)
    push   SYS_read
    pop    eax
    lea    ebx, [edi+esi]  ; ebx = p + u
    int    0x80
    ; if (len < 0)
    test   eax, eax
        
exit_rnd:
           
    popad
    ret