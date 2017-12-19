;
;  Copyright © 2017 Odzhan. All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.
;      
    
    bits 32
    
    %ifndef BIN
      global randomx
      global _randomx
    %endif
    
%define O_RDONLY             00
%define O_WRONLY             01
%define O_RDWR               02

%define SYS_read          0x003
%define SYS_open          0x005
%define SYS_close         0x006

%define EINTR                 4

; void randomx(void *out, size_t outlen);
;
; OUT: ZF=1 on success, else ZF=0
;
randomx:
_randomx:
int3
    pushad    
    xor    esi, esi          ; u = 0    
    ; fd = open("/dev/urandom", O_RDONLY);
    push   SYS_open
    pop    eax
    call   open_rnd
    db     "/dev/urandom", 0
open_rnd:    
    pop    ebx
    xor    ecx, ecx          ; ecx = O_RDONLY  
    mov    edx, 0xFFF
    int    0x80
    ; if (fd >= 0)
    jl     exit_rnd          ; failed if fd < 0
    xchg   eax, ebx          ; ebx = fd
    
    ; for (u=0; u<outlen;)
    ; esi already set to zero
read_rnd:
    ; u < outlen
    cmp    esi, [esp+32+8]
    jae    close_rnd
    ; len = read(fd, p + u, outlen - u);
    push   SYS_read
    pop    eax
    mov    ecx, [esp+32+4]   ; ecx = &out[u]
    add    ecx, esi          ; 
    mov    edx, [esp+32+8]   ; edx = outlen - u   
    sub    edx, esi          ; 
    int    0x80
    ; if (len < 0) break;
    jl     close_rnd
upd_len:    
    ; u += len
    add    esi, eax
    jmp    read_rnd    
close_rnd:
    pushfd                   ; save flags
    ; close(fd);
    push   SYS_close
    pop    eax
    int    0x80
    popfd                    ; restore flags
exit_rnd:
    ; return u == outlen   
    popad
    ret
    