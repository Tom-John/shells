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

%define SPP_MAC_LEN   8               ; 64-bits
%define SPP_CTR_LEN   8               ; 64-bits
%define SPP_EKEY_LEN  16              ; 128-bits              
%define SPP_MKEY_LEN  32              ; 256-bits 

%define SPP_ENCRYPT   0
%define SPP_DECRYPT   1

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
%define SYS_LISTEN      4   
%define SYS_ACCEPT      5 
%define SYS_GETSOCKNAME 6   
%define SYS_GETPEERNAME 7   
%define SYS_SOCKETPAIR  8   
%define SYS_SEND        9   
%define SYS_RECV       10 
%define SYS_SENDTO     11   
%define SYS_RECVFROM   12   
%define SYS_SHUTDOWN   13   
%define SYS_SETSOCKOPT 14 
%define SYS_GETSOCKOPT 15   
%define SYS_SENDMSG    16   
%define SYS_RECVMSG    17     
%define SYS_ACCEPT4    18   
%define SYS_RECVMMSG   19 
%define SYS_SENDMMSG   20 

%define SIGCHLD 20
%define BUFSIZ  128

%define SHUT_RDWR     1

struc epoll_event
  events resd 1
  data   resd 1
endstruc

struc crypto_ctx
  ctr  resb  8     ; 64-bit counter + nonce
  ekey resb 16     ; 128-bit encryption key
  mkey resb 32     ; 256-bit mac key
endstruc
         
struc sc_prop
  p_in  resd 2     ; pipe for stdin of shell
  p_out resd 2     ; pipe for stdout/stderr of shell
  pid   resd 1     ; process id for shell
  s     resd 1     ; socket handle
  s2    resd 1     ; socket for bind
  efd   resd 1     ; event handle
  evts  resb epoll_event_size
  buf   resb BUFSIZ
  mac   resb 8     ; for mac
  ctx   resb crypto_ctx_size
endstruc
 
struc pushad_t
  _edi resd 1
  _esi resd 1
  _ebp resd 1
  _esp resd 1
  _ebx resd 1
  _edx resd 1
  _ecx resd 1
  _eax resd 1
  .size:
endstruc
