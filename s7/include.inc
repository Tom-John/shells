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

struc crypto_ctx
  ctr  resb  8     ; 64-bit counter + nonce
  ekey resb 16     ; 128-bit encryption key
  mkey resb 32     ; 256-bit mac key
endstruc

%ifndef WIN

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

%else
  %define FD_MAX_EVENTS 10
  %define FD_CLOSE      16
  %define BUFSIZ        64
  
  struc SECURITY_ATTRIBUTES
    nLength              resd 1
    lpSecurityDescriptor resd 1
    bInheritHandle       resd 1
  endstruc
  
  struc WSANETWORKEVENTS
    lNetworkEvents resd 1
    iErrorCode     resd FD_MAX_EVENTS
  endstruc
  
  struc OVERLAPPED
    Internal     resd 1
    InternalHigh resd 1
    Pointer      resd 1
    Offset       equ Pointer
    OffsetHigh   equ Pointer
    hEvent       resd 1    
  endstruc
  
  struc PROCESS_INFORMATION
    hProcess    resd 1
    hThread     resd 1
    dwProcessId resd 1
    dwThreadId  resd 1
  endstruc
  
  struc STARTUPINFO
    cb              resd 1
    lpReserved      resd 1
    lpDesktop       resd 1
    lpTitle         resd 1
    dwX             resd 1
    dwY             resd 1
    dwXSize         resd 1
    dwYSize         resd 1
    dwXCountChars   resd 1
    dwYCountChars   resd 1
    dwFillAttribute resd 1
    dwFlags         resd 1
    wShowWindow     resw 1
    cbReserved2     resw 1
    lpReserved2     resd 1
    hStdInput       resd 1
    hStdOutput      resd 1
    hStdError       resd 1
  endstruc
  
  ; data structure
  struc ds_tbl
    @ne      resb WSANETWORKEVENTS_size
    @p       resd 1
    @lap     resb OVERLAPPED_size
    @s       resd 1
    @out1    resd 1
    @in0     resd 1
    @in1     resd 1
    @out0    resd 1
    @evt0    resd 1
    @evt1    resd 1
    @si      resb STARTUPINFO_size
    @pi      equ @si    
    @len     resd 1
    @buf     resb BUFSIZ+SPP_MAC_LEN
    @ctx     resb crypto_ctx_size
  endstruc
  
  ; code structure
  struc cs_tbl
    ; kernel32
    @TerminateProcess       resd 1
    @CreateProcess          resd 1
    @CreateEvent            resd 1
    @WaitForMultipleObjects resd 1
    @CloseHandle            resd 1
    @WriteFile              resd 1
    @ReadFile               resd 1
    @GetOverlappedResult    resd 1
    @CreateFile             resd 1
    @CreatePipe             resd 1
    @CreateNamedPipe        resd 1
    
    ; ws2_32 
    @socket                 resd 1
    @connect                resd 1
    @send                   resd 1
    @recv                   resd 1
    @closesocket            resd 1
    @WSAEventSelect         resd 1  
    @WSACreateEvent         resd 1
    @WSAEnumNetworkEvents   resd 1 
    @ioctlsocket            resd 1
  endstruc  
  
  %macro xcall 1.nolist
    call dword[ebp-%1]
  %endmacro
%endif
  
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
