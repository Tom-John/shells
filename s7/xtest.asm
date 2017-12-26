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

    bits 32
    
    global key_xchg_x86
    global _key_xchg_x86
    
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

key_xchg_x86:
_key_xchg_x86:
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
      ;call   spp_send
      
      ; receive B from Bob      
      ;call   spp_recv
      
      ; Alice computes key: s = B ^ x mod p
      mov    mx_base, edi    ; set base B
      mov    mx_res, [esp+s] ; set result buffer
      mov    mx_exp, [esp+x] ; set exponent
      call   modexp
      popad
      
      ; reset the counter, set the encryption + mac keys
      xor    eax, eax
      mov    edi, [ebp+ctx]
      rep    movsb            ; set encryption + mac keys
      
      ; release stack
      mov    ch, 5
      add    esp, ecx
      popad
      ret
      
%include "mxp.asm"
%include "rnx.asm"

