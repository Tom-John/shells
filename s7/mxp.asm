;
;  Copyright © 2016, 2017 Odzhan, Peter Ferrie. All Rights Reserved.
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

; -----------------------------------------------
; Modular Exponentiation in x86 assembly
; -----------------------------------------------

  bits 32
  
  %ifndef BIN
    global _modexp
    global modexp
  %endif

  ; IN: ebx = exponent, esi = base, edi = result
_modexp:
modexp:
      pushad    
      call   set_m
modp_group:    
      ; https://www.ietf.org/rfc/rfc3526.txt
      db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
      db 0x68, 0xaa, 0xac, 0x8a, 0x5a, 0x8e, 0x72, 0x15
      db 0x10, 0x05, 0xfa, 0x98, 0x18, 0x26, 0xd2, 0x15
      db 0xe5, 0x6a, 0x95, 0xea, 0x7c, 0x49, 0x95, 0x39
      db 0x18, 0x17, 0x58, 0x95, 0xf6, 0xcb, 0x2b, 0xde
      db 0xc9, 0x52, 0x4c, 0x6f, 0xf0, 0x5d, 0xc5, 0xb5
      db 0x8f, 0xa2, 0x07, 0xec, 0xa2, 0x83, 0x27, 0x9b
      db 0x03, 0x86, 0x0e, 0x18, 0x2c, 0x77, 0x9e, 0xe3
      db 0x3b, 0xce, 0x36, 0x2e, 0x46, 0x5e, 0x90, 0x32
      db 0x7c, 0x21, 0x18, 0xca, 0x08, 0x6c, 0x74, 0xf1
      db 0x04, 0x98, 0xbc, 0x4a, 0x4e, 0x35, 0x0c, 0x67
      db 0x6d, 0x96, 0x96, 0x70, 0x07, 0x29, 0xd5, 0x9e
      db 0xbb, 0x52, 0x85, 0x20, 0x56, 0xf3, 0x62, 0x1c
      db 0x96, 0xad, 0xa3, 0xdc, 0x23, 0x5d, 0x65, 0x83
      db 0x5f, 0xcf, 0x24, 0xfd, 0xa8, 0x3f, 0x16, 0x69
      db 0x9a, 0xd3, 0x55, 0x1c, 0x36, 0x48, 0xda, 0x98
      db 0x05, 0xbf, 0x63, 0xa1, 0xb8, 0x7c, 0x00, 0xc2
      db 0x3d, 0x5b, 0xe4, 0xec, 0x51, 0x66, 0x28, 0x49
      db 0xe6, 0x1f, 0x4b, 0x7c, 0x11, 0x24, 0x9f, 0xae
      db 0xa5, 0x9f, 0x89, 0x5a, 0xfb, 0x6b, 0x38, 0xee
      db 0xed, 0xb7, 0x06, 0xf4, 0xb6, 0x5c, 0xff, 0x0b
      db 0x6b, 0xed, 0x37, 0xa6, 0xe9, 0x42, 0x4c, 0xf4
      db 0xc6, 0x7e, 0x5e, 0x62, 0x76, 0xb5, 0x85, 0xe4
      db 0x45, 0xc2, 0x51, 0x6d, 0x6d, 0x35, 0xe1, 0x4f
      db 0x37, 0x14, 0x5f, 0xf2, 0x6d, 0x0a, 0x2b, 0x30
      db 0x1b, 0x43, 0x3a, 0xcd, 0xb3, 0x19, 0x95, 0xef
      db 0xdd, 0x04, 0x34, 0x8e, 0x79, 0x08, 0x4a, 0x51
      db 0x22, 0x9b, 0x13, 0x3b, 0xa6, 0xbe, 0x0b, 0x02
      db 0x74, 0xcc, 0x67, 0x8a, 0x08, 0x4e, 0x02, 0x29
      db 0xd1, 0x1c, 0xdc, 0x80, 0x8b, 0x62, 0xc6, 0xc4
      db 0x34, 0xc2, 0x68, 0x21, 0xa2, 0xda, 0x0f, 0xc9
      db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
set_m:
      pop    ebp    
      xor    ecx, ecx
      mov    ch, 1  ; set_m - modp_group
      push   1
      pop    edx               ; edx = x=1
      db     0b0h              ; mov al, 0x60 to mask pushad
mulmod:
      pushad                   ; save registers
  ; cf=1 : r = mulmod (r, t, m);
  ; cf=0 : t = mulmod (t, t, m);
      push   edi               ; save edi
      ; r=x
      sub    esp, ecx          ; create space for r and assign x
      ; t=b
      sub    esp, ecx          ; create space for t and assign b
      mov    edi, esp
      push   ecx
      rep    movsb
      pop    ecx
      mov    esi, esp
      pushad
      dec    ecx               ; skip 1
      xchg   eax, edx          ; r=x
      stosb
      xor    al, al            ; zero remainder of buffer
      rep    stosb
      popad
      call    ld_fn
    
; cf=1 : r = addmod (r, t, m);
; cf=0 : t = addmod (t, t, m);

; ebp  : m
; esi  : t
; edi  : r or t
; ecx  : size in bytes
;
addmod:
      shr     ecx, 2            ; /= 4
      clc
      pushad
am_l1:
      lodsd
      adc     eax, [edi]
      stosd
      loop    am_l1
      popad
      mov     esi, ebp
      push    ecx
      dec     ecx
am_l2:
      mov     eax, [edi+ecx*4]
      cmp     eax, [esi+ecx*4]
      loope   am_l2
      pop     ecx
      jb      am_l4
am_l3:
      mov     eax, [edi]
      sbb     eax, [esi]
      stosd
      lodsd
      loop    am_l3
am_l4:
      ret
    ; -----------------------------
ld_fn:
      dec     edx
      js      cntbits
      sub     dword[esp], addmod - mulmod
cntbits:
      xor     edx, edx
      lea     eax, [edx+ecx*8]
cnt_l1:
      dec     eax
      jz      xm_l1
      bt      [ebx], eax
      jnc     cnt_l1
xm_l1:
      ; if (e & 1)
      bt      [ebx], edx
xm_l2:
      pushfd
      pushad
      cdq
      cmovnc  edi, esi          ; if (cf==0) do t = xmod(t, t, m)
      mov     ebx, edi          ; else r = xmod(r, t, m)
      call    dword[esp+32+4]   ; invoke mulmod or addmod
      popad
      popfd
      cmc
      jnc     xm_l2
    
      inc     edx
      dec     eax
      jns     xm_l1

      ; return r
      mov     esi, edi
      lea     esp, [esp+ecx*2+4]
      pop     edi
      rep     movsb
      popad
      ret
