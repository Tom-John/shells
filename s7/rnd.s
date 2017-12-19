	.file	"rnd.c"
	.intel_syntax noprefix
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"\n // %s"
.LC1:
	.string	" 0x%02x,"
	.text
	.globl	bin2hex
	.type	bin2hex, @function
bin2hex:
.LFB2:
	.cfi_startproc
	push	ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	mov	ebp, esp
	.cfi_def_cfa_register 5
	push	edi
	push	esi
	push	ebx
	.cfi_offset 7, -12
	.cfi_offset 6, -16
	.cfi_offset 3, -20
	xor	edi, edi
	call	__x86.get_pc_thunk.bx
	add	ebx, OFFSET FLAT:_GLOBAL_OFFSET_TABLE_
	sub	esp, 20
	push	DWORD PTR 8[ebp]
	lea	eax, .LC0@GOTOFF[ebx]
	lea	esi, .LC1@GOTOFF[ebx]
	push	eax
	call	printf@PLT
	add	esp, 16
.L2:
	cmp	edi, DWORD PTR 16[ebp]
	jge	.L7
	test	edi, 7
	jne	.L3
	sub	esp, 12
	push	10
	call	putchar@PLT
	add	esp, 16
.L3:
	push	eax
	push	eax
	mov	eax, DWORD PTR 12[ebp]
	movzx	eax, BYTE PTR [eax+edi]
	inc	edi
	push	eax
	push	esi
	call	printf@PLT
	add	esp, 16
	jmp	.L2
.L7:
	sub	esp, 12
	push	10
	call	putchar@PLT
	add	esp, 16
	lea	esp, -12[ebp]
	pop	ebx
	.cfi_restore 3
	pop	esi
	.cfi_restore 6
	pop	edi
	.cfi_restore 7
	pop	ebp
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE2:
	.size	bin2hex, .-bin2hex
	.section	.rodata.str1.1
.LC2:
	.string	"/dev/urandom"
	.text
	.globl	random
	.type	random, @function
random:
.LFB3:
	.cfi_startproc
	push	ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	mov	ebp, esp
	.cfi_def_cfa_register 5
	push	edi
	push	esi
	push	ebx
	.cfi_offset 7, -12
	.cfi_offset 6, -16
	.cfi_offset 3, -20
	xor	esi, esi
	call	__x86.get_pc_thunk.bx
	add	ebx, OFFSET FLAT:_GLOBAL_OFFSET_TABLE_
	sub	esp, 20
	lea	eax, .LC2@GOTOFF[ebx]
	push	0
	push	eax
	call	open@PLT
	add	esp, 16
	test	eax, eax
	mov	edi, eax
	js	.L9
.L10:
	cmp	esi, DWORD PTR 12[ebp]
	jnb	.L14
	push	eax
	mov	eax, DWORD PTR 12[ebp]
	sub	eax, esi
	push	eax
	mov	eax, DWORD PTR 8[ebp]
	add	eax, esi
	push	eax
	push	edi
	call	read@PLT
	add	esp, 16
	test	eax, eax
	jns	.L11
	call	__errno_location@PLT
	cmp	DWORD PTR [eax], 4
	je	.L10
.L14:
	sub	esp, 12
	push	edi
	call	close@PLT
	add	esp, 16
	jmp	.L9
.L11:
	add	esi, eax
	jmp	.L10
.L9:
	xor	eax, eax
	cmp	esi, DWORD PTR 12[ebp]
	sete	al
	lea	esp, -12[ebp]
	pop	ebx
	.cfi_restore 3
	pop	esi
	.cfi_restore 6
	pop	edi
	.cfi_restore 7
	pop	ebp
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE3:
	.size	random, .-random
	.section	.rodata.str1.1
.LC3:
	.string	"random"
	.section	.text.startup,"ax",@progbits
	.globl	main
	.type	main, @function
main:
.LFB4:
	.cfi_startproc
	lea	ecx, 4[esp]
	.cfi_def_cfa 1, 0
	and	esp, -16
	push	DWORD PTR -4[ecx]
	push	ebp
	.cfi_escape 0x10,0x5,0x2,0x75,0
	mov	ebp, esp
	push	esi
	push	ebx
	push	ecx
	.cfi_escape 0xf,0x3,0x75,0x74,0x6
	.cfi_escape 0x10,0x6,0x2,0x75,0x7c
	.cfi_escape 0x10,0x3,0x2,0x75,0x78
	lea	ebx, -88[ebp]
	call	__x86.get_pc_thunk.si
	add	esi, OFFSET FLAT:_GLOBAL_OFFSET_TABLE_
	sub	esp, 84
	push	64
	push	ebx
	call	random
	add	esp, 16
	test	eax, eax
	je	.L18
	push	eax
	lea	eax, .LC3@GOTOFF[esi]
	push	64
	push	ebx
	push	eax
	call	bin2hex
	add	esp, 16
.L18:
	lea	esp, -12[ebp]
	xor	eax, eax
	pop	ecx
	.cfi_restore 1
	.cfi_def_cfa 1, 0
	pop	ebx
	.cfi_restore 3
	pop	esi
	.cfi_restore 6
	pop	ebp
	.cfi_restore 5
	lea	esp, -4[ecx]
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE4:
	.size	main, .-main
	.section	.text.__x86.get_pc_thunk.bx,"axG",@progbits,__x86.get_pc_thunk.bx,comdat
	.globl	__x86.get_pc_thunk.bx
	.hidden	__x86.get_pc_thunk.bx
	.type	__x86.get_pc_thunk.bx, @function
__x86.get_pc_thunk.bx:
.LFB5:
	.cfi_startproc
	mov	ebx, DWORD PTR [esp]
	ret
	.cfi_endproc
.LFE5:
	.section	.text.__x86.get_pc_thunk.si,"axG",@progbits,__x86.get_pc_thunk.si,comdat
	.globl	__x86.get_pc_thunk.si
	.hidden	__x86.get_pc_thunk.si
	.type	__x86.get_pc_thunk.si, @function
__x86.get_pc_thunk.si:
.LFB6:
	.cfi_startproc
	mov	esi, DWORD PTR [esp]
	ret
	.cfi_endproc
.LFE6:
	.ident	"GCC: (Debian 6.3.0-18) 6.3.0 20170516"
	.section	.note.GNU-stack,"",@progbits
