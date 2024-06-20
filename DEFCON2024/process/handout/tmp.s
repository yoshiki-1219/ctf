	.file	"tmp.c"
	.intel_syntax noprefix
	.text
	.globl	main
	.type	main, @function
main:
	endbr64
	push	rbp
	mov	rbp, rsp
	sub	rsp, 192
	call	getppid@PLT
	mov	DWORD PTR -4[rbp], eax
	movabs	rax, 7016996765293437281
	movabs	rdx, 7089336938131513954
	mov	QWORD PTR -160[rbp], rax
	mov	QWORD PTR -152[rbp], rdx
	movabs	rax, 7161677110969590627
	movabs	rdx, 7234017283807667300
	mov	QWORD PTR -144[rbp], rax
	mov	QWORD PTR -136[rbp], rdx
	movabs	rax, 7306357456645743973
	movabs	rdx, 7378697629483820646
	mov	QWORD PTR -128[rbp], rax
	mov	QWORD PTR -120[rbp], rdx
	movabs	rax, 7451037802321897319
	movabs	rdx, 7523377975159973992
	mov	QWORD PTR -112[rbp], rax
	mov	QWORD PTR -104[rbp], rdx
	movabs	rax, 7595718147998050665
	movabs	rdx, 7668058320836127338
	mov	QWORD PTR -96[rbp], rax
	mov	QWORD PTR -88[rbp], rdx
	movabs	rax, 7740398493674204011
	movabs	rdx, 7812738666512280684
	mov	QWORD PTR -80[rbp], rax
	mov	QWORD PTR -72[rbp], rdx
	movabs	rax, 7885078839350357357
	movabs	rdx, 7957419012188434030
	mov	QWORD PTR -64[rbp], rax
	mov	QWORD PTR -56[rbp], rdx
	movabs	rax, 8029759185026510703
	movabs	rdx, 8102099357864587376
	mov	QWORD PTR -48[rbp], rax
	mov	QWORD PTR -40[rbp], rdx
	lea	rax, -160[rbp]
	mov	QWORD PTR -176[rbp], rax
	mov	QWORD PTR -168[rbp], 128
	mov	eax, 3735928559
	mov	QWORD PTR -16[rbp], rax
	mov	rax, QWORD PTR -16[rbp]
	mov	QWORD PTR -192[rbp], rax
	mov	QWORD PTR -184[rbp], 128
	lea	rdx, -192[rbp]
	lea	rsi, -176[rbp]
	mov	eax, DWORD PTR -4[rbp]
	mov	r9d, 0
	mov	r8d, 1
	mov	rcx, rdx
	mov	edx, 1
	mov	edi, eax
	mov	eax, 0
	call	process_vm_writev@PLT
	cdqe
	mov	QWORD PTR -24[rbp], rax
	mov	eax, 0
	leave
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
