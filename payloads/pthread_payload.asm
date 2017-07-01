;; payload to create new remote thread
;; borrows a lot of code from https://github.com/skeeto/pure-linux-threads-demo/blob/master/threads-x86_64.s
;; see also the corresponding blog post http://nullprogram.com/blog/2015/05/15/
bits 64
global _start
	
;; sys/syscall.h
%define SYS_mmap	9
%define SYS_clone	56

;; sched.h
%define CLONE_VM	0x00000100
%define CLONE_FS	0x00000200
%define CLONE_FILES	0x00000400
%define CLONE_SIGHAND	0x00000800
%define CLONE_PARENT	0x00008000
%define CLONE_THREAD	0x00010000
%define CLONE_IO	0x80000000

;; sys/mman.h
%define MAP_GROWSDOWN	0x0100
%define MAP_ANONYMOUS	0x0020
%define MAP_PRIVATE	0x0002
%define PROT_READ	0x1
%define PROT_WRITE	0x2
%define PROT_EXEC	0x4

%define THREAD_FLAGS \
 CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO

%define STACK_SIZE	(4096 * 1024)

section .text
_start:
;; setup buffer for shellcode
        xor   r8, r8
	dec   r8     
        xor   r9, r9
	mov rdi, 0
	mov rsi, 4096
	mov rdx, PROT_WRITE | PROT_READ | PROT_EXEC 
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE
	mov rax, SYS_mmap
        syscall
	push rax
	
;; setup space for pthread_t
        xor   r8, r8
	dec   r8     
        xor   r9, r9
	mov rdi, 0
	mov rsi, 128
	mov rdx, PROT_WRITE | PROT_READ | PROT_EXEC 
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE
	mov rax, SYS_mmap
	syscall

;; create new thread 
	mov rdi, rax
	xor rax, rax
	xor rsi, rsi
	pop rdx
	xor rcx, rcx
	int 3
	call r11
        int 3

