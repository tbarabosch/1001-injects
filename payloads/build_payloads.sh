#!/bin/bash

function delete_file_if_exists {
    if [ -e $1 ] ; then
	rm $1
    fi
}

function build_elf {
    nasm -f elf64 $1.asm
    ld $1.o -o $1.elf	
    delete_file_if_exists $1.o
}

function build_shellcode {
    build_elf $1
    objcopy --output-target=binary --only-section=.text $1.elf $1.bin
    delete_file_if_exists $1.elf
}

echo "Building demo shellcode"
build_shellcode "raw_shellcode"

echo "Building sys_clone_payload"
build_shellcode "sys_clone_payload"

echo "Building pthread_payload"
build_shellcode "pthread_payload"

echo "Building simple ELF"
build_elf "raw_shellcode"
if [ -e raw_shellcode.elf ] ; then
   mv raw_shellcode.elf simple.elf
fi

echo "Building shared library"
make
