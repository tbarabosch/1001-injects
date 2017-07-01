CC=clang
CFLAGS=-ggdb -std=gnu99 -I/usr/local/include -I./injections
LINKERFLAGS=-L/usr/local/lib -lzlog -lpthread -ldl
DEPS = 1001-injects.h zlog.h inject_library_dlopen.h utils.h ptrace.h inject_shellcode_hijack_thread.h inject_shellcode_new_thread.h inject_shellcode_new_pthread.h inject_simple_elf_dev_mem.h
OBJ = 1001-injects.o ptrace.o utils.o injections/inject_library_dlopen.o injections/inject_shellcode_hijack_thread.o injections/inject_shellcode_new_thread.o injections/inject_shellcode_new_pthread.o injections/inject_simple_elf_dev_mem.o

.DEFAULT_GOAL := 1001-injects

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

1001-injects: $(OBJ)
	$(CC) -o $@.elf $^ $(LINKERFLAGS)

.PHONY: clean
clean:
	-rm 1001-injects.elf *.o
