CC=clang
CFLAGS=-I.

.DEFAULT_GOAL := victim

victim: victim.o
	$(CC) -o victim.elf victim.o -I. -ldl -lpthread

.PHONY: clean 
clean:
	-rm *.o victim.elf
